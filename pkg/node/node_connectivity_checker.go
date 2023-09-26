/*
 *
 * Copyright © 2022-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/goiscsi"
	"github.com/dell/gonvme"
	"github.com/dell/gopowerstore"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// pollingFrequency in seconds
var pollingFrequencyInSeconds int64

// probeStatus map[string]ArrayConnectivityStatus
var probeStatus *sync.Map

// startAPIService reads nodes to array status periodically
func (s *Service) startAPIService(ctx context.Context) {
	if !s.isPodmonEnabled {
		log.Info("podmon is not enabled")
		return
	}
	pollingFrequencyInSeconds = common.SetPollingFrequency(ctx)
	s.startNodeToArrayConnectivityCheck(ctx)
	s.apiRouter(ctx)
}

// apiRouter serves http requests
func (s *Service) apiRouter(ctx context.Context) {
	log.Infof("starting http server on port %s", common.APIPort)
	// create a new mux router
	router := mux.NewRouter()
	// route to connectivity status
	// connectivityStatus is the handlers
	router.HandleFunc(common.ArrayStatus, connectivityStatus).Methods("GET")
	router.HandleFunc(common.ArrayStatus+"/"+"{arrayId}", getArrayConnectivityStatus).Methods("GET")
	// start http server to serve requests
	server := &http.Server{
		Addr:         common.APIPort,
		Handler:      router,
		ReadTimeout:  common.Timeout,
		WriteTimeout: common.Timeout,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Errorf("unable to start http server to serve status requests due to %s", err)
	}
}

// connectivityStatus handler returns array connectivity status
func connectivityStatus(w http.ResponseWriter, _ *http.Request) {
	log.Infof("connectivityStatus called, status is %v \n", probeStatus)
	// w.Header().Set("Content-Type", "application/json")
	if probeStatus == nil {
		log.Errorf("error probeStatus map in cache is empty")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		return
	}

	// convert struct to JSON
	log.Debugf("ProbeStatus fetched from the cache has %+v", probeStatus)

	jsonResponse, err := MarshalSyncMapToJSON(probeStatus)
	if err != nil {
		log.Errorf("error %s during marshaling to json", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		return
	}
	log.Info("sending connectivityStatus for all arrays ")
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonResponse)
	if err != nil {
		log.Errorf("unable to write response %s", err)
	}
}

// MarshalSyncMapToJSON marshal the sync Map to Json
func MarshalSyncMapToJSON(m *sync.Map) ([]byte, error) {
	tmpMap := make(map[string]common.ArrayConnectivityStatus)
	m.Range(func(k, value interface{}) bool {
		// this check is not necessary but just in case is someone in future play around this
		switch value.(type) {
		case common.ArrayConnectivityStatus:
			tmpMap[k.(string)] = value.(common.ArrayConnectivityStatus)
			return true
		default:
			log.Errorf("invalid data is stored in cache")
			return false
		}
	})
	log.Debugf("map value is %+v", tmpMap)
	if len(tmpMap) == 0 {
		return nil, fmt.Errorf("invalid data is stored in cache")
	}
	return json.Marshal(tmpMap)
}

// getArrayConnectivityStatus handler lists status of the requested array
func getArrayConnectivityStatus(w http.ResponseWriter, r *http.Request) {
	arrayID := mux.Vars(r)["arrayId"]
	log.Infof("GetArrayConnectivityStatus called for array %s \n", arrayID)
	status, found := probeStatus.Load(arrayID)
	if !found {
		// specify status code
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		// update response writer
		fmt.Fprintf(w, "array %s not found \n", arrayID)
		return
	}
	// convert status struct to JSON
	jsonResponse, err := json.Marshal(status)
	if err != nil {
		log.Errorf("error %s during marshaling to json", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		return
	}
	log.Infof("sending response %+v for array %s \n", status, arrayID)
	// update response
	_, err = w.Write(jsonResponse)
	if err != nil {
		log.Errorf("unable to write response %s", err)
	}
}

// startNodeToArrayConnectivityCheck starts connectivityTest as one goroutine for each array
func (s *Service) startNodeToArrayConnectivityCheck(ctx context.Context) {
	log.Debug("startNodeToArrayConnectivityCheck called")
	probeStatus = new(sync.Map)
	// in case if we want to store the status of default array, uncomment below line
	// powerStoreArray := s.DefaultArray()
	powerStoreArray := s.Arrays()
	for _, array := range powerStoreArray {
		// start one goroutine for each array, so each array's nodeProbe run concurrently
		// should we really store the status of all array instead of default one, currently podman query only default array?
		go s.testConnectivityAndUpdateStatus(ctx, array, common.Timeout)
	}
	log.Infof("startNodeToArrayConnectivityCheck is running probes at pollingFrequency %d ", pollingFrequencyInSeconds/2)
}

// testConnectivityAndUpdateStatus runs probe to test connectivity from node to array
// updates probeStatus map[array]ArrayConnectivityStatus
func (s *Service) testConnectivityAndUpdateStatus(ctx context.Context, array *array.PowerStoreArray, timeout time.Duration) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("panic occurred in testConnectivityAndUpdateStatus: %s for array having %s", err, array.GlobalID)
		}
		// if panic occurs restart new goroutine
		go s.testConnectivityAndUpdateStatus(ctx, array, timeout)
	}()
	var status common.ArrayConnectivityStatus
	for {
		// add timeout to context
		timeOutCtx, cancel := context.WithTimeout(ctx, timeout)
		log.Debugf("Running probe for array %s at time %v \n", array.GlobalID, time.Now())
		if existingStatus, ok := probeStatus.Load(array.GlobalID); !ok {
			log.Debugf("%s not in probeStatus ", array.GlobalID)
		} else {
			if status, ok = existingStatus.(common.ArrayConnectivityStatus); !ok {
				log.Errorf("failed to extract ArrayConnectivityStatus for array '%s'", array.GlobalID)
			}
		}
		// for the first time status will not be there.
		log.Debugf("array %s , status is %+v", array.GlobalID, status)
		// run nodeProbe to test connectivity
		err := s.nodeProbe(timeOutCtx, array)
		if err == nil {
			log.Debugf("Probe successful for %s", array.GlobalID)
			status.LastSuccess = time.Now().Unix()
		} else {
			log.Debugf("Probe failed for array '%s' error:'%s'", array.GlobalID, err)
		}
		status.LastAttempt = time.Now().Unix()
		log.Debugf("array %s , storing status %+v", array.GlobalID, status)
		probeStatus.Store(array.GlobalID, status)
		cancel()
		// sleep for half the pollingFrequency and run check again
		time.Sleep(time.Second * time.Duration(pollingFrequencyInSeconds/2))
	}
}

// nodeProbe function used to store the status of array
func (s *Service) nodeProbe(_ context.Context, array *array.PowerStoreArray) error {
	// try to get the host
	host, err := array.Client.GetHostByName(context.Background(), s.nodeID)
	// possibly NFS could be there.
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() && s.useNFS {
			log.Debugf("Error %s, while probing %s but since it's NFS this is expected", err.Error(), array.GlobalID)
			return nil
		}
		// nodeId is not right or it's not NFS and still host is not preset
		log.Infof("Error %s, while probing %s", err.Error(), array.GlobalID)
		return err
	}

	log.Debugf("Successfully got Host on %s", array.GlobalID)
	s.populateTargetsInCache(array)
	// check if nvme sessions are active
	if s.useNVME {
		log.Debugf("Checking if nvme sessions are active on node or not")
		sessions, _ := s.nvmeLib.GetSessions()
		for _, target := range s.nvmeTargets[array.GlobalID] {
			for _, session := range sessions {
				log.Debugf("matching %v with %v", target, session)
				if session.Target == target && session.NVMESessionState == gonvme.NVMESessionStateLive {
					if s.useNFS {
						s.useNFS = false
					}
					return nil
				}
			}
		}
		if s.useNFS {
			log.Infof("Host Entry found but failed to login to nvme target, seems to be this worker has only NFS")
			return nil
		}
		return fmt.Errorf("no active nvme sessions")
	} else if s.useFC {
		log.Debugf("Checking if FC sessions are active on node or not")
		for _, initiator := range host.Initiators {
			if len(initiator.ActiveSessions) > 0 {
				return nil
			}
		}
		return fmt.Errorf("no active fc sessions")
	} else {
		// check if iscsi sessions are active
		// if !s.useNVME && !s.useFC {
		log.Debugf("Checking if iscsi sessions are active on node or not")
		sessions, _ := s.iscsiLib.GetSessions()
		for _, target := range s.iscsiTargets[array.GlobalID] {
			for _, session := range sessions {
				log.Debugf("matching %v with %v", target, session)
				if session.Target == target && session.ISCSISessionState == goiscsi.ISCSISessionStateLOGGEDIN {
					if s.useNFS {
						s.useNFS = false
					}
					return nil
				}
			}
		}
		if s.useNFS {
			log.Infof("Host Entry found but failed to login to iscsi target, seems to be this worker has only NFS")
			return nil
		}
		return fmt.Errorf("no active iscsi sessions")
	}
}

// populateTargetsInCache checks if nvmeTargets or iscsiTargets in cache is empty, try to fetch the targets from array and populate the cache
func (s *Service) populateTargetsInCache(array *array.PowerStoreArray) {
	// if nvmeTargets in cache is empty
	// this could be empty in 2 cases: Either container is getting restarted or discovery & login has failed in NodeGetInfo
	if s.useNVME {
		if len(s.nvmeTargets[array.GlobalID]) != 0 {
			return
		}
		// for NVMeFC
		if s.useFC {
			nvmefcInfo, err := common.GetNVMEFCTargetInfoFromStorage(array.GetClient(), "")
			if err != nil {
				log.Errorf("couldn't get targets from the array: %s", err.Error())
				return
			}
			for _, info := range nvmefcInfo {
				NVMeFCTargets, err := s.nvmeLib.DiscoverNVMeFCTargets(info.Portal, false)
				if err != nil {
					log.Errorf("couldn't discover NVMeFC targets")
					continue
				}
				for _, target := range NVMeFCTargets {
					otherTargets := s.nvmeTargets[array.GlobalID]
					s.nvmeTargets[array.GlobalID] = append(otherTargets, target.TargetNqn)
				}
				break
			}
		} else {
			infoList, err := common.GetISCSITargetsInfoFromStorage(array.GetClient(), "")
			if err != nil {
				log.Errorf("couldn't get targets from array: %s", err.Error())
				return
			}

			for _, address := range infoList {
				nvmeIP := strings.Split(address.Portal, ":")
				log.Info("Trying to discover NVMe target from portal ", nvmeIP[0])
				nvmeTargets, err := s.nvmeLib.DiscoverNVMeTCPTargets(nvmeIP[0], false)
				if err != nil {
					log.Error("couldn't discover targets")
					continue
				}
				for _, target := range nvmeTargets {
					otherTargets := s.nvmeTargets[array.GlobalID]
					s.nvmeTargets[array.GlobalID] = append(otherTargets, target.TargetNqn)
				}
				break
			}
		}
	} else if !s.useFC && !s.useNFS {
		// if iscsiTargets in cache is empty
		if len(s.iscsiTargets[array.GlobalID]) != 0 {
			return
		}
		infoList, err := common.GetISCSITargetsInfoFromStorage(array.GetClient(), "")
		if err != nil {
			log.Errorf("couldn't get targets from array: %s", err.Error())
			return
		}

		var iscsiTargets []goiscsi.ISCSITarget
		for _, address := range infoList {
			// first check if this portal is reachable from this machine or not
			if ReachableEndPoint(address.Portal) {
				// doesn't matter how many portals are present, discovering from any one will list out all targets
				log.Info("Trying to discover iSCSI target from portal ", address.Portal)
				iscsiTargets, err = s.iscsiLib.DiscoverTargets(address.Portal, false)
				if err != nil {
					log.Error("couldn't discover targets")
					continue
				}
				for _, target := range iscsiTargets {
					otherTargets := s.iscsiTargets[array.GlobalID]
					s.iscsiTargets[array.GlobalID] = append(otherTargets, target.Target)
				}
				break
			} else {
				log.Debugf("Portal %s is not rechable from the node", address.Portal)
			}
		}

	}
}
