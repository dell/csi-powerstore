/*
 *
 * Copyright © 2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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

	"github.com/dell/csi-powerstore/pkg/array"
	"github.com/dell/csi-powerstore/pkg/common"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gopowerstore"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// end points
const (
	nodeStatus  = "/node-status"
	arrayStatus = "/array-status"
)

// pollingFrequency in seconds
var pollingFrequencyInSeconds int64

// port for API calls
var apiPort string

// probeStatus map[string]ArrayConnectivityStatus
var probeStatus *sync.Map

// ArrayConnectivityStatus Status of the array probe
type ArrayConnectivityStatus struct {
	LastSuccess int64 `json:"lastSuccess"` // connectivity status
	LastAttempt int64 `json:"lastAttempt"` // last timestamp attempted to check connectivity
}

// startAPIService reads nodes to array status periodically
func (s *Service) startAPIService(ctx context.Context) {
	if !s.isPodmonEnabled {
		log.Info("podmon is not enabled")
		return
	}
	pollingFrequencyInSeconds = common.SetPollingFrequency(ctx)
	setAPIPort(ctx)
	s.startNodeToArrayConnectivityCheck(ctx)
	s.apiRouter(ctx)
}

// setAPIPort set the port for running server
func setAPIPort(ctx context.Context) {
	if port, ok := csictx.LookupEnv(ctx, common.EnvPodmonAPIPORT); ok && strings.TrimSpace(port) != "" {
		apiPort = fmt.Sprintf(":%s", port)
		log.Debugf("set podmon API port to %s", apiPort)
		return
	}
	// If the port number cannot be fetched, set it to default
	apiPort = ":" + common.DefaultPodmonAPIPortNumber
	log.Debugf("set podmon API port to default %s", apiPort)
}

// apiRouter serves http requests
func (s *Service) apiRouter(ctx context.Context) {
	log.Infof("starting http server on port %s", apiPort)
	// create a new mux router
	router := mux.NewRouter()
	// route to connectivity status
	// nodeHealth & connectivityStatus are the handlers
	router.HandleFunc(nodeStatus, nodeHealth).Methods("GET")
	router.HandleFunc(arrayStatus, connectivityStatus).Methods("GET")
	router.HandleFunc(arrayStatus+"/"+"{arrayId}", getArrayConnectivityStatus).Methods("GET")
	// start http server to serve requests
	server := &http.Server{
		Addr:         apiPort,
		Handler:      router,
		ReadTimeout:  common.Timeout,
		WriteTimeout: common.Timeout,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Errorf("unable to start http server to serve status requests due to %s", err)
	}
}

// nodeHealth handler states if the node is up
func nodeHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "node is up and running \n")
}

// connectivityStatus handler returns array connectivity status
func connectivityStatus(w http.ResponseWriter, r *http.Request) {
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
	_, err = w.Write(jsonResponse)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		log.Errorf("unable to write response %s", err)
	}
}

// MarshalSyncMapToJSON marshal the sync Map to Json
func MarshalSyncMapToJSON(m *sync.Map) ([]byte, error) {
	tmpMap := make(map[string]ArrayConnectivityStatus)
	m.Range(func(k, value interface{}) bool {
		// this check is not necessary but just in case is someone in future play around this
		switch value.(type) {
		case ArrayConnectivityStatus:
			tmpMap[k.(string)] = value.(ArrayConnectivityStatus)
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
	//convert status struct to JSON
	jsonResponse, err := json.Marshal(status)
	if err != nil {
		log.Errorf("error %s during marshaling to json", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		return
	}
	log.Infof("sending response %+v for array %s \n", status, arrayID)
	//update response
	w.WriteHeader(http.StatusOK)
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
	// this could be an improvement ...?
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
			log.Errorf("panic occurred in testConnectivityAndUpdateStatus:%s for clsuter %v", err, array)
		}
		// if panic occurs restart new goroutine
		go s.testConnectivityAndUpdateStatus(ctx, array, timeout)
	}()
	var status ArrayConnectivityStatus
	for {
		// add timeout to context
		timeOutCtx, cancel := context.WithTimeout(ctx, timeout)
		log.Debugf("Running probe for array %s at time %v \n", array.GlobalID, time.Now())
		if existingStatus, ok := probeStatus.Load(array.GlobalID); !ok {
			log.Debugf("%s not in probeStatus ", array.GlobalID)
		} else {
			if status, ok = existingStatus.(ArrayConnectivityStatus); !ok {
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
func (s *Service) nodeProbe(timeOutCtx context.Context, array *array.PowerStoreArray) error {
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
	log.Debugf("Successfully got Host for %s", array.GlobalID)

	for _, initiator := range host.Initiators {
		if len(initiator.ActiveSessions) > 0 {
			// iscsiConnection = true
			return nil
		}
	}
	log.Errorf("initiators for the host is not present")
	return fmt.Errorf("initiators for the host is not present")
}
