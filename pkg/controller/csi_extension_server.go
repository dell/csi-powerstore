/*
 *
 * Copyright © 2022-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	log "github.com/dell/csmlog"
	podmon "github.com/dell/dell-csi-extensions/podmon"
	"github.com/dell/gopowerstore"
	"github.com/go-openapi/strfmt"
)

// StateReady resembles ready state
const StateReady = "Ready"

// ValidateVolumeHostConnectivity menthod will be called by podmon sidecars to check host connectivity with array
func (s *Service) ValidateVolumeHostConnectivity(ctx context.Context, req *podmon.ValidateVolumeHostConnectivityRequest) (*podmon.ValidateVolumeHostConnectivityResponse, error) {
	log.WithContext(ctx).Infof("ValidateVolumeHostConnectivity called %+v", req)
	rep := &podmon.ValidateVolumeHostConnectivityResponse{
		Messages: make([]string, 0),
	}

	if (len(req.GetVolumeIds()) == 0 || len(req.GetArrayId()) == 0) && len(req.GetNodeId()) == 0 {
		// This is a nop call just testing the interface is present
		rep.Messages = append(rep.Messages, "ValidateVolumeHostConnectivity is implemented")
		return rep, nil
	}

	if req.GetNodeId() == "" {
		return nil, fmt.Errorf("the NodeID is a required field")
	}

	// Check node connectivity with array
	err := s.validateNodeConnectivity(ctx, req.GetArrayId(), req.GetNodeId(), req.GetVolumeIds(), rep)
	if err != nil {
		return nil, err
	}

	// Check for IOinProgress only when volumes IDs are present in the request
	if len(req.GetVolumeIds()) > 0 {
		err := s.validateVolumeIOProgress(ctx, req.GetVolumeIds(), rep)
		if err != nil {
			return nil, err
		}
	}

	log.WithContext(ctx).Infof("ValidateVolumeHostConnectivity reply %+v", rep)
	return rep, nil
}

// validateNodeConnectivity checks if the node is connected to the array
func (s *Service) validateNodeConnectivity(ctx context.Context, arrayID, nodeID string, volumeIDs []string, rep *podmon.ValidateVolumeHostConnectivityResponse) error {
	// create the map of all the array with array's GloabalID as key
	globalIDs := make(map[string]bool)
	globalID := arrayID
	if globalID == "" {
		if len(volumeIDs) == 0 {
			log.WithContext(ctx).Info("neither globalId nor volumeID is present in request")
			// need to put all arrays to check not only default array and not matched ID will be filtered later.
			for _, array := range s.Arrays() {
				globalIDs[array.GlobalID] = true
			}
		}

		for _, volID := range volumeIDs {
			volumeHandle, err := array.ParseVolumeID(ctx, volID, s.DefaultArray(), nil)
			if err != nil || (volumeHandle.LocalArrayGlobalID == "" && volumeHandle.RemoteArrayGlobalID == "") {
				log.WithContext(ctx).Errorf("unable to retrieve array's globalID after parsing volumeID")
				globalIDs[s.DefaultArray().GlobalID] = true
			} else {
				if volumeHandle.LocalArrayGlobalID != "" {
					globalIDs[volumeHandle.LocalArrayGlobalID] = true
				}

				if volumeHandle.RemoteArrayGlobalID != "" {
					globalIDs[volumeHandle.RemoteArrayGlobalID] = true
				}
			}
		}
	} else {
		globalIDs[globalID] = true
	}

	rep.Connected = false
	arrayConnection := make(map[string]bool)

	// Go through each of the globalIDs
	for globalID := range globalIDs {
		// Check if array is non-uniform and matches the node label
		arr, err := s.GetOneArray(globalID)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to get array %s: %s", globalID, err.Error())
			return err
		}
		if arr == nil {
			log.WithContext(ctx).Errorf("failed to find secret entry for array %s", globalID)
			return fmt.Errorf("failed to find secret entry for array %s", globalID)
		}

		if !arr.HasHostEntry(ctx, nodeID) {
			log.WithContext(ctx).Warnf("Not a match for node %s on array %s, skipping connectivity check", nodeID, globalID)
			continue
		}

		// Check if the array is visible from the node
		isConnected, msg, err := s.checkIfNodeIsConnected(ctx, globalID, nodeID)
		arrayConnection[globalID] = isConnected
		rep.Messages = append(rep.Messages, msg...)
		if err != nil {
			// consider timeout and host unreachable as not connected
			if err == context.DeadlineExceeded || errors.Is(err, syscall.EHOSTUNREACH) {
				log.WithContext(ctx).Warnf("ValidateVolumeHostConnectivity: check failed for node %s and array %s: %v", nodeID, globalID, err)
				rep.Connected = false
				continue
			}
			log.WithContext(ctx).Errorf("ValidateVolumeHostConnectivity: check failed for node %s and array %s: %v", nodeID, globalID, err)
			return err
		}
	}

	if len(arrayConnection) > 0 {
		// only report status as "connected" if all arrays are connected
		rep.Connected = true
		for _, isConnected := range arrayConnection {
			if !isConnected {
				rep.Connected = false
				break
			}
		}
	}

	return nil
}

// validateVolumeIOProgress checks if IO is in-progress for the volumes
func (s *Service) validateVolumeIOProgress(ctx context.Context, volumeIDs []string, rep *podmon.ValidateVolumeHostConnectivityResponse) error {
	// Get array config
	for _, volID := range volumeIDs {
		volume, err := array.ParseVolumeID(ctx, volID, s.DefaultArray(), nil)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to parse volumeID, %s, for querying IO metrics. err: %s", volID, err.Error())
			return err
		}
		isMetroVol := volume.IsMetro()

		localArray, err := s.GetOneArray(volume.LocalArrayGlobalID)
		if err != nil || localArray == nil {
			log.WithContext(ctx).Errorf("failed to get local array configuration for array %s for volume activity validation: %s",
				volume.LocalArrayGlobalID, err.Error())
			return err
		}

		// set to nil to avoid unnecessary API calls by subsequent iterations
		var remoteArray *array.PowerStoreArray
		if isMetroVol {
			remoteArray, err = s.GetOneArray(volume.RemoteArrayGlobalID)
			if err != nil {
				log.WithContext(ctx).Errorf("failed to get remote array configuration for array %s for volume activity validation: %s",
					volume.RemoteArrayGlobalID, err.Error())
				return err
			}
		}

		// This context is for the set of requests for the current volume.
		// Used to cancel any pending requests before checking for IO on any
		// subsequent volumes.
		ioCtx, ioCtxCancel := context.WithCancel(ctx)
		defer ioCtxCancel()

		// channels for receiving responses from async requests
		reqChs := make([]<-chan error, 0)

		if isMetroVol && remoteArray != nil {
			metroResp, localDemoted, err := array.CheckMetroState(ioCtx, volume, localArray.Client, remoteArray.Client)
			if err != nil {
				// default to checking both sides if we can't get the metro state

				log.WithContext(ctx).Warnf("failed to determine metro fracture state for volume %s: %s, proceeding to check both sides", volID, err.Error())
				// check if any IO is inProgress for the current local globalID/array
				reqChs = append(reqChs, asyncGetIOInProgress(ioCtx, volume.LocalUUID, *localArray, volume.Protocol))
				// check if any IO is inProgress for the current remote globalID/array
				reqChs = append(reqChs, asyncGetIOInProgress(ioCtx, volume.RemoteUUID, *remoteArray, volume.Protocol))

			} else if metroResp.IsFractured {
				// if metro is fractured, we only want to check the promoted side,
				// because the other side might time out and delay the response.

				log.WithContext(ctx).Infof("metro volume %s is fractured, localDemoted: %v, checking only promoted side", volID, localDemoted)
				if localDemoted {
					// Local is demoted, so check remote (promoted) side
					reqChs = append(reqChs, asyncGetIOInProgress(ioCtx, volume.RemoteUUID, *remoteArray, volume.Protocol))
				} else {
					// Local is promoted, so check local side
					reqChs = append(reqChs, asyncGetIOInProgress(ioCtx, volume.LocalUUID, *localArray, volume.Protocol))
				}

			} else {
				// Not fractured, check both sides
				reqChs = append(reqChs, asyncGetIOInProgress(ioCtx, volume.LocalUUID, *localArray, volume.Protocol))
				reqChs = append(reqChs, asyncGetIOInProgress(ioCtx, volume.RemoteUUID, *remoteArray, volume.Protocol))
			}
		} else {
			// Non-metro volume, check local side only
			reqChs = append(reqChs, asyncGetIOInProgress(ioCtx, volume.LocalUUID, *localArray, volume.Protocol))
		}

		if rep.IosInProgress = isIOInProgress(ioCtx, reqChs...); rep.IosInProgress {
			// so long as at least one volume has IO in-progress
			// we should report it.
			// This status is effectively a logical OR of all the volumes
			ioCtxCancel()
			log.WithContext(ctx).Infof("IO detected for volume %s", volID)
			break
		}

		// make sure to cancel any pending requests from this iteration
		// so no goroutines are left running.
		ioCtxCancel()
	}

	log.WithContext(ctx).Infof("ValidateVolumeHostConnectivity reply %+v", rep)
	return nil
}

// waitAndClose waits for all goroutines to complete by waiting on the WaitGroup, wg,
// then closes the provided channel, ch.
func waitAndClose(wg *sync.WaitGroup, ch chan error) {
	log.Debugf("waiting to IO in-progress queries to complete")
	wg.Wait()
	// close the channel to signal there are no more results
	// to be processed and the receiver can move on
	log.Debugf("all goroutines complete; closing the channel")
	close(ch)
}

// isIOInProgress listens for responses on channels returned by asyncGetIOInProgress using the
// fan-in concurrency pattern and returns true if at least one response is a nil error,
// denoting IO is in-progress.
func isIOInProgress(ctx context.Context, chs ...<-chan error) bool {
	// single channel on which the channels in "chs" will write their results
	errCh := make(chan error)
	wg := &sync.WaitGroup{}

	// writes results from all channels to a single channel so the results can be
	// received as they're made available
	asyncReceiveWithCtx := func(ctx context.Context, errCh chan<- error, repCh <-chan error, wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			// read the channel until it is closed
			case err, isOpen := <-repCh:
				if !isOpen {
					return
				}
				errCh <- err
			}
		}
	}

	// Used to exit early if there is no IO in-progress
	ioCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	wg.Add(len(chs))
	for _, ch := range chs {
		go asyncReceiveWithCtx(ioCtx, errCh, ch, wg)
	}

	// make sure to close errCh when all asyncReceiveWithCtx goroutines are done
	// to signal to the range statement below that there are no more results.
	go waitAndClose(wg, errCh)

	// Read results as they're ready.
	// If the errCh channel is closed before a nil error is
	// received, assume there is no IO in-progress.
	for err := range errCh {
		if err != nil {
			log.WithContext(ctx).Debugf("error received while validating volume connectivity: %s", err.Error())
			continue
		}

		// cancel any remaining goroutines so we can report IO in-progress ASAP
		// and we don't leave any goroutines blocking, trying to write to the channel.
		cancel()
		log.WithContext(ctx).Info("IO in-progress detected while validating volume connectivity")
		return true
	}

	log.WithContext(ctx).Info("no IO in-progress was detected while validating volume connectivity")
	return false
}

// asyncGetIOInProgress starts an async request to getIOInProgress and returns a channel
// on which the result can be received.
// It can be used to dispatch multiple requests in parallel for situations such as metro
// volumes where multiple volumes need to be checked for IO to determine if the volume is active.
func asyncGetIOInProgress(ctx context.Context, volID string, array array.PowerStoreArray, protocol string) <-chan error {
	errCh := make(chan error)
	go func() {
		defer close(errCh)
		log.WithContext(ctx).Infof("checking if IO is in-progress for volume %s on array %s", volID, array.GlobalID)

		// This blocks until both functions have been evaluated, which can be slow.
		// Only then can the select statement determine which case to execute. If context has
		// been canceled when the function returns, don't try to write anything to the channel
		// because there will likely be no listeners and the select will block forever
		// if the channel is not read.
		select {
		case errCh <- getIOInProgress(ctx, volID, array, protocol):
		case <-ctx.Done():
			log.WithContext(ctx).Errorf("context deadline exceeded while querying for IOs in-progress for volume %s on array %s", volID, array.GlobalID)
		}
	}()
	return errCh
}

// buildNodeConnectivityURL constructs the URL used to query the node connectivity
// checker on a given node. It extracts the last IP from nodeID and uses
// net.JoinHostPort to correctly bracket IPv6 addresses (Bug-H.2).
// This is a pure function with no network dependency, making it directly testable.
func buildNodeConnectivityURL(nodeID, port, arrayID string) (string, error) {
	nodeIPs := identifiers.GetIPListFromString(nodeID)
	if len(nodeIPs) == 0 {
		return "", fmt.Errorf("failed to parse node ID")
	}
	ip := nodeIPs[len(nodeIPs)-1]
	return "http://" + net.JoinHostPort(ip, port) + identifiers.ArrayStatus + "/" + arrayID, nil
}

// checkIfNodeIsConnected looks at the 'nodeId' to determine if there is connectivity to the 'arrayId' array.
// The 'rep' object will be filled with the results of the check.
func (s *Service) checkIfNodeIsConnected(ctx context.Context, arrayID string, nodeID string) (isConnected bool, messages []string, err error) {
	log.WithContext(ctx).Infof("Checking if array %s is connected to node %s", arrayID, nodeID)
	connected := false

	port := strings.TrimPrefix(identifiers.APIPort, ":")
	url, err := buildNodeConnectivityURL(nodeID, port, arrayID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to parse node ID '%s'", nodeID)
		return false, messages, err
	}
	connected, err = s.QueryArrayStatus(ctx, url)
	if err != nil {
		msg := fmt.Sprintf("connectivity unknown for array %s to node %s due to %s", arrayID, nodeID, err)
		log.WithContext(ctx).Error(msg)
		messages = append(messages, msg)
		log.WithContext(ctx).Errorf("%s", err.Error())
	}

	if connected {
		msg := fmt.Sprintf("array %s is connected to node %s", arrayID, nodeID)
		log.WithContext(ctx).Info(msg)
		messages = append(messages, msg)
	} else {
		msg := fmt.Sprintf("array %s is not connected to node %s", arrayID, nodeID)
		log.WithContext(ctx).Info(msg)
		messages = append(messages, msg)
	}
	return connected, messages, nil
}

// getIOInProgress attempts to determine if IO has recently occurred for a given volume, volID,
// and returns a nil error if IO has occurred.
func getIOInProgress(ctx context.Context, volID string, arrayConfig array.PowerStoreArray, protocol string) (err error) {
	// Call PerformanceMetricsByVolume  or  PerformanceMetricsByFileSystem in gopowerstore based on the volume type
	if protocol == "scsi" {
		resp, err := arrayConfig.Client.PerformanceMetricsByVolume(ctx, volID, gopowerstore.TwentySec)
		if err != nil {
			log.WithContext(ctx).Errorf("Error %v while checking IsIOInProgress for array having globalId %s for volumeId %s", err.Error(), arrayConfig.GlobalID, volID)
			return fmt.Errorf("error %v while while checking IsIOInProgress", err.Error())
		}
		// check last four entries status recieved in the response
		for i := len(resp) - 1; i >= (len(resp)-4) && i >= 0; i-- {
			if resp[i].TotalIops > 0.0 && checkIfEntryIsLatest(resp[i].Timestamp) {
				return nil
			}
		}
		return fmt.Errorf("no IOInProgress for volume %s on array %s", volID, arrayConfig.GlobalID)
	}
	// nfs volume type logic
	resp, err := arrayConfig.Client.PerformanceMetricsByFileSystem(ctx, volID, gopowerstore.TwentySec)
	if err != nil {
		log.WithContext(ctx).Errorf("Error %v while checking IsIOInProgress for array having globalId %s for volumeId %s", err.Error(), arrayConfig.GlobalID, volID)
		return fmt.Errorf("error %v while while checking IsIOInProgress", err.Error())
	}
	// check last four entries status recieved in the response
	for i := len(resp) - 1; i >= len(resp)-4 && i >= 0; i-- {
		if resp[i].TotalIops > 0.0 && checkIfEntryIsLatest(resp[i].Timestamp) {
			return nil
		}
	}
	return fmt.Errorf("no IOInProgress for volume %s on array %s", volID, arrayConfig.GlobalID)
}

func checkIfEntryIsLatest(timestamp strfmt.DateTime) bool {
	RFC3339MillisNoColon := "2006-01-02T15:04:05Z"
	stringTime := timestamp.String()
	timeFromResponse, err := time.Parse(RFC3339MillisNoColon, stringTime)
	if err != nil {
		log.Errorf("error in parsing the time recieved in the response %v", err)
		return false
	}
	log.Debugf("timestamp recieved from the response body is %v", timeFromResponse)
	currentTime := time.Now().UTC()
	log.Debugf("current time %v", currentTime)
	if currentTime.Sub(timeFromResponse).Seconds() < 60 {
		log.Debug("found a fresh metric")
		return true
	}
	return false
}
