/*
 *
 * Copyright © 2022-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	podmon "github.com/dell/dell-csi-extensions/podmon"
	vgsext "github.com/dell/dell-csi-extensions/volumeGroupSnapshot"
	"github.com/dell/gopowerstore"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StateReady resembles ready state
const StateReady = "Ready"

// CreateVolumeGroupSnapshot creates volume group snapshot
func (s *Service) CreateVolumeGroupSnapshot(ctx context.Context, request *vgsext.CreateVolumeGroupSnapshotRequest) (*vgsext.CreateVolumeGroupSnapshotResponse, error) {
	log.Infof("CreateVolumeGroupSnapshot called with req: %v", request)

	err := validateCreateVGSreq(request)
	if err != nil {
		log.Errorf("Error from CreateVolumeGroupSnapshot: %v ", err)
		return nil, err
	}
	var reqParams gopowerstore.VolumeGroupSnapshotCreate
	reqParams.Name = request.GetName()
	reqParams.Description = request.GetDescription()
	parsedVolHandle := strings.Split(request.SourceVolumeIDs[0], "/")
	var arr string
	if len(parsedVolHandle) >= 2 {
		arr = parsedVolHandle[1]
	}

	var sourceVols []string
	var volGroup gopowerstore.VolumeGroup
	var snapsList []*vgsext.Snapshot
	var int64CreationTime int64
	var existingVgID string

	for _, v := range request.GetSourceVolumeIDs() {
		sourceVols = append(sourceVols, strings.Split(v, "/")[0])
	}
	// To create volume group
	vgParams := gopowerstore.VolumeGroupCreate{
		Name:        request.GetName(),
		Description: request.GetDescription(),
		VolumeIDs:   sourceVols,
	}

	gotVg, err := s.Arrays()[arr].GetClient().GetVolumeGroupByName(ctx, request.GetName())
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.NotFound()) {
			return nil, status.Errorf(codes.Internal, "Error getting volume group by name: %s", err.Error())
		}
	}

	// Check whether volume group already exists, if yes proceed to create a snapshot else create a new volume group
	if gotVg.ID != "" {
		// taking the existing volume group to re-create
		existingVgID = gotVg.ID
		// add members to existing volume group before taking snapshot
		_, err := s.Arrays()[arr].GetClient().AddMembersToVolumeGroup(ctx, &gopowerstore.VolumeGroupMembers{VolumeIDs: sourceVols}, existingVgID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.VolumeNameIsAlreadyUse()) {
				return nil, status.Errorf(codes.Internal, "Error adding volume group members: %s", err.Error())
			}
		}
	} else {
		r, err := s.Arrays()[arr].GetClient().GetVolumeGroupsByVolumeID(ctx, vgParams.VolumeIDs[0])
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.NotFound()) {
				return nil, status.Errorf(codes.Internal, "Error getting volume group by volume ID: %s", err.Error())
			}
		}
		if len(r.VolumeGroup) == 0 {
			resp, err := s.Arrays()[arr].GetClient().CreateVolumeGroup(ctx, &vgParams)
			if err != nil {
				if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.VolumeNameIsAlreadyUse()) {
					return nil, status.Errorf(codes.Internal, "Error creating volume group: %s", err.Error())
				}
			}
			if resp.ID != "" {
				existingVgID = resp.ID
			}
		} else {
			existingVgID = r.VolumeGroup[0].ID
		}
	}
	if existingVgID != "" {
		resp, err := s.Arrays()[arr].GetClient().CreateVolumeGroupSnapshot(ctx, existingVgID, &reqParams)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.VolumeNameIsAlreadyUse()) {
				return nil, status.Errorf(codes.Internal, "Error creating volume group snapshot: %s", err.Error())
			}
		}

		volGroup, err = s.Arrays()[arr].GetClient().GetVolumeGroup(ctx, resp.ID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.VolumeNameIsAlreadyUse()) {
				return nil, status.Errorf(codes.Internal, "Error getting volume group snapshot: %s", err.Error())
			}
		}
		etime, _ := time.Parse(time.RFC3339, volGroup.CreationTimeStamp)
		int64CreationTime = etime.Unix() * 1000000000 // we need to convert to nano seconds

		for _, v := range volGroup.Volumes {
			var snapState bool
			if v.State == StateReady {
				snapState = true
			}
			volID := strings.Split(request.SourceVolumeIDs[0], "/")
			if len(volID) >= 3 {
				snapsList = append(snapsList, &vgsext.Snapshot{
					Name:          v.Name,
					SnapId:        v.ID + "/" + arr + "/" + volID[2],
					ReadyToUse:    snapState,
					CapacityBytes: v.Size,
					SourceId:      v.ProtectionData.SourceID + "/" + arr + "/" + volID[2],
					CreationTime:  int64CreationTime,
				})
			}
		}
	}

	return &vgsext.CreateVolumeGroupSnapshotResponse{
		SnapshotGroupID: volGroup.ID,
		Snapshots:       snapsList,
		CreationTime:    int64CreationTime,
	}, nil
}

// validate if request has VGS name, and VGS name must be less than 28 chars
func validateCreateVGSreq(request *vgsext.CreateVolumeGroupSnapshotRequest) error {
	if request.Name == "" {
		err := status.Error(codes.InvalidArgument, "CreateVolumeGroupSnapshotRequest needs Name to be set")
		log.Errorf("Error from validateCreateVGSreq: %v ", err)
		return err
	}

	// name must be less than 28 chars, because we name snapshots with -<index>, and index can at most be 3 chars
	if len(request.Name) > 27 {
		err := status.Errorf(codes.InvalidArgument, "Requested name %s longer than 27 character max", request.Name)
		log.Errorf("Error from validateCreateVGSreq: %v ", err)
		return err
	}

	if len(request.SourceVolumeIDs) == 0 {
		err := status.Errorf(codes.InvalidArgument, "Source volumes are not present")
		log.Errorf("Error from validateCreateVGSreq: %v ", err)
		return err
	}

	return nil
}

// ValidateVolumeHostConnectivity menthod will be called by podmon sidecars to check host connectivity with array
func (s *Service) ValidateVolumeHostConnectivity(ctx context.Context, req *podmon.ValidateVolumeHostConnectivityRequest) (*podmon.ValidateVolumeHostConnectivityResponse, error) {
	// ctx, log, _ := GetRunIDLog(ctx)
	log.Infof("ValidateVolumeHostConnectivity called %+v", req)
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
	// create the map of all the array with array's GloabalID as key
	globalIDs := make(map[string]bool)
	globalID := req.GetArrayId()
	if globalID == "" {
		if len(req.GetVolumeIds()) == 0 {
			log.Info("neither globalId nor volumeID is present in request")
			globalIDs[s.DefaultArray().GlobalID] = true
		}
		// for loop req.GetVolumeIds()
		for _, volID := range req.GetVolumeIds() {
			volumeHandle, err := array.ParseVolumeID(ctx, volID, s.DefaultArray(), nil)
			globalID = volumeHandle.LocalArrayGlobalID
			if err != nil || globalID == "" {
				log.Errorf("unable to retrieve array's globalID after parsing volumeID")
				globalIDs[s.DefaultArray().GlobalID] = true
			} else {
				globalIDs[globalID] = true
			}
		}
	} else {
		globalIDs[globalID] = true
	}

	// Go through each of the globalIDs
	for globalID := range globalIDs {
		// First - check if the array is visible from the node
		err := s.checkIfNodeIsConnected(ctx, globalID, req.GetNodeId(), rep)
		if err != nil {
			return rep, err
		}

		// Check for IOinProgress only when volumes IDs are present in the request as the field is required only in the latter case also to reduce number of calls to the API making it efficient
		if len(req.GetVolumeIds()) > 0 {
			// Get array config
			for _, volID := range req.GetVolumeIds() {
				volume, err := array.ParseVolumeID(ctx, volID, s.DefaultArray(), nil)
				if err != nil {
					log.Errorf("failed to parse volumeID, %s, for querying IO metrics. err: %s", volID, err.Error())
					return nil, err
				}

				if volume.LocalArrayGlobalID != globalID {
					log.Errorf("Recived globalId from podman is %s and retrieved from array is %s ", globalID, volume.LocalArrayGlobalID)
					return nil, fmt.Errorf("invalid globalId %s is provided", globalID)
				}

				localArray, err := s.GetOneArray(volume.LocalArrayGlobalID)
				if err != nil || localArray == nil {
					log.Errorf("failed to get local array configuration for array \"%s\" for volume activity validation: %s",
						volume.LocalArrayGlobalID, err.Error())
					return nil, err
				}

				// set to nil to avoid unnecessary API calls by subsequent iterations
				var remoteArray *array.PowerStoreArray = nil
				if volume.RemoteArrayGlobalID != "" {
					remoteArray, err = s.GetOneArray(volume.RemoteArrayGlobalID)
					if err != nil {
						log.Errorf("failed to get remote array configuration for array \"%s\" for volume activity validation: %s",
							volume.RemoteArrayGlobalID, err.Error())
					}
				}

				ioCtx, ioCtxCancel := context.WithCancel(ctx)

				errCh := make(chan error)
				wg := &sync.WaitGroup{}
				wg.Add(1)
				// check if any IO is inProgress for the current local globalID/array
				go goIsIoInProgress(ioCtx, errCh, wg, volume.LocalUUID, *localArray, volume.Protocol)

				if remoteArray != nil {
					// check if any IO is inProgress for the current remote globalID/array
					wg.Add(1)
					go goIsIoInProgress(ioCtx, errCh, wg, volume.RemoteUUID, *remoteArray, volume.Protocol)
				}

				go waitAndClose(wg, errCh)

				if isIOInProgress(ioCtx, errCh) {
					// so long as at least one volume has IO in-progress
					// we should report it
					ioCtxCancel()
					rep.IosInProgress = true
					log.Infof("IO detected for volume %s", volID)
					return rep, nil
				}

				// make sure to cancel any pending requests from this iteration
				// so no goroutines are left running.
				ioCtxCancel()
			}
		}
	}
	log.Infof("ValidateVolumeHostConnectivity reply %+v", rep)
	return rep, nil
}

func waitAndClose(wg *sync.WaitGroup, ch chan error) {
	log.Debugf("waiting to IO in-progress queries to complete")
	wg.Wait()
	// close the channel to signal there are no more results
	// to be processed and the receiver can move on
	log.Debugf("all goroutines complete; closing the channel")
	close(ch)
}

func isIOInProgress(ctx context.Context, ch <-chan error) bool {
	for {
		select {
		case <-ctx.Done():
			log.Errorf("timeout reached while checking if IO is in-progress: %s", ctx.Err())
			return false
		case err, ok := <-ch:
			// if the channel is closed before returning a non-nil error
			// indicate no IO is in-progress
			if !ok {
				log.Infof("no IO detected")
				return false
			}
			if err == nil {
				log.Infof("IO detected")
				return true
			} else {
				// the error is not truly an error, but has valuable info
				// about which volume reported no IO in-progress, so log
				// it as "info"
				log.Info(err.Error())
			}
		}
	}
}

func goIsIoInProgress(ctx context.Context, repCh chan<- error, wg *sync.WaitGroup, volID string, array array.PowerStoreArray, protocol string) {
	defer wg.Done()

	log.Infof("checking if IO is in-progress for volume %s on array %s", volID, array.GlobalID)
	err := IsIOInProgress(ctx, volID, array, protocol)
	select {
	case repCh <- err:

	// we only care if the error is nil,
	// because the array may be unreachable.
	// No need to return context errors upon timeout.
	case <-ctx.Done():
		log.Errorf("context deadline exceeded while querying for IOs in-progress for volume %s on array %s", volID, array.GlobalID)
	}
}

// checkIfNodeIsConnected looks at the 'nodeId' to determine if there is connectivity to the 'arrayId' array.
// The 'rep' object will be filled with the results of the check.
func (s *Service) checkIfNodeIsConnected(ctx context.Context, arrayID string, nodeID string, rep *podmon.ValidateVolumeHostConnectivityResponse) error {
	log.Infof("Checking if array %s is connected to node %s", arrayID, nodeID)
	var message string
	rep.Connected = false

	nodeIP := identifiers.GetIPListFromString(nodeID)
	if len(nodeIP) == 0 {
		log.Errorf("failed to parse node ID '%s'", nodeID)
		return fmt.Errorf("failed to parse node ID")
	}
	ip := nodeIP[len(nodeIP)-1]
	// form url to call array on node
	url := "http://" + ip + identifiers.APIPort + identifiers.ArrayStatus + "/" + arrayID
	connected, err := s.QueryArrayStatus(ctx, url)
	if err != nil {
		message = fmt.Sprintf("connectivity unknown for array %s to node %s due to %s", arrayID, nodeID, err)
		log.Error(message)
		rep.Messages = append(rep.Messages, message)
		log.Errorf("%s", err.Error())
	}

	if connected {
		rep.Connected = true
		message = fmt.Sprintf("array %s is connected to node %s", arrayID, nodeID)
	} else {
		message = fmt.Sprintf("array %s is not connected to node %s", arrayID, nodeID)
	}
	log.Info(message)
	rep.Messages = append(rep.Messages, message)
	return nil
}

// IsIOInProgress function check the IO operation status on array
func IsIOInProgress(ctx context.Context, volID string, arrayConfig array.PowerStoreArray, protocol string) (err error) {
	// Call PerformanceMetricsByVolume  or  PerformanceMetricsByFileSystem in gopowerstore based on the volume type
	if protocol == "scsi" {
		resp, err := arrayConfig.Client.PerformanceMetricsByVolume(ctx, volID, gopowerstore.TwentySec)
		if err != nil {
			log.Errorf("Error %v while checking IsIOInProgress for array having globalId %s for volumeId %s", err.Error(), arrayConfig.GlobalID, volID)
			return fmt.Errorf("error %v while while checking IsIOInProgress", err.Error())
		}
		// check last four entries status recieved in the response
		for i := len(resp) - 1; i >= (len(resp)-4) && i >= 0; i-- {
			if resp[i].TotalIops > 0.0 && checkIfEntryIsLatest(resp[i].CommonMetricsFields.Timestamp) {
				return nil
			}
		}
		return fmt.Errorf("no IOInProgress for volume %s on array %s", volID, arrayConfig.GlobalID)
	}
	// nfs volume type logic
	resp, err := arrayConfig.Client.PerformanceMetricsByFileSystem(ctx, volID, gopowerstore.TwentySec)
	if err != nil {
		log.Errorf("Error %v while checking IsIOInProgress for array having globalId %s for volumeId %s", err.Error(), arrayConfig.GlobalID, volID)
		return fmt.Errorf("error %v while while checking IsIOInProgress", err.Error())
	}
	// check last four entries status recieved in the response
	for i := len(resp) - 1; i >= len(resp)-4 && i >= 0; i-- {
		if resp[i].TotalIops > 0.0 && checkIfEntryIsLatest(resp[i].CommonMetricsFields.Timestamp) {
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
