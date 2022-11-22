/*
 *
 * Copyright © 2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"strings"
	"time"

	vgsext "github.com/dell/dell-csi-extensions/volumeGroupSnapshot"
	"github.com/dell/gopowerstore"
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
		VolumeIds:   sourceVols,
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
		_, err := s.Arrays()[arr].GetClient().AddMembersToVolumeGroup(ctx, &gopowerstore.VolumeGroupMembers{VolumeIds: sourceVols}, existingVgID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.VolumeNameIsAlreadyUse()) {
				return nil, status.Errorf(codes.Internal, "Error adding volume group members: %s", err.Error())
			}
		}
	} else {
		r, err := s.Arrays()[arr].GetClient().GetVolumeGroupsByVolumeID(ctx, vgParams.VolumeIds[0])
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

//validate if request has VGS name, and VGS name must be less than 28 chars
func validateCreateVGSreq(request *vgsext.CreateVolumeGroupSnapshotRequest) error {
	if request.Name == "" {
		err := status.Error(codes.InvalidArgument, "CreateVolumeGroupSnapshotRequest needs Name to be set")
		log.Errorf("Error from validateCreateVGSreq: %v ", err)
		return err
	}

	//name must be less than 28 chars, because we name snapshots with -<index>, and index can at most be 3 chars
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
