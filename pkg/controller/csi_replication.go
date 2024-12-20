/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	log "github.com/sirupsen/logrus"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/csi-addons/spec/lib/go/replication"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/gopowerstore"
	 
 )


 func (s *Service) EnableVolumeReplication(ctx context.Context, req *replication.EnableVolumeReplicationRequest) (*replication.EnableVolumeReplicationResponse, error) {
	//validate replication request
	volumeID := getIDFromReplication(req)
	if volumeID == "" {
		return nil, status.Error(codes.InvalidArgument, "empty volume ID in request")
	}

	id, arrayID, _, remoteId, remoteArrayID, err := array.ParseVolumeID(ctx, volumeID, s.DefaultArray(), nil)
	if err != nil {
		return nil, err
	}

	if remoteId !="" || remoteArrayID != "" {
		return nil, status.Error(codes.InvalidArgument, "volume is already replicated")
	}

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given IP")
	}

	params := req.GetParameters()

	rpo, ok := params[s.WithRP(KeyReplicationRPO)]
	repMode := params[s.WithRP(KeyReplicationMode)]
	if !ok {
		// If Replication mode is ASYNC and there is no RPO specified, returning an error
		if repMode == common.AsyncMode {
			return nil, status.Error(codes.InvalidArgument, "replication mode is ASYNC but no RPO specified in storage class")
		}
		// If Replication mode is SYNC and there is no RPO, defaulting the value to Zero
		rpo = common.Zero
	}
	rpoEnum := gopowerstore.RPOEnum(rpo)
	if err := rpoEnum.IsValid(); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid RPO value")
	}
	remoteSystemName, ok := params[s.WithRP(KeyReplicationRemoteSystem)]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "replication enabled but no remote system specified in storage class")
	}
	
	vgPrefix, ok := params[s.WithRP(KeyReplicationVGPrefix)]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "replication enabled but no volume group prefix specified in storage class")
	}

	// Validating RPO to be non Zero when replication mode is ASYNC
	if repMode == common.AsyncMode && rpo == common.Zero {
		log.Errorf("RPO value for %s cannot be : %s", repMode, rpo)
		return nil, status.Error(codes.InvalidArgument, "replication mode ASYNC requires RPO value to be non Zero")
	}

	// Validating RPO to be Zero whe replication mode is SYNC
	if repMode == common.SyncMode && rpo != common.Zero {
		return nil, status.Error(codes.InvalidArgument, "replication mode SYNC requires RPO value to be Zero")
	}

	//create volume replication, by ensuring ReplicationRule, Protection Policy and VG are all configured
	

	//Determine volume group name
	namespace := ""
	if ignoreNS, ok := params[s.WithRP(KeyReplicationIgnoreNamespaces)]; ok && ignoreNS == "false" {
		pvcNS, ok := params[KeyCSIPVCNamespace]
		if ok {
			namespace = pvcNS + "-"
		}
	}
	vgName := vgPrefix + "-" + namespace + remoteSystemName + "-" + rpo
	if len(vgName) > 128 {
		vgName = vgName[:128]
	}

	//Check if volume is part of a VG
	vgs, err := arr.GetClient().GetVolumeGroupsByVolumeID(ctx, id)
	if err != nil {
		return nil, err
	}
	
	//if volume is a member of a volume group, ensure it is configured correctly for replication
	if len(vgs.VolumeGroup) != 0 {
		for _, vg := range vgs.VolumeGroup {
			if vg.Name == vgName && vg.ProtectionPolicyID == "" {
				_, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
				if err !=nil {
					return nil, status.Error(codes.InvalidArgument, "cant ensure protection policy exists")
				}
			} else {
				//TODO: assumption is that volume should belong to only one VG. Is that true?
				return nil, status.Error(codes.InvalidArgument, "volume belongs to another volume group already.")
			}
		}
		
	} 

	//If volume is not assiged to a volume group, configure the VG and add the volume to it
	vg, err := arr.Client.GetVolumeGroupByName(ctx, vgName)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			log.Infof("Volume group with name %s not found, creating it", vgName)

			// ensure protection policy exists
			pp, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "can't ensure protection policy exists %s", err.Error())
			}

			group, err := arr.Client.CreateVolumeGroup(ctx, &gopowerstore.VolumeGroupCreate{
				Name:               vgName,
				ProtectionPolicyID: pp,
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "can't create volume group: %s", err.Error())
			}

			vg, err = arr.Client.GetVolumeGroup(ctx, group.ID)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "can't query volume group by id %s : %s", group.ID, err.Error())
			}

		} else {
			return nil, status.Errorf(codes.Internal, "can't query volume group by name %s : %s", vgName, err.Error())
		}
	} else {
		// if Replication mode is SYNC, check if the VolumeGroup is write-order consistent
		if repMode == common.SyncMode {
			if !vg.IsWriteOrderConsistent {
				return nil, status.Errorf(codes.Internal, "can't apply protection policy with sync rule if volume group is not write-order consistent")
			}
		}
		// group exists, check that protection policy applied
		if vg.ProtectionPolicyID == "" {
			pp, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "can't ensure protection policy exists %s", err.Error())
			}
			policyUpdate := gopowerstore.VolumeGroupChangePolicy{ProtectionPolicyID: pp}
			_, err = arr.Client.UpdateVolumeGroupProtectionPolicy(ctx, vg.ID, &policyUpdate)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "can't update volume group policy %s", err.Error())
			}
		}
	}

	//Add volume to VG
	_, err = arr.Client.AddMembersToVolumeGroup(ctx, &gopowerstore.VolumeGroupMembers{ VolumeIDs: []string{id}}, vg.ID)
	if err!=nil {
		return nil, status.Errorf(codes.Internal, "can't add volume to volume group %s", err.Error())
	}

	return &replication.EnableVolumeReplicationResponse{}, nil

 }

 func (s *Service) DisableVolumeReplication(ctx context.Context, req *replication.DisableVolumeReplicationRequest) (*replication.DisableVolumeReplicationResponse, error) {
	volumeID := getIDFromReplication(req)
	if volumeID == "" {
		return nil, status.Error(codes.InvalidArgument, "empty volume ID in request")
	}

	id, arrayID, _, _, _, err := array.ParseVolumeID(ctx, volumeID, s.DefaultArray(), nil)
	if err != nil {
		return nil, err
	}

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given IP")
	}

	vgs, err := arr.GetClient().GetVolumeGroupsByVolumeID(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(vgs.VolumeGroup) != 0 {
		// Remove volume from volume group
		// TODO: If volume has multiple volume group then how we should find ours?
		// TODO: Maybe adding volumegroup id/name to volume id can help?
		_, err := arr.GetClient().RemoveMembersFromVolumeGroup(ctx, &gopowerstore.VolumeGroupMembers{VolumeIDs: []string{id}}, vgs.VolumeGroup[0].ID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeAlreadyRemovedFromVolumeGroup() { // idempotency check
				log.Debugf("Volume %s has already been removed from volume group %s", id, vgs.VolumeGroup[0].ID) // continue to delete volume
			} else {
				return nil, status.Errorf(codes.Internal, "failed to remove volume %s from volume group: %s", id, err.Error())
			}
		}

		// Unassign protection policy
		_, err = arr.GetClient().ModifyVolume(ctx, &gopowerstore.VolumeModify{ProtectionPolicyID: ""}, id)
		if err != nil {
			return nil, err
		}
	}
	return &replication.DisableVolumeReplicationResponse{}, nil
	 
 }
 func (s *Service) GetVolumeReplicationInfo(ctx context.Context, req *replication.GetVolumeReplicationInfoRequest) (*replication.GetVolumeReplicationInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetVolumeReplicationInfo not implemented")
 }

 func (s *Service) PromoteVolume(ctx context.Context, req *replication.PromoteVolumeRequest) (*replication.PromoteVolumeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "PromoteVolume not implemented")	
 }

 func (s *Service) DemoteVolume(ctx context.Context, req *replication.DemoteVolumeRequest) (*replication.DemoteVolumeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "DemoteVolume not implemented")	
 }

 func (s *Service) ResyncVolume(ctx context.Context, req *replication.ResyncVolumeRequest) (*replication.ResyncVolumeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "ResyncVolume not implemented")	
 }

 func getIDFromReplication(req interface{}) string {
	getID := func(r interface {
		GetVolumeId() string
		GetReplicationSource() *replication.ReplicationSource
	},
	) string {
		reqID := ""
		src := r.GetReplicationSource()
		if src != nil && src.GetVolume() != nil {
			reqID = src.GetVolume().GetVolumeId()
		}
		if reqID == "" {
			if src != nil && src.GetVolumegroup() != nil {
				reqID = src.GetVolumegroup().GetVolumeGroupId()
			}
		}
		if reqID == "" {
			reqID = r.GetVolumeId() //nolint:nolintlint,staticcheck // req.VolumeId is deprecated
		}

		return reqID
	}

	switch r := req.(type) {
	case *replication.EnableVolumeReplicationRequest:
		return getID(r)
	case *replication.DisableVolumeReplicationRequest:
		return getID(r)
	case *replication.PromoteVolumeRequest:
		return getID(r)
	case *replication.DemoteVolumeRequest:
		return getID(r)
	case *replication.ResyncVolumeRequest:
		return getID(r)
	case *replication.GetVolumeReplicationInfoRequest:
		return getID(r)
	default:
		return ""
	}
}

func GetParamsFromRequest(req interface{}) map[string]string {
	getParams := func(r interface {
		GetParameters() map[string]string
	},
	) map[string]string {
		return r.GetParameters()
	}

	switch r := req.(type) {
	case *replication.EnableVolumeReplicationRequest:
		return getParams(r)
	case *replication.DisableVolumeReplicationRequest:
		return getParams(r)
	case *replication.PromoteVolumeRequest:
		return getParams(r)
	case *replication.DemoteVolumeRequest:
		return getParams(r)
	case *replication.ResyncVolumeRequest:
		return getParams(r)
	default:
		return nil
	}
}


