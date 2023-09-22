/*
 *
 * Copyright © 2021-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package controller provides CSI specification compatible controller service.
package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/core"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/common/fs"
	commonext "github.com/dell/dell-csi-extensions/common"
	podmon "github.com/dell/dell-csi-extensions/podmon"
	csiext "github.com/dell/dell-csi-extensions/replication"
	vgsext "github.com/dell/dell-csi-extensions/volumeGroupSnapshot"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gopowerstore"
	"github.com/golang/protobuf/ptypes/wrappers"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Interface provides most important controller methods.
// This essentially serves as a wrapper for controller service that is used in ephemeral volumes.
type Interface interface {
	CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error)
	DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error)
	ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error)
	ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error)
	array.Consumer
}

// Service is a controller service that contains array connection information and implements ControllerServer API
type Service struct {
	Fs fs.Interface

	externalAccess string
	nfsAcls        string

	array.Locker

	replicationContextPrefix    string
	replicationPrefix           string
	isHealthMonitorEnabled      bool
	isAutoRoundOffFsSizeEnabled bool

	K8sVisibilityAutoRegistration bool
}

// Init is a method that initializes internal variables of controller service
func (s *Service) Init() error {
	ctx := context.Background()
	if nat, ok := csictx.LookupEnv(ctx, common.EnvExternalAccess); ok {
		s.externalAccess = nat
	}

	if replicationContextPrefix, ok := csictx.LookupEnv(ctx, common.EnvReplicationContextPrefix); ok {
		s.replicationContextPrefix = replicationContextPrefix + "/"
	}

	if replicationPrefix, ok := csictx.LookupEnv(ctx, common.EnvReplicationPrefix); ok {
		s.replicationPrefix = replicationPrefix
	}

	if isHealthMonitorEnabled, ok := csictx.LookupEnv(ctx, common.EnvIsHealthMonitorEnabled); ok {
		s.isHealthMonitorEnabled, _ = strconv.ParseBool(isHealthMonitorEnabled)
	}

	s.nfsAcls = ""
	if nfsAcls, ok := csictx.LookupEnv(ctx, common.EnvNfsAcls); ok {
		if nfsAcls != "" {
			s.nfsAcls = nfsAcls
		}
	}

	if isAutoRoundOffFsSizeEnabled, ok := csictx.LookupEnv(ctx, common.EnvAllowAutoRoundOffFilesystemSize); ok {
		log.Warn("Auto round off Filesystem size has been enabled! This will round off NFS PVC size to 3Gi when the requested size is less than 3Gi.")
		s.isAutoRoundOffFsSizeEnabled, _ = strconv.ParseBool(isAutoRoundOffFsSizeEnabled)
	}

	if isk8sVisibilityAutoRegistrationEnabled, ok := csictx.LookupEnv(ctx, common.EnvK8sVisibilityAutoRegistration); ok {
		s.K8sVisibilityAutoRegistration, _ = strconv.ParseBool(isk8sVisibilityAutoRegistrationEnabled)
	}

	return nil
}

// CreateVolume creates either FileSystem or Volume on storage array.
func (s *Service) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	params := req.GetParameters()

	// Get array from map
	arrayID, ok := params[common.KeyArrayID]

	var arr *array.PowerStoreArray
	// If no ArrayID was provided in storage class we just use default array
	if !ok {
		if _, ok := params["arrayIP"]; ok {
			return nil, status.Error(codes.Internal, "Array IP's been provided, however it is not supported in "+
				"current version. Configure you storage classes according to the documentation")
		}
		arr = s.DefaultArray()
	} else {
		arr, ok = s.Arrays()[arrayID]
		if !ok {
			return nil, status.Errorf(codes.Internal, "can't find array with provided id %s", arrayID)
		}
	}

	// Check if should use nfs
	useNFS := false
	fsType := req.VolumeCapabilities[0].GetMount().GetFsType()
	useNFS = fsType == "nfs"

	if req.VolumeCapabilities[0].GetBlock() != nil {
		// We need to check if user requests raw block access from nfs and prevent that
		fsType, ok := params[KeyFsType]
		// FsType can be empty
		if ok && fsType == "nfs" {
			return nil, status.Errorf(codes.InvalidArgument, "raw block requested from NFS Volume")
		}

		fsType, ok = params[KeyFsTypeOld]
		if ok && fsType == "nfs" {
			return nil, status.Errorf(codes.InvalidArgument, "raw block requested from NFS Volume")
		}
	}

	// Prevent user from creating an NFS volume with incorrect topology(e.g. iscsi, nvme). At least one entry for nfs should be present in the topology, otherwise return an error
	if useNFS && req.AccessibilityRequirements != nil {
		if ok := common.HasRequiredTopology(req.AccessibilityRequirements.Preferred, arr.GetIP(), "nfs"); !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid topology requested for NFS Volume. Please validate your storage class has nfs topology.")
		}
	}

	var creator VolumeCreator
	var protocol string

	nfsAcls := s.nfsAcls
	if useNFS {
		protocol = "nfs"
		nasParamsName, ok := params[KeyNasName]
		if ok {
			creator = &NfsCreator{
				nasName: nasParamsName,
			}
		} else {
			creator = &NfsCreator{
				nasName: arr.GetNasName(),
			}
		}

		if params[common.KeyNfsACL] != "" {
			nfsAcls = params[common.KeyNfsACL] // Storage class takes precedence
		} else if arr.NfsAcls != "" {
			nfsAcls = arr.NfsAcls // Secrets next
		}
	} else {
		protocol = "scsi"
		creator = &SCSICreator{}
	}

	var topology []*csi.Topology
	if req.AccessibilityRequirements != nil {
		topology = req.AccessibilityRequirements.Preferred
	}

	if err := creator.CheckName(ctx, req.GetName()); err != nil {
		return nil, err
	}

	sizeInBytes, err := creator.CheckSize(ctx, req.GetCapacityRange(), s.isAutoRoundOffFsSizeEnabled)
	if err != nil {
		return nil, err
	}

	contentSource := req.GetVolumeContentSource()
	if contentSource != nil {
		var volResp *csi.Volume
		var err error
		volumeSource := contentSource.GetVolume()
		if volumeSource != nil {
			log.Printf("volume %s specified as volume content source", volumeSource.VolumeId)
			parsedID, _, _, _ := array.ParseVolumeID(ctx, volumeSource.VolumeId, s.DefaultArray(), nil)
			volumeSource.VolumeId = parsedID
			volResp, err = creator.Clone(ctx, volumeSource, req.GetName(), sizeInBytes, req.Parameters, arr.GetClient())
		}
		snapshotSource := contentSource.GetSnapshot()
		if snapshotSource != nil {
			log.Printf("snapshot %s specified as volume content source", snapshotSource.SnapshotId)
			parsedID, _, _, _ := array.ParseVolumeID(ctx, snapshotSource.SnapshotId, s.DefaultArray(), nil)
			snapshotSource.SnapshotId = parsedID
			volResp, err = creator.CreateVolumeFromSnapshot(ctx, snapshotSource,
				req.GetName(), sizeInBytes, req.Parameters, arr.GetClient())
		}
		if err != nil {
			resp, err := creator.CheckIfAlreadyExists(ctx, req.GetName(), sizeInBytes, arr.GetClient())
			if err != nil {
				return nil, err
			}
			if snapshotSource != nil {
				volResp = getCSIVolumeFromSnapshot(resp.VolumeId, snapshotSource, sizeInBytes)
			} else {
				volResp = getCSIVolumeFromClone(resp.VolumeId, volumeSource, sizeInBytes)
			}
			volResp.VolumeContext = req.Parameters
		}
		if volResp == nil {
			return nil, err
		}
		volResp.VolumeId = volResp.VolumeId + "/" + arr.GetGlobalID() + "/" + protocol
		if useNFS {
			topology = common.GetNfsTopology(arr.GetIP())
			log.Infof("Modified topology to nfs for %s", req.GetName())
		}
		volResp.AccessibleTopology = topology
		return &csi.CreateVolumeResponse{
			Volume: volResp,
		}, nil
	}

	var vg gopowerstore.VolumeGroup

	// Check if replication is enabled
	replicationEnabled := params[s.WithRP(KeyReplicationEnabled)]

	if replicationEnabled == "true" && !useNFS {
		log.Info("Preparing volume replication")

		vgPrefix, ok := params[s.WithRP(KeyReplicationVGPrefix)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "replication enabled but no volume group prefix specified in storage class")
		}
		rpo, ok := params[s.WithRP(KeyReplicationRPO)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "replication enabled but no RPO specified in storage class")
		}
		rpoEnum := gopowerstore.RPOEnum(rpo)
		if err := rpoEnum.IsValid(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid rpo value")
		}
		remoteSystemName, ok := params[s.WithRP(KeyReplicationRemoteSystem)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "replication enabled but no remote system specified in storage class")
		}

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

		vg, err = arr.Client.GetVolumeGroupByName(ctx, vgName)
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

		if c, ok := creator.(*SCSICreator); ok {
			c.vg = &vg
		}
	}

	params[common.KeyVolumeDescription] = getDescription(req.GetParameters())

	var volumeResponse *csi.Volume
	resp, err := creator.Create(ctx, req, sizeInBytes, arr.GetClient())
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && (apiError.VolumeNameIsAlreadyUse() || apiError.FSNameIsAlreadyUse()) {
			volumeResponse, err = creator.CheckIfAlreadyExists(ctx, req.GetName(), sizeInBytes, arr.GetClient())
			if err != nil {
				return nil, err
			}
		} else {
			return nil, status.Error(codes.Internal, err.Error())
		}
	} else {
		volumeResponse = getCSIVolume(resp.ID, sizeInBytes)
	}

	// Fetch the service tag
	var serviceTag = GetServiceTag(ctx, req, arr, resp.ID, protocol)

	volumeResponse.VolumeContext = req.Parameters
	volumeResponse.VolumeContext[common.KeyArrayID] = arr.GetGlobalID()
	volumeResponse.VolumeContext[common.KeyArrayVolumeName] = req.Name
	volumeResponse.VolumeContext[common.KeyProtocol] = protocol
	volumeResponse.VolumeContext[common.KeyServiceTag] = serviceTag

	if useNFS {
		volumeResponse.VolumeContext[common.KeyNfsACL] = nfsAcls
		volumeResponse.VolumeContext[common.KeyNasName] = arr.GetNasName()
		topology = common.GetNfsTopology(arr.GetIP())
		log.Infof("Modified topology to nfs for %s", req.GetName())
	}

	volumeResponse.VolumeId = volumeResponse.VolumeId + "/" + arr.GetGlobalID() + "/" + protocol
	volumeResponse.AccessibleTopology = topology
	return &csi.CreateVolumeResponse{
		Volume: volumeResponse,
	}, nil
}

// DeleteVolume deletes either FileSystem or Volume from storage array.
func (s *Service) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	id, arrayID, protocol, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), nil)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return &csi.DeleteVolumeResponse{}, nil
		}
		return nil, err
	}

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.Internal, "can't find array with provided id %s", arrayID)
	}

	if protocol == "nfs" {
		listSnaps, err := arr.GetClient().GetFsSnapshotsByVolumeID(ctx, id)
		if err != nil {
			return nil, status.Errorf(codes.Unknown, "failure getting snapshot: %s", err.Error())
		}
		if len(listSnaps) > 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"unable to delete FS volume -- snapshots based on this volume still exist: %v",
				listSnaps)
		}

		// Validate if filesystem has any NFS or SMB shares or snapshots attached
		nfsExportResp, _ := arr.GetClient().GetNFSExportByFileSystemID(ctx, id)

		if len(nfsExportResp.ROHosts) > 0 ||
			len(nfsExportResp.RORootHosts) > 0 ||
			len(nfsExportResp.RWHosts) > 0 ||
			len(nfsExportResp.RWRootHosts) > 0 {
			// if one entry is there for RWRootHosts or RWHosts, check if this is the same externalAccess defined in value.yaml
			// if yes modifyNFSExport and remove externalAccess from the HostAcceesList on the array
			if (len(nfsExportResp.RWRootHosts) == 1 || len(nfsExportResp.RWHosts) == 1) && s.externalAccess != "" {
				externalAccess, err := common.ParseCIDR(s.externalAccess)
				if err != nil {
					log.Debug("error occurred  while parsing externalAccess: ", err.Error(), s.externalAccess)
					return nil, status.Errorf(codes.FailedPrecondition,
						"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
						id)
				}
				modifyNFSExport := false
				// we need to construct the payload dynamically otherwise 400 error will be thrown
				var modifyHostPayload gopowerstore.NFSExportModify
				// Removing externalAccess from RWHosts as well as RWRootHosts
				if len(nfsExportResp.RWRootHosts) == 1 && externalAccess == nfsExportResp.RWRootHosts[0] {
					log.Debug("Trying to remove externalAccess IP with mask having RWRootHosts access while deleting the volume: ", externalAccess)
					modifyNFSExport = true
					modifyHostPayload.RemoveRWRootHosts = []string{externalAccess}
				}
				if len(nfsExportResp.RWHosts) == 1 && externalAccess == nfsExportResp.RWHosts[0] {
					log.Debug("Trying to remove externalAccess IP with mask having RWHosts access while deleting the volume: ", externalAccess)
					modifyNFSExport = true
					modifyHostPayload.RemoveRWHosts = []string{externalAccess}
				}
				// call ModifyNFSExport API only when payload is not empty i.e.  something is there to modify
				if modifyNFSExport {
					_, err = arr.GetClient().ModifyNFSExport(ctx, &modifyHostPayload, nfsExportResp.ID)
					if err != nil {
						log.Debug("failure when removing externalAccess from nfs export: ", err.Error())
						if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.HostAlreadyRemovedFromNFSExport()) {
							return nil, status.Errorf(codes.FailedPrecondition,
								"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
								id)
						}
					}
				} else {
					// either of RWRootHosts or RWHosts has one entry but it is not externalAccess
					return nil, status.Errorf(codes.FailedPrecondition,
						"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
						id)
				}
			} else {
				return nil, status.Errorf(codes.FailedPrecondition,
					"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
					id)
			}
		}
		_, err = arr.GetClient().DeleteFS(ctx, id)
		if err == nil {
			return &csi.DeleteVolumeResponse{}, nil
		}
		if apiError, ok := err.(gopowerstore.APIError); ok {
			if apiError.NotFound() {
				return &csi.DeleteVolumeResponse{}, nil
			}
		}
		return nil, err

	} else if protocol == "scsi" {
		// query volume groups?
		vgs, err := arr.GetClient().GetVolumeGroupsByVolumeID(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, err
			}
		}

		if len(vgs.VolumeGroup) != 0 {
			// Remove volume from volume group
			// TODO: If volume has multiple volume group then how we should find ours?
			// TODO: Maybe adding volumegroup id/name to volume id can help?
			_, err := arr.GetClient().RemoveMembersFromVolumeGroup(ctx, &gopowerstore.VolumeGroupMembers{VolumeIds: []string{id}}, vgs.VolumeGroup[0].ID)
			if err != nil {
				// TODO: check for idempotency cases
				return nil, err
			}

			// Unassign protection policy
			_, err = arr.GetClient().ModifyVolume(ctx, &gopowerstore.VolumeModify{ProtectionPolicyID: ""}, id)
			if err != nil {
				return nil, err
			}
		}
		// TODO: if len(vgs.VolumeGroup == 1) && it is the last volume : delete volume group
		// TODO: What to do with RPO snaps?
		// listSnaps, err := arr.GetClient().GetSnapshotsByVolumeID(ctx, id)
		// if err != nil {
		// 	return nil, status.Errorf(codes.Unknown, "failure getting snapshot: %s", err.Error())
		// }
		// if len(listSnaps) > 0 {
		// 	return nil, status.Errorf(codes.FailedPrecondition,
		// 		"unable to delete volume -- snapshots based on this volume still exist: %v",
		// 		listSnaps)
		// }

		_, err = arr.GetClient().DeleteVolume(ctx, nil, id)
		if err == nil {
			return &csi.DeleteVolumeResponse{}, nil
		}
		if apiError, ok := err.(gopowerstore.APIError); ok {
			if apiError.NotFound() {
				return &csi.DeleteVolumeResponse{}, nil
			}
			if apiError.VolumeAttachedToHost() {
				return nil, status.Errorf(codes.Internal,
					"volume with ID '%s' is still attached to host: %s", id, apiError.Error())
			}
		}
		return nil, err
	}

	return nil, status.Errorf(codes.InvalidArgument, "can't figure out protocol")
}

// ControllerPublishVolume prepares Volume/FileSystem to be consumed by node by attaching/allowing access to the host.
func (s *Service) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	id, arrayID, protocol, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), req.VolumeCapability)
	if err != nil {
		log.Info(err)
		return nil, err
	}
	arr, ok := s.Arrays()[arrayID]
	if !ok {
		log.Info("ip is nil")
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given ID")
	}

	vc := req.GetVolumeCapability()
	if vc == nil {
		return nil, status.Error(codes.InvalidArgument, "volume capability is required")
	}
	am := vc.GetAccessMode()
	if am == nil {
		return nil, status.Error(codes.InvalidArgument, "access mode is required")
	}

	if am.Mode == csi.VolumeCapability_AccessMode_UNKNOWN {
		return nil, status.Error(codes.InvalidArgument, ErrUnknownAccessMode)
	}

	kubeNodeID := req.GetNodeId()
	if kubeNodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "node ID is required")
	}

	var publisher VolumePublisher

	if protocol == "nfs" {
		publisher = &NfsPublisher{
			ExternalAccess: s.externalAccess,
		}
	} else {
		publisher = &SCSIPublisher{}
	}

	if err := publisher.CheckIfVolumeExists(ctx, arr.GetClient(), id); err != nil {
		return nil, err
	}

	return publisher.Publish(ctx, req, arr.GetClient(), kubeNodeID, id)
}

// ControllerUnpublishVolume prepares Volume/FileSystem to be deleted by unattaching/disabling access to the host.
func (s *Service) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	kubeNodeID := req.GetNodeId()
	if kubeNodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "node ID is required")
	}

	id, arrayID, protocol, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), nil)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return &csi.ControllerUnpublishVolumeResponse{}, nil
		}
		return nil, status.Errorf(codes.Unknown,
			"failure checking volume status for volume unpublishing: %s", err.Error())
	}

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "cannot find array %s", arrayID)
	}

	if protocol == "scsi" {
		node, err := arr.GetClient().GetHostByName(ctx, kubeNodeID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.HostIsNotExist() {
				// We need additional check here since we can just have host without ip in it
				ipList := common.GetIPListFromString(kubeNodeID)
				if ipList == nil {
					return nil, errors.New("can't find IP in nodeID")
				}
				ip := ipList[len(ipList)-1]
				nodeID := kubeNodeID[:len(kubeNodeID)-len(ip)-1]
				node, err = arr.GetClient().GetHostByName(ctx, nodeID)
				if err != nil {
					return nil, status.Errorf(codes.NotFound, "host with k8s node ID '%s' not found", kubeNodeID)
				}
			} else {
				return nil, status.Errorf(codes.Internal,
					"failure checking host '%s' status for volume unpublishing: %s", kubeNodeID, err.Error())
			}
		}

		err = detachVolumeFromHost(ctx, node.ID, id, arr.GetClient())
		if err != nil {
			return nil, err
		}

		return &csi.ControllerUnpublishVolumeResponse{}, nil
	} else if protocol == "nfs" {
		fs, err := arr.GetClient().GetFS(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
				return &csi.ControllerUnpublishVolumeResponse{}, nil
			}
			return nil, status.Errorf(codes.Unknown, "failure checking volume status for volume unpublishing: %s", err.Error())
		}

		// Parse volumeID to get an IP
		ipList := common.GetIPListFromString(kubeNodeID)
		if ipList == nil {
			return nil, errors.New("can't find IP in nodeID")
		}
		ip := ipList[0]

		export, err := arr.GetClient().GetNFSExportByFileSystemID(ctx, fs.ID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
				return &csi.ControllerUnpublishVolumeResponse{}, nil
			}
			return nil, status.Errorf(codes.Internal,
				"failure checking nfs export status for volume unpublishing: %s", err.Error())
		}

		// we need to construct the payload dynamically otherwise 400 error will be thrown
		var modifyHostPayload gopowerstore.NFSExportModify
		sort.Strings(export.ROHosts)
		index := sort.SearchStrings(export.ROHosts, ip)
		if len(export.ROHosts) > 0 {
			if index >= 0 {
				modifyHostPayload.RemoveROHosts = []string{ip + "/255.255.255.255"} // we can't remove without netmask
				log.Debug("Going to remove IP from ROHosts: ", modifyHostPayload.RemoveROHosts[0])
			}
		}

		sort.Strings(export.RORootHosts)
		index = sort.SearchStrings(export.RORootHosts, ip)
		if len(export.RORootHosts) > 0 {
			if index >= 0 {
				modifyHostPayload.RemoveRORootHosts = []string{ip + "/255.255.255.255"} // we can't remove without netmask
				log.Debug("Going to remove IP from RORootHosts: ", modifyHostPayload.RemoveRORootHosts[0])
			}
		}

		if common.Contains(export.RWHosts, ip+"/255.255.255.255") {
			modifyHostPayload.RemoveRWHosts = []string{ip + "/255.255.255.255"} // we can't remove without netmask
			log.Debug("Going to remove IP from RWHosts: ", modifyHostPayload.RemoveRWHosts[0])
		}

		if common.Contains(export.RWRootHosts, ip+"/255.255.255.255") {
			modifyHostPayload.RemoveRWRootHosts = []string{ip + "/255.255.255.255"} // we can't remove without netmask
			log.Debug("Going to remove IP from RWRootHosts: ", modifyHostPayload.RemoveRWRootHosts[0])
		}
		// Detach host from nfs export
		_, err = arr.GetClient().ModifyNFSExport(ctx, &modifyHostPayload, export.ID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.HostAlreadyRemovedFromNFSExport()) {
				log.Debug("Error occured while modifying NFS export during UnPublishVolume", err.Error())
				return nil, status.Errorf(codes.Internal,
					"failure when removing new host to nfs export: %s", err.Error())
			}
		}
		return &csi.ControllerUnpublishVolumeResponse{}, nil
	}

	return nil, status.Errorf(codes.InvalidArgument, "can't figure out protocol")
}

// GetServiceTag returns the service tag associated with an appliance
func GetServiceTag(ctx context.Context, req *csi.CreateVolumeRequest, arr *array.PowerStoreArray, volID string, protocol string) string {
	var ap gopowerstore.ApplianceInstance
	var vol gopowerstore.Volume
	var f gopowerstore.FileSystem
	var nas gopowerstore.NAS
	var applianceName string
	var err error

	// Check if appliance id is present in PVC manifest
	if applianceID, ok := (req.Parameters)["appliance_id"]; ok {
		// Fetching appliance information using the appliance id
		ap, err = arr.Client.GetAppliance(ctx, applianceID)
		if err != nil {
			log.Warn("Received error while calling GetAppliance ", err.Error())
		}
	} else {
		if protocol != "nfs" {
			vol, err = arr.Client.GetVolume(ctx, volID)
			if err != nil {
				log.Warn("Received error while calling GetVolume ", err.Error())
			}
			if vol.ApplianceID == "" {
				log.Warn("Unable to fetch ApplianceID from the volume")
			} else {
				ap, err = arr.Client.GetAppliance(ctx, vol.ApplianceID)
				if err != nil {
					log.Warn("Received error while calling GetAppliance ", err.Error())
				}
			}
		} else {
			f, err = arr.Client.GetFS(ctx, volID)
			if err != nil {
				log.Warn("Received error while calling GetFS ", err.Error())
			}
			if f.NasServerID == "" {
				log.Warn("Unable to fetch the NasServerID from the file system")
			} else {
				nas, err = arr.Client.GetNAS(ctx, f.NasServerID)
				if err != nil {
					log.Warn("Received error while calling GetNAS ", err.Error())
				}
				if nas.CurrentNodeID == "" {
					log.Warn("Unable to fetch the CurrentNodeID from the nas server")
				} else {
					// Removing "-node-X" from the end of CurrentNodeId to get Appliance Name
					applianceName = strings.Split(nas.CurrentNodeID, "-node-")[0]
					// Fetching appliance information using the appliance name
					ap, err = arr.Client.GetApplianceByName(ctx, applianceName)
					if err != nil {
						log.Warn("Received error while calling GetApplianceByName ", err.Error())
					}
				}
			}
		}
	}
	return ap.ServiceTag
}

// ValidateVolumeCapabilities checks if capabilities found in request are supported by driver.
func (s *Service) ValidateVolumeCapabilities(ctx context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	var (
		supported = true
		isBlock   = accTypeIsBlock(req.VolumeCapabilities)
		reason    string
	)
	// Check that all access types are valid
	if !checkValidAccessTypes(req.VolumeCapabilities) {
		return &csi.ValidateVolumeCapabilitiesResponse{
			Confirmed: nil,
			Message:   ErrUnknownAccessType,
		}, status.Error(codes.Internal, ErrUnknownAccessType)
	}

	for _, vc := range req.VolumeCapabilities {
		am := vc.GetAccessMode()
		if am == nil {
			continue
		}
		switch am.Mode {
		case csi.VolumeCapability_AccessMode_UNKNOWN:
			supported = false
			reason = ErrUnknownAccessMode
			break
		// SINGLE_NODE_WRITER to be deprecated in future
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER:
			break
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_SINGLE_WRITER:
			break
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_MULTI_WRITER:
			break
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY:
			break
		case csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY:
			break
		case csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER:
			fallthrough
		case csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER:
			if !isBlock {
				supported = false
				reason = ErrNoMultiNodeWriter
			}
			break
		default:
			// This is to guard against new access modes not understood
			supported = false
			reason = ErrUnknownAccessMode
		}
	}
	// for sanity
	id := req.GetVolumeId()
	id, arrayID, proto, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), nil)
	if err != nil {
		return &csi.ValidateVolumeCapabilitiesResponse{}, status.Error(codes.NotFound, "No such volume")
	}
	if proto == "nfs" {
		_, err := s.Arrays()[arrayID].Client.GetFS(ctx, id)
		if err != nil {
			return &csi.ValidateVolumeCapabilitiesResponse{
				Confirmed: nil,
				Message:   "Failed to get volume",
			}, status.Error(codes.NotFound, "Failed to get volume")
		}
	} else {
		_, err := s.Arrays()[arrayID].Client.GetVolume(ctx, id)
		if err != nil {
			return &csi.ValidateVolumeCapabilitiesResponse{
				Confirmed: nil,
				Message:   "Failed to get volume",
			}, status.Error(codes.NotFound, "Failed to get volume")
		}

	}

	if supported {
		return &csi.ValidateVolumeCapabilitiesResponse{
			Confirmed: &csi.ValidateVolumeCapabilitiesResponse_Confirmed{
				VolumeContext:      req.VolumeContext,
				VolumeCapabilities: req.VolumeCapabilities,
				Parameters:         req.Parameters,
			},
			Message: reason,
		}, nil
	}
	return &csi.ValidateVolumeCapabilitiesResponse{
		Confirmed: nil,
		Message:   reason,
	}, status.Error(codes.Internal, reason)
}

// ListVolumes returns all accessible volumes from the storage array.
func (s *Service) ListVolumes(ctx context.Context, req *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error) {
	var (
		startToken int
		maxEntries = int(req.GetMaxEntries())
	)

	if v := req.GetStartingToken(); v != "" {
		i, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, status.Errorf(codes.Aborted, "unable to parse StartingToken: %v into uint32", v)
		}
		startToken = int(i)
	}

	// Call the common listVolumes code
	source, nextToken, err := s.listPowerStoreVolumes(ctx, startToken, maxEntries)
	if err != nil {
		return nil, err
	}

	// Process the source volumes and make CSI Volumes
	entries := make([]*csi.ListVolumesResponse_Entry, len(source))
	for i, vol := range source {
		entries[i] = &csi.ListVolumesResponse_Entry{
			Volume: getCSIVolume(vol.ID, vol.Size),
		}
	}

	return &csi.ListVolumesResponse{
		Entries:   entries,
		NextToken: nextToken,
	}, nil
}

// GetCapacity returns available capacity for a storage array.
func (s *Service) GetCapacity(ctx context.Context, req *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error) {
	params := req.GetParameters()

	// Get array from map
	arrayID, ok := params[common.KeyArrayID]

	var arr *array.PowerStoreArray
	// If no ArrayIP was provided in storage class we just use default array
	if !ok {
		arr = s.DefaultArray()
	} else {
		arr, ok = s.Arrays()[arrayID]
		if !ok {
			return nil, status.Errorf(codes.Internal, "can't find array with provided id %s", arrayID)
		}
	}
	resp, err := arr.Client.GetCapacity(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &csi.GetCapacityResponse{
		AvailableCapacity: resp,
	}, nil
}

// ControllerGetCapabilities returns list of capabilities that are supported by the driver.
func (s *Service) ControllerGetCapabilities(ctx context.Context, request *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	newCap := func(cap csi.ControllerServiceCapability_RPC_Type) *csi.ControllerServiceCapability {
		return &csi.ControllerServiceCapability{
			Type: &csi.ControllerServiceCapability_Rpc{
				Rpc: &csi.ControllerServiceCapability_RPC{
					Type: cap,
				},
			},
		}
	}

	var capabilities []*csi.ControllerServiceCapability
	for _, capability := range []csi.ControllerServiceCapability_RPC_Type{
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
		csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME,
		csi.ControllerServiceCapability_RPC_GET_CAPACITY,
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_SNAPSHOT,
		csi.ControllerServiceCapability_RPC_LIST_SNAPSHOTS,
		csi.ControllerServiceCapability_RPC_CLONE_VOLUME,
		csi.ControllerServiceCapability_RPC_EXPAND_VOLUME,
		csi.ControllerServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
	} {
		capabilities = append(capabilities, newCap(capability))
	}

	if s.isHealthMonitorEnabled {
		for _, capability := range []csi.ControllerServiceCapability_RPC_Type{
			csi.ControllerServiceCapability_RPC_GET_VOLUME,
			csi.ControllerServiceCapability_RPC_LIST_VOLUMES_PUBLISHED_NODES,
			csi.ControllerServiceCapability_RPC_VOLUME_CONDITION,
		} {
			capabilities = append(capabilities, newCap(capability))
		}
	}

	return &csi.ControllerGetCapabilitiesResponse{
		Capabilities: capabilities,
	}, nil
}

// CreateSnapshot creates a snapshot of the Volume or FileSystem.
func (s *Service) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	snapName := req.GetName()
	if err := volumeNameValidation(snapName); err != nil {
		return nil, err
	}

	// Validate snapshot volume sourceVolID
	sourceVolID := req.GetSourceVolumeId()
	if sourceVolID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "volume ID to be snapped is required")
	}

	id, arrayID, protocol, err := array.ParseVolumeID(ctx, sourceVolID, s.DefaultArray(), nil)
	if err != nil {
		return nil, err
	}

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given ID")
	}

	var snapshotter VolumeSnapshotter
	var sourceVolumeSize int64

	if protocol == "nfs" {
		f, err := arr.GetClient().GetFS(ctx, id)
		if err == nil {
			sourceVolumeSize = f.SizeTotal - ReservedSize
		} else {
			return &csi.CreateSnapshotResponse{}, status.Errorf(codes.Internal,
				"can't find source volume '%s': %s", id, err.Error())
		}
		snapshotter = &NfsSnapshotter{}
	} else {
		f, err := arr.GetClient().GetVolume(ctx, id)
		if err == nil {
			sourceVolumeSize = f.Size
		} else {
			return &csi.CreateSnapshotResponse{}, status.Errorf(codes.Internal,
				"can't find source volume '%s': %s", id, err.Error())
		}
		snapshotter = &SCSISnapshotter{}
	}

	var snapResponse *csi.Snapshot

	// Check if snapshot with provided name already exists but has a different source volume id
	existingSnapshot, err := snapshotter.GetExistingSnapshot(ctx, snapName, arr.GetClient())
	if err == nil {
		if existingSnapshot.GetSourceID() != id {
			return nil, status.Errorf(codes.AlreadyExists,
				"snapshot with name '%s' exists, but SourceVolumeId %s doesn't match", snapName, id)
		}
		snapResponse = getCSISnapshot(existingSnapshot.GetID(), id, existingSnapshot.GetSize())
	} else {
		resp, err := snapshotter.Create(ctx, snapName, id, arr.GetClient())
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.SnapshotNameIsAlreadyUse() {
				existingSnapshot, err := snapshotter.GetExistingSnapshot(ctx, snapName, arr.GetClient())
				if err != nil {
					return nil, err
				}
				snapResponse = getCSISnapshot(existingSnapshot.GetID(), id, existingSnapshot.GetSize())
			} else {
				return nil, status.Error(codes.Internal, err.Error())
			}
		} else {
			snapResponse = getCSISnapshot(resp.ID, id, sourceVolumeSize)
		}
	}

	snapResponse.SnapshotId = snapResponse.SnapshotId + "/" + arrayID + "/" + protocol
	return &csi.CreateSnapshotResponse{
		Snapshot: snapResponse,
	}, nil
}

// DeleteSnapshot deletes a snapshot of the Volume or FileSystem.
func (s *Service) DeleteSnapshot(ctx context.Context, req *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	snapID := req.GetSnapshotId()
	if snapID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "snapshot ID to be deleted is required")
	}

	id, arrayID, protocol, err := array.ParseVolumeID(ctx, snapID, s.DefaultArray(), nil)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return &csi.DeleteSnapshotResponse{}, nil
		}
		return nil, err
	}

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given ID")
	}

	if protocol == "nfs" {
		_, err = arr.GetClient().GetFsSnapshot(ctx, id)
		if err == nil {
			_, err := arr.GetClient().DeleteFsSnapshot(ctx, id)
			if err == nil {
				return &csi.DeleteSnapshotResponse{}, nil
			}
			if apiError, ok := err.(gopowerstore.APIError); ok {
				if apiError.NotFound() {
					return &csi.DeleteSnapshotResponse{}, nil
				}
			}
			return nil, err
		}
	} else {
		snap, err := arr.GetClient().GetSnapshot(ctx, id)
		if err == nil {
			// we will check whether this snapshot is a part of volume group snapshot, if yes then we will delete the volume group snapshot
			vgs, err := arr.GetClient().GetVolumeGroupsByVolumeID(ctx, snap.ID)
			if len(vgs.VolumeGroup) != 0 && err == nil { // This means this snap is a part of VGS
				_, err = arr.GetClient().DeleteVolumeGroup(ctx, vgs.VolumeGroup[0].ID)
				if err == nil {
					return &csi.DeleteSnapshotResponse{}, nil
				}
			}
			_, err = arr.GetClient().DeleteSnapshot(ctx, nil, id)
			if err == nil {
				return &csi.DeleteSnapshotResponse{}, nil
			}
			if apiError, ok := err.(gopowerstore.APIError); ok {
				if apiError.NotFound() {
					return &csi.DeleteSnapshotResponse{}, nil
				}
			}
			return nil, err
		}
	}

	if apiError, ok := err.(gopowerstore.APIError); ok {
		if apiError.NotFound() {
			return &csi.DeleteSnapshotResponse{}, nil
		}
	}
	return nil, err
}

// ListSnapshots list all accessible snapshots from the storage array.
func (s *Service) ListSnapshots(ctx context.Context, req *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	var (
		startToken  int
		maxEntries  = int(req.GetMaxEntries())
		snapshotID  string
		sourceVolID string
	)

	if req.SnapshotId != "" {
		snapshotID = req.SnapshotId
	}

	if req.SourceVolumeId != "" {
		sourceVolID = req.SourceVolumeId
	}

	if v := req.GetStartingToken(); v != "" {
		i, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, status.Errorf(codes.Aborted, "unable to parse StartingToken: %v into uint32", v)
		}
		startToken = int(i)
	}
	// Call the common listVolumes code
	source, nextToken, err := s.listPowerStoreSnapshots(ctx, startToken, maxEntries, snapshotID, sourceVolID)
	if err != nil {
		return nil, err
	}
	if len(source) == 0 {
		return &csi.ListSnapshotsResponse{}, nil
	}

	// Process the source volumes and make CSI Volumes
	entries := make([]*csi.ListSnapshotsResponse_Entry, len(source))
	for i, snap := range source {
		size := snap.GetSize()
		// Correct size of filesystem snapshot
		if snap.GetType() == FilesystemSnapshotType {
			size = size - ReservedSize
		}
		entries[i] = &csi.ListSnapshotsResponse_Entry{
			Snapshot: getCSISnapshot(snap.GetID(), snap.GetSourceID(), size),
		}
	}

	return &csi.ListSnapshotsResponse{
		Entries:   entries,
		NextToken: nextToken,
	}, nil
}

// ControllerExpandVolume resizes Volume or FileSystem by increasing available volume capacity in the storage array.
func (s *Service) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	id, arrayID, protocol, err := array.ParseVolumeID(ctx, req.VolumeId, s.DefaultArray(), nil)
	if err != nil {
		return nil, status.Errorf(codes.OutOfRange, "unable to parse the volume id")
	}

	requiredBytes := req.GetCapacityRange().GetRequiredBytes()
	if requiredBytes > MaxVolumeSizeBytes {
		return nil, status.Errorf(codes.OutOfRange, "volume exceeds allowed limit")
	}

	if protocol == "scsi" {
		vol, err := s.Arrays()[arrayID].Client.GetVolume(ctx, id)
		if err != nil {
			return nil, status.Errorf(codes.OutOfRange, "detected SCSI protocol but wasn't able to fetch the volume info")
		}
		if vol.Size < requiredBytes {
			_, err = s.Arrays()[arrayID].Client.ModifyVolume(context.Background(), &gopowerstore.VolumeModify{Size: requiredBytes}, id)
			if err != nil {
				return nil, err
			}
			return &csi.ControllerExpandVolumeResponse{CapacityBytes: requiredBytes, NodeExpansionRequired: true}, nil
		}
		return &csi.ControllerExpandVolumeResponse{}, nil
	}
	fs, err := s.Arrays()[arrayID].Client.GetFS(ctx, id)
	if err == nil {
		if fs.SizeTotal < requiredBytes {
			_, err = s.Arrays()[arrayID].Client.ModifyFS(context.Background(), &gopowerstore.FSModify{Size: int(requiredBytes + ReservedSize)}, id)
			if err != nil {
				return nil, err
			}
		}
	}
	return &csi.ControllerExpandVolumeResponse{CapacityBytes: requiredBytes, NodeExpansionRequired: false}, nil
}

// ControllerGetVolume fetch current information about a volume
func (s *Service) ControllerGetVolume(ctx context.Context, req *csi.ControllerGetVolumeRequest) (*csi.ControllerGetVolumeResponse, error) {
	id, arrayID, protocol, err := array.ParseVolumeID(ctx, req.VolumeId, s.DefaultArray(), nil)
	if err != nil {
		return nil, status.Errorf(codes.OutOfRange, "unable to parse the volume id")
	}
	var hosts []string
	abnormal := false
	message := ""
	if protocol == "nfs" {
		// check if filesystem exists
		fs, err := s.Arrays()[arrayID].Client.GetFS(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.NotFound, "failed to find filesystem %s with error: %v", id, err.Error())
			}
			abnormal = true
			message = fmt.Sprintf("Filesystem %s is not found", id)
		} else {
			// get exports for filesystem if exists
			nfsExport, err := s.Arrays()[arrayID].Client.GetNFSExportByFileSystemID(ctx, fs.ID)
			if err != nil {
				if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
					return nil, status.Errorf(codes.NotFound, "failed to find nfs export for filesystem with error: %v", err.Error())
				}
			} else {
				// get hosts publish to export
				hosts = append(nfsExport.ROHosts, nfsExport.RORootHosts...)
				hosts = append(hosts, nfsExport.RWHosts...)
				hosts = append(hosts, nfsExport.RWRootHosts...)
			}
		}
	} else {
		// check if volume exists
		vol, err := s.Arrays()[arrayID].Client.GetVolume(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.NotFound, "failed to find volume %s with error: %v", id, err.Error())
			}
			abnormal = true
			message = fmt.Sprintf("Volume %s is not found", id)
		} else {
			// get hosts published to volume
			hostMappings, err := s.Arrays()[arrayID].Client.GetHostVolumeMappingByVolumeID(ctx, id)
			if err != nil {
				return nil, status.Errorf(codes.NotFound, "failed to get host volume mapping for volume: %s with error: %v", id, err.Error())
			}
			for _, hostMapping := range hostMappings {
				host, err := s.Arrays()[arrayID].Client.GetHost(ctx, hostMapping.HostID)
				if err != nil {
					if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
						return nil, status.Errorf(codes.NotFound, "failed to get host: %s with error: %v", hostMapping.HostID, err.Error())
					}
				} else {
					hosts = append(hosts, host.Name)
				}
			}
			// check if volume is in ready state
			if vol.State != gopowerstore.VolumeStateEnumReady {
				abnormal = true
				message = fmt.Sprintf("Volume %s is in %s state", id, string(vol.State))
			}
		}
	}

	resp := &csi.ControllerGetVolumeResponse{
		Volume: &csi.Volume{
			VolumeId: id,
		},
		Status: &csi.ControllerGetVolumeResponse_VolumeStatus{
			PublishedNodeIds: hosts,
			VolumeCondition: &csi.VolumeCondition{
				Abnormal: abnormal,
				Message:  message,
			},
		},
	}
	return resp, nil
}

// RegisterAdditionalServers registers replication extension
func (s *Service) RegisterAdditionalServers(server *grpc.Server) {
	csiext.RegisterReplicationServer(server, s)
	vgsext.RegisterVolumeGroupSnapshotServer(server, s)
	podmon.RegisterPodmonServer(server, s)
}

// ProbeController probes the controller service
func (s *Service) ProbeController(ctx context.Context, req *commonext.ProbeControllerRequest) (*commonext.ProbeControllerResponse, error) {
	ready := new(wrappers.BoolValue)
	ready.Value = true
	rep := new(commonext.ProbeControllerResponse)
	rep.Ready = ready
	rep.Name = common.Name
	rep.VendorVersion = core.SemVer
	rep.Manifest = common.Manifest

	log.Debug(fmt.Sprintf("ProbeController returning: %v", rep.Ready.GetValue()))
	return rep, nil
}

func (s *Service) listPowerStoreVolumes(ctx context.Context, startToken, maxEntries int) ([]gopowerstore.Volume, string, error) {
	var volumes []gopowerstore.Volume

	// Get the volumes from the cache if we can
	for _, arr := range s.Arrays() {
		v, err := arr.GetClient().GetVolumes(ctx)
		if err != nil {
			return nil, "", status.Errorf(codes.Internal, "unable to list volumes: %s", err.Error())
		}

		volumes = append(volumes, v...)
	}

	if startToken > len(volumes) {
		return nil, "", status.Errorf(codes.Aborted, "startingToken=%d > len(volumes)=%d", startToken, len(volumes))
	}
	// Discern the number of remaining entries.
	rem := len(volumes) - startToken

	// If maxEntries is 0 or greater than the number of remaining entries then
	// set max entries to the number of remaining entries.
	if maxEntries == 0 || maxEntries > rem {
		maxEntries = rem
	}

	// We can't really return more per page
	if maxEntries > 700 {
		maxEntries = 700
	}

	// Compute the next starting point; if at end reset
	nextToken := startToken + maxEntries
	nextTokenStr := ""
	if nextToken < (startToken + rem) {
		nextTokenStr = fmt.Sprintf("%d", nextToken)
	}

	return volumes[startToken : startToken+maxEntries], nextTokenStr, nil
}

func (s *Service) listPowerStoreSnapshots(ctx context.Context, startToken, maxEntries int, snapID, srcID string) ([]GeneralSnapshot, string, error) {
	var generalSnapshots []GeneralSnapshot

	if snapID == "" && srcID == "" {
		log.Info("Requested all snapshots, iterating through arrays")
		for _, arr := range s.Arrays() {
			// List block snapshots
			snaps, err := arr.GetClient().GetSnapshots(ctx)
			if err != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to list block snapshots: %s", err.Error())
			}

			for _, snap := range snaps {
				generalSnapshots = append(generalSnapshots, VolumeSnapshot(snap))
			}

			// List filesystem snapshots too
			fsSnaps, err := arr.GetClient().GetFsSnapshots(ctx)
			if err != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to list filesystem snapshots: %s", err.Error())
			}

			for _, snap := range fsSnaps {
				generalSnapshots = append(generalSnapshots, FilesystemSnapshot(snap))
			}
		}
	} else if snapID != "" {
		log.Infof("Requested snapshot via snapshot id %s", snapID)
		id, arrayID, protocol, err := array.ParseVolumeID(ctx, snapID, s.DefaultArray(), nil)
		if err != nil {
			log.Error(err)
			return []GeneralSnapshot{}, "", nil
		}

		arr, ok := s.Arrays()[arrayID]
		if !ok {
			return nil, "", status.Errorf(codes.Internal, "unable to get array with arrayID %s", arrayID)
		}

		if protocol == "nfs" {
			fsSnapshot, getErr := arr.GetClient().GetFsSnapshot(ctx, id)
			if apiError, ok := getErr.(gopowerstore.APIError); ok && apiError.NotFound() {
				// given snapshot id does not exist, should return empty response
				return generalSnapshots, "", nil
			}
			if getErr != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to get filesystem snapshot: %s", getErr.Error())
			}

			log.Info(fsSnapshot)

			fsSnapshot.ID = fsSnapshot.ID + "/" + arrayID + "/" + protocol
			generalSnapshots = append(generalSnapshots, FilesystemSnapshot(fsSnapshot))
		} else {
			blockSnap, getErr := arr.GetClient().GetSnapshot(ctx, id)
			if apiError, ok := getErr.(gopowerstore.APIError); ok && apiError.NotFound() {
				// given snapshot id does not exist, should return empty response
				return generalSnapshots, "", nil
			}
			if getErr != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to get block snapshot: %s", getErr.Error())
			}
			blockSnap.ID = blockSnap.ID + "/" + arrayID + "/" + protocol
			generalSnapshots = append(generalSnapshots, VolumeSnapshot(blockSnap))
		}
	} else {
		log.Infof("Requested snapshot via source id %s", srcID)
		// This works VGS on single default array, But for multiple array scenario this default array should be changed to dynamic array
		id, arrayID, protocol, err := array.ParseVolumeID(ctx, srcID, s.DefaultArray(), nil)
		if err != nil {
			log.Error(err)
			return []GeneralSnapshot{}, "", nil
		}

		arr, ok := s.Arrays()[arrayID]
		if !ok {
			return nil, "", status.Errorf(codes.Internal, "unable to get array with arrayID %s", arrayID)
		}
		if protocol == "nfs" {
			snaps, err := arr.GetClient().GetFsSnapshotsByVolumeID(ctx, id)
			if err != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to list filesystem snapshots: %s", err.Error())
			}
			for _, snap := range snaps {
				generalSnapshots = append(generalSnapshots, FilesystemSnapshot(snap))
			}
		} else {
			snaps, err := arr.GetClient().GetSnapshotsByVolumeID(ctx, id)
			if err != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to list block snapshots: %s", err.Error())
			}
			for _, snap := range snaps {
				generalSnapshots = append(generalSnapshots, VolumeSnapshot(snap))
			}
		}
	}

	if startToken > len(generalSnapshots) {
		return nil, "", status.Errorf(codes.Aborted, "startingToken=%d > len(generalSnapshots)=%d", startToken, len(generalSnapshots))
	}
	// Discern the number of remaining entries.
	rem := len(generalSnapshots) - startToken

	// If maxEntries is 0 or greater than the number of remaining entries then
	// set max entries to the number of remaining entries.
	if maxEntries == 0 || maxEntries > rem {
		maxEntries = rem
	}

	// We can't really return more per page
	if maxEntries > 300 {
		maxEntries = 300
	}

	// Compute the next starting point; if at end reset
	nextToken := startToken + maxEntries
	nextTokenStr := ""
	if nextToken < (startToken + rem) {
		nextTokenStr = fmt.Sprintf("%d", nextToken)
	}

	return generalSnapshots[startToken : startToken+maxEntries], nextTokenStr, nil
}
