/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// VolumePublisher allows to publish a volume
type VolumePublisher interface {
	// CheckIfVolumeExists queries storage array if given volume already exists
	CheckIfVolumeExists(ctx context.Context, client gopowerstore.Client, volID string) error
	// Publish does the steps necessary for volume to be available on the node
	Publish(ctx context.Context, publishContext map[string]string, req *csi.ControllerPublishVolumeRequest, client gopowerstore.Client,
		kubeNodeID string, volumeID string, isRemote bool) (*csi.ControllerPublishVolumeResponse, error)
}

// SCSIPublisher implementation of VolumePublisher for SCSI based (FC, iSCSI) volumes
type SCSIPublisher struct{}

// Publish publishes Volume by attaching it to the host
func (s *SCSIPublisher) Publish(ctx context.Context, publishContext map[string]string, req *csi.ControllerPublishVolumeRequest,
	client gopowerstore.Client, kubeNodeID string, volumeID string, isRemote bool,
) (*csi.ControllerPublishVolumeResponse, error) {
	volume, err := client.GetVolume(ctx, volumeID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return nil, status.Errorf(codes.NotFound, "volume with ID '%s' not found", volumeID)
		}
		return nil, status.Errorf(codes.Internal, "failure checking volume status for volume publishing: %s", err.Error())
	}

	var node gopowerstore.Host
	node, err = client.GetHostByName(ctx, kubeNodeID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.HostIsNotExist() {
			// We need additional check here since we can just have host without ip in it
			ipList := identifiers.GetIPListFromString(kubeNodeID)
			if ipList == nil || len(ipList) == 0 {
				return nil, status.Errorf(codes.NotFound, "can't find IP in node ID")
			}
			ip := ipList[len(ipList)-1]
			nodeID := kubeNodeID[:len(kubeNodeID)-len(ip)-1]
			node, err = client.GetHostByName(ctx, nodeID)
			if err != nil {
				return nil, status.Errorf(codes.NotFound, "host with k8s node ID '%s' not found", kubeNodeID)
			}
		} else {
			return nil, status.Errorf(codes.Internal, "failure checking host '%s' status for volume publishing: %s",
				kubeNodeID, err.Error())
		}
	}

	mapping, err := client.GetHostVolumeMappingByVolumeID(ctx, volume.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to get mapping for volume with ID '%s': %s", volume.ID, err.Error())
	}

	err = s.addTargetsInfoToPublishContext(publishContext, volume.ApplianceID, client, isRemote)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not get scsi Targets: %s", err.Error())
	}

	mappingCount := len(mapping)

	// Check if the volume is already attached to some host
	for _, m := range mapping {
		if m.HostID == node.ID {
			log.Debug("Volume already mapped")
			s.addLUNIDToPublishContext(publishContext, m, volume, isRemote)
			return &csi.ControllerPublishVolumeResponse{
				PublishContext: publishContext,
			}, nil
		}
	}

	if mappingCount != 0 {
		switch req.VolumeCapability.AccessMode.Mode {
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_SINGLE_WRITER,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_MULTI_WRITER:
			log.Error(fmt.Sprintf(
				"ControllerPublishVolume: Volume present in a different lun mapping - '%s'",
				mapping[0].HostID))
			return nil, status.Errorf(
				codes.FailedPrecondition,
				"volume already present in a different lun mapping on node '%s'",
				mapping[0].HostID)
		}
	}
	// Attach volume to host
	log.Debugf("Attach volume %s to host %s", volume.ID, node.ID)
	params := gopowerstore.HostVolumeAttach{VolumeID: &volume.ID}
	_, err = client.AttachVolumeToHost(ctx, node.ID, &params)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to attach volume with ID '%s' to host with ID '%s': %s", volume.ID, node.ID, err.Error())
	}

	mapping, err = client.GetHostVolumeMappingByVolumeID(ctx, volume.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to get mapping for volume with ID '%s' after attaching: %s", volume.ID, err.Error())
	}
	for _, m := range mapping {
		if m.HostID == node.ID {
			s.addLUNIDToPublishContext(publishContext, m, volume, isRemote)
			return &csi.ControllerPublishVolumeResponse{PublishContext: publishContext}, nil
		}
	}
	return nil, status.Errorf(codes.Internal,
		"failed to find mapping of volume with ID '%s' to host '%s'", volume.ID, node.ID)
}

// CheckIfVolumeExists queries storage array if Volume with given name exists
func (s *SCSIPublisher) CheckIfVolumeExists(ctx context.Context, client gopowerstore.Client, volID string) error {
	_, err := client.GetVolume(ctx, volID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return status.Errorf(codes.NotFound, "volume with ID '%s' not found", volID)
		}
		return status.Errorf(codes.Internal, "failure checking volume status for volume publishing: %s", err.Error())
	}

	return nil
}

func (s *SCSIPublisher) addLUNIDToPublishContext(
	publishContext map[string]string,
	mapping gopowerstore.HostVolumeMapping,
	volume gopowerstore.Volume,
	isRemote bool,
) {
	if !isRemote {
		publishContext[identifiers.PublishContextDeviceWWN] = strings.TrimPrefix(volume.Wwn, identifiers.WWNPrefix)
		publishContext[identifiers.PublishContextLUNAddress] = strconv.FormatInt(mapping.LogicalUnitNumber, 10)
	} else {
		publishContext[identifiers.PublishContextRemoteDeviceWWN] = strings.TrimPrefix(volume.Wwn, identifiers.WWNPrefix)
		publishContext[identifiers.PublishContextRemoteLUNAddress] = strconv.FormatInt(mapping.LogicalUnitNumber, 10)
	}
}

func (s *SCSIPublisher) addTargetsInfoToPublishContext(
	publishContext map[string]string, volumeApplianceID string, client gopowerstore.Client, isRemote bool,
) error {
	iscsiPortalsKey := identifiers.PublishContextISCSIPortalsPrefix
	iscsiTargetsKey := identifiers.PublishContextISCSITargetsPrefix
	fcWwpnKey := identifiers.PublishContextFCWWPNPrefix
	nvmeFcPortalsKey := identifiers.PublishContextNVMEFCPortalsPrefix
	nvmeFcTargetsKey := identifiers.PublishContextNVMEFCTargetsPrefix
	nvmeTCPPortalsKey := identifiers.PublishContextNVMETCPPortalsPrefix
	nvmeTCPTargetsKey := identifiers.PublishContextNVMETCPTargetsPrefix
	if isRemote {
		iscsiPortalsKey = identifiers.PublishContextRemoteISCSIPortalsPrefix
		iscsiTargetsKey = identifiers.PublishContextRemoteISCSITargetsPrefix
		fcWwpnKey = identifiers.PublishContextRemoteFCWWPNPrefix
		nvmeFcPortalsKey = identifiers.PublishContextRemoteNVMEFCPortalsPrefix
		nvmeFcTargetsKey = identifiers.PublishContextRemoteNVMEFCTargetsPrefix
		nvmeTCPPortalsKey = identifiers.PublishContextRemoteNVMETCPPortalsPrefix
		nvmeTCPTargetsKey = identifiers.PublishContextRemoteNVMETCPTargetsPrefix
	}

	iscsiTargetsInfo, err := identifiers.GetISCSITargetsInfoFromStorage(client, volumeApplianceID)
	if err != nil {
		log.Error("error unable to get iSCSI targets from array", err)
	}
	for i, t := range iscsiTargetsInfo {
		publishContext[fmt.Sprintf("%s%d", iscsiPortalsKey, i)] = t.Portal
		publishContext[fmt.Sprintf("%s%d", iscsiTargetsKey, i)] = t.Target
	}
	fcTargetsInfo, err := identifiers.GetFCTargetsInfoFromStorage(client, volumeApplianceID)
	if err != nil {
		log.Error("error unable to get FC targets from array", err)
	}
	for i, t := range fcTargetsInfo {
		publishContext[fmt.Sprintf("%s%d", fcWwpnKey, i)] = t.WWPN
	}

	nvmefcTargetInfo, err := identifiers.GetNVMEFCTargetInfoFromStorage(client, volumeApplianceID)
	if err != nil {
		log.Error("error unable to get NVMeFC targets from array", err)
	}
	for i, t := range nvmefcTargetInfo {
		publishContext[fmt.Sprintf("%s%d", nvmeFcPortalsKey, i)] = t.Portal
		publishContext[fmt.Sprintf("%s%d", nvmeFcTargetsKey, i)] = t.Target
	}

	nvmetcpTargetInfo, err := identifiers.GetNVMETCPTargetsInfoFromStorage(client, volumeApplianceID)
	if err != nil {
		log.Error("error unable to get NVMeTCP targets from array", err)
	}
	for i, t := range nvmetcpTargetInfo {
		publishContext[fmt.Sprintf("%s%d", nvmeTCPPortalsKey, i)] = t.Portal
		publishContext[fmt.Sprintf("%s%d", nvmeTCPTargetsKey, i)] = t.Target
	}

	// If the system is not capable of any protocol, then we will through the error
	if len(iscsiTargetsInfo) == 0 && len(fcTargetsInfo) == 0 && len(nvmefcTargetInfo) == 0 && len(nvmetcpTargetInfo) == 0 {
		return errors.New("unable to get targets for any protocol")
	}
	return nil
}

// NfsPublisher implementation of VolumePublisher for NFS volumes
type NfsPublisher struct {
	// ExternalAccess used to set custom ip to be added to the NFS Export 'hosts' list
	ExternalAccess string
}

// Publish publishes FileSystem by adding host (node) to the NFS Export 'hosts' list
func (n *NfsPublisher) Publish(ctx context.Context, publishContext map[string]string, req *csi.ControllerPublishVolumeRequest, client gopowerstore.Client,
	kubeNodeID string, volumeID string, _ bool,
) (*csi.ControllerPublishVolumeResponse, error) {
	fs, err := client.GetFS(ctx, volumeID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return nil, status.Errorf(codes.NotFound, "volume with ID '%s' not found", volumeID)
		}
		return nil, status.Errorf(codes.Internal, "failure checking volume status for volume publishing: %s", err.Error())
	}

	ipList := identifiers.GetIPListFromString(kubeNodeID)
	if ipList == nil || len(ipList) == 0 {
		return nil, status.Error(codes.NotFound, "can't find IP in node ID")
	}
	ip := ipList[0]

	ipWithNat := make([]string, 0, 2)
	ipWithNat = append(ipWithNat, ip)

	// Create NFS export if it doesn't exist
	_, err = client.GetNFSExportByFileSystemID(ctx, fs.ID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			_, err := client.CreateNFSExport(ctx, &gopowerstore.NFSExportCreate{
				Name:         fs.Name,
				FileSystemID: volumeID,
				Path:         "/" + fs.Name,
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failure creating nfs export: %s", err.Error())
			}
		} else {
			return nil, status.Errorf(codes.Internal,
				"failure checking nfs export status for volume publishing: %s", err.Error())
		}
	}

	export, err := client.GetNFSExportByFileSystemID(ctx, fs.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failure getting nfs export: %s", err.Error())
	}

	if n.ExternalAccess != "" && !identifiers.ExternalAccessAlreadyAdded(export, n.ExternalAccess) {
		externalAccess, err := identifiers.GetIPListWithMaskFromString(n.ExternalAccess)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "can't find IP in X_CSI_POWERSTORE_EXTERNAL_ACCESS variable")
		}
		log.Debug("externalAccess parsed IP:", externalAccess)
		ipWithNat = append(ipWithNat, externalAccess)
	}
	// Add host IP to existing nfs export
	_, err = client.ModifyNFSExport(ctx, &gopowerstore.NFSExportModify{
		AddRWRootHosts: ipWithNat,
	}, export.ID)
	if err != nil {
		log.Debug("Error while PublishVolume: ", err.Error())
		if apiError, ok := err.(gopowerstore.APIError); !(ok && (apiError.NotFound() || apiError.HostAlreadyPresentInNFSExport())) {
			return nil, status.Errorf(codes.Internal, "failure when adding new host to nfs export: %s", err.Error())
		}
	}

	nas, err := client.GetNAS(ctx, fs.NasServerID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failure getting nas %s", err.Error())
	}
	fileInterface, err := client.GetFileInterface(ctx, nas.CurrentPreferredIPv4InterfaceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failure getting file interface %s", err.Error())
	}
	publishContext[KeyNasName] = nas.Name // we need to pass that to node part of the driver
	publishContext[identifiers.KeyNfsExportPath] = fileInterface.IPAddress + ":/" + export.Name
	publishContext[identifiers.KeyHostIP] = ipWithNat[0]
	if n.ExternalAccess != "" {
		parsedExternalAccess, _ := identifiers.GetIPListWithMaskFromString(n.ExternalAccess)
		publishContext[identifiers.KeyNatIP] = parsedExternalAccess
	}
	publishContext[identifiers.KeyExportID] = export.ID
	publishContext[identifiers.KeyAllowRoot] = req.VolumeContext[identifiers.KeyAllowRoot]
	publishContext[identifiers.KeyNfsACL] = req.VolumeContext[identifiers.KeyNfsACL]
	return &csi.ControllerPublishVolumeResponse{PublishContext: publishContext}, nil
}

// CheckIfVolumeExists queries storage array if FileSystem with given name exists
func (n *NfsPublisher) CheckIfVolumeExists(ctx context.Context, client gopowerstore.Client, volID string) error {
	_, err := client.GetFS(ctx, volID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return status.Errorf(codes.NotFound, "volume with ID '%s' not found", volID)
		}
		return status.Errorf(codes.Internal, "failure checking volume status for volume publishing: %s", err.Error())
	}
	return nil
}
