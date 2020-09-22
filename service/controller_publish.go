/*
 *
 * Copyright © 2020 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package service

import (
	"context"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sort"
	"strconv"
	"strings"
)

type VolumePublisher interface {
	CheckIfVolumeExists(ctx context.Context, client gopowerstore.Client, volID string) error
	Publish(ctx context.Context, req *csi.ControllerPublishVolumeRequest, client gopowerstore.Client,
		apiThrottle timeoutSemaphore, kubeNodeID string) (*csi.ControllerPublishVolumeResponse, error)
}

type SCSIPublisher struct {
	volume gopowerstore.Volume
}

func (s *SCSIPublisher) Publish(ctx context.Context, req *csi.ControllerPublishVolumeRequest, client gopowerstore.Client, apiThrottle timeoutSemaphore,
	kubeNodeID string) (*csi.ControllerPublishVolumeResponse, error) {

	if s.volume.ID == "" {
		err := s.CheckIfVolumeExists(ctx, client, req.GetVolumeId())
		if err != nil {
			return nil, err
		}
	}

	volume := &s.volume
	publishContext := make(map[string]string)

	node, err := client.GetHostByName(ctx, kubeNodeID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.HostIsNotExist() {
			return nil, status.Errorf(codes.NotFound, "host with k8s node ID '%s' not found", kubeNodeID)
		}
		return nil, status.Errorf(codes.Internal,
			"failure checking host '%s' status for volume publishing: %s",
			kubeNodeID, err.Error())
	}

	mapping, err := client.GetHostVolumeMappingByVolumeID(ctx, volume.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to get mapping for volume with ID '%s': %s",
			volume.ID, err.Error())
	}

	err = s.addTargetsInfoToPublishContext(publishContext, client)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not get iscsi iscsiTargets: %s", err.Error())
	}

	mappingCount := len(mapping)

	// Check if the volume is already attached to some host
	for _, m := range mapping {
		if m.HostID == node.ID {
			log.Debug("Volume already mapped")
			s.addLUNIDToPublishContext(publishContext, m, *volume)
			return &csi.ControllerPublishVolumeResponse{
				PublishContext: publishContext}, nil
		}
	}

	if mappingCount != 0 {
		switch req.VolumeCapability.AccessMode.Mode {
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY:
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

	if err = apiThrottle.Acquire(ctx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	_, err = client.AttachVolumeToHost(ctx, node.ID, &params)
	apiThrottle.Release(ctx)

	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to attach volume with ID '%s' to host with ID '%s': %s",
			volume.ID, node.ID, err.Error())
	}

	mapping, err = client.GetHostVolumeMappingByVolumeID(ctx, volume.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to get mapping for volume with ID '%s' after attaching: %s",
			volume.ID, err.Error())
	}
	s.addLUNIDToPublishContext(publishContext, mapping[0], *volume)
	return &csi.ControllerPublishVolumeResponse{PublishContext: publishContext}, nil
}

func (s *SCSIPublisher) CheckIfVolumeExists(ctx context.Context, client gopowerstore.Client, volID string) error {
	volume, err := client.GetVolume(ctx, volID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeIsNotExist() {
			return status.Errorf(codes.NotFound, "volume with ID '%s' not found", volID)
		}
		return status.Errorf(codes.Internal,
			"failure checking volume status for volume publishing: %s",
			err.Error())
	}
	s.volume = volume

	return nil
}

func (s *SCSIPublisher) addLUNIDToPublishContext(
	publishContext map[string]string,
	mapping gopowerstore.HostVolumeMapping,
	volume gopowerstore.Volume) {
	publishContext[PublishContextDeviceWWN] = strings.TrimPrefix(volume.Wwn, WWNPrefix)
	publishContext[PublishContextLUNAddress] = strconv.FormatInt(mapping.LogicalUnitNumber, 10)
}

func (s *SCSIPublisher) addTargetsInfoToPublishContext(
	publishContext map[string]string, client gopowerstore.Client) error {

	iscsiTargetsInfo, err := s.getISCSITargetsInfoFromStorage(client)
	if err != nil {
		return err
	}
	for i, t := range iscsiTargetsInfo {
		publishContext[fmt.Sprintf("%s%d", PublishContextISCSIPortalsPrefix, i)] = t.Portal
		publishContext[fmt.Sprintf("%s%d", PublishContextISCSITargetsPrefix, i)] = t.Target
	}
	fcTargetsInfo, err := s.getFCTargetsInfoFromStorage(client)
	if err != nil {
		return err
	}
	for i, t := range fcTargetsInfo {
		publishContext[fmt.Sprintf("%s%d", PublishContextFCWWPNPrefix, i)] = t.WWPN
	}

	return nil
}

func (s *SCSIPublisher) getISCSITargetsInfoFromStorage(client gopowerstore.Client) ([]ISCSITargetInfo, error) {
	addrInfo, err := client.GetStorageISCSITargetAddresses(context.Background())
	if err != nil {
		log.Error(err.Error())
		return []ISCSITargetInfo{}, err
	}
	// sort data by id
	sort.Slice(addrInfo, func(i, j int) bool {
		return addrInfo[i].ID < addrInfo[j].ID
	})
	result := make([]ISCSITargetInfo, len(addrInfo))
	for i, t := range addrInfo {
		result[i] = ISCSITargetInfo{Target: t.IPPort.TargetIqn, Portal: fmt.Sprintf("%s:3260", t.Address)}
	}
	return result, nil
}

func (s *SCSIPublisher) getFCTargetsInfoFromStorage(client gopowerstore.Client) ([]FCTargetInfo, error) {
	fcPorts, err := client.GetFCPorts(context.Background())
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	var result []FCTargetInfo
	for _, t := range fcPorts {
		if t.IsLinkUp {
			result = append(result, FCTargetInfo{WWPN: strings.Replace(t.Wwn, ":", "", -1)})
		}
	}
	return result, nil
}

type NfsPublisher struct {
}

func (n *NfsPublisher) Publish(ctx context.Context, req *csi.ControllerPublishVolumeRequest, client gopowerstore.Client, apiThrottle timeoutSemaphore,
	kubeNodeID string) (*csi.ControllerPublishVolumeResponse, error) {
	fs, err := client.GetFS(ctx, req.GetVolumeId())
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeIsNotExist() {
			return nil, status.Errorf(codes.NotFound, "volume with ID '%s' not found", req.GetVolumeId())
		}
		return nil, status.Errorf(codes.Internal,
			"failure checking volume status for volume publishing: %s",
			err.Error())
	}
	publishContext := make(map[string]string)

	ip, err := getIPFromNodeID(kubeNodeID)
	if err != nil {
		return nil, err
	}

	// Create NFS export if it doesn't exist
	var exportID string

	export, err := client.GetNFSExportByFileSystemID(ctx, fs.ID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeIsNotExist() {
			if err = apiThrottle.Acquire(ctx); err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			resp, err := client.CreateNFSExport(ctx, &gopowerstore.NFSExportCreate{
				Name:         fs.Name,
				FileSystemID: req.GetVolumeId(),
				Path:         "/" + fs.Name,
			})
			apiThrottle.Release(ctx)
			if err != nil {
				return nil, status.Errorf(codes.Internal,
					"failure creating nfs export: %s",
					err.Error())
			}
			exportID = resp.ID
		} else {
			return nil, status.Errorf(codes.Internal,
				"failure checking nfs export status for volume publishing: %s",
				err.Error())
		}
	} else {
		exportID = export.ID
	}

	// Add host IP to existing nfs export
	if err = apiThrottle.Acquire(ctx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	_, err = client.ModifyNFSExport(ctx, &gopowerstore.NFSExportModify{
		AddHosts: &[]string{ip},
	}, exportID)
	apiThrottle.Release(ctx)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.VolumeIsNotExist()) {
			return nil, status.Errorf(codes.Internal,
				"failure when adding new host to nfs export: %s",
				err.Error())
		}
	}

	nas, err := client.GetNAS(ctx, fs.NasServerID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failure getting nas %s", err.Error())
	}
	fileInterface, err := client.GetFileInterface(ctx, nas.CurrentPreferredIPv4InterfaceId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failure getting file interface %s", err.Error())
	}
	publishContext[keyNasName] = nas.Name // we need to pass that to node part of the driver
	publishContext[keyFsType] = "nfs"     // we in nfs publish
	publishContext["NfsExportPath"] = fileInterface.IpAddress + ":/" + fs.Name
	return &csi.ControllerPublishVolumeResponse{PublishContext: publishContext}, nil
}

func (n *NfsPublisher) CheckIfVolumeExists(ctx context.Context, client gopowerstore.Client, volID string) error {
	_, err := client.GetFS(ctx, volID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeIsNotExist() {
			return status.Errorf(codes.NotFound, "volume with ID '%s' not found", volID)
		}
		return status.Errorf(codes.Internal,
			"failure checking volume status for volume publishing: %s",
			err.Error())
	}
	return nil
}

func getIPFromNodeID(kubeNodeID string) (string, error) {
	list := strings.Split(kubeNodeID, "-")
	if len(list) < 3 {
		return "", status.Error(codes.Internal, "can't find the ip in volumeID")
	}
	ip := list[len(list)-1]
	return ip, nil
}
