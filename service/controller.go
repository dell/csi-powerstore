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
	"github.com/dell/gopowerstore"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strconv"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	log "github.com/sirupsen/logrus"
)

const (
	// MinVolumeSizeBytes is minimal size for volume creation on PowerStore
	MinVolumeSizeBytes = 1048576
	// MaxVolumeSizeBytes is maximum size for volume creation on PowerStore
	MaxVolumeSizeBytes = 1099511627776 * 256 // 256 TB
	// VolumeSizeMultiple multiplier for volumes
	VolumeSizeMultiple = 8192
	// MaxVolumeNameLength max length for the volume name
	MaxVolumeNameLength = 128

	errUnknownAccessType = "unknown access type is not Block or Mount"
	errUnknownAccessMode = "access mode cannot be UNKNOWN"
	errNoMultiNodeWriter = "multi-node with writer(s) only supported for block access type"

	PublishContextDeviceWWN          = "DEVICE_WWN"
	PublishContextLUNAddress         = "LUN_ADDRESS"
	PublishContextISCSIPortalsPrefix = "PORTAL"
	PublishContextISCSITargetsPrefix = "TARGET"
	PublishContextFCWWPNPrefix       = "FCWWPN"
	WWNPrefix                        = "naa."
)

func (s *service) CreateVolume(
	ctx context.Context,
	req *csi.CreateVolumeRequest) (
	*csi.CreateVolumeResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

	params := req.GetParameters()
	if err := parameterCreateValidation(params); err != nil {
		return nil, err
	}

	// Get the required capacity
	sizeInBytes, err := getVolumeSize(req.GetCapacityRange())
	if err != nil {
		return nil, err
	}

	// Get the volume name
	volumeName := req.GetName()
	if err := volumeNameValidation(volumeName); err != nil {
		return nil, err
	}

	contentSource := req.GetVolumeContentSource()
	if contentSource != nil {
		volumeSource := contentSource.GetVolume()
		if volumeSource != nil {
			return nil, status.Error(codes.InvalidArgument, "Volume as a VolumeContentSource is not supported (i.e. clone)")
		}
		snapshotSource := contentSource.GetSnapshot()
		if snapshotSource != nil {
			log.Printf("snapshot %s specified as volume content source", snapshotSource.SnapshotId)
			return s.createVolumeFromSnapshot(ctx, req, snapshotSource, volumeName, sizeInBytes)
		}
	}

	storageType := gopowerstore.StorageTypeEnumBlock
	reqParams := &gopowerstore.VolumeCreate{Name: &volumeName, Size: &sizeInBytes, StorageType: &storageType}

	var volumeResponse *csi.Volume

	if err = s.apiThrottle.Acquire(ctx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	resp, err := s.adminClient.CreateVolume(ctx, reqParams)
	s.apiThrottle.Release(ctx)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeNameIsAlreadyUse() {
			alreadyExistVolume, err := s.getExistVolume(ctx, volumeName, sizeInBytes)
			if err != nil {
				return nil, err
			}
			volumeResponse = getCSIVolume(alreadyExistVolume.ID, alreadyExistVolume.Size)
		} else {
			return nil, status.Error(codes.Internal, err.Error())
		}
	} else {
		volumeResponse = getCSIVolume(resp.ID, sizeInBytes)
	}

	return &csi.CreateVolumeResponse{
		Volume: volumeResponse,
	}, nil
}

func (s *service) getExistVolume(ctx context.Context, volumeName string, requiredSize int64) (gopowerstore.Volume, error) {
	alreadyExistVolume, err := s.adminClient.GetVolumeByName(ctx, volumeName)
	if err != nil {
		return gopowerstore.Volume{}, status.Errorf(codes.Internal, "can't find volume '%s': %s", volumeName, err.Error())
	}

	if alreadyExistVolume.Size < requiredSize {
		return gopowerstore.Volume{}, status.Errorf(codes.AlreadyExists,
			"volume '%s' already exists but is incompatible volume size: %d < %d",
			volumeName, alreadyExistVolume.Size, requiredSize)
	}
	return alreadyExistVolume, nil
}

func getVolumeSize(cr *csi.CapacityRange) (int64, error) {
	minSize := cr.GetRequiredBytes()
	maxSize := cr.GetLimitBytes()

	if minSize == 0 {
		minSize = MinVolumeSizeBytes
	}
	if maxSize == 0 {
		maxSize = MaxVolumeSizeBytes
	}

	mod := minSize % VolumeSizeMultiple
	if mod > 0 {
		minSize = minSize + VolumeSizeMultiple - mod
	}

	if err := volumeSizeValidation(minSize, maxSize); err != nil {
		return 0, err
	}

	return minSize, nil
}

func getCSIVolume(VolumeID string, size int64) *csi.Volume {
	volume := &csi.Volume{
		VolumeId:      VolumeID,
		CapacityBytes: size,
	}
	return volume
}

func getCSIVolumeFromSnapshot(VolumeID string, snapshotSource *csi.VolumeContentSource_SnapshotSource, size int64) *csi.Volume {
	volume := &csi.Volume{
		CapacityBytes: size,
		VolumeId:      VolumeID,
		ContentSource: &csi.VolumeContentSource{
			Type: &csi.VolumeContentSource_Snapshot{
				Snapshot: snapshotSource,
			},
		},
	}
	return volume
}

func getCSISnapshot(snapshotId string, sourceVolumeId string, sizeInBytes int64) *csi.Snapshot {
	snap := &csi.Snapshot{
		SizeBytes:      sizeInBytes,
		SnapshotId:     snapshotId,
		SourceVolumeId: sourceVolumeId,
		CreationTime:   ptypes.TimestampNow(),
		ReadyToUse:     true,
	}
	return snap
}

// Create a volume (which is actually a snapshot) from an existing snapshot.
// The snapshotSource gives the SnapshotId which is the volume to be replicated.
func (s *service) createVolumeFromSnapshot(ctx context.Context, req *csi.CreateVolumeRequest,
	snapshotSource *csi.VolumeContentSource_SnapshotSource,
	volumeName string, sizeInBytes int64) (*csi.CreateVolumeResponse, error) {
	var volumeResponse *csi.Volume
	// Lookup the volume source volume.
	sourceVol, err := s.getVolByID(ctx, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "snapshot not found: %s", snapshotSource.SnapshotId)
	}
	if sourceVol.Size != sizeInBytes {
		return nil, status.Errorf(codes.InvalidArgument,
			"snapshot %s has incompatible size %d bytes with requested %d bytes",
			snapshotSource.SnapshotId, sourceVol.Size, sizeInBytes)
	}

	createParams := gopowerstore.VolumeClone{
		Name:        &volumeName,
		Description: nil,
	}

	volume, err := s.adminClient.CreateVolumeFromSnapshot(ctx, &createParams, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't create volume: %s", snapshotSource.SnapshotId)
	}

	volumeResponse = getCSIVolumeFromSnapshot(volume.ID, snapshotSource, sizeInBytes)
	return &csi.CreateVolumeResponse{
		Volume: volumeResponse,
	}, nil
}

func (s *service) DeleteVolume(
	ctx context.Context,
	req *csi.DeleteVolumeRequest) (
	*csi.DeleteVolumeResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

	id := req.GetVolumeId()

	if err := s.apiThrottle.Acquire(ctx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	_, err := s.adminClient.DeleteVolume(ctx, nil, id)
	s.apiThrottle.Release(ctx)
	if err == nil {
		return &csi.DeleteVolumeResponse{}, nil
	}
	if apiError, ok := err.(gopowerstore.APIError); ok {
		if apiError.VolumeIsNotExist() {
			return &csi.DeleteVolumeResponse{}, nil
		}
		if apiError.VolumeAttachedToHost() {
			err = status.Errorf(codes.Internal,
				"volume with ID '%s' is still attached to host: %s", id, apiError.Error())
		}
	}
	return nil, err
}

func (si *serviceIMPL) detachVolumeFromAllHosts(ctx context.Context, volumeID string) error {
	mappings, err := si.service.adminClient.GetHostVolumeMappingByVolumeID(ctx, volumeID)
	if err != nil {
		return err
	}
	for _, m := range mappings {
		err = si.implProxy.detachVolumeFromHost(ctx, m.HostID, volumeID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (si *serviceIMPL) detachVolumeFromHost(ctx context.Context, hostID string, volumeID string) error {
	dp := &gopowerstore.HostVolumeDetach{VolumeID: &volumeID}
	_, err := si.service.adminClient.DetachVolumeFromHost(ctx, hostID, dp)
	if err != nil {
		apiError, ok := err.(gopowerstore.APIError)
		if ok && apiError.HostIsNotExist() {
			return status.Errorf(codes.NotFound, "host with ID '%s' not found", hostID)
		}
		if !ok || !apiError.HostIsNotAttachedToVolume() {
			return status.Errorf(codes.Unknown,
				"failed to detach volume '%s' from host: %s",
				volumeID, err.Error())
		}
	}
	return nil
}

func (s *service) ControllerPublishVolume(
	ctx context.Context,
	req *csi.ControllerPublishVolumeRequest) (
	*csi.ControllerPublishVolumeResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
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
		return nil, status.Error(codes.InvalidArgument, errUnknownAccessMode)
	}

	volID := req.GetVolumeId()
	if volID == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}
	volume, err := s.getVolByID(ctx, volID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeIsNotExist() {
			return nil, status.Errorf(codes.NotFound, "volume with ID '%s' not found", volID)
		}
		return nil, status.Errorf(codes.Internal,
			"failure checking volume status for volume publishing: %s",
			err.Error())
	}

	kubeNodeID := req.GetNodeId()
	if kubeNodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "node ID is required")
	}
	node, err := s.getNodeByID(ctx, kubeNodeID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.HostIsNotExist() {
			return nil, status.Errorf(codes.NotFound, "host with k8s node ID '%s' not found", kubeNodeID)
		}
		return nil, status.Errorf(codes.Internal,
			"failure checking host '%s' status for volume publishing: %s",
			kubeNodeID, err.Error())
	}

	mapping, err := s.adminClient.GetHostVolumeMappingByVolumeID(ctx, volume.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to get mapping for volume with ID '%s': %s",
			volume.ID, err.Error())
	}

	publishContext := make(map[string]string)

	err = s.addTargetsInfoToPublishContext(publishContext)
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
		switch am.Mode {
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
	if err = s.apiThrottle.Acquire(ctx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	_, err = s.adminClient.AttachVolumeToHost(ctx, node.ID, &params)
	s.apiThrottle.Release(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to attach volume with ID '%s' to host with ID '%s': %s",
			volume.ID, node.ID, err.Error())
	}

	mapping, err = s.adminClient.GetHostVolumeMappingByVolumeID(ctx, volume.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to get mapping for volume with ID '%s' after attaching: %s",
			volume.ID, err.Error())
	}
	s.addLUNIDToPublishContext(publishContext, mapping[0], *volume)

	return &csi.ControllerPublishVolumeResponse{
		PublishContext: publishContext}, nil
}

func (s *service) addLUNIDToPublishContext(
	publishContext map[string]string,
	mapping gopowerstore.HostVolumeMapping,
	volume gopowerstore.Volume) {

	publishContext[PublishContextDeviceWWN] = strings.TrimPrefix(volume.Wwn, WWNPrefix)
	publishContext[PublishContextLUNAddress] = strconv.FormatInt(mapping.LogicalUnitNumber, 10)
}

func (s *service) addTargetsInfoToPublishContext(
	publishContext map[string]string) error {

	iscsiTargetsInfo, err := s.impl.getISCSITargetsInfoFromStorage()
	if err != nil {
		return err
	}
	for i, t := range iscsiTargetsInfo {
		publishContext[fmt.Sprintf("%s%d", PublishContextISCSIPortalsPrefix, i)] = t.Portal
		publishContext[fmt.Sprintf("%s%d", PublishContextISCSITargetsPrefix, i)] = t.Target
	}
	fcTargetsInfo, err := s.impl.getFCTargetsInfoFromStorage()
	if err != nil {
		return err
	}
	for i, t := range fcTargetsInfo {
		publishContext[fmt.Sprintf("%s%d", PublishContextFCWWPNPrefix, i)] = t.WWPN
	}

	return nil
}

func (s *service) ControllerUnpublishVolume(
	ctx context.Context,
	req *csi.ControllerUnpublishVolumeRequest) (
	*csi.ControllerUnpublishVolumeResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

	volID := req.GetVolumeId()
	if volID == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}
	_, err := s.getVolByID(ctx, volID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeIsNotExist() {
			return nil, status.Errorf(codes.NotFound, "volume with ID '%s' not found", volID)
		}
		return nil, status.Errorf(codes.Unknown,
			"failure checking volume status for volume unpublishing: %s",
			err.Error())
	}

	kubeNodeID := req.GetNodeId()
	if kubeNodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "node ID is required")
	}
	node, err := s.getNodeByID(ctx, kubeNodeID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.HostIsNotExist() {
			return nil, status.Errorf(codes.NotFound, "host with k8s node ID '%s' not found", kubeNodeID)
		}
		return nil, status.Errorf(codes.Unknown,
			"failure checking host '%s' status for volume unpublishing: %s",
			kubeNodeID, err.Error())
	}

	err = s.impl.detachVolumeFromHost(ctx, node.ID, volID)
	if err != nil {
		return nil, err
	}

	return &csi.ControllerUnpublishVolumeResponse{}, nil
}

func (s *service) ValidateVolumeCapabilities(
	ctx context.Context,
	req *csi.ValidateVolumeCapabilitiesRequest) (
	*csi.ValidateVolumeCapabilitiesResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

	volID := req.GetVolumeId()
	vol, err := s.getVolByID(ctx, volID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeIsNotExist() {
			return nil, status.Errorf(codes.NotFound, "volume with ID '%s' not found", volID)
		}
		return nil, status.Errorf(codes.Internal,
			"failure checking volume status for capabilities: %s",
			err.Error())
	}

	vcs := req.GetVolumeCapabilities()
	supported, reason := valVolumeCaps(vcs, vol)

	resp := &csi.ValidateVolumeCapabilitiesResponse{}
	if supported {
		// The optional fields volume_context and parameters are not passed.
		confirmed := &csi.ValidateVolumeCapabilitiesResponse_Confirmed{}
		confirmed.VolumeCapabilities = vcs
		resp.Confirmed = confirmed
	} else {
		resp.Message = reason
	}

	return resp, nil
}

func accTypeIsBlock(vcs []*csi.VolumeCapability) bool {
	for _, vc := range vcs {
		if at := vc.GetBlock(); at != nil {
			return true
		}
	}
	return false
}

func checkValidAccessTypes(vcs []*csi.VolumeCapability) bool {
	for _, vc := range vcs {
		if vc == nil {
			continue
		}
		atblock := vc.GetBlock()
		if atblock != nil {
			continue
		}
		atmount := vc.GetMount()
		if atmount != nil {
			continue
		}
		// Unknown access type, we should reject it.
		return false
	}
	return true
}

func valVolumeCaps(
	vcs []*csi.VolumeCapability,
	vol *gopowerstore.Volume) (bool, string) {

	var (
		supported = true
		isBlock   = accTypeIsBlock(vcs)
		reason    string
	)
	// Check that all access types are valid
	if !checkValidAccessTypes(vcs) {
		return false, errUnknownAccessType
	}

	for _, vc := range vcs {
		am := vc.GetAccessMode()
		if am == nil {
			continue
		}
		switch am.Mode {
		case csi.VolumeCapability_AccessMode_UNKNOWN:
			supported = false
			reason = errUnknownAccessMode
			break
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER:
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
				reason = errNoMultiNodeWriter
			}
			break
		default:
			// This is to guard against new access modes not understood
			supported = false
			reason = errUnknownAccessMode
		}
	}

	return supported, reason
}

func (s *service) listPowerStoreSnapshots(
	ctx context.Context,
	startToken, maxEntries int, snapID, srcID string) (
	[]gopowerstore.Volume, string, error) {

	var (
		volumes []gopowerstore.Volume
		err     error
	)

	if snapID == "" && srcID == "" {
		volumes, err = s.adminClient.GetSnapshots(ctx)
	} else if snapID != "" {
		volume, getErr := s.adminClient.GetSnapshot(ctx, snapID)
		if apiError, ok := getErr.(gopowerstore.APIError); ok && apiError.VolumeIsNotExist() {
			// given snapshot id does not exist, should return empty response
			return volumes, "", nil
		}

		volumes = append(volumes, volume)
	} else {
		volumes, err = s.adminClient.GetSnapshotsByVolumeID(ctx, srcID)
	}

	if err != nil {
		return nil, "", status.Errorf(
			codes.Internal,
			"unable to list snapshots: %s", err.Error())
	}

	if startToken > len(volumes) {
		return nil, "", status.Errorf(
			codes.Aborted,
			"startingToken=%d > len(volumes)=%d",
			startToken, len(volumes))
	}
	// Discern the number of remaining entries.
	rem := len(volumes) - startToken

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

	return volumes[startToken : startToken+maxEntries], nextTokenStr, nil
}

func (s *service) listPowerStoreVolumes(
	ctx context.Context,
	startToken, maxEntries int) (
	[]gopowerstore.Volume, string, error) {

	var (
		volumes []gopowerstore.Volume
		err     error
	)

	// Get the volumes from the cache if we can
	volumes, err = s.adminClient.GetVolumes(ctx)
	if err != nil {
		return nil, "", status.Errorf(
			codes.Internal,
			"unable to list volumes: %s", err.Error())
	}

	if startToken > len(volumes) {
		return nil, "", status.Errorf(
			codes.Aborted,
			"startingToken=%d > len(volumes)=%d",
			startToken, len(volumes))
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

func (s *service) ListVolumes(
	ctx context.Context,
	req *csi.ListVolumesRequest) (
	*csi.ListVolumesResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

	var (
		startToken int
		maxEntries = int(req.GetMaxEntries())
	)

	if v := req.GetStartingToken(); v != "" {
		i, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, status.Errorf(
				codes.Aborted,
				"Unable to parse StartingToken: %v into uint32", v)
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

func (s *service) ListSnapshots(
	ctx context.Context,
	req *csi.ListSnapshotsRequest) (
	*csi.ListSnapshotsResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

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
			return nil, status.Errorf(
				codes.Aborted,
				"Unable to parse StartingToken: %v into uint32", v)
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
		entries[i] = &csi.ListSnapshotsResponse_Entry{
			Snapshot: getCSISnapshot(snap.ID, snap.ProtectionData.SourceID, snap.Size),
		}
	}

	return &csi.ListSnapshotsResponse{
		Entries:   entries,
		NextToken: nextToken,
	}, nil
}

func (s *service) GetCapacity(
	ctx context.Context,
	req *csi.GetCapacityRequest) (
	*csi.GetCapacityResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

	// Optionally validate the volume capability
	vcs := req.GetVolumeCapabilities()
	if vcs != nil {
		supported, reason := valVolumeCaps(vcs, nil)
		if !supported {
			return nil, status.Errorf(codes.InvalidArgument, reason)
		}
	}
	resp, err := s.adminClient.GetCapacity(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &csi.GetCapacityResponse{
		AvailableCapacity: resp,
	}, nil
}

func (s *service) ControllerGetCapabilities(
	ctx context.Context,
	req *csi.ControllerGetCapabilitiesRequest) (
	*csi.ControllerGetCapabilitiesResponse, error) {

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
		csi.ControllerServiceCapability_RPC_LIST_VOLUMES,
		csi.ControllerServiceCapability_RPC_GET_CAPACITY,
	} {
		capabilities = append(capabilities, newCap(capability))
	}

	return &csi.ControllerGetCapabilitiesResponse{
		Capabilities: capabilities,
	}, nil
}

func (s *service) controllerProbe(ctx context.Context) (ready bool, err error) {
	if err = s.impl.initPowerStoreClient(); err != nil {
		return false, err
	}
	if err = s.impl.initApiThrottle(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *service) requireProbe(ctx context.Context) error {
	if s.adminClient == nil {
		if !s.opts.AutoProbe {
			return status.Error(codes.FailedPrecondition,
				"Controller Service has not been probed")
		}
		log.Debug("probing controller service automatically")
		if _, err := s.controllerProbe(ctx); err != nil {
			return status.Errorf(codes.FailedPrecondition,
				"failed to probe/init plugin: %s", err.Error())
		}
	}
	return nil
}

func (s *service) CreateSnapshot(
	ctx context.Context,
	req *csi.CreateSnapshotRequest) (
	*csi.CreateSnapshotResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

	snapName := req.GetName()
	if err := volumeNameValidation(snapName); err != nil {
		return nil, err
	}

	// Validate snapshot volume sourceVolId
	sourceVolId := req.GetSourceVolumeId()
	if sourceVolId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "volume ID to be snapped is required")
	}

	var snapResponse *csi.Snapshot

	reqParams := &gopowerstore.SnapshotCreate{
		Name:        &snapName,
		Description: nil,
	}
	if err := s.apiThrottle.Acquire(ctx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer s.apiThrottle.Release(ctx)

	// Check if snapshot with provided name already exists but has a different source volume id
	existingSnapshot, err := s.getExistingSnapshot(ctx, snapName, sourceVolId)
	if err == nil {
		if existingSnapshot.ProtectionData.SourceID != sourceVolId {
			return nil, status.Errorf(codes.AlreadyExists,
				"snapshot with name '%s' exists, but SourceVolumeId %s doesn't match", snapName, sourceVolId)
		} else {
			snapResponse = getCSISnapshot(existingSnapshot.ID, sourceVolId, existingSnapshot.Size)
		}
	} else {
		resp, err := s.adminClient.CreateSnapshot(ctx, reqParams, sourceVolId)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.SnapshotNameIsAlreadyUse() {
				existingSnapshot, err := s.getExistingSnapshot(ctx, snapName, sourceVolId)
				if err != nil {
					return nil, err
				}
				snapResponse = getCSISnapshot(existingSnapshot.ID, sourceVolId, existingSnapshot.Size)
			} else {
				return nil, status.Error(codes.Internal, err.Error())
			}
		} else {
			// Get sourceVolume size
			sourceVolume, err := s.adminClient.GetVolume(ctx, sourceVolId)
			if err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			snapResponse = getCSISnapshot(resp.ID, sourceVolId, sourceVolume.Size)
		}
	}

	return &csi.CreateSnapshotResponse{
		Snapshot: snapResponse,
	}, nil
}

func (s *service) getExistingSnapshot(ctx context.Context, snapName, sourceVolId string) (gopowerstore.Volume, error) {
	snap, err := s.adminClient.GetVolumeByName(ctx, snapName)
	if err != nil {
		return gopowerstore.Volume{}, status.Errorf(codes.Internal, "can't find snapshot '%s': %s", snapName, err.Error())
	}
	return snap, nil
}

func (s *service) DeleteSnapshot(
	ctx context.Context,
	req *csi.DeleteSnapshotRequest) (
	*csi.DeleteSnapshotResponse, error) {

	if err := s.requireProbe(ctx); err != nil {
		return nil, err
	}

	id := req.GetSnapshotId()
	if id == "" {
		return nil, status.Errorf(codes.InvalidArgument, "snapshot ID to be deleted is required")
	}

	_, err := s.adminClient.DeleteSnapshot(ctx, nil, id)
	if err == nil {
		return &csi.DeleteSnapshotResponse{}, nil
	}
	if apiError, ok := err.(gopowerstore.APIError); ok {
		if apiError.VolumeIsNotExist() {
			return &csi.DeleteSnapshotResponse{}, nil
		}
	}
	return nil, err
}

func (s *service) ControllerExpandVolume(
	ctx context.Context,
	req *csi.ControllerExpandVolumeRequest) (
	*csi.ControllerExpandVolumeResponse, error) {

	return nil, status.Error(codes.Unimplemented, "")
}
