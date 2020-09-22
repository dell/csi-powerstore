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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// ReservedSize number of bytes reserved by creation of FS
	ReservedSize = 1610612736
)

type VolumeCreator interface {
	// CheckSize validates that size is correct and returns size in bytes
	CheckSize(ctx context.Context, cr *csi.CapacityRange) (int64, error)
	// CheckName validates volume name
	CheckName(ctx context.Context, name string) error
	// CheckIfAlreadyExists
	CheckIfAlreadyExists(ctx context.Context, req *csi.CreateVolumeRequest,
		sizeInBytes int64, client gopowerstore.Client) (*csi.Volume, error)
	// Create creates new volume
	Create(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64,
		client gopowerstore.Client) (gopowerstore.CreateResponse, error)
	// Create volume from snapshot
	CreateVolumeFromSnapshot(ctx context.Context, snapshotSource *csi.VolumeContentSource_SnapshotSource,
		volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.CreateVolumeResponse, error)
	// Create a volume from another volume
	Clone(ctx context.Context, volumeSource *csi.VolumeContentSource_VolumeSource, volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.CreateVolumeResponse, error)
}

type SCSICreator struct {
}

// CheckSize validates that size is correct and returns size in bytes
func (*SCSICreator) CheckSize(ctx context.Context, cr *csi.CapacityRange) (int64, error) {
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

// CheckName validates volume name
func (*SCSICreator) CheckName(ctx context.Context, name string) error {
	return volumeNameValidation(name)
}

func (*SCSICreator) CheckIfAlreadyExists(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64, client gopowerstore.Client) (*csi.Volume, error) {
	alreadyExistVolume, err := client.GetVolumeByName(ctx, req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find volume '%s': %s", req.GetName(), err.Error())
	}

	if alreadyExistVolume.Size < sizeInBytes {
		return nil, status.Errorf(codes.AlreadyExists,
			"volume '%s' already exists but is incompatible volume size: %d < %d",
			req.GetName(), alreadyExistVolume.Size, sizeInBytes)
	}
	volumeResponse := getCSIVolume(alreadyExistVolume.ID, alreadyExistVolume.Size)
	return volumeResponse, nil
}

func (*SCSICreator) Create(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	storageType := gopowerstore.StorageTypeEnumBlock
	name := req.GetName()
	reqParams := &gopowerstore.VolumeCreate{Name: &name, Size: &sizeInBytes, StorageType: &storageType}
	return client.CreateVolume(ctx, reqParams)
}

// Create a volume (which is actually a snapshot) from an existing snapshot.
// The snapshotSource gives the SnapshotId which is the volume to be replicated.
func (*SCSICreator) CreateVolumeFromSnapshot(ctx context.Context, snapshotSource *csi.VolumeContentSource_SnapshotSource,
	volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.CreateVolumeResponse, error) {
	var volumeResponse *csi.Volume
	// Lookup the volume source volume.

	sourceVol, err := client.GetVolume(ctx, snapshotSource.SnapshotId)
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

	volume, err := client.CreateVolumeFromSnapshot(ctx, &createParams, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't create volume: %s", snapshotSource.SnapshotId)
	}

	volumeResponse = getCSIVolumeFromSnapshot(volume.ID, snapshotSource, sizeInBytes)
	volumeResponse.VolumeContext = parameters
	return &csi.CreateVolumeResponse{
		Volume: volumeResponse,
	}, nil
}

func (*SCSICreator) Clone(ctx context.Context, volumeSource *csi.VolumeContentSource_VolumeSource,
	volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.CreateVolumeResponse, error) {
	var volumeResponse *csi.Volume
	// Lookup the volume source volume.

	sourceVol, err := client.GetVolume(ctx, volumeSource.VolumeId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "volume not found: %s", volumeSource.VolumeId)
	}

	if sourceVol.Size != sizeInBytes {
		return nil, status.Errorf(codes.InvalidArgument,
			"volume %s has incompatible size %d bytes with requested %d bytes",
			volumeSource.VolumeId, sourceVol.Size, sizeInBytes)
	}

	createParams := gopowerstore.VolumeClone{
		Name:        &volumeName,
		Description: nil,
	}

	volume, err := client.CloneVolume(ctx, &createParams, volumeSource.VolumeId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't create volume: %s", volumeSource.VolumeId)
	}

	volumeResponse = &csi.Volume{
		CapacityBytes: sizeInBytes,
		VolumeId:      volume.ID,
		VolumeContext: parameters,
		ContentSource: &csi.VolumeContentSource{
			Type: &csi.VolumeContentSource_Volume{
				Volume: volumeSource,
			},
		},
	}

	return &csi.CreateVolumeResponse{
		Volume: volumeResponse,
	}, nil
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

type NfsCreator struct {
}

// CheckSize validates that size is correct and returns size in bytes
func (*NfsCreator) CheckSize(ctx context.Context, cr *csi.CapacityRange) (int64, error) {
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

// CheckName validates volume name
func (*NfsCreator) CheckName(ctx context.Context, name string) error {
	return volumeNameValidation(name)
}

func (*NfsCreator) CheckIfAlreadyExists(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64, client gopowerstore.Client) (*csi.Volume, error) {
	alreadyExistVolume, err := client.GetFSByName(ctx, req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find volume '%s': %s", req.GetName(), err.Error())
	}

	if alreadyExistVolume.SizeTotal < sizeInBytes {
		return nil, status.Errorf(codes.AlreadyExists,
			"volume '%s' already exists but is incompatible volume size: %d < %d",
			req.GetName(), alreadyExistVolume.SizeTotal, sizeInBytes)
	}
	volumeResponse := getCSIVolume(alreadyExistVolume.ID, alreadyExistVolume.SizeTotal)
	return volumeResponse, nil
}

func (c *NfsCreator) Create(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	params := req.GetParameters()
	nasName, ok := params[keyNasName]
	if !ok {
		return gopowerstore.CreateResponse{}, fmt.Errorf("no nasName parameter provided")
	}

	nas, err := client.GetNASByName(ctx, nasName)
	if err != nil {
		return gopowerstore.CreateResponse{}, err
	}

	reqParams := &gopowerstore.FsCreate{
		Name:        req.GetName(),
		NASServerID: nas.ID,
		Size:        sizeInBytes + ReservedSize,
	}
	return client.CreateFS(ctx, reqParams)
}

func (*NfsCreator) CreateVolumeFromSnapshot(ctx context.Context, snapshotSource *csi.VolumeContentSource_SnapshotSource,
	volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.CreateVolumeResponse, error) {
	var volumeResponse *csi.Volume
	// Lookup the volume source volume.

	sourceVol, err := client.GetFS(ctx, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "snapshot not found: %s", snapshotSource.SnapshotId)
	}

	if sourceVol.SizeTotal != sizeInBytes+ReservedSize {
		return nil, status.Errorf(codes.InvalidArgument,
			"snapshot %s has incompatible size %d bytes (additional %d bytes) with requested %d bytes",
			snapshotSource.SnapshotId, sourceVol.SizeTotal, ReservedSize, sizeInBytes)
	}

	createParams := gopowerstore.FsClone{
		Name:        &volumeName,
		Description: nil,
	}

	volume, err := client.CreateFsFromSnapshot(ctx, &createParams, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't create fs: %s", snapshotSource.SnapshotId)
	}

	volumeResponse = getCSIVolumeFromSnapshot(volume.ID, snapshotSource, sizeInBytes)
	volumeResponse.VolumeContext = parameters
	return &csi.CreateVolumeResponse{
		Volume: volumeResponse,
	}, nil
}

func (*NfsCreator) Clone(ctx context.Context, volumeSource *csi.VolumeContentSource_VolumeSource,
	volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.CreateVolumeResponse, error) {
	var volumeResponse *csi.Volume
	// Lookup the volume source volume.
	sourceVol, err := client.GetFS(ctx, volumeSource.VolumeId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "fs not found: %s", volumeSource.VolumeId)
	}

	if sourceVol.SizeTotal != sizeInBytes+ReservedSize {
		return nil, status.Errorf(codes.InvalidArgument,
			"fs %s has incompatible size %d bytes (additional %d bytes) with requested %d bytes",
			volumeSource.VolumeId, sourceVol.SizeTotal, ReservedSize, sizeInBytes)
	}

	createParams := gopowerstore.FsClone{
		Name:        &volumeName,
		Description: nil,
	}

	volume, err := client.CloneFS(ctx, &createParams, volumeSource.VolumeId)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't create fs: %s", volumeSource.VolumeId)
	}

	volumeResponse = &csi.Volume{
		CapacityBytes: sizeInBytes,
		VolumeId:      volume.ID,
		VolumeContext: parameters,
		ContentSource: &csi.VolumeContentSource{
			Type: &csi.VolumeContentSource_Volume{
				Volume: volumeSource,
			},
		},
	}

	return &csi.CreateVolumeResponse{
		Volume: volumeResponse,
	}, nil
}
