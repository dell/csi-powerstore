/*
 *
 * Copyright © 2021 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"net/http"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// ReservedSize number of bytes reserved by creation of FS
	ReservedSize = 1610612736
)

// Extra metadata field names for propagating to gopowerstore and beyond.
const (
	// These are available when enabling --extra-create-metadata for the external-provisioner.
	CSIPersistentVolumeName           = "csi.storage.k8s.io/pv/name"
	CSIPersistentVolumeClaimName      = "csi.storage.k8s.io/pvc/name"
	CSIPersistentVolumeClaimNamespace = "csi.storage.k8s.io/pvc/namespace"
	// These map to the above fields in the form of HTTP header names.
	HeaderPersistentVolumeName           = "x-csi-pv-name"
	HeaderPersistentVolumeClaimName      = "x-csi-pv-claimname"
	HeaderPersistentVolumeClaimNamespace = "x-csi-pv-namespace"
)

// VolumeCreator allows to call Create and similar operations used in CreateVolume call
type VolumeCreator interface {
	// CheckSize validates that size is correct and returns size in bytes
	CheckSize(ctx context.Context, cr *csi.CapacityRange) (int64, error)
	// CheckName validates volume name
	CheckName(ctx context.Context, name string) error
	// CheckIfAlreadyExists queries storage array if given volume already exists
	CheckIfAlreadyExists(ctx context.Context, name string,
		sizeInBytes int64, client gopowerstore.Client) (*csi.Volume, error)
	// Create creates new volume
	Create(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64,
		client gopowerstore.Client) (gopowerstore.CreateResponse, error)
	// Create volume from snapshot
	CreateVolumeFromSnapshot(ctx context.Context, snapshotSource *csi.VolumeContentSource_SnapshotSource,
		volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.Volume, error)
	// Create a volume from another volume
	Clone(ctx context.Context, volumeSource *csi.VolumeContentSource_VolumeSource, volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.Volume, error)
}

// SCSICreator implementation of VolumeCreator for SCSI based (FC, iSCSI) volumes
type SCSICreator struct {
}

func setMetaData(reqParams map[string]string, createParams interface{}) {
	// If the VolumeParam has a MetaData method, set the values accordingly.
	if t, ok := createParams.(interface {
		MetaData() http.Header
	}); ok {
		t.MetaData().Set(HeaderPersistentVolumeName, reqParams[CSIPersistentVolumeName])
		t.MetaData().Set(HeaderPersistentVolumeClaimName, reqParams[CSIPersistentVolumeClaimName])
		t.MetaData().Set(HeaderPersistentVolumeClaimNamespace, reqParams[CSIPersistentVolumeClaimNamespace])
	} else {
		log.Printf("warning: %T: no MetaData method exists, consider updating gopowerstore library.", createParams)
	}
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

// CheckIfAlreadyExists queries storage array if Volume with given name exists
func (*SCSICreator) CheckIfAlreadyExists(ctx context.Context, name string, sizeInBytes int64, client gopowerstore.Client) (*csi.Volume, error) {
	alreadyExistVolume, err := client.GetVolumeByName(ctx, name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find volume '%s': %s", name, err.Error())
	}

	if alreadyExistVolume.Size < sizeInBytes {
		return nil, status.Errorf(codes.AlreadyExists,
			"volume '%s' already exists but is incompatible volume size: %d < %d",
			name, alreadyExistVolume.Size, sizeInBytes)
	}
	volumeResponse := getCSIVolume(alreadyExistVolume.ID, alreadyExistVolume.Size)
	return volumeResponse, nil
}

// Create creates new block volume on storage array
func (*SCSICreator) Create(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	storageType := gopowerstore.StorageTypeEnumBlock
	name := req.GetName()
	reqParams := &gopowerstore.VolumeCreate{Name: &name, Size: &sizeInBytes, StorageType: &storageType}
	setMetaData(req.Parameters, reqParams)
	return client.CreateVolume(ctx, reqParams)
}

// CreateVolumeFromSnapshot create a volume from an existing snapshot.
// The snapshotSource gives the SnapshotId which is the volume to be replicated.
func (*SCSICreator) CreateVolumeFromSnapshot(ctx context.Context, snapshotSource *csi.VolumeContentSource_SnapshotSource,
	volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.Volume, error) {
	var volumeResponse *csi.Volume
	// Lookup the volume source volume.
	sourceVol, err := client.GetVolume(ctx, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "volume snapshot not found: %s", snapshotSource.SnapshotId)
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
	setMetaData(parameters, &createParams)

	volume, err := client.CreateVolumeFromSnapshot(ctx, &createParams, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't create volume: %s", snapshotSource.SnapshotId)
	}

	volumeResponse = getCSIVolumeFromSnapshot(volume.ID, snapshotSource, sizeInBytes)
	volumeResponse.VolumeContext = parameters
	return volumeResponse, nil
}

// Clone creates a clone of a Volume
func (*SCSICreator) Clone(ctx context.Context, volumeSource *csi.VolumeContentSource_VolumeSource,
	volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.Volume, error) {
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
	setMetaData(parameters, &createParams)

	volume, err := client.CloneVolume(ctx, &createParams, volumeSource.VolumeId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't clone volume: %s", err.Error())
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

	return volumeResponse, nil
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

func getCSIVolumeFromClone(VolumeID string, volumeSource *csi.VolumeContentSource_VolumeSource, size int64) *csi.Volume {
	volume := &csi.Volume{
		CapacityBytes: size,
		VolumeId:      VolumeID,
		ContentSource: &csi.VolumeContentSource{
			Type: &csi.VolumeContentSource_Volume{
				Volume: volumeSource,
			},
		},
	}
	return volume
}

// NfsCreator implementation of VolumeCreator for NFS volumes
type NfsCreator struct {
	nasName string
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

// CheckIfAlreadyExists queries storage array if FileSystem with given name exists
func (*NfsCreator) CheckIfAlreadyExists(ctx context.Context, name string, sizeInBytes int64, client gopowerstore.Client) (*csi.Volume, error) {
	alreadyExistVolume, err := client.GetFSByName(ctx, name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find filesystem '%s': %s", name, err.Error())
	}

	if alreadyExistVolume.SizeTotal < sizeInBytes {
		return nil, status.Errorf(codes.AlreadyExists,
			"filesystem '%s' already exists but is incompatible volume size: %d < %d",
			name, alreadyExistVolume.SizeTotal, sizeInBytes)
	}
	volumeResponse := getCSIVolume(alreadyExistVolume.ID, alreadyExistVolume.SizeTotal)
	return volumeResponse, nil
}

// Create creates new FileSystem on storage array
func (c *NfsCreator) Create(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	nas, err := client.GetNASByName(ctx, c.nasName)
	if err != nil {
		return gopowerstore.CreateResponse{}, err
	}

	reqParams := &gopowerstore.FsCreate{
		Name:        req.GetName(),
		NASServerID: nas.ID,
		Size:        sizeInBytes + ReservedSize,
	}
	setMetaData(req.Parameters, reqParams)
	return client.CreateFS(ctx, reqParams)
}

// CreateVolumeFromSnapshot create a FileSystem from an existing FileSystem snapshot.
func (*NfsCreator) CreateVolumeFromSnapshot(ctx context.Context, snapshotSource *csi.VolumeContentSource_SnapshotSource,
	volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.Volume, error) {
	var volumeResponse *csi.Volume
	// Lookup the volume source volume.

	sourceVol, err := client.GetFS(ctx, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "fs snapshot not found: %s", snapshotSource.SnapshotId)
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
	setMetaData(parameters, &createParams)

	volume, err := client.CreateFsFromSnapshot(ctx, &createParams, snapshotSource.SnapshotId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't create fs: %s", snapshotSource.SnapshotId)
	}

	volumeResponse = getCSIVolumeFromSnapshot(volume.ID, snapshotSource, sizeInBytes)
	volumeResponse.VolumeContext = parameters
	return volumeResponse, nil
}

// Clone creates a clone of a FileSystem
func (*NfsCreator) Clone(ctx context.Context, volumeSource *csi.VolumeContentSource_VolumeSource,
	volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.Volume, error) {
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
	setMetaData(parameters, &createParams)
	volume, err := client.CloneFS(ctx, &createParams, volumeSource.VolumeId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't clone fs: %s", err.Error())
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

	return volumeResponse, nil
}
