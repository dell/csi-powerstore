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

	"github.com/dell/gopowerstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// FilesystemSnapshotType represents filesystem snapshot type
	FilesystemSnapshotType SnapshotType = "filesystem"
	// BlockSnapshotType represents block snapshot type
	BlockSnapshotType SnapshotType = "block"
)

// SnapshotType represents type of snapshot
type SnapshotType string

// VolumeSnapshot represents snapshot of the block Volume
type VolumeSnapshot gopowerstore.Volume

// FilesystemSnapshot represents snapshot of the FileSystem
type FilesystemSnapshot gopowerstore.FileSystem

// GeneralSnapshot is an interface for combining both Volume and FileSystem
type GeneralSnapshot interface {
	// GetID returns ID of the snapshot
	GetID() string
	// GetSourceID returns ID of the volume/fs that snapshot was created from
	GetSourceID() string
	// GetSize returns current size of the snapshot
	GetSize() int64
	// GetType returns type of general snapshot (either filesystem or block)
	GetType() SnapshotType
}

// GetID returns ID of the snapshot
func (v VolumeSnapshot) GetID() string {
	return v.ID
}

// GetSourceID returns ID of the volume/fs that snapshot was created from
func (v VolumeSnapshot) GetSourceID() string {
	return v.ProtectionData.SourceID
}

// GetSize returns current size of the snapshot
func (v VolumeSnapshot) GetSize() int64 {
	return v.Size
}

// GetType returns type of general snapshot (either filesystem or block)
func (v VolumeSnapshot) GetType() SnapshotType {
	return BlockSnapshotType
}

// GetID returns ID of the snapshot
func (f FilesystemSnapshot) GetID() string {
	return f.ID
}

// GetSourceID returns ID of the volume/fs that snapshot was created from
func (f FilesystemSnapshot) GetSourceID() string {
	return f.ParentID
}

// GetSize returns current size of the snapshot
func (f FilesystemSnapshot) GetSize() int64 {
	return f.SizeTotal
}

// GetType returns type of general snapshot (either filesystem or block)
func (f FilesystemSnapshot) GetType() SnapshotType {
	return FilesystemSnapshotType
}

// VolumeSnapshotter allow to create snapshot of the volume/fs
type VolumeSnapshotter interface {
	// GetExistingSnapshot queries storage array if given snapshot already exists
	GetExistingSnapshot(context.Context, string, gopowerstore.Client) (GeneralSnapshot, error)
	// Create creates new snapshot of a given volume
	Create(context.Context, string, string, gopowerstore.Client) (gopowerstore.CreateResponse, error)
}

// SCSISnapshotter is a implementation of VolumeSnapshotter for SCSI based (FC, iSCSI) volumes
type SCSISnapshotter struct {
}

// GetExistingSnapshot queries storage array if given snapshot of the Volume already exists
func (*SCSISnapshotter) GetExistingSnapshot(ctx context.Context, snapName string, client gopowerstore.Client) (GeneralSnapshot, error) {
	snap, err := client.GetVolumeByName(ctx, snapName)
	if err != nil {
		return VolumeSnapshot{}, status.Errorf(codes.Internal,
			"can't find volume snapshot '%s'", snapName)
	}
	return VolumeSnapshot(snap), nil
}

// Create creates new snapshot of a given Volume
func (*SCSISnapshotter) Create(ctx context.Context, snapName string, sourceID string, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	reqParams := &gopowerstore.SnapshotCreate{
		Name:        &snapName,
		Description: nil,
	}
	return client.CreateSnapshot(ctx, reqParams, sourceID)
}

// NfsSnapshotter is a implementation of VolumeSnapshotter for NFS volumes
type NfsSnapshotter struct {
}

// GetExistingSnapshot queries storage array if given snapshot of the FileSystem already exists
func (*NfsSnapshotter) GetExistingSnapshot(ctx context.Context, snapName string, client gopowerstore.Client) (GeneralSnapshot, error) {
	snap, err := client.GetFSByName(ctx, snapName)
	if err != nil {
		return FilesystemSnapshot{}, status.Errorf(codes.Internal,
			"can't find filesystem snapshot '%s': %s", snapName, err.Error())
	}
	return FilesystemSnapshot(snap), nil
}

// Create creates new snapshot of a given FileSystem
func (*NfsSnapshotter) Create(ctx context.Context, snapName string, sourceID string, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	reqParams := &gopowerstore.SnapshotFSCreate{
		Name:        snapName,
		Description: "",
	}
	return client.CreateFsSnapshot(ctx, reqParams, sourceID)
}
