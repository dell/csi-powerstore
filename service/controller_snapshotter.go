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
	"github.com/dell/gopowerstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type VolumeSnapshot gopowerstore.Volume
type FilesystemSnapshot gopowerstore.FileSystem

// GeneralSnapshot is an interface for combining both Volume and FileSystem
type GeneralSnapshot interface {
	GetID() string
	GetSourceID() string
	GetSize() int64
}

func (v VolumeSnapshot) GetID() string {
	return v.ID
}

func (v VolumeSnapshot) GetSourceID() string {
	return v.ProtectionData.SourceID
}

func (v VolumeSnapshot) GetSize() int64 {
	return v.Size
}

func (f FilesystemSnapshot) GetID() string {
	return f.ID
}

func (f FilesystemSnapshot) GetSourceID() string {
	return f.ParentId
}

func (f FilesystemSnapshot) GetSize() int64 {
	return f.SizeTotal
}

type VolumeSnapshotter interface {
	GetExistingSnapshot(context.Context, string, gopowerstore.Client) (GeneralSnapshot, error)
	Create(context.Context, string, string, gopowerstore.Client) (gopowerstore.CreateResponse, error)
}

type SCSISnapshotter struct {
}

func (*SCSISnapshotter) GetExistingSnapshot(ctx context.Context, snapName string, client gopowerstore.Client) (GeneralSnapshot, error) {
	snap, err := client.GetVolumeByName(ctx, snapName)
	if err != nil {
		return VolumeSnapshot{}, status.Errorf(codes.Internal,
			"can't find volume snapshot '%s'", snapName)
	}
	return VolumeSnapshot(snap), nil
}

func (*SCSISnapshotter) Create(ctx context.Context, snapName string, sourceID string, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	reqParams := &gopowerstore.SnapshotCreate{
		Name:        &snapName,
		Description: nil,
	}
	return client.CreateSnapshot(ctx, reqParams, sourceID)
}

type NfsSnapshotter struct {
}

func (*NfsSnapshotter) GetExistingSnapshot(ctx context.Context, snapName string, client gopowerstore.Client) (GeneralSnapshot, error) {
	snap, err := client.GetFSByName(ctx, snapName)
	if err != nil {
		return FilesystemSnapshot{}, status.Errorf(codes.Internal,
			"can't find filesystem snapshot '%s': %s", snapName, err.Error())
	}
	return FilesystemSnapshot(snap), nil
}

func (*NfsSnapshotter) Create(ctx context.Context, snapName string, sourceID string, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	reqParams := &gopowerstore.SnapshotFSCreate{
		Name:        snapName,
		Description: "",
	}
	return client.CreateFsSnapshot(ctx, reqParams, sourceID)
}
