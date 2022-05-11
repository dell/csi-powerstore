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
	"unicode/utf8"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gopowerstore"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	// ErrUnknownAccessType represents error message for unknown access type
	ErrUnknownAccessType = "unknown access type is not Block or Mount"
	// ErrUnknownAccessMode represents error message for unknown access mode
	ErrUnknownAccessMode = "access mode cannot be UNKNOWN"
	// ErrNoMultiNodeWriter represents error message for multi node access
	ErrNoMultiNodeWriter = "multi-node with writer(s) only supported for block access type"
	// KeyFsType represents key for Fs Type
	KeyFsType = "csi.storage.k8s.io/fstype"
	// KeyFsTypeOld represents old key for Fs Type
	KeyFsTypeOld = "FsType"
	// KeyReplicationEnabled represents key for replication enabled
	KeyReplicationEnabled = "isReplicationEnabled"
	// KeyReplicationRPO represents key for replication RPO
	KeyReplicationRPO = "rpo"
	// KeyReplicationRemoteSystem represents key for replication remote system
	KeyReplicationRemoteSystem = "remoteSystem"
	// KeyReplicationIgnoreNamespaces represents key for replication ignore namespaces
	KeyReplicationIgnoreNamespaces = "ignoreNamespaces"
	// KeyReplicationVGPrefix represents key for replication vg prefix
	KeyReplicationVGPrefix = "volumeGroupPrefix"
	// KeyNasName represents key for nas name
	KeyNasName = "nasName"
	// KeyCSIPVCNamespace represents key for csi pvc namespace
	KeyCSIPVCNamespace = "csi.storage.k8s.io/pvc/namespace"
	// KeyCSIPVCName represents key for csi pvc name
	KeyCSIPVCName = "csi.storage.k8s.io/pvc/name"
)

func volumeNameValidation(volumeName string) error {
	if volumeName == "" {
		return status.Errorf(codes.InvalidArgument, "name cannot be empty")
	}

	if utf8.RuneCountInString(volumeName) > MaxVolumeNameLength {
		return status.Errorf(codes.InvalidArgument, "name must contain %d or fewer printable Unicode characters", MaxVolumeNameLength)
	}

	return nil
}

func volumeSizeValidation(minSize, maxSize int64) error {
	if minSize < 0 || maxSize < 0 {
		return status.Errorf(
			codes.OutOfRange,
			"bad capacity: volume size bytes %d and limit size bytes: %d must not be negative", minSize, maxSize)
	}

	if maxSize < minSize {
		return status.Errorf(
			codes.OutOfRange,
			"bad capacity: max size bytes %d can't be less than minimum size bytes %d", maxSize, minSize)
	}

	if maxSize > MaxVolumeSizeBytes {
		return status.Errorf(
			codes.OutOfRange,
			"bad capacity: max size bytes %d can't be more than maximum size bytes %d", maxSize, MaxVolumeSizeBytes)
	}

	return nil
}

func getCSIVolume(volumeID string, size int64) *csi.Volume {
	volume := &csi.Volume{
		VolumeId:      volumeID,
		CapacityBytes: size,
	}
	return volume
}

func getCSISnapshot(snapshotID string, sourceVolumeID string, sizeInBytes int64) *csi.Snapshot {
	snap := &csi.Snapshot{
		SizeBytes:      sizeInBytes,
		SnapshotId:     snapshotID,
		SourceVolumeId: sourceVolumeID,
		CreationTime:   ptypes.TimestampNow(),
		ReadyToUse:     true,
	}
	return snap
}

func detachVolumeFromHost(ctx context.Context, hostID string, volumeID string, client gopowerstore.Client) error {
	dp := &gopowerstore.HostVolumeDetach{VolumeID: &volumeID}
	_, err := client.DetachVolumeFromHost(ctx, hostID, dp)
	if err != nil {
		apiError, ok := err.(gopowerstore.APIError)
		if !ok {
			return status.Errorf(codes.Unknown, "failed to detach volume '%s' from host: %s", volumeID, err.Error())
		}

		if apiError.HostIsNotExist() {
			return status.Errorf(codes.NotFound, "host with ID '%s' not found", hostID)
		}
		if !apiError.VolumeIsNotAttachedToHost() && !apiError.HostIsNotAttachedToVolume() && !apiError.NotFound() {
			return status.Errorf(codes.Unknown, "unexpected api error when detaching volume from host:%s", err.Error())
		}

	}
	return nil
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

func getDescription(params map[string]string) string {
	if description, ok := params["description"]; ok {
		return description
	}
	return params[KeyCSIPVCName] + "-" + params[KeyCSIPVCNamespace]
}
