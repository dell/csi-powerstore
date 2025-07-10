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

package node

import (
	"context"

	"github.com/container-storage-interface/spec/lib/go/csi"
	commonutils "github.com/dell/csi-powerstore/v2/pkg/commonutils"
	"github.com/dell/csi-powerstore/v2/pkg/commonutils/fs"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// VolumePublisher allows to node publish a volume
type VolumePublisher interface {
	Publish(ctx context.Context, logFields log.Fields, fs fs.Interface,
		vc *csi.VolumeCapability, isRO bool, targetPath string, stagingPath string) (*csi.NodePublishVolumeResponse, error)
}

// SCSIPublisher implementation of NodeVolumePublisher for SCSI based (FC, iSCSI) volumes
type SCSIPublisher struct {
	isBlock bool
}

// Publish publishes volume as either raw block or mount by mounting it to the target path
func (sp *SCSIPublisher) Publish(ctx context.Context, logFields log.Fields, fs fs.Interface, vc *csi.VolumeCapability, isRO bool, targetPath string, stagingPath string) (*csi.NodePublishVolumeResponse, error) {
	published, err := isAlreadyPublished(ctx, targetPath, getRWModeString(isRO), fs)
	if err != nil {
		return nil, err
	}

	if published {
		return &csi.NodePublishVolumeResponse{}, nil
	}

	if sp.isBlock {
		return sp.publishBlock(ctx, logFields, fs, vc, isRO, targetPath, stagingPath)
	}
	return sp.publishMount(ctx, logFields, fs, vc, isRO, targetPath, stagingPath)
}

func (sp *SCSIPublisher) publishBlock(ctx context.Context, logFields log.Fields, fs fs.Interface, _ *csi.VolumeCapability, isRO bool, targetPath string, stagingPath string) (*csi.NodePublishVolumeResponse, error) {
	log.WithFields(logFields).Info("start publishing as block device")

	if isRO {
		return nil, status.Error(codes.InvalidArgument, "read only not supported for Block Volume")
	}

	if _, err := fs.MkFileIdempotent(targetPath); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create target file %s: %s", targetPath, err.Error())
	}
	log.WithFields(logFields).Info("target path successfully created")

	if err := fs.GetUtil().BindMount(ctx, stagingPath, targetPath); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error bind disk %s to target path: %s", stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("volume successfully binded")

	return &csi.NodePublishVolumeResponse{}, nil
}

func (sp *SCSIPublisher) publishMount(ctx context.Context, logFields log.Fields, fs fs.Interface, vc *csi.VolumeCapability, isRO bool, targetPath string, stagingPath string) (*csi.NodePublishVolumeResponse, error) {
	if vc.GetAccessMode().GetMode() == csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER {
		// MULTI_WRITER not supported for mount volumes
		return nil, status.Error(codes.Unimplemented, "Mount volumes do not support AccessMode MULTI_NODE_MULTI_WRITER")
	}

	if vc.GetAccessMode().GetMode() == csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY {
		// Warning in case of MULTI_NODE_READER_ONLY for mount volumes
		log.Warningf("Mount volume with the AccessMode ReadOnlyMany")
	}

	var opts []string
	mountCap := vc.GetMount()
	mountFsType := mountCap.GetFsType()
	mntFlags := commonutils.GetMountFlags(vc)
	if mountFsType == "xfs" {
		mntFlags = append(mntFlags, "nouuid")
	}
	targetFS := mountCap.GetFsType()
	if targetFS == "xfs" {
		opts = []string{"-m", "crc=0,finobt=0"}
	}
	if err := fs.MkdirAll(targetPath, 0o750); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create target dir with Mkdirall %s: %s", targetPath, err.Error())
	}

	log.WithFields(logFields).Info("target dir successfully created")

	curFS, err := fs.GetUtil().GetDiskFormat(ctx, stagingPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"error while trying to detect fs for staging path %s: %s", stagingPath, err.Error())
	}

	if curFS != "" && targetFS != "" && curFS != targetFS {
		return nil, status.Errorf(codes.FailedPrecondition,
			"filesystem mismatch. Target device already formatted to %s mount spec require %s",
			curFS, targetFS)
	}

	if curFS == "" {
		log.WithFields(logFields).Infof("no filesystem found on staged disk %s", stagingPath)
		if isRO {
			return nil, status.Errorf(codes.FailedPrecondition,
				"RO mount required but no fs detected on staged volume %s", stagingPath)
		}

		if err := format(ctx, stagingPath, targetFS, fs, opts...); err != nil {
			return nil, status.Errorf(codes.Internal,
				"can't format staged device %s: %s", stagingPath, err.Error())
		}
		log.WithFields(logFields).Infof("staged disk %s successfully formatted to %s", stagingPath, targetFS)
	}
	if isRO {
		mntFlags = append(mntFlags, "ro")
	}

	if err := fs.GetUtil().Mount(ctx, stagingPath, targetPath, targetFS, mntFlags...); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error performing mount for staging path %s: %s", stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("volume successfully mounted")

	return &csi.NodePublishVolumeResponse{}, nil
}

// NFSPublisher implementation of NodeVolumePublisher for NFS volumes
type NFSPublisher struct{}

// Publish publishes nfs volume by mounting it to the target path
func (np *NFSPublisher) Publish(ctx context.Context, logFields log.Fields, fs fs.Interface,
	vc *csi.VolumeCapability, isRO bool, targetPath string, stagingPath string,
) (*csi.NodePublishVolumeResponse, error) {
	published, err := isAlreadyPublished(ctx, targetPath, getRWModeString(isRO), fs)
	if err != nil {
		return nil, err
	}

	if published {
		return &csi.NodePublishVolumeResponse{}, nil
	}

	if err := fs.MkdirAll(targetPath, 0o750); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create target folder %s: %s", stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("target path successfully created")

	mntFlags := commonutils.GetMountFlags(vc)

	if isRO {
		mntFlags = append(mntFlags, "ro")
	}

	if err := fs.GetUtil().BindMount(ctx, stagingPath, targetPath, mntFlags...); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error bind disk %s to target path: %s", stagingPath, err.Error())
	}

	log.WithFields(logFields).Info("volume successfully binded")
	return &csi.NodePublishVolumeResponse{}, nil
}
