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
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newMountLibPublishIMPL(
	publishCheck mountLibPublishCheck,
	helpers reqHelpers,
	mountBlock mountLibPublishBlock,
	mountMount mountLibPublishMount,
	mkdir dirCreator,
	fsLib wrapperFsLib) *mountLibPublishIMPL {
	return &mountLibPublishIMPL{
		publishCheck: publishCheck,
		helpers:      helpers,
		mountBlock:   mountBlock,
		mountMount:   mountMount,
		mkdir:        mkdir,
		fsLib:        fsLib,
	}
}

type mountLibPublishIMPL struct {
	publishCheck mountLibPublishCheck
	helpers      reqHelpers
	mountBlock   mountLibPublishBlock
	mountMount   mountLibPublishMount
	mkdir        dirCreator
	fsLib        wrapperFsLib
}

func (mpi *mountLibPublishIMPL) publish(ctx context.Context, req *csi.NodePublishVolumeRequest) error {
	targetPath := req.GetTargetPath()
	isRO := req.GetReadonly()
	published, err := mpi.publishCheck.isAlreadyPublished(ctx, targetPath, getRWModeString(isRO))
	if err != nil {
		return err
	}
	if published {
		return nil
	}
	if mpi.helpers.isBlock(req) {
		return mpi.mountBlock.publishBlock(ctx, req)
	}
	return mpi.mountMount.publishMount(ctx, req)
}

func (mpi *mountLibPublishIMPL) publishNFS(ctx context.Context, req *csi.NodePublishVolumeRequest) error {
	stagingPath := mpi.helpers.getStagingPath(ctx, req)
	targetPath := req.GetTargetPath()
	logFields := getLogFields(ctx)
	isRO := req.GetReadonly()
	published, err := mpi.publishCheck.isAlreadyPublished(ctx, targetPath, getRWModeString(isRO))
	if err != nil {
		return err
	}
	if published {
		return nil
	}

	if _, err := mpi.mkdir.mkDir(targetPath); err != nil {
		return status.Errorf(codes.Internal, "can't create target folder %s: %s",
			stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("target path successfully created")

	mountCap := req.GetVolumeCapability().GetMount()

	mntFlags := mountCap.GetMountFlags()

	if isRO {
		mntFlags = append(mntFlags, "ro")
	}

	if err := mpi.fsLib.BindMount(ctx, stagingPath, targetPath, mntFlags...); err != nil {
		return status.Errorf(codes.Internal,
			"error bind disk %s to target path: %s", stagingPath,
			err.Error())
	}

	log.WithFields(logFields).Info("volume successfully binded")
	return nil
}

func newMountLibUnpublishIMPL(mountsReader mountLibMountsReader,
	fsLib wrapperFsLib, os limitedOSIFace) *mountLibUnpublishIMPL {
	return &mountLibUnpublishIMPL{
		mountsReader: mountsReader,
		fsLib:        fsLib,
		os:           os,
	}
}

type mountLibUnpublishIMPL struct {
	mountsReader mountLibMountsReader
	fsLib        wrapperFsLib
	os           limitedOSIFace
}

func (mui *mountLibUnpublishIMPL) unpublish(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) error {
	logFields := getLogFields(ctx)
	targetPath := req.GetTargetPath()

	_, found, err := mui.mountsReader.getTargetMount(ctx, targetPath)
	if err != nil {
		return status.Errorf(codes.Internal,
			"could not reliably determine existing mount status for path %s: %s",
			targetPath, err.Error())
	}
	if !found {
		// no mounts
		log.WithFields(logFields).Infof("no mounts found")
		return nil
	}
	log.WithFields(logFields).Infof("active mount exist")
	err = mui.fsLib.Unmount(ctx, targetPath)
	if err != nil {
		return status.Errorf(codes.Internal,
			"could not unmount dev %s: %s",
			targetPath, err.Error())
	}
	log.WithFields(logFields).Infof("unmount without error")
	return nil
}

func newMountLibPublishBlockIMPL(
	mkfile fileCreator, helpers reqHelpers,
	fsLib wrapperFsLib) *mountLibPublishBlockIMPL {
	return &mountLibPublishBlockIMPL{
		mkfile:  mkfile,
		helpers: helpers,
		fsLib:   fsLib}
}

type mountLibPublishBlockIMPL struct {
	mkfile  fileCreator
	helpers reqHelpers
	fsLib   wrapperFsLib
}

func (mpb *mountLibPublishBlockIMPL) publishBlock(
	ctx context.Context, req *csi.NodePublishVolumeRequest) error {
	logFields := getLogFields(ctx)
	log.WithFields(logFields).Info("start publishing as block device")

	isRO := req.GetReadonly()
	targetPath := req.GetTargetPath()
	stagingPath := mpb.helpers.getStagingPath(ctx, req)

	if isRO {
		return status.Error(codes.InvalidArgument,
			"read only not supported for Block Volume")
	}
	if _, err := mpb.mkfile.mkFile(targetPath); err != nil {
		return status.Errorf(codes.Internal, "can't create target file %s: %s",
			targetPath, err.Error())
	}
	log.WithFields(logFields).Info("target path successfully created")

	if err := mpb.fsLib.BindMount(ctx, stagingPath, targetPath); err != nil {
		return status.Errorf(codes.Internal,
			"error bind disk %s to target path: %s", stagingPath,
			err.Error())
	}
	log.WithFields(logFields).Info("volume successfully binded")

	return nil
}

func newMountLibPublishMountIMPL(
	mkdir dirCreator, helpers reqHelpers,
	fsLib wrapperFsLib, mkfs fsCreator) *mountLibPublishMountIMPL {
	return &mountLibPublishMountIMPL{
		mkdir:   mkdir,
		mkfs:    mkfs,
		helpers: helpers,
		fsLib:   fsLib}
}

type mountLibPublishMountIMPL struct {
	mkdir   dirCreator
	mkfs    fsCreator
	helpers reqHelpers
	fsLib   wrapperFsLib
}

func (mpm *mountLibPublishMountIMPL) publishMount(
	ctx context.Context, req *csi.NodePublishVolumeRequest) error {

	logFields := getLogFields(ctx)
	isRO := req.GetReadonly()
	accMode := req.GetVolumeCapability().GetAccessMode().GetMode()
	if accMode == csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER {
		// MULTI_WRITER not supported for mount volumes
		return status.Error(codes.Unimplemented,
			"Mount volumes do not support AccessMode MULTI_NODE_MULTI_WRITER")
	}
	opts := []string{}
	mountCap := req.GetVolumeCapability().GetMount()
	fs := mountCap.GetFsType()
	mntFlags := mountCap.GetMountFlags()
	if fs == "xfs" {
		mntFlags = append(mntFlags, "nouuid")
	}
	targetFS := mountCap.GetFsType()
	if targetFS == "xfs" {
		opts = []string{"-m", "crc=0,finobt=0"}
	}
	targetPath := req.GetTargetPath()
	stagingPath := mpm.helpers.getStagingPath(ctx, req)

	if _, err := mpm.mkdir.mkDir(targetPath); err != nil {
		return status.Errorf(codes.Internal, "can't create target dir %s: %s",
			targetPath, err.Error())
	}
	log.WithFields(logFields).Info("target dir successfully created")

	curFS, err := mpm.fsLib.GetDiskFormat(ctx, stagingPath)
	if err != nil {
		return status.Errorf(codes.Internal,
			"error while trying to detect fs for staging path %s: %s",
			stagingPath, err.Error())
	}

	if curFS != "" && targetFS != "" && curFS != targetFS {
		return status.Errorf(codes.FailedPrecondition,
			"filesystem mismatch. Target device already formatted to %s mount spec require %s",
			curFS, targetFS)
	}

	if curFS == "" {
		log.WithFields(logFields).Infof("no filesystem found on staged disk %s", stagingPath)
		if isRO {
			return status.Errorf(codes.FailedPrecondition,
				"RO mount required but no fs detected on staged volume %s",
				stagingPath)
		}
		if err := mpm.mkfs.format(ctx, stagingPath, targetFS, opts...); err != nil {
			return status.Errorf(codes.Internal,
				"can't format staged device %s: %s",
				stagingPath, err.Error())
		}
		log.WithFields(logFields).Infof("staged disk %s successfully formatted to %s", stagingPath, targetFS)
	}
	if isRO {
		mntFlags = append(mntFlags, "ro")
	}

	if err := mpm.fsLib.Mount(ctx, stagingPath, targetPath, targetFS, mntFlags...); err != nil {
		return status.Errorf(codes.Internal,
			"error performing mount for staging path %s: %s",
			stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("volume successfully mounted")

	return nil
}

func newMountLibPublishCheckIMPL(mr mountLibMountsReader, fsLib wrapperFsLib) *mountLibPublishCheckIMPL {
	return &mountLibPublishCheckIMPL{mountsReader: mr, fsLib: fsLib}
}

type mountLibPublishCheckIMPL struct {
	mountsReader mountLibMountsReader
	fsLib        wrapperFsLib
}

func (pc *mountLibPublishCheckIMPL) isAlreadyPublished(ctx context.Context, targetPath, rwMode string) (bool, error) {
	mount, found, err := pc.mountsReader.getTargetMount(ctx, targetPath)
	if err != nil {
		return false, status.Errorf(codes.Internal,
			"can't check mounts for path %s: %s", targetPath, err.Error())
	}
	if !found {
		return false, nil
	}
	if !contains(mount.Opts, rwMode) {
		return false, status.Errorf(codes.FailedPrecondition,
			"volume already mounted but with different capabilities: %s",
			mount.Opts)
	}
	return true, nil
}

func (pc *mountLibPublishCheckIMPL) isReadyToPublish(ctx context.Context, stagingPath string) (bool, bool, error) {
	logFields := getLogFields(ctx)
	stageInfo, found, err := pc.mountsReader.getTargetMount(ctx, stagingPath)
	if err != nil {
		return found, false, err
	}
	if !found {
		log.WithFields(logFields).Warning("staged device not found")
		return found, false, nil
	}

	if strings.HasSuffix(stageInfo.Source, "deleted") {
		log.WithFields(logFields).Warning("staged device linked with deleted path")
		return found, false, nil
	}

	devFS, err := pc.fsLib.GetDiskFormat(ctx, stagingPath)
	if err != nil {
		return found, false, err
	}
	return found, devFS != "mpath_member", nil
}

func (pc *mountLibPublishCheckIMPL) isReadyToPublishNFS(ctx context.Context, stagingPath string) (bool, error) {
	logFields := getLogFields(ctx)
	stageInfo, found, err := pc.mountsReader.getTargetMount(ctx, stagingPath)
	if err != nil {
		return found, err
	}
	if !found {
		log.WithFields(logFields).Warning("staged device not found")
		return found, nil
	}

	if strings.HasSuffix(stageInfo.Source, "deleted") {
		log.WithFields(logFields).Warning("staged device linked with deleted path")
		return found, nil
	}

	return found, nil
}

func getRWModeString(isRO bool) string {
	if isRO {
		return "ro"
	}
	return "rw"
}
