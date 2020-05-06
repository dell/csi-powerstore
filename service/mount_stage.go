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
	"github.com/container-storage-interface/spec/lib/go/csi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"path"
)

func newMountLibStageIMPL(mkfile fileCreator, reqHelper reqHelpers, fsLib wrapperFsLib,
	stageCheck mountLibStageCheck) *mountLibStageIMPL {
	return &mountLibStageIMPL{
		reqHelper:  reqHelper,
		fsLib:      fsLib,
		mkfile:     mkfile,
		stageCheck: stageCheck}
}

type mountLibStageIMPL struct {
	// required handlers
	reqHelper  reqHelpers
	fsLib      wrapperFsLib
	mkfile     fileCreator
	stageCheck mountLibStageCheck
}

func newMountLibUnstageIMPL(
	os limitedOSIFace,
	reqHelper reqHelpers,
	fsLib wrapperFsLib,
	stageCheck mountLibStageCheck) *mountLibUnstageIMPL {
	return &mountLibUnstageIMPL{
		reqHelper:  reqHelper,
		fsLib:      fsLib,
		stageCheck: stageCheck,
		os:         os}
}

type mountLibUnstageIMPL struct {
	// required handlers
	reqHelper  reqHelpers
	fsLib      wrapperFsLib
	stageCheck mountLibStageCheck
	os         limitedOSIFace
}

func (msi *mountLibStageIMPL) stage(ctx context.Context, req *csi.NodeStageVolumeRequest, device string) error {
	stagingPath := msi.reqHelper.getStagingPath(ctx, req)
	logFields := getLogFields(ctx)
	log.WithFields(logFields).Info("start staging")
	if _, err := msi.mkfile.mkFile(stagingPath); err != nil {
		return status.Errorf(codes.Internal, "can't create target file %s: %s",
			stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("target path successfully created")

	if err := msi.fsLib.BindMount(ctx, device, stagingPath); err != nil {
		return status.Errorf(codes.Internal,
			"error bind disk %s to target path: %s", device,
			err.Error())
	}
	log.WithFields(logFields).Info("volume successfully binded")

	return nil
}

func (mui *mountLibUnstageIMPL) unstage(ctx context.Context,
	req *csi.NodeUnstageVolumeRequest) (string, error) {
	stagingPath := mui.reqHelper.getStagingPath(ctx, req)
	logFields := getLogFields(ctx)

	log.WithFields(logFields).Info("start unstaging")
	device, err := mui.stageCheck.getStagedDev(ctx, stagingPath)
	if err != nil {
		return "", status.Errorf(codes.Internal,
			"could not reliably determine existing mount for path %s: %s",
			stagingPath, err.Error())
	}
	if device != "" {
		_, device = path.Split(device)
		log.WithFields(logFields).Infof("active mount exist")
		err = mui.fsLib.Unmount(ctx, stagingPath)
		if err != nil {
			return "", status.Errorf(codes.Internal,
				"could not unmount dev %s: %s",
				device, err.Error())
		}
		log.WithFields(logFields).Infof("unmount without error")
	} else {
		// no mounts
		log.WithFields(logFields).Infof("no mounts found")
	}
	err = mui.os.Remove(stagingPath)
	if err != nil {
		if mui.os.IsNotExist(err) {
			return device, nil
		}
		return "", status.Errorf(codes.Internal,
			"failed to delete mount path %s: %s",
			stagingPath, err.Error())
	}
	log.WithFields(logFields).Infof("target mount file deleted")
	return device, nil
}

func newMountLibStageCheckIMPL(rh reqHelpers, mr mountLibMountsReader) *mountLibStageCheckIMPL {
	return &mountLibStageCheckIMPL{rh, mr}
}

type mountLibStageCheckIMPL struct {
	reqHelper reqHelpers
	getMounts mountLibMountsReader
}

func (sc *mountLibStageCheckIMPL) getStagedDev(ctx context.Context, stagePath string) (string, error) {
	mountInfo, found, err := sc.getMounts.getTargetMount(ctx, stagePath)
	if err != nil {
		return "", status.Errorf(codes.Internal,
			"can't check mounts for path %s: %s", stagePath, err.Error())
	}
	if !found {
		return "", nil
	}
	sourceDev := mountInfo.Device
	// for bind mounts
	if sourceDev == "devtmpfs" || sourceDev == "udev" {
		sourceDev = mountInfo.Source
	}
	return sourceDev, nil
}
