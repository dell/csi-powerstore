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
	"github.com/dell/gobrick"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"path"
	"strconv"
	"time"
)

type VolumeStager interface {
	Stage(ctx context.Context, req *csi.NodeStageVolumeRequest, svc *service,
		logFields log.Fields, mountLib mountLib) (*csi.NodeStageVolumeResponse, error)
}

type SCSIStager struct {
}

func (s *SCSIStager) Stage(ctx context.Context, req *csi.NodeStageVolumeRequest, svc *service,
	logFields log.Fields, mountLib mountLib) (*csi.NodeStageVolumeResponse, error) {
	// append additional path to be able to do bind mounts
	stagingPath := mountLib.GetStagingPath(ctx, req)

	publishContext, err := svc.impl.readSCSIPublishContext(req)
	if err != nil {
		return nil, err
	}

	logFields["ID"] = req.GetVolumeId()
	logFields["Targets"] = publishContext.iscsiTargets
	logFields["WWN"] = publishContext.deviceWWN
	logFields["Lun"] = publishContext.volumeLUNAddress
	logFields["StagingPath"] = stagingPath
	ctx = setLogFields(ctx, logFields)

	found, ready, err := mountLib.IsReadyToPublish(ctx, stagingPath)
	if err != nil {
		return nil, err
	}
	if ready {
		log.WithFields(logFields).Info("device already staged")
		return &csi.NodeStageVolumeResponse{}, nil
	} else if found {
		log.WithFields(logFields).Warning("volume found in staging path but it is not ready for publish," +
			"try to unmount it and retry staging again")
		_, err := mountLib.UnstageVolume(ctx,
			&csi.NodeUnstageVolumeRequest{VolumeId: req.GetVolumeId(), StagingTargetPath: req.GetStagingTargetPath()})
		if err != nil {
			log.WithFields(logFields).Error(err)
			return nil, status.Errorf(codes.Internal, "failed to unmount volume: %s", err.Error())
		}
	}

	devicePath, err := svc.impl.connectDevice(ctx, publishContext)
	if err != nil {
		return nil, err
	}

	logFields["DevicePath"] = devicePath

	log.WithFields(logFields).Info("calling stage")

	if err := mountLib.StageVolume(ctx, req, devicePath); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error during volume staging: %s", err.Error())
	}
	log.WithFields(logFields).Info("stage complete")
	return &csi.NodeStageVolumeResponse{}, nil
}

type NFSStager struct {
}

func (n *NFSStager) Stage(ctx context.Context, req *csi.NodeStageVolumeRequest, svc *service,
	logFields log.Fields, mountLib mountLib) (*csi.NodeStageVolumeResponse, error) {
	// append additional path to be able to do bind mounts
	stagingPath := mountLib.GetStagingPath(ctx, req)

	nfsExport := req.PublishContext["NfsExportPath"]
	logFields["NfsExportPath"] = nfsExport
	logFields["StagingPath"] = req.GetStagingTargetPath()
	logFields["ID"] = req.GetVolumeId()
	ctx = setLogFields(ctx, logFields)

	found, err := mountLib.IsReadyToPublishNFS(ctx, stagingPath)
	if err != nil {
		return nil, err
	}
	if found {
		log.WithFields(logFields).Info("device already staged")
		return &csi.NodeStageVolumeResponse{}, nil
	}

	log.WithFields(logFields).Info("calling stage")

	if err := mountLib.StageVolumeNFS(ctx, req, nfsExport); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error during volume staging: %s", err.Error())
	}
	log.WithFields(logFields).Info("stage complete")
	return &csi.NodeStageVolumeResponse{}, nil
}

type scsiPublishContextData struct {
	deviceWWN        string
	volumeLUNAddress string
	iscsiTargets     []ISCSITargetInfo
	fcTargets        []FCTargetInfo
}

func (si *serviceIMPL) readSCSIPublishContext(
	req publishContextGetter) (scsiPublishContextData, error) {
	// Get publishContext
	var data scsiPublishContextData
	publishContext := req.GetPublishContext()
	deviceWWN, ok := publishContext[PublishContextDeviceWWN]
	if !ok {
		return data, status.Error(codes.InvalidArgument, "deviceWWN must be in publish context")
	}
	volumeLUNAddress, ok := publishContext[PublishContextLUNAddress]
	if !ok {
		return data, status.Error(codes.InvalidArgument, "volumeLUNAddress must be in publish context")
	}

	iscsiTargets := si.implProxy.readISCSITargetsFromPublishContext(publishContext)
	if len(iscsiTargets) == 0 && !si.service.useFC {
		return data, status.Error(codes.InvalidArgument, "iscsiTargets data must be in publish context")
	}
	fcTargets := si.implProxy.readFCTargetsFromPublishContext(publishContext)
	if len(fcTargets) == 0 && si.service.useFC {
		return data, status.Error(codes.InvalidArgument, "fcTargets data must be in publish context")
	}
	return scsiPublishContextData{deviceWWN: deviceWWN, volumeLUNAddress: volumeLUNAddress,
		iscsiTargets: iscsiTargets, fcTargets: fcTargets}, nil
}

func (si *serviceIMPL) connectDevice(ctx context.Context, data scsiPublishContextData) (string, error) {
	logFields := getLogFields(ctx)
	var err error
	lun, err := strconv.Atoi(data.volumeLUNAddress)
	if err != nil {
		log.WithFields(logFields).Errorf("failed to convert lun number to int: %s", err.Error())
		return "", err
	}
	var device gobrick.Device
	if si.service.useFC {
		device, err = si.implProxy.connectFCDevice(ctx, lun, data)
	} else {
		device, err = si.implProxy.connectISCSIDevice(ctx, lun, data)
	}

	if err != nil {
		log.Errorf("Unable to find device after multiple discovery attempts: %s", err.Error())
		return "", status.Errorf(codes.Internal,
			"Unable to find device after multiple discovery attempts: %s", err.Error())
	}
	devicePath := path.Join("/dev/", device.Name)
	return devicePath, nil
}

func (si *serviceIMPL) connectISCSIDevice(ctx context.Context,
	lun int, data scsiPublishContextData) (gobrick.Device, error) {
	logFields := getLogFields(ctx)
	var targets []gobrick.ISCSITargetInfo
	for _, t := range data.iscsiTargets {
		targets = append(targets, gobrick.ISCSITargetInfo{Target: t.Target, Portal: t.Portal})
	}
	// separate context to prevent 15 seconds cancel from kubernetes
	connectorCtx, cFunc := context.WithTimeout(context.Background(), time.Second*120)
	defer cFunc()
	connectorCtx = copyTraceObj(ctx, connectorCtx)
	connectorCtx = setLogFields(connectorCtx, logFields)
	return si.service.iscsiConnector.ConnectVolume(connectorCtx, gobrick.ISCSIVolumeInfo{
		Targets: targets,
		Lun:     lun,
	})
}

func (si *serviceIMPL) connectFCDevice(ctx context.Context,
	lun int, data scsiPublishContextData) (gobrick.Device, error) {
	logFields := getLogFields(ctx)
	var targets []gobrick.FCTargetInfo
	for _, t := range data.fcTargets {
		targets = append(targets, gobrick.FCTargetInfo{WWPN: t.WWPN})
	}
	// separate context to prevent 15 seconds cancel from kubernetes
	connectorCtx, cFunc := context.WithTimeout(context.Background(), time.Second*120)
	defer cFunc()
	connectorCtx = copyTraceObj(ctx, connectorCtx)
	connectorCtx = setLogFields(connectorCtx, logFields)
	return si.service.fcConnector.ConnectVolume(connectorCtx, gobrick.FCVolumeInfo{
		Targets: targets,
		Lun:     lun,
	})
}
