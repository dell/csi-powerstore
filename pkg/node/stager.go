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

package node

import (
	"context"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/pkg/array"
	"github.com/dell/csi-powerstore/pkg/common"
	"github.com/dell/csi-powerstore/pkg/common/fs"
	"github.com/dell/gobrick"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	procMountsPath    = "/proc/self/mountinfo"
	procMountsRetries = 15
)

// NodeVolumeStager allows to stage a volume
type NodeVolumeStager interface {
	Stage(ctx context.Context, req *csi.NodeStageVolumeRequest, logFields log.Fields, fs fs.FsInterface, id string) (*csi.NodeStageVolumeResponse, error)
}

// SCSIStager implementation of NodeVolumeStager for SCSI based (FC, iSCSI) volumes
type SCSIStager struct {
	useFC          bool
	iscsiConnector ISCSIConnector
	fcConnector    FcConnector
}

// Stage stages volume by connecting it through either FC or iSCSI and creating bind mount to staging path
func (s *SCSIStager) Stage(ctx context.Context, req *csi.NodeStageVolumeRequest,
	logFields log.Fields, fs fs.FsInterface, id string) (*csi.NodeStageVolumeResponse, error) {
	// append additional path to be able to do bind mounts
	stagingPath := getStagingPath(ctx, req.GetStagingTargetPath(), id)

	publishContext, err := readSCSIInfoFromPublishContext(req.PublishContext, s.useFC)
	if err != nil {
		return nil, err
	}

	logFields["ID"] = id
	logFields["Targets"] = publishContext.iscsiTargets
	logFields["WWN"] = publishContext.deviceWWN
	logFields["Lun"] = publishContext.volumeLUNAddress
	logFields["StagingPath"] = stagingPath
	ctx = common.SetLogFields(ctx, logFields)

	found, ready, err := isReadyToPublish(ctx, stagingPath, fs)
	if err != nil {
		return nil, err
	}
	if ready {
		log.WithFields(logFields).Info("device already staged")
		return &csi.NodeStageVolumeResponse{}, nil
	} else if found {
		log.WithFields(logFields).Warning("volume found in staging path but it is not ready for publish," +
			"try to unmount it and retry staging again")
		_, err := unstageVolume(ctx, stagingPath, id, logFields, err, fs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to unmount volume: %s", err.Error())
		}
	}

	devicePath, err := s.connectDevice(ctx, publishContext)
	if err != nil {
		return nil, err
	}

	logFields["DevicePath"] = devicePath

	log.WithFields(logFields).Info("start staging")
	if _, err := fs.MkFileIdempotent(stagingPath); err != nil {
		return nil, status.Errorf(codes.Internal, "can't create target file %s: %s",
			stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("target path successfully created")

	if err := fs.GetUtil().BindMount(ctx, devicePath, stagingPath); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error bind disk %s to target path: %s", devicePath, err.Error())
	}

	log.WithFields(logFields).Info("stage complete")
	return &csi.NodeStageVolumeResponse{}, nil
}

// NFSStager implementation of NodeVolumeStager for NFS volumes
type NFSStager struct {
	array *array.PowerStoreArray
}

// Stage stages volume by mounting volumes as nfs to the staging path
func (n *NFSStager) Stage(ctx context.Context, req *csi.NodeStageVolumeRequest,
	logFields log.Fields, fs fs.FsInterface, id string) (*csi.NodeStageVolumeResponse, error) {
	// append additional path to be able to do bind mounts
	stagingPath := getStagingPath(ctx, req.GetStagingTargetPath(), id)

	hostIP := req.PublishContext[common.KeyHostIP]
	exportID := req.PublishContext[common.KeyExportID]
	nfsExport := req.PublishContext[common.KeyNfsExportPath]
	allowRoot := req.PublishContext[common.KeyAllowRoot]

	natIP := ""
	if ip, ok := req.PublishContext[common.KeyNatIP]; ok {
		natIP = ip
	}

	logFields["NfsExportPath"] = nfsExport
	logFields["StagingPath"] = req.GetStagingTargetPath()
	logFields["ID"] = id
	logFields["AllowRoot"] = allowRoot
	logFields["ExportID"] = exportID
	logFields["HostIP"] = hostIP
	logFields["NatIP"] = natIP
	ctx = common.SetLogFields(ctx, logFields)

	found, err := isReadyToPublishNFS(ctx, stagingPath, fs)
	if err != nil {
		return nil, err
	}

	if found {
		log.WithFields(logFields).Info("device already staged")
		return &csi.NodeStageVolumeResponse{}, nil
	}

	if err := fs.MkdirAll(stagingPath, 0750); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create target folder %s: %s", stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("stage path successfully created")

	if err := fs.GetUtil().Mount(ctx, nfsExport, stagingPath, ""); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error mount nfs share %s to target path: %s", nfsExport, err.Error())
	}

	// Create folder with 1777 in nfs share so every user can use it
	log.WithFields(logFields).Info("creating common folder")
	if err := fs.MkdirAll(filepath.Join(stagingPath, commonNfsVolumeFolder), 0750); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create common folder %s: %s", filepath.Join(stagingPath, "volume"), err.Error())
	}

	if err := fs.Chmod(filepath.Join(stagingPath, commonNfsVolumeFolder), os.ModeSticky|os.ModePerm); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't change permissions of folder %s: %s", filepath.Join(stagingPath, "volume"), err.Error())
	}

	if allowRoot == "false" {
		log.WithFields(logFields).Info("removing allow root from nfs export")
		var hostsToRemove []string
		var hostsToAdd []string

		hostsToRemove = append(hostsToRemove, hostIP+"/255.255.255.255")
		hostsToAdd = append(hostsToAdd, hostIP)

		if natIP != "" {
			hostsToRemove = append(hostsToRemove, natIP)
			hostsToAdd = append(hostsToAdd, natIP)
		}

		// Modify NFS export to RW with `root_squashing`
		_, err = n.array.GetClient().ModifyNFSExport(ctx, &gopowerstore.NFSExportModify{
			RemoveRWRootHosts: hostsToRemove,
			AddRWHosts:        hostsToAdd,
		}, exportID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.NotFound()) {
				return nil, status.Errorf(codes.Internal, "failure when modifying nfs export: %s", err.Error())
			}
		}
	}

	log.WithFields(logFields).Info("nfs share successfully mounted")
	return &csi.NodeStageVolumeResponse{}, nil
}

type scsiPublishContextData struct {
	deviceWWN        string
	volumeLUNAddress string
	iscsiTargets     []gobrick.ISCSITargetInfo
	fcTargets        []gobrick.FCTargetInfo
}

func readSCSIInfoFromPublishContext(publishContext map[string]string, useFC bool) (scsiPublishContextData, error) {
	// Get publishContext
	var data scsiPublishContextData
	deviceWWN, ok := publishContext[common.PublishContextDeviceWWN]
	if !ok {
		return data, status.Error(codes.InvalidArgument, "deviceWWN must be in publish context")
	}
	volumeLUNAddress, ok := publishContext[common.PublishContextLUNAddress]
	if !ok {
		return data, status.Error(codes.InvalidArgument, "volumeLUNAddress must be in publish context")
	}

	iscsiTargets := readISCSITargetsFromPublishContext(publishContext)
	if len(iscsiTargets) == 0 && !useFC {
		return data, status.Error(codes.InvalidArgument, "iscsiTargets data must be in publish context")
	}
	fcTargets := readFCTargetsFromPublishContext(publishContext)
	if len(fcTargets) == 0 && useFC {
		return data, status.Error(codes.InvalidArgument, "fcTargets data must be in publish context")
	}
	return scsiPublishContextData{deviceWWN: deviceWWN, volumeLUNAddress: volumeLUNAddress,
		iscsiTargets: iscsiTargets, fcTargets: fcTargets}, nil
}

func readISCSITargetsFromPublishContext(pc map[string]string) []gobrick.ISCSITargetInfo {
	var targets []gobrick.ISCSITargetInfo
	for i := 0; ; i++ {
		target := gobrick.ISCSITargetInfo{}
		t, tfound := pc[fmt.Sprintf("%s%d", common.PublishContextISCSITargetsPrefix, i)]
		if tfound {
			target.Target = t
		}
		p, pfound := pc[fmt.Sprintf("%s%d", common.PublishContextISCSIPortalsPrefix, i)]
		if pfound {
			target.Portal = p
		}
		if !tfound || !pfound {
			break
		}
		targets = append(targets, target)
	}
	log.Infof("iSCSI iscsiTargets from context: %v", targets)
	return targets
}

func readFCTargetsFromPublishContext(pc map[string]string) []gobrick.FCTargetInfo {
	var targets []gobrick.FCTargetInfo
	for i := 0; ; i++ {
		wwpn, tfound := pc[fmt.Sprintf("%s%d", common.PublishContextFCWWPNPrefix, i)]
		if !tfound {
			break
		}
		targets = append(targets, gobrick.FCTargetInfo{WWPN: wwpn})
	}
	log.Infof("FC iscsiTargets from context: %v", targets)
	return targets
}

func (s *SCSIStager) connectDevice(ctx context.Context, data scsiPublishContextData) (string, error) {
	logFields := common.GetLogFields(ctx)
	var err error
	lun, err := strconv.Atoi(data.volumeLUNAddress)
	if err != nil {
		log.WithFields(logFields).Errorf("failed to convert lun number to int: %s", err.Error())
		return "", status.Errorf(codes.Internal,
			"failed to convert lun number to int: %s", err.Error())
	}
	var device gobrick.Device
	if s.useFC {
		device, err = s.connectFCDevice(ctx, lun, data)
	} else {
		device, err = s.connectISCSIDevice(ctx, lun, data)
	}

	if err != nil {
		log.WithFields(logFields).Errorf("Unable to find device after multiple discovery attempts: %s", err.Error())
		return "", status.Errorf(codes.Internal,
			"unable to find device after multiple discovery attempts: %s", err.Error())
	}
	devicePath := path.Join("/dev/", device.Name)
	return devicePath, nil
}

func (s *SCSIStager) connectISCSIDevice(ctx context.Context,
	lun int, data scsiPublishContextData) (gobrick.Device, error) {
	logFields := common.GetLogFields(ctx)
	var targets []gobrick.ISCSITargetInfo
	for _, t := range data.iscsiTargets {
		targets = append(targets, gobrick.ISCSITargetInfo{Target: t.Target, Portal: t.Portal})
	}
	// separate context to prevent 15 seconds cancel from kubernetes
	connectorCtx, cFunc := context.WithTimeout(context.Background(), time.Second*120)
	defer cFunc()

	connectorCtx = common.SetLogFields(connectorCtx, logFields)
	return s.iscsiConnector.ConnectVolume(connectorCtx, gobrick.ISCSIVolumeInfo{
		Targets: targets,
		Lun:     lun,
	})
}

func (s *SCSIStager) connectFCDevice(ctx context.Context,
	lun int, data scsiPublishContextData) (gobrick.Device, error) {
	logFields := common.GetLogFields(ctx)
	var targets []gobrick.FCTargetInfo

	for _, t := range data.fcTargets {
		targets = append(targets, gobrick.FCTargetInfo{WWPN: t.WWPN})
	}
	// separate context to prevent 15 seconds cancel from kubernetes
	connectorCtx, cFunc := context.WithTimeout(context.Background(), time.Second*120)
	defer cFunc()

	connectorCtx = common.SetLogFields(connectorCtx, logFields)
	return s.fcConnector.ConnectVolume(connectorCtx, gobrick.FCVolumeInfo{
		Targets: targets,
		Lun:     lun,
	})
}

func isReadyToPublish(ctx context.Context, stagingPath string, fs fs.FsInterface) (bool, bool, error) {
	logFields := common.GetLogFields(ctx)
	stageInfo, found, err := getTargetMount(ctx, stagingPath, fs)
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

	devFS, err := fs.GetUtil().GetDiskFormat(ctx, stagingPath)
	if err != nil {
		return found, false, err
	}
	return found, devFS != "mpath_member", nil
}

func isReadyToPublishNFS(ctx context.Context, stagingPath string, fs fs.FsInterface) (bool, error) {
	logFields := common.GetLogFields(ctx)
	stageInfo, found, err := getTargetMount(ctx, stagingPath, fs)
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
