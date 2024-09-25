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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/common/fs"
	"github.com/dell/gobrick"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	procMountsPath    = "/proc/self/mountinfo"
	procMountsRetries = 15
)

// VolumeStager allows to node stage a volume
type VolumeStager interface {
	Stage(ctx context.Context, req *csi.NodeStageVolumeRequest, logFields log.Fields, fs fs.Interface, id string, isRemote bool) (*csi.NodeStageVolumeResponse, error)
}

// ReachableEndPoint checks if the endpoint is reachable or not
var ReachableEndPoint = common.ReachableEndPoint

// SCSIStager implementation of NodeVolumeStager for SCSI based (FC, iSCSI) volumes
type SCSIStager struct {
	useFC          bool
	useNVME        bool
	iscsiConnector ISCSIConnector
	nvmeConnector  NVMEConnector
	fcConnector    FcConnector
}

// Stage stages volume by connecting it through either FC or iSCSI and creating bind mount to staging path
func (s *SCSIStager) Stage(ctx context.Context, req *csi.NodeStageVolumeRequest,
	logFields log.Fields, fs fs.Interface, id string, isRemote bool,
) (*csi.NodeStageVolumeResponse, error) {
	// append additional path to be able to do bind mounts
	stagingPath := getStagingPath(ctx, req.GetStagingTargetPath(), id)

	publishContext, err := readSCSIInfoFromPublishContext(req.PublishContext, s.useFC, s.useNVME, isRemote)
	if err != nil {
		return nil, err
	}

	logFields["ID"] = id
	if s.useNVME {
		if s.useFC {
			logFields["Targets"] = publishContext.nvmefcTargets
		} else {
			logFields["Targets"] = publishContext.nvmetcpTargets
		}
	} else {
		logFields["Targets"] = publishContext.iscsiTargets
	}
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
	logFields log.Fields, fs fs.Interface, id string, _ bool,
) (*csi.NodeStageVolumeResponse, error) {
	// append additional path to be able to do bind mounts
	stagingPath := getStagingPath(ctx, req.GetStagingTargetPath(), id)

	hostIP := req.PublishContext[common.KeyHostIP]
	exportID := req.PublishContext[common.KeyExportID]
	nfsExport := req.PublishContext[common.KeyNfsExportPath]
	allowRoot := req.PublishContext[common.KeyAllowRoot]
	nasName := req.PublishContext[common.KeyNasName]

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
	logFields["NFSv4ACLs"] = req.PublishContext[common.KeyNfsACL]
	logFields["NasName"] = nasName
	ctx = common.SetLogFields(ctx, logFields)

	found, err := isReadyToPublishNFS(ctx, stagingPath, fs)
	if err != nil {
		return nil, err
	}

	if found {
		log.WithFields(logFields).Info("device already staged")
		return &csi.NodeStageVolumeResponse{}, nil
	}

	if err := fs.MkdirAll(stagingPath, 0o750); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create target folder %s: %s", stagingPath, err.Error())
	}
	log.WithFields(logFields).Info("stage path successfully created")

	if err := fs.GetUtil().Mount(ctx, nfsExport, stagingPath, ""); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error mount nfs share %s to target path: %s", nfsExport, err.Error())
	}

	// Create folder with 1777 in nfs share so every user can use it
	if err := fs.MkdirAll(filepath.Join(stagingPath, commonNfsVolumeFolder), 0o750); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create common folder %s: %s", filepath.Join(stagingPath, "volume"), err.Error())
	}

	mode := os.ModePerm
	acls := req.PublishContext[common.KeyNfsACL]
	aclsConfigured := false
	if acls != "" {
		if posixMode(acls) {
			perm, err := strconv.ParseUint(acls, 8, 32)
			if err == nil {
				mode = os.FileMode(perm) // #nosec: G115 false positive
			} else {
				log.WithFields(logFields).Warn("can't parse file mode, invalid mode specified. Default mode permissions will be set.")
			}
		} else {
			aclsConfigured, err = validateAndSetACLs(ctx, &NFSv4ACLs{}, nasName, n.array.GetClient(), acls, filepath.Join(stagingPath, commonNfsVolumeFolder))
			if err != nil || !aclsConfigured {
				return nil, err
			}
		}
	}

	if !aclsConfigured {
		if err := fs.Chmod(filepath.Join(stagingPath, commonNfsVolumeFolder), os.ModeSticky|mode); err != nil {
			return nil, status.Errorf(codes.Internal,
				"can't change permissions of folder %s: %s", filepath.Join(stagingPath, "volume"), err.Error())
		}
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
	nvmetcpTargets   []gobrick.NVMeTargetInfo
	nvmefcTargets    []gobrick.NVMeTargetInfo
	fcTargets        []gobrick.FCTargetInfo
}

func readSCSIInfoFromPublishContext(publishContext map[string]string, useFC bool, useNVMe bool, isRemote bool) (scsiPublishContextData, error) {
	// Get publishContext
	var data scsiPublishContextData
	deviceWwnKey := common.PublishContextDeviceWWN
	lunAddressKey := common.PublishContextLUNAddress
	if isRemote {
		deviceWwnKey = common.PublishContextRemoteDeviceWWN
		lunAddressKey = common.PublishContextRemoteLUNAddress
	}

	deviceWWN, ok := publishContext[deviceWwnKey]
	if !ok {
		return data, status.Error(codes.InvalidArgument, "deviceWWN must be in publish context")
	}
	volumeLUNAddress, ok := publishContext[lunAddressKey]
	if !ok {
		return data, status.Error(codes.InvalidArgument, "volumeLUNAddress must be in publish context")
	}

	iscsiTargets := readISCSITargetsFromPublishContext(publishContext, isRemote)
	if len(iscsiTargets) == 0 && !useFC && !useNVMe {
		return data, status.Error(codes.InvalidArgument, "iscsiTargets data must be in publish context")
	}
	nvmeTCPTargets := readNVMETCPTargetsFromPublishContext(publishContext, isRemote)
	if len(nvmeTCPTargets) == 0 && useNVMe && !useFC {
		return data, status.Error(codes.InvalidArgument, "NVMeTCP Targets data must be in publish context")
	}
	nvmeFCTargets := readNVMEFCTargetsFromPublishContext(publishContext, isRemote)
	if len(nvmeFCTargets) == 0 && useNVMe && useFC {
		return data, status.Error(codes.InvalidArgument, "NVMeFC Targets data must be in publish context")
	}
	fcTargets := readFCTargetsFromPublishContext(publishContext, isRemote)
	if len(fcTargets) == 0 && useFC && !useNVMe {
		return data, status.Error(codes.InvalidArgument, "fcTargets data must be in publish context")
	}
	return scsiPublishContextData{
		deviceWWN: deviceWWN, volumeLUNAddress: volumeLUNAddress,
		iscsiTargets: iscsiTargets, nvmetcpTargets: nvmeTCPTargets, nvmefcTargets: nvmeFCTargets, fcTargets: fcTargets,
	}, nil
}

func readISCSITargetsFromPublishContext(pc map[string]string, isRemote bool) []gobrick.ISCSITargetInfo {
	var targets []gobrick.ISCSITargetInfo
	iscsiTargetsKey := common.PublishContextISCSITargetsPrefix
	iscsiPortalsKey := common.PublishContextISCSIPortalsPrefix
	if isRemote {
		iscsiTargetsKey = common.PublishContextRemoteISCSITargetsPrefix
		iscsiPortalsKey = common.PublishContextRemoteISCSIPortalsPrefix
	}
	for i := 0; ; i++ {
		target := gobrick.ISCSITargetInfo{}
		t, tfound := pc[fmt.Sprintf("%s%d", iscsiTargetsKey, i)]
		if tfound {
			target.Target = t
		}
		p, pfound := pc[fmt.Sprintf("%s%d", iscsiPortalsKey, i)]
		if pfound {
			target.Portal = p
		}
		if !tfound || !pfound {
			break
		}

		if ReachableEndPoint(p) {
			// if the portals from the context (set in ControllerPublishVolume) is not reachable from the nodes
			targets = append(targets, target)
		}
	}
	log.Infof("iSCSI iscsiTargets from context: %v", targets)
	return targets
}

func readNVMETCPTargetsFromPublishContext(pc map[string]string, isRemote bool) []gobrick.NVMeTargetInfo {
	var targets []gobrick.NVMeTargetInfo
	nvmeTCPTargetsKey := common.PublishContextNVMETCPTargetsPrefix
	nvmeTCPPortalsKey := common.PublishContextNVMETCPPortalsPrefix
	if isRemote {
		nvmeTCPTargetsKey = common.PublishContextRemoteNVMETCPTargetsPrefix
		nvmeTCPPortalsKey = common.PublishContextRemoteNVMETCPPortalsPrefix
	}
	for i := 0; ; i++ {
		target := gobrick.NVMeTargetInfo{}
		t, tfound := pc[fmt.Sprintf("%s%d", nvmeTCPTargetsKey, i)]
		if tfound {
			target.Target = t
		}
		p, pfound := pc[fmt.Sprintf("%s%d", nvmeTCPPortalsKey, i)]
		if pfound {
			target.Portal = p
		}
		if !tfound || !pfound {
			break
		}
		targets = append(targets, target)
	}
	log.Infof("NVMeTCP Targets from context: %v", targets)
	return targets
}

func readNVMEFCTargetsFromPublishContext(pc map[string]string, isRemote bool) []gobrick.NVMeTargetInfo {
	var targets []gobrick.NVMeTargetInfo
	nvmeFcTargetsKey := common.PublishContextNVMEFCTargetsPrefix
	nvmeFcPortalsKey := common.PublishContextNVMEFCPortalsPrefix
	if isRemote {
		nvmeFcTargetsKey = common.PublishContextRemoteNVMEFCTargetsPrefix
		nvmeFcPortalsKey = common.PublishContextRemoteNVMEFCPortalsPrefix
	}
	for i := 0; ; i++ {
		target := gobrick.NVMeTargetInfo{}
		t, tfound := pc[fmt.Sprintf("%s%d", nvmeFcTargetsKey, i)]
		if tfound {
			target.Target = t
		}
		p, pfound := pc[fmt.Sprintf("%s%d", nvmeFcPortalsKey, i)]
		if pfound {
			target.Portal = p
		}
		if !tfound || !pfound {
			break
		}
		targets = append(targets, target)
	}
	log.Infof("NVMeFC Targets from context: %v", targets)
	return targets
}

func readFCTargetsFromPublishContext(pc map[string]string, isRemote bool) []gobrick.FCTargetInfo {
	var targets []gobrick.FCTargetInfo
	fcWwpnKey := common.PublishContextFCWWPNPrefix
	if isRemote {
		fcWwpnKey = common.PublishContextRemoteFCWWPNPrefix
	}
	for i := 0; ; i++ {
		wwpn, tfound := pc[fmt.Sprintf("%s%d", fcWwpnKey, i)]
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
	wwn := data.deviceWWN
	var device gobrick.Device
	if s.useNVME {
		device, err = s.connectNVMEDevice(ctx, wwn, data, s.useFC)
	} else if s.useFC {
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
	lun int, data scsiPublishContextData,
) (gobrick.Device, error) {
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

func (s *SCSIStager) connectNVMEDevice(ctx context.Context,
	wwn string, data scsiPublishContextData, useFC bool,
) (gobrick.Device, error) {
	logFields := common.GetLogFields(ctx)
	var targets []gobrick.NVMeTargetInfo

	if useFC {
		for _, t := range data.nvmefcTargets {
			targets = append(targets, gobrick.NVMeTargetInfo{Target: t.Target, Portal: t.Portal})
		}
	} else {
		for _, t := range data.nvmetcpTargets {
			targets = append(targets, gobrick.NVMeTargetInfo{Target: t.Target, Portal: t.Portal})
		}
	}
	// separate context to prevent 15 seconds cancel from kubernetes
	connectorCtx, cFunc := context.WithTimeout(context.Background(), time.Second*120)
	defer cFunc()

	connectorCtx = common.SetLogFields(connectorCtx, logFields)
	return s.nvmeConnector.ConnectVolume(connectorCtx, gobrick.NVMeVolumeInfo{
		Targets: targets,
		WWN:     wwn,
	}, useFC)
}

func (s *SCSIStager) connectFCDevice(ctx context.Context,
	lun int, data scsiPublishContextData,
) (gobrick.Device, error) {
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

func isReadyToPublish(ctx context.Context, stagingPath string, fs fs.Interface) (bool, bool, error) {
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

func isReadyToPublishNFS(ctx context.Context, stagingPath string, fs fs.Interface) (bool, error) {
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
