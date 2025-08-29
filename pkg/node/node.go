/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package node provides CSI specification compatible node service.
package node

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/dell/csm-sharednfs/nfs"
	"github.com/dell/gonvme"
	"github.com/dell/gopowerstore/api"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/helpers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/gobrick"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gofsutil"
	"github.com/dell/goiscsi"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

//go:generate mockgen -destination=../../mocks/NodeInterface.go -package=mocks github.com/dell/csi-powerstore/v2/pkg/node Interface
type Interface interface {
	csi.NodeServer
	array.Consumer
}

// Opts defines service configuration options.
type Opts struct {
	NodeIDFilePath        string
	NodeNamePrefix        string
	NodeChrootPath        string
	MaxVolumesPerNode     int64
	FCPortsFilterFilePath string
	KubeNodeName          string
	KubeConfigPath        string
	CHAPUsername          string
	CHAPPassword          string
	TmpDir                string
	EnableCHAP            bool
}

// Service is a controller service that contains scsi connectors and implements NodeServer API
type Service struct {
	Fs fs.Interface

	ctrlSvc        controller.Interface
	iscsiConnector ISCSIConnector
	fcConnector    FcConnector
	nvmeConnector  NVMEConnector
	iscsiLib       goiscsi.ISCSIinterface
	nvmeLib        gonvme.NVMEinterface
	iscsiTargets   map[string][]string
	nvmeTargets    map[string][]string
	opts           Opts
	nodeID         string

	useFC                  map[string]bool
	useNVME                map[string]bool
	useNFS                 bool
	initialized            bool
	reusedHost             bool
	isHealthMonitorEnabled bool
	isPodmonEnabled        bool

	array.Locker
}

const (
	maxPowerstoreVolumesPerNodeLabel = "max-powerstore-volumes-per-node"
)

// Init initializes node service by parsing environmental variables, connecting it as a host.
// Will init ISCSIConnector, FcConnector and ControllerService if they are nil.
func (s *Service) Init() error {
	ctx := context.Background()
	s.opts = getNodeOptions()

	s.initConnectors()

	err := s.updateNodeID()
	if err != nil {
		return fmt.Errorf("can't update node id: %s", err.Error())
	}
	s.iscsiTargets = make(map[string][]string)
	s.nvmeTargets = make(map[string][]string)
	s.useFC = make(map[string]bool)
	s.useNVME = make(map[string]bool)
	iscsiInitiators, fcInitiators, nvmeInitiators, err := s.getInitiators()
	if err != nil {
		return fmt.Errorf("can't get initiators of the node: %s", err.Error())
	}

	if isPodmonEnabled, ok := csictx.LookupEnv(ctx, identifiers.EnvPodmonEnabled); ok {
		// in case of any error in reading/parsing the env variable default value will be false
		s.isPodmonEnabled, _ = strconv.ParseBool(isPodmonEnabled)
	}

	if len(iscsiInitiators) == 0 && len(fcInitiators) == 0 && len(nvmeInitiators) == 0 {
		s.useNFS = true
		go s.startAPIService(ctx)
		return nil
	}

	if len(nvmeInitiators) != 0 {
		err = k8sutils.AddNVMeLabels(ctx, s.opts.KubeConfigPath, s.opts.KubeNodeName, "hostnqn-uuid", nvmeInitiators)
		if err != nil {
			log.Warnf("Unable to add hostnqn uuid label for node %s: %v", s.opts.KubeNodeName, err.Error())
		}
	}

	// Setup host on each of available arrays
	for _, arr := range s.Arrays() {
		if arr.BlockProtocol == identifiers.NoneTransport {
			continue
		}

		var initiators []string
		var useNVME, useFC bool

		switch arr.BlockProtocol {
		case identifiers.NVMETCPTransport:
			if len(nvmeInitiators) == 0 {
				log.Errorf("NVMeTCP transport was requested but NVMe initiator is not available")
			}
			useNVME = true
			useFC = false
		case identifiers.NVMEFCTransport:
			if len(nvmeInitiators) == 0 {
				log.Errorf("NVMeFC transport was requested but NVMe initiator is not available")
			}
			useNVME = true
			useFC = true
		case identifiers.ISCSITransport:
			if len(iscsiInitiators) == 0 {
				log.Errorf("iSCSI transport was requested but iSCSI initiator is not available")
			}
			useNVME = false
			useFC = false
		case identifiers.FcTransport:
			if len(fcInitiators) == 0 {
				log.Errorf("FC transport was requested but FC initiator is not available")
			}
			useNVME = false
			useFC = true
		default:
			useNVME = len(nvmeInitiators) > 0
			useFC = len(fcInitiators) > 0
		}
		if useNVME {
			initiators = nvmeInitiators
			if useFC {
				log.Infof("NVMeFC Protocol is requested")
			} else {
				log.Infof("NVMeTCP Protocol is requested")
			}
		} else if useFC {
			initiators = fcInitiators
			log.Infof("FC Protocol is requested")
		} else {
			initiators = iscsiInitiators
			log.Infof("iSCSI Protocol is requested")
		}

		// store the values in the array list for later use
		s.useNVME[arr.GlobalID] = useNVME
		s.useFC[arr.GlobalID] = useFC

		err = s.setupHost(initiators, arr.GetClient(), arr.GetIP(), arr.GetGlobalID())
		if err != nil {
			log.Errorf("can't setup host on %s: %s", arr.Endpoint, err.Error())
		}
	}

	if isHealthMonitorEnabled, ok := csictx.LookupEnv(ctx, identifiers.EnvIsHealthMonitorEnabled); ok {
		s.isHealthMonitorEnabled, _ = strconv.ParseBool(isHealthMonitorEnabled)
	}

	go s.startAPIService(ctx)
	return nil
}

func (s *Service) initConnectors() {
	gobrick.SetLogger(&identifiers.CustomLogger{})

	if s.iscsiConnector == nil {
		s.iscsiConnector = gobrick.NewISCSIConnector(
			gobrick.ISCSIConnectorParams{
				Chroot:       s.opts.NodeChrootPath,
				ChapUser:     s.opts.CHAPUsername,
				ChapPassword: s.opts.CHAPPassword,
				ChapEnabled:  s.opts.EnableCHAP,
			})
	}

	if s.fcConnector == nil {
		s.fcConnector = gobrick.NewFCConnector(
			gobrick.FCConnectorParams{Chroot: s.opts.NodeChrootPath})
	}

	if s.nvmeConnector == nil {
		s.nvmeConnector = gobrick.NewNVMeConnector(
			gobrick.NVMeConnectorParams{Chroot: s.opts.NodeChrootPath})
	}

	if s.ctrlSvc == nil {
		svc := &controller.Service{Fs: s.Fs}
		svc.SetArrays(s.Arrays())
		svc.SetDefaultArray(s.DefaultArray())
		s.ctrlSvc = svc
	}

	if s.iscsiLib == nil {
		iSCSIOpts := make(map[string]string)
		iSCSIOpts["chrootDirectory"] = s.opts.NodeChrootPath

		s.iscsiLib = goiscsi.NewLinuxISCSI(iSCSIOpts)
	}

	if s.nvmeLib == nil {
		NVMeOpts := make(map[string]string)
		NVMeOpts["chrootDirectory"] = s.opts.NodeChrootPath

		s.nvmeLib = gonvme.NewNVMe(NVMeOpts)
	}
}

// Check for duplicate hostnqn uuids
func (s *Service) checkForDuplicateUUIDs() {
	nodeUUIDs := make(map[string]string)
	duplicateUUIDs := make(map[string]string)

	var err error
	nodeUUIDs, err = k8sutils.GetNVMeUUIDs(context.Background(), s.opts.KubeConfigPath)
	if err != nil {
		log.Errorf("Unable to check uuids")
		return
	}

	// Iterate over all nodes to check their uuid
	for node, uuid := range nodeUUIDs {
		if existingNode, found := duplicateUUIDs[uuid]; found {
			log.Errorf("Duplicate hostnqn uuid %s found on nodes: %s and %s", uuid, existingNode, node)
		} else {
			duplicateUUIDs[uuid] = node
		}
	}
}

// NodeStageVolume prepares volume to be consumed by node publish by connecting volume to the node
func (s *Service) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	logFields := identifiers.GetLogFields(ctx)

	if req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "volume capability is required")
	}

	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	if req.GetStagingTargetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "staging target path is required")
	}

	volumeHandle, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), req.VolumeCapability)
	if err != nil {
		return nil, err
	}

	id = volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol
	remoteVolumeID := volumeHandle.RemoteUUID

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.Internal, "can't find array with ID %s", arrayID)
	}

	var stager VolumeStager
	if protocol == "nfs" {
		stager = &NFSStager{
			array: arr,
		}
	} else {
		stager = &SCSIStager{
			useFC:          s.useFC[arr.GlobalID],
			useNVME:        s.useNVME[arr.GlobalID],
			iscsiConnector: s.iscsiConnector,
			nvmeConnector:  s.nvmeConnector,
			fcConnector:    s.fcConnector,
		}
	}

	response, err := stager.Stage(ctx, req, logFields, s.Fs, id, false)
	if err != nil {
		return nil, err
	}

	if remoteVolumeID != "" { // For Remote Metro volume
		log.Info("Staging remote metro volume")
		// need to change the staging path for nfs
		if nfs.IsNFSVolumeID(req.VolumeId) {
			req.StagingTargetPath = nfs.NfsExportDirectory
		}
		response, err = stager.Stage(ctx, req, logFields, s.Fs, remoteVolumeID, true)
	}

	return response, err
}

// NodeUnstageVolume reverses steps done in NodeStage by disconnecting volume from the node
func (s *Service) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	logFields := identifiers.GetLogFields(ctx)
	var err error

	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	if req.GetStagingTargetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "staging target path is required")
	}

	volumeHandle, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), nil)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return &csi.NodeUnstageVolumeResponse{}, nil
		}
		return nil, status.Errorf(codes.Unknown,
			"failure checking volume status for volume node unstage: %s",
			err.Error())
	}
	id = volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol
	remoteVolumeID := volumeHandle.RemoteUUID

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.Internal, "can't find array with ID %s", arrayID)
	}

	stagingPath := req.GetStagingTargetPath()

	id, stagingPath = getStagingPath(ctx, stagingPath, id)

	device, err := unstageVolume(ctx, stagingPath, id, logFields, err, s.Fs)
	if err != nil {
		return nil, err
	}
	if remoteVolumeID != "" { // For Remote Metro volume
		log.Info("Unstaging remote metro volume")
		_, remoteStagingPath := getStagingPath(ctx, req.GetStagingTargetPath(), remoteVolumeID)
		// need to change the staging path for nfs
		if nfs.IsNFSVolumeID(req.VolumeId) {
			_, remoteStagingPath = getStagingPath(ctx, nfs.NfsExportDirectory, remoteVolumeID)
		}
		_, err = unstageVolume(ctx, remoteStagingPath, remoteVolumeID, logFields, err, s.Fs)
		if err != nil {
			return nil, err
		}
	}

	if protocol == "nfs" {
		return &csi.NodeUnstageVolumeResponse{}, nil
	}

	if device != "" {
		err := createMapping(id, device, s.opts.TmpDir, s.Fs)
		if err != nil {
			log.WithFields(logFields).Warningf("failed to create vol to device mapping: %s", err.Error())
		}
	} else {
		device, err = getMapping(id, s.opts.TmpDir, s.Fs)
		if err != nil {
			log.WithFields(logFields).Info("no device found. skip device removal")
			return &csi.NodeUnstageVolumeResponse{}, nil
		}
	}

	f := log.Fields{"Device": device}

	connectorCtx := identifiers.SetLogFields(context.Background(), logFields)

	if s.useNVME[arr.GlobalID] {
		err = s.nvmeConnector.DisconnectVolumeByDeviceName(connectorCtx, device)
	} else if s.useFC[arr.GlobalID] {
		err = s.fcConnector.DisconnectVolumeByDeviceName(connectorCtx, device)
	} else {
		err = s.iscsiConnector.DisconnectVolumeByDeviceName(connectorCtx, device)
	}
	if err != nil {
		log.WithFields(logFields).Error(err)
		return nil, err
	}
	log.WithFields(logFields).WithFields(f).Info("block device removal complete")

	err = deleteMapping(id, s.opts.TmpDir, s.Fs)
	if err != nil {
		log.WithFields(logFields).Warningf("failed to remove vol to Dev mapping: %s", err.Error())
	}

	return &csi.NodeUnstageVolumeResponse{}, nil
}

func unstageVolume(ctx context.Context, stagingPath, id string, logFields log.Fields, err error, fs fs.Interface) (string, error) {
	logFields["ID"] = id
	logFields["StagingPath"] = stagingPath
	ctx = identifiers.SetLogFields(ctx, logFields)

	log.WithFields(logFields).Info("calling unstage")

	device, err := getStagedDev(ctx, stagingPath, fs)
	if err != nil {
		return "", status.Errorf(codes.Internal,
			"could not reliably determine existing mount for path %s: %s", stagingPath, err.Error())
	}

	if device != "" {
		_, device = path.Split(device)
		log.WithFields(logFields).Infof("active mount exist")
		err = fs.GetUtil().Unmount(ctx, stagingPath)
		if err != nil {
			return "", status.Errorf(codes.Internal,
				"could not unmount dev %s: %s", device, err.Error())
		}
		log.WithFields(logFields).Infof("unmount without error")
	} else {
		// no mounts
		log.WithFields(logFields).Infof("no mounts found")
	}

	err = fs.Remove(stagingPath)
	if err != nil && fs.IsDeviceOrResourceBusy(err) {
		log.Warnf("failed to delete mount path : %s", err)
		var remnantDevice string
		remnantDevice, err = removeRemnantMounts(ctx, stagingPath, fs, logFields)
		if device == "" {
			device = remnantDevice
		}
	}
	if err != nil && !fs.IsNotExist(err) {
		return "", status.Errorf(codes.Internal, "failed to delete mount path %s: %s", stagingPath, err.Error())
	}

	log.WithFields(logFields).Infof("target mount file deleted")
	return device, nil
}

func removeRemnantMounts(ctx context.Context, stagingPath string, fs fs.Interface, logFields log.Fields) (string, error) {
	log.WithFields(logFields).Infof("getting remnant mount")
	mounts, found, err := getRemnantTargetMounts(ctx, stagingPath, fs)
	if !found || err != nil {
		return "", fmt.Errorf("could not reliably determine remnant mounts for path %s: %s", stagingPath, err.Error())
	}

	log.WithFields(logFields).Infof("%d remnant mount exist", len(mounts))
	for _, mount := range mounts {
		delete(logFields, "StagingPath")
		logFields["RemnantPath"] = mount.Path
		err = fs.GetUtil().Unmount(ctx, mount.Path)
		if err != nil {
			return "", fmt.Errorf("could not unmount dev %s: %s", mount.Path, err.Error())
		}
		log.WithFields(logFields).Infof("unmount without error")
	}

	delete(logFields, "RemnantPath")
	logFields["StagingPath"] = stagingPath

	err = fs.Remove(stagingPath)

	return mounts[0].Device, err
}

// NodePublishVolume publishes volume to the node by mounting it to the target path
func (s *Service) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	logFields := identifiers.GetLogFields(ctx)
	var ephemeralVolume bool
	isHBN := nfs.IsNFSVolumeID(req.VolumeId)
	if isHBN {
		req.VolumeId = nfs.ToArrayVolumeID(req.VolumeId)
	}
	ephemeral, ok := req.VolumeContext["csi.storage.k8s.io/ephemeral"]
	if ok {
		ephemeralVolume = strings.ToLower(ephemeral) == "true"
	}

	if ephemeralVolume {
		return s.ephemeralNodePublish(ctx, req)
	}
	// Get the VolumeID and validate against the volume
	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	targetPath := req.GetTargetPath()
	if targetPath == "" {
		return nil, status.Error(codes.InvalidArgument, "targetPath is required")
	}

	if req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "VolumeCapability is required")
	}

	if req.GetStagingTargetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "stagingPath is required")
	}

	volumeHandle, _ := array.ParseVolumeID(ctx, id, s.DefaultArray(), req.VolumeCapability)
	id = volumeHandle.LocalUUID
	protocol := volumeHandle.Protocol

	stagingPath := req.GetStagingTargetPath()

	if !isHBN {
		// append additional path to be able to do bind mounts
		_, stagingPath = getStagingPath(ctx, req.GetStagingTargetPath(), id)
	}

	isRO := req.GetReadonly()
	volumeCapability := req.GetVolumeCapability()

	logFields["ID"] = id
	logFields["TargetPath"] = targetPath
	logFields["StagingPath"] = stagingPath
	logFields["ReadOnly"] = req.GetReadonly()
	ctx = identifiers.SetLogFields(ctx, logFields)

	log.WithFields(logFields).Info("calling publish")

	var publisher VolumePublisher

	if protocol == "nfs" {
		if s.fileExists(filepath.Join(stagingPath, commonNfsVolumeFolder)) {
			// Assume root squashing is enabled
			stagingPath = filepath.Join(stagingPath, commonNfsVolumeFolder)
		}

		publisher = &NFSPublisher{}
	} else {
		publisher = &SCSIPublisher{
			isBlock: isBlock(req.VolumeCapability),
		}
	}

	return publisher.Publish(ctx, logFields, s.Fs, volumeCapability, isRO, targetPath, stagingPath)
}

// NodeUnpublishVolume unpublishes volume from the node by unmounting it from the target path
func (s *Service) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	logFields := identifiers.GetLogFields(ctx)
	var err error

	targetPath := req.GetTargetPath()
	if targetPath == "" {
		log.Error("target path required")
		return nil, status.Error(codes.InvalidArgument, "target path required")
	}
	volID := req.GetVolumeId()
	if volID == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	var ephemeralVolume bool
	lockFile := ephemeralStagingMountPath + volID + "/id"

	if s.fileExists(lockFile) {
		ephemeralVolume = true
	}
	logFields["ID"] = volID
	logFields["TargetPath"] = targetPath
	ctx = identifiers.SetLogFields(ctx, logFields)
	log.WithFields(logFields).Info("calling unpublish")

	_, found, err := getTargetMount(ctx, targetPath, s.Fs)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"could not reliably determine existing mount status for path %s: %s",
			targetPath, err.Error())
	}

	if !found {
		// no mounts
		log.WithFields(logFields).Infof("no mounts found")
		return &csi.NodeUnpublishVolumeResponse{}, nil
	}

	log.WithFields(logFields).Infof("active mount exist")
	err = s.Fs.GetUtil().Unmount(ctx, targetPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"could not unmount dev %s: %s",
			targetPath, err.Error())
	}

	// remove target path
	err = s.Fs.Remove(targetPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to remove target path: %s as part of NodeUnpublish: %s", targetPath, err.Error())
	}

	log.WithFields(logFields).Info("unpublish complete")
	log.Debug("Checking for ephemeral after node unpublish")

	if ephemeralVolume {
		log.Info("Detected ephemeral")
		err = s.ephemeralNodeUnpublish(ctx, req)
		if err != nil {
			return nil, err
		}

	}

	return &csi.NodeUnpublishVolumeResponse{}, nil
}

// NodeGetVolumeStats returns volume usage stats
func (s *Service) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no volume ID provided")
	}

	volumePath := req.GetVolumePath()
	if len(volumePath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no volume Path provided")
	}

	if !filepath.IsAbs(volumePath) {
		return nil, status.Error(codes.NotFound, "no volume Path provided")
	}

	// parse volume Id
	volumeHandle, err := array.ParseVolumeID(ctx, volumeID, s.DefaultArray(), nil)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return nil, err
		}
		return nil, err
	}
	id := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given ID")
	}
	// default empty usage
	usage := []*csi.VolumeUsage{
		{
			Available: 0,
			Total:     0,
			Used:      0,
			Unit:      csi.VolumeUsage_BYTES,
		},
	}
	// Validate if volume exists
	if protocol == "nfs" {
		fs, err := arr.Client.GetFS(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.NotFound, "failed to find filesystem %s with error: %v", id, err.Error())
			}
			resp := &csi.NodeGetVolumeStatsResponse{
				Usage: usage,
				VolumeCondition: &csi.VolumeCondition{
					Abnormal: true,
					Message:  fmt.Sprintf("Filesystem %s is not found", id),
				},
			}
			return resp, nil
		}
		nfsExport, err := s.Arrays()[arrayID].Client.GetNFSExportByFileSystemID(ctx, fs.ID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.NotFound, "failed to find nfs export for filesystem with error: %v", err.Error())
			}
			resp := &csi.NodeGetVolumeStatsResponse{
				Usage: usage,
				VolumeCondition: &csi.VolumeCondition{
					Abnormal: true,
					Message:  fmt.Sprintf("NFS export for volume %s is not found", id),
				},
			}
			return resp, nil
		}
		// get hosts publish to export
		hosts := append(nfsExport.ROHosts, nfsExport.RORootHosts...)
		hosts = append(hosts, nfsExport.RWHosts...)
		hosts = append(hosts, nfsExport.RWRootHosts...)
		attached := false
		// Extract the IP address from the node ID
		ipList := identifiers.GetIPListFromString(s.nodeID)
		if len(ipList) == 0 {
			return nil, status.Errorf(codes.NotFound, "failed to find IP in nodeID %s", s.nodeID)
		}
		nodeIP := ipList[0]
		for _, host := range hosts {
			// Extract the IP address from the host (IP/netmask)
			hostIP := strings.Split(host, "/")[0]
			if nodeIP == hostIP {
				attached = true
				break
			}
		}
		if !attached {
			resp := &csi.NodeGetVolumeStatsResponse{
				Usage: usage,
				VolumeCondition: &csi.VolumeCondition{
					Abnormal: true,
					Message:  fmt.Sprintf("host %s is not attached to NFS export for filesystem %s", s.nodeID, id),
				},
			}
			return resp, nil
		}
	} else {
		_, err := arr.Client.GetVolume(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.NotFound, "failed to find volume %s with error: %v", id, err.Error())
			}
			resp := &csi.NodeGetVolumeStatsResponse{
				Usage: usage,
				VolumeCondition: &csi.VolumeCondition{
					Abnormal: true,
					Message:  fmt.Sprintf("Volume %s is not found", id),
				},
			}
			return resp, nil
		}
		// get hosts published to volume
		hostMappings, err := s.Arrays()[arrayID].Client.GetHostVolumeMappingByVolumeID(ctx, id)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "failed to get host volume mapping for volume: %s with error: %v", id, err.Error())
		}
		hostMapped := false
		for _, hostMapping := range hostMappings {
			host, err := s.Arrays()[arrayID].Client.GetHost(ctx, hostMapping.HostID)
			if err != nil {
				if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
					return nil, status.Errorf(codes.NotFound, "failed to get host: %s with error: %v", hostMapping.HostID, err.Error())
				}
				resp := &csi.NodeGetVolumeStatsResponse{
					Usage: usage,
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("host %s is not attached to volume %s", s.nodeID, id),
					},
				}
				return resp, nil
			}

			if host.Name == s.nodeID {
				hostMapped = true
			}

			iscsiConnection := false
			for _, initiator := range host.Initiators {
				if len(initiator.ActiveSessions) > 0 {
					iscsiConnection = true
				}
			}
			if !iscsiConnection {
				resp := &csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("host %s has no active initiator connection", s.nodeID),
					},
				}
				return resp, nil
			}
		}
		if !hostMapped {
			resp := &csi.NodeGetVolumeStatsResponse{
				Usage: usage,
				VolumeCondition: &csi.VolumeCondition{
					Abnormal: true,
					Message:  fmt.Sprintf("host %s is not attached to volume %s", s.nodeID, id),
				},
			}
			return resp, nil
		}
	}

	stagingPath := req.GetStagingTargetPath()
	if len(stagingPath) != 0 {
		// Check if staging target path is mounted
		_, found, err := getTargetMount(ctx, stagingPath, s.Fs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't check mounts for path %s: %s", stagingPath, err.Error())
		}
		if !found {
			resp := &csi.NodeGetVolumeStatsResponse{
				Usage: usage,
				VolumeCondition: &csi.VolumeCondition{
					Abnormal: true,
					Message:  fmt.Sprintf("staging target path %s not mounted for volume %s", stagingPath, id),
				},
			}
			return resp, nil
		}
	}

	// Check if target path is mounted
	_, found, err := getTargetMount(ctx, volumePath, s.Fs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't check mounts for path %s: %s", volumePath, err.Error())
	}
	if !found {
		resp := &csi.NodeGetVolumeStatsResponse{
			Usage: usage,
			VolumeCondition: &csi.VolumeCondition{
				Abnormal: true,
				Message:  fmt.Sprintf("volume path %s not mounted for volume %s", volumePath, id),
			},
		}
		return resp, nil
	}

	// check if volume path is accessible
	_, err = os.ReadDir(volumePath)
	if err != nil {
		resp := &csi.NodeGetVolumeStatsResponse{
			Usage: usage,
			VolumeCondition: &csi.VolumeCondition{
				Abnormal: true,
				Message:  fmt.Sprintf("volume path %s not accessible for volume %s", volumePath, id),
			},
		}
		return resp, nil
	}

	// get volume metrics for mounted volume path
	availableBytes, totalBytes, usedBytes, totalInodes, freeInodes, usedInodes, err := gofsutil.FsInfo(ctx, volumePath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get metrics for volume with error: %v", err)
	}

	resp := &csi.NodeGetVolumeStatsResponse{
		Usage: []*csi.VolumeUsage{
			{
				Available: availableBytes,
				Total:     totalBytes,
				Used:      usedBytes,
				Unit:      csi.VolumeUsage_BYTES,
			},
			{
				Available: freeInodes,
				Total:     totalInodes,
				Used:      usedInodes,
				Unit:      csi.VolumeUsage_INODES,
			},
		},
		VolumeCondition: &csi.VolumeCondition{
			Abnormal: false,
			Message:  "",
		},
	}

	return resp, nil
}

// NodeExpandVolume expands the volume by re-scanning and resizes filesystem if needed
func (s *Service) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	var reqID string
	var err error
	headers, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if req, ok := headers["csi.requestid"]; ok && len(req) > 0 {
			reqID = req[0]
		}
	}

	isHBN := nfs.IsNFSVolumeID(req.VolumeId)
	if isHBN {
		req.VolumeId = nfs.ToArrayVolumeID(req.VolumeId)
	}

	// Get the VolumeID and validate against the volume
	volumeHandle, err := array.ParseVolumeID(ctx, req.VolumeId, s.DefaultArray(), nil)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			// Return error code csi-sanity test expects
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, err
	}

	targetPath := req.GetVolumePath()
	if targetPath == "" {
		return nil, status.Error(codes.InvalidArgument, "targetPath is required")
	}

	if volumeHandle.Protocol == "nfs" {
		// workaround for https://github.com/kubernetes/kubernetes/issues/131419
		return &csi.NodeExpandVolumeResponse{}, nil
	}

	id := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given ID")
	}

	isBlock := strings.Contains(targetPath, blockVolumePathMarker)
	// Parse the CSI VolumeId and validate against the volume
	vol, err := arr.Client.GetVolume(ctx, id)
	if err != nil {
		// If the volume isn't found, we cannot stage it
		return nil, status.Error(codes.NotFound, "Volume not found")
	}

	isAuthEnabled := os.Getenv("X_CSM_AUTH_ENABLED")
	if isAuthEnabled == "true" {
		// If the volume is created from Auth v2 which has tenant prefix then we need to remove that while publishing, otherwise mount will fail - THIS IS A TEMPORARY FIX
		splittedVolName := strings.Split(vol.Name, "-")
		if len(splittedVolName) > 2 {
			vol.Name = strings.Join(splittedVolName[1:], "-") // we will just discard first part which is tenant prefix - Ex: tn1-csivol-12345
		}
	}

	log.Debug("Volume name: ", vol.Name)

	volumeWWN := vol.Wwn

	// Locate and fetch all (multipath/regular) mounted paths using this volume
	var devMnt *gofsutil.DeviceMountInfo
	var targetmount string
	if isHBN {
		devMnt, err = s.Fs.GetUtil().GetMountInfoFromDevice(ctx, id)
	} else {
		devMnt, err = s.Fs.GetUtil().GetMountInfoFromDevice(ctx, vol.Name)
	}

	// Stop block volume expansion if metro session is paused
	// User needs to resume it first.
	remoteVolumeID := volumeHandle.RemoteUUID // metro indicator
	if remoteVolumeID != "" {
		if vol.MetroReplicationSessionID == "" {
			return nil, status.Errorf(codes.Internal,
				"cannot expand volume %s: missing metro replication session ID", vol.Name)
		}

		state, err := controller.GetMetroSessionState(ctx, vol.MetroReplicationSessionID, arr)
		if err != nil {
			return nil, status.Errorf(codes.Internal,
				"cannot expand volume %s: failed to get metro session state: %v", vol.Name, err)
		}

		if state != gopowerstore.RsStateOk {
			return nil, status.Errorf(codes.Aborted,
				"cannot expand volume %s: metro session %s is not active, its in %s state",
				vol.Name, vol.MetroReplicationSessionID, state)
		}
	}

	if err != nil {
		if isBlock {
			return s.nodeExpandRawBlockVolume(ctx, volumeWWN)
		}
		log.Infof("Failed to find mount info for (%s) with error (%s)", vol.Name, err.Error())
		log.Info("Probably offline volume expansion. Will try to perform a temporary mount.")
		var disklocation string

		disklocation = fmt.Sprintf("%s/%s", targetPath, vol.ID)
		log.Infof("DisklLocation: %s", disklocation)
		targetmount = fmt.Sprintf("tmp/%s/%s", vol.ID, vol.Name)
		log.Infof("TargetMount: %s", targetmount)
		err = s.Fs.MkdirAll(targetmount, 0o750)
		if err != nil {
			return nil, status.Error(codes.Internal,
				fmt.Sprintf("Failed to find mount info for (%s) with error (%s)", vol.Name, err.Error()))
		}

		mntFlags := identifiers.GetMountFlags(req.GetVolumeCapability())
		err = s.Fs.GetUtil().Mount(ctx, disklocation, targetmount, "", mntFlags...)
		if err != nil {
			return nil, status.Error(codes.Internal,
				fmt.Sprintf("Failed to find mount info for (%s) with error (%s)", vol.Name, err.Error()))
		}

		defer func() {
			if targetmount != "" {
				log.Infof("Clearing down temporary mount points in: %s", targetmount)
				err := s.Fs.GetUtil().Unmount(ctx, targetmount)
				if err != nil {
					log.Error("Failed to remove temporary mount points")
				}
				err = s.Fs.RemoveAll(targetmount)
				if err != nil {
					log.Error("Failed to remove temporary mount points")
				}
			}
		}()

		devMnt, err = s.Fs.GetUtil().GetMountInfoFromDevice(ctx, vol.Name)
		if err != nil {
			return nil, status.Error(codes.Internal,
				fmt.Sprintf("Failed to find mount info for (%s) with error (%s)", vol.Name, err.Error()))
		}

	}

	log.Infof("Mount info for volume %s: %+v", vol.Name, devMnt)

	size := req.GetCapacityRange().GetRequiredBytes()

	f := log.Fields{
		"CSIRequestID": reqID,
		"VolumeName":   vol.Name,
		"VolumePath":   targetPath,
		"Size":         size,
		"VolumeWWN":    volumeWWN,
	}
	log.WithFields(f).Info("Calling resize the file system")

	if !s.useNVME[arr.GlobalID] {
		// Rescan the device for the volume expanded on the array
		for _, device := range devMnt.DeviceNames {
			devicePath := sysBlock + device
			err = s.Fs.GetUtil().DeviceRescan(context.Background(), devicePath)
			if err != nil {
				log.Errorf("Failed to rescan device (%s) with error (%s)", devicePath, err.Error())
				return nil, status.Error(codes.Internal, err.Error())
			}
		}
	}
	// Expand the filesystem with the actual expanded volume size.
	if devMnt.MPathName != "" {
		err = s.Fs.GetUtil().ResizeMultipath(context.Background(), devMnt.MPathName)
		if err != nil {
			log.Errorf("Failed to resize filesystem: device  (%s) with error (%s)", devMnt.MountPoint, err.Error())

			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	// For a regular device, get the device path (devMnt.DeviceNames[1]) where the filesystem is mounted
	// PublishVolume creates devMnt.DeviceNames[0] but is left unused for regular devices
	var devicePath string
	if len(devMnt.DeviceNames) > 1 {
		devicePath = "/dev/" + devMnt.DeviceNames[1]
	} else if len(devMnt.DeviceNames) == 0 {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("Failed to find mount info for (%s) DeviceNames (%v)", vol.Name, devMnt.DeviceNames))
	} else {
		devicePath = "/dev/" + devMnt.DeviceNames[0]
	}
	fsType, err := s.Fs.GetUtil().FindFSType(context.Background(), devMnt.MountPoint)
	if err != nil {
		log.Errorf("Failed to fetch filesystem for volume  (%s) with error (%s)", devMnt.MountPoint, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}
	log.Infof("Found %s filesystem mounted on volume %s", fsType, devMnt.MountPoint)
	// Resize the filesystem
	var xfsNew bool
	checkVersCmd := "xfs_growfs -V"
	bufcheck, errcheck := s.Fs.ExecCommandOutput("bash", "-c", checkVersCmd)
	if errcheck != nil {
		return nil, errcheck
	}
	outputcheck := string(bufcheck)
	versionRegx := regexp.MustCompile(`version (?P<versmaj>\d+)\.(?P<versmin>\d+)\..+`)
	match := versionRegx.FindStringSubmatch(outputcheck)
	subMatchMap := make(map[string]string)
	for i, name := range versionRegx.SubexpNames() {
		if i != 0 {
			subMatchMap[name] = match[i]
		}
	}

	if s, err := strconv.ParseFloat(subMatchMap["versmaj"]+"."+subMatchMap["versmin"], 64); err == nil {
		fmt.Println(s)
		if s >= 5.0 { // need to check exact version
			xfsNew = true
		} else {
			xfsNew = false
		}
	} else {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if fsType == "xfs" && xfsNew {
		// Passing empty string for ppathDevice since we don't need the powerpath device
		err = s.Fs.GetUtil().ResizeFS(context.Background(), devMnt.MountPoint, devicePath, "", "", fsType)
		if err != nil {
			log.Errorf("Failed to resize filesystem: mountpoint (%s) device (%s) with error (%s)",
				devMnt.MountPoint, devicePath, err.Error())
			return nil, status.Error(codes.Internal, err.Error())
		}
	} else {
		// Passing empty string for ppathDevice since we don't need the powerpath device
		err = s.Fs.GetUtil().ResizeFS(context.Background(), devMnt.MountPoint, devicePath, "", devMnt.MPathName, fsType)
		if err != nil {
			log.Errorf("Failed to resize filesystem: mountpoint (%s) device (%s) with error (%s)",
				devMnt.MountPoint, devicePath, err.Error())
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	return &csi.NodeExpandVolumeResponse{}, nil
}

func (s *Service) nodeExpandRawBlockVolume(ctx context.Context, volumeWWN string) (*csi.NodeExpandVolumeResponse, error) {
	log.Info(" Block volume expansion. Will try to perform a rescan...")
	wwnNum := strings.Replace(volumeWWN, "naa.", "", 1)
	deviceNames, err := s.Fs.GetUtil().GetSysBlockDevicesForVolumeWWN(context.Background(), wwnNum)
	if err != nil {
		log.Errorf("Failed to get block devices with error (%s)", err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}
	if len(deviceNames) > 0 {
		var devName string
		for _, deviceName := range deviceNames {
			if strings.HasPrefix(deviceName, "nvme") {
				nvmeControllerDevice, err := s.Fs.GetUtil().GetNVMeController(deviceName)
				if err != nil {
					log.Errorf("Failed to rescan device (%s) with error (%s)", deviceName, err.Error())
					return nil, status.Error(codes.Internal, err.Error())
				}
				if nvmeControllerDevice != "" {
					devicePath := dev + nvmeControllerDevice
					log.Infof("Rescanning unmounted (raw block) device %s to expand size", devicePath)
					err = s.nvmeLib.DeviceRescan(devicePath)
					if err != nil {
						log.Errorf("Failed to rescan device (%s) with error (%s)", devicePath, err.Error())
						return nil, status.Error(codes.Internal, err.Error())
					}
				}
			} else {
				devicePath := sysBlock + deviceName
				log.Infof("Rescanning unmounted (raw block) device %s to expand size", deviceName)
				err = s.Fs.GetUtil().DeviceRescan(context.Background(), devicePath)
				if err != nil {
					log.Errorf("Failed to rescan device (%s) with error (%s)", devicePath, err.Error())
					return nil, status.Error(codes.Internal, err.Error())
				}
			}
			devName = deviceName
		}

		mpathDev, err := s.Fs.GetUtil().GetMpathNameFromDevice(ctx, devName)
		fmt.Println("mpathDev: " + mpathDev)
		if err != nil {
			log.Errorf("Failed to get mpath name for device (%s) with error (%s)", devName, err.Error())
			return nil, status.Error(codes.Internal, err.Error())
		}
		if mpathDev != "" {
			err = s.Fs.GetUtil().ResizeMultipath(context.Background(), mpathDev)
			if err != nil {
				log.Errorf("Failed to resize multipath of block device (%s) with error (%s)", mpathDev, err.Error())
				return nil, status.Error(codes.Internal, err.Error())
			}
		}

		log.Info("Block volume successfuly rescaned.")
		return &csi.NodeExpandVolumeResponse{}, nil
	}
	log.Error("No raw block devices found")
	return nil, status.Error(codes.NotFound, "No raw block devices found")
}

// NodeGetCapabilities returns supported features by the node service
func (s *Service) NodeGetCapabilities(_ context.Context, _ *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	newCap := func(capability csi.NodeServiceCapability_RPC_Type) *csi.NodeServiceCapability {
		return &csi.NodeServiceCapability{
			Type: &csi.NodeServiceCapability_Rpc{
				Rpc: &csi.NodeServiceCapability_RPC{
					Type: capability,
				},
			},
		}
	}
	var capabilities []*csi.NodeServiceCapability
	for _, capability := range []csi.NodeServiceCapability_RPC_Type{
		csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
		csi.NodeServiceCapability_RPC_EXPAND_VOLUME,
		csi.NodeServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
	} {
		capabilities = append(capabilities, newCap(capability))
	}

	if s.isHealthMonitorEnabled {
		for _, capability := range []csi.NodeServiceCapability_RPC_Type{
			csi.NodeServiceCapability_RPC_GET_VOLUME_STATS,
			csi.NodeServiceCapability_RPC_VOLUME_CONDITION,
		} {
			capabilities = append(capabilities, newCap(capability))
		}
	}

	return &csi.NodeGetCapabilitiesResponse{
		Capabilities: capabilities,
	}, nil
}

// NodeGetInfo returns id of the node and topology constraints
func (s *Service) NodeGetInfo(ctx context.Context, _ *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	// Create the topology keys
	// <driver name>/<endpoint>-<protocol>: true
	resp := &csi.NodeGetInfoResponse{
		NodeId: s.nodeID,
		AccessibleTopology: &csi.Topology{
			Segments: map[string]string{},
		},
	}

	for _, arr := range s.Arrays() {
		if isNFSEnabled, err := identifiers.IsNFSServiceEnabled(ctx, arr.GetClient()); err != nil {
			log.Errorf("failed to validate NFS service for the array: %s", err.Error())
		} else if isNFSEnabled {
			log.Info("NFS service is enabled on the array ", arr.GetGlobalID())
			// we will chop off port from the host if present.
			port, err := ExtractPort(arr.Endpoint)
			_, err = getOutboundIP(arr.GetIP(), port, s.Fs)
			if err == nil {
				resp.AccessibleTopology.Segments[identifiers.Name+"/"+arr.GetIP()+"-nfs"] = "true"
			} else {
				log.Errorf("Error: failed to get ip details: %s\n", err.Error())
			}
		}
		if arr.BlockProtocol != identifiers.NoneTransport {
			if s.useNVME[arr.GlobalID] {
				if s.useFC[arr.GlobalID] {
					nvmefcInfo, err := identifiers.GetNVMEFCTargetInfoFromStorage(arr.GetClient(), "")
					if err != nil {
						log.Errorf("couldn't get targets from the array: %s", err.Error())
						continue
					}

					log.Infof("Discovering NVMeFC targets")
					nvmefcConnectCount := 0
					for _, info := range nvmefcInfo {
						NVMeFCTargets, err := s.nvmeLib.DiscoverNVMeFCTargets(info.Portal, false)
						if err != nil {
							log.Errorf("couldn't discover NVMeFC targets")
							continue
						}
						for _, target := range NVMeFCTargets {
							err = s.nvmeLib.NVMeFCConnect(target, false)
							if err != nil {
								log.Errorf("couldn't connect to NVMeFC target")
							} else {
								nvmefcConnectCount = nvmefcConnectCount + 1
								otherTargets := s.nvmeTargets[arr.GlobalID]
								s.nvmeTargets[arr.GlobalID] = append(otherTargets, target.TargetNqn)
							}
						}
					}
					if nvmefcConnectCount != 0 {
						resp.AccessibleTopology.Segments[identifiers.Name+"/"+arr.GetIP()+"-nvmefc"] = "true"
					}
				} else {
					// useNVME/TCP
					infoList, err := identifiers.GetNVMETCPTargetsInfoFromStorage(arr.GetClient(), "")
					if err != nil {
						log.Errorf("couldn't get targets from array: %s", err.Error())
						continue
					}
					var nvmeTargets []gonvme.NVMeTarget
					for _, address := range infoList {
						// doesn't matter how many portals are present, discovering from any one will list out all targets
						nvmeIP := strings.Split(address.Portal, ":")
						log.Info("Trying to discover NVMe target from portal ", nvmeIP[0])
						nvmeTargets, err = s.nvmeLib.DiscoverNVMeTCPTargets(nvmeIP[0], false)
						if err != nil {
							log.Error("couldn't discover targets")
							continue
						}
						break
					}
					loginToAtleastOneTarget := false
					for _, target := range nvmeTargets {
						log.Info("Logging to NVMe target ", target)
						err = s.nvmeLib.NVMeTCPConnect(target, false)
						if err != nil {
							log.Errorf("couldn't connect to the nvme target")
							continue
						}
						otherTargets := s.nvmeTargets[arr.GlobalID]
						s.nvmeTargets[arr.GlobalID] = append(otherTargets, target.TargetNqn)
						loginToAtleastOneTarget = true
					}
					if loginToAtleastOneTarget {
						resp.AccessibleTopology.Segments[identifiers.Name+"/"+arr.GetIP()+"-nvmetcp"] = "true"
					} else {
						s.useNFS = true
					}
				}
			} else if s.useFC[arr.GlobalID] {
				// Check node initiators connection to array
				nodeID := s.nodeID
				if s.reusedHost {
					ipList := identifiers.GetIPListFromString(nodeID)
					if ipList == nil || len(ipList) == 0 {
						log.Errorf("can't find ip in nodeID %s", nodeID)
						continue
					}
					ip := ipList[len(ipList)-1]
					nodeID = nodeID[:len(nodeID)-len(ip)-1]
				}

				host, err := arr.GetClient().GetHostByName(ctx, nodeID)
				if err != nil {
					log.WithFields(log.Fields{
						"hostName": nodeID,
						"error":    err,
					}).Error("could not find host on PowerStore array")
					continue
				}

				if len(host.Initiators) == 0 {
					log.Error("host initiators array is empty")
					continue
				}

				if len(host.Initiators[0].ActiveSessions) != 0 {
					resp.AccessibleTopology.Segments[identifiers.Name+"/"+arr.GetIP()+"-fc"] = "true"
				} else {
					log.WithFields(log.Fields{
						"hostName":  host.Name,
						"initiator": host.Initiators[0].PortName,
					}).Error("there is no active FC sessions")
					continue
				}
			} else {
				infoList, err := identifiers.GetISCSITargetsInfoFromStorage(arr.GetClient(), "")
				if err != nil {
					log.Errorf("couldn't get targets from array: %s", err.Error())
					continue
				}
				var ipAddress string
				var iscsiTargets []goiscsi.ISCSITarget
				for _, address := range infoList {
					// first check if this portal is reachable from this machine or not
					if ReachableEndPoint(address.Portal) {
						ipAddressList := splitIPAddress(address.Portal)
						ipAddress = ipAddressList[0]
						// doesn't matter how many portals are present, discovering from any one will list out all targets
						log.Info("Trying to discover iSCSI target from portal ", ipAddress)

						ipInterface, err := s.iscsiLib.GetInterfaceForTargetIP(ipAddress)
						if err != nil {
							log.Errorf("couldn't get interface: %s", err.Error())
							continue
						}
						iscsiTargets, err = s.iscsiLib.DiscoverTargetsWithInterface(address.Portal, ipInterface[ipAddress], false)
						if err != nil {
							log.Error("couldn't discover targets")
							continue
						}
						break
					}
					log.Debugf("Portal is not rechable from the node")
				}
				// login is also performed as a part of ConnectVolume by using dynamically created chap credentials, In case if it fails here
				if len(iscsiTargets) > 0 {
					resp.AccessibleTopology.Segments[identifiers.Name+"/"+arr.GetIP()+"-iscsi"] = "true"
				}
				loginToAtleastOneTarget := false
				for _, target := range iscsiTargets {
					if ReachableEndPoint(target.Portal) {
						log.Info("Logging to Iscsi target ", target)
						if s.opts.EnableCHAP {
							log.Debug("Setting CHAP Credentials before login")
							err = s.iscsiLib.SetCHAPCredentials(target, s.opts.CHAPUsername, s.opts.CHAPPassword)
							if err != nil {
								log.Errorf("couldn't connect to the iscsi target")
							}
						}
						err = s.iscsiLib.PerformLogin(target)
						if err != nil {
							log.Errorf("couldn't connect to the iscsi target")
							continue
						}
						otherTargets := s.iscsiTargets[arr.GlobalID]
						s.iscsiTargets[arr.GlobalID] = append(otherTargets, target.Target)
						loginToAtleastOneTarget = true
					} else {
						log.Debugf("Target's Portal %s is not rechable from the node ", target.Portal)
					}
				}

				if !loginToAtleastOneTarget {
					s.useNFS = true
				}
			}
		}
	}

	var maxVolumesPerNode int64

	// Setting maxVolumesPerNode using the value of field maxPowerstoreVolumesPerNode specified in values.yaml
	if s.opts.MaxVolumesPerNode > 0 {
		maxVolumesPerNode = s.opts.MaxVolumesPerNode
	}

	// Check for node label 'max-powerstore-volumes-per-node'. If present set 'maxVolumesPerNode' to this value.
	labels, err := k8sutils.GetNodeLabels(ctx, s.opts.KubeConfigPath, s.opts.KubeNodeName)
	if err != nil {
		log.Warnf("failed to get Node Labels with error: %s", err.Error())
	} else if labels != nil {
		if val, ok := labels[maxPowerstoreVolumesPerNodeLabel]; ok {
			maxVols, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				log.Warnf("invalid value '%s' specified for 'max-powerstore-volumes-per-node' node label", val)
			} else if maxVols > 0 {
				maxVolumesPerNode = maxVols
				log.Infof("node label 'max-powerstore-volumes-per-node' is available and is set to value '%d'", maxVolumesPerNode)
			}

		}
	}

	if maxVolumesPerNode >= 0 {
		resp.MaxVolumesPerNode = maxVolumesPerNode
		log.Infof("Setting MaxVolumesPerNode to '%d'", maxVolumesPerNode)
	}

	return resp, nil
}

func (s *Service) updateNodeID() error {
	if s.nodeID == "" {
		hostID, err := s.Fs.ReadFile(s.opts.NodeIDFilePath)
		if err != nil {
			log.WithFields(log.Fields{
				"path":  s.opts.NodeIDFilePath,
				"error": err,
			}).Error("Could not read Node ID file")
			return status.Errorf(codes.FailedPrecondition, "Could not readNode ID file: %s", err.Error())
		}

		// Check connection to array and get ip
		defaultArray := s.DefaultArray()
		if defaultArray == nil {
			return status.Errorf(codes.FailedPrecondition, "Could not fetch default PowerStore array")
		}
		// we will chop off port from the host if present.
		port, err := ExtractPort(defaultArray.Endpoint)
		ip, err := getOutboundIP(defaultArray.GetIP(), port, s.Fs)
		log.Debug("Outbound IP address: ", ip.String())

		// When Authorization v2 is enabled the host IP address will be localhost. We should get the actual IP else volume will not mount
		if ip.String() == "127.0.0.1" || ip.String() == "localhost" {
			log.Debug("Detected localhost IP address, trying to get node IP address")
			ip, err = helpers.GetNodeIP()
			if err != nil {
				return status.Errorf(codes.FailedPrecondition, "Could not get node IP address: %s", err.Error())
			}
		}

		log.Debug("Outbound IP address after check: ", ip.String())
		if err != nil {
			log.WithFields(log.Fields{
				"endpoint": s.DefaultArray().GetIP(),
				"error":    err,
			}).Error("Could not connect to PowerStore array")
			return status.Errorf(codes.FailedPrecondition, "Could not connect to PowerStore array: %s", err.Error())
		}

		nodeID := fmt.Sprintf(
			"%s-%s-%s", s.opts.NodeNamePrefix, strings.TrimSpace(string(hostID)), ip.String(),
		)

		if len(nodeID) > powerStoreMaxNodeNameLength {
			err := errors.New("node name prefix is too long")
			log.WithFields(log.Fields{
				"value": s.opts.NodeNamePrefix,
				"error": err,
			}).Error("Invalid Node ID")
			return err
		}
		s.nodeID = nodeID
	}
	return nil
}

func (s *Service) getInitiators() ([]string, []string, []string, error) {
	ctx := context.Background()

	var iscsiAvailable bool
	var fcAvailable bool
	var nvmeAvailable bool

	iscsiInitiators, err := s.iscsiConnector.GetInitiatorName(ctx)
	if err != nil {
		log.Error("nodeStartup could not GetInitiatorIQNs")
	} else if len(iscsiInitiators) == 0 {
		log.Error("iscsi initiators not found on node")
	} else {
		log.Debug("iscsi initiators found on node")
		iscsiAvailable = true
	}

	fcInitiators, err := s.getNodeFCPorts(ctx)
	if err != nil {
		log.Error("nodeStartup could not FC initiators for node")
	} else if len(fcInitiators) == 0 {
		log.Error("FC was not found or filtered with FCPortsFilterFile")
	} else {
		log.Debug("FC initiators found on node")
		fcAvailable = true
	}

	nvmeInitiators, err := s.nvmeConnector.GetInitiatorName(ctx)
	if err != nil {
		log.Error("nodeStartup could not get Initiator NQNs")
	} else if len(nvmeInitiators) == 0 {
		log.Error("NVMe initiators not found on node")
	} else {
		log.Debug("NVMe initiators found on node")
		nvmeAvailable = true
	}

	if !iscsiAvailable && !fcAvailable && !nvmeAvailable {
		// If we haven't found any initiators we still can use NFS
		log.Info("FC, iSCSI and NVMe initiators not found on node")
	}

	return iscsiInitiators, fcInitiators, nvmeInitiators, nil
}

func (s *Service) getNodeFCPorts(ctx context.Context) ([]string, error) {
	var err error
	var initiators []string

	defer func() {
		initiators := initiators
		log.Infof("FC initiators found: %s", initiators)
	}()

	rawInitiatorsData, err := s.fcConnector.GetInitiatorPorts(ctx)
	if err != nil {
		log.Error("failed FC initiators list from node")
		return nil, err
	}

	for _, initiator := range rawInitiatorsData {
		data, err := formatWWPN(strings.TrimPrefix(initiator, "0x"))
		if err != nil {
			return nil, err
		}
		initiators = append(initiators, data)
	}
	if len(initiators) == 0 {
		return initiators, nil
	}
	portsFilter, _ := s.readFCPortsFilterFile()
	if len(portsFilter) == 0 {
		return initiators, nil
	}
	var filteredInitiators []string
	for _, filterValue := range portsFilter {
		for _, initiator := range initiators {
			if initiator != filterValue {
				continue
			}
			log.Infof("FC initiator port %s match filter", initiator)
			filteredInitiators = append(filteredInitiators, initiator)
		}
	}
	initiators = filteredInitiators

	return initiators, nil
}

func (s *Service) readFCPortsFilterFile() ([]string, error) {
	if s.opts.FCPortsFilterFilePath == "" {
		return nil, nil
	}
	data, err := s.Fs.ReadFile(s.opts.FCPortsFilterFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var result []string
	wwpns := strings.Split(strings.TrimSpace(string(data)), ",")
	for _, p := range wwpns {
		if !strings.Contains(p, ":") {
			log.Error("invalid FCPortsFilterFile format")
			return nil, nil
		}
		result = append(result, p)
	}
	return result, nil
}

func (s *Service) setupHost(initiators []string, client gopowerstore.Client, arrayIP, arrayID string) error {
	log.Infof("setting up host on %s", arrayIP)
	defer log.Infof("finished setting up host on %s", arrayIP)

	if s.nodeID == "" {
		return fmt.Errorf("nodeID not set")
	}

	if s.useNVME[arrayID] {
		s.checkForDuplicateUUIDs()
	}

	reqInitiators := s.buildInitiatorsArray(initiators, arrayID)
	var existingHost *gopowerstore.Host

	hosts, err := client.GetHosts(context.Background())
	if err != nil {
		return fmt.Errorf("failed getting hosts on %s", arrayIP)
	}

	for i := range hosts {
		for _, hI := range hosts[i].Initiators {
			for _, rI := range reqInitiators {
				if hI.PortName == *rI.PortName && hI.PortType == *rI.PortType {
					existingHost = &hosts[i]
					break
				}
			}
			if existingHost != nil {
				break
			}
		}
		if existingHost != nil {
			break
		}
	}

	if existingHost == nil {
		log.Infof("Creating host %s on array %s", s.nodeID, arrayID)
		_, err := s.createHost(context.Background(), initiators)
		if err != nil {
			return err
		}
	} else {
		log.Infof("Host with initiator already exists. Updating metadata or CHAP if needed.")
		if s.opts.EnableCHAP {
			err := s.modifyHostInitiators(context.Background(), existingHost.ID, client, nil, nil, initiators, arrayID, &existingHost.HostConnectivity)
			if err != nil {
				return fmt.Errorf("failed to update CHAP: %v", err)
			}
		}

		if s.nodeID != existingHost.ID {
			err := s.modifyHostName(context.Background(), client, s.nodeID, existingHost.ID)
			if err != nil {
				return fmt.Errorf("failed to update host name: %v", err)
			}
		}
		s.reusedHost = true
	}

	s.initialized = true
	return nil
}

func (s *Service) modifyHostName(ctx context.Context, client gopowerstore.Client, nodeID string, hostID string) error {
	modifyParams := gopowerstore.HostModify{}
	modifyParams.Name = &nodeID
	_, err := client.ModifyHost(ctx, &modifyParams, hostID)
	if err != nil {
		return err
	}
	log.Info("Updated nodeID ", nodeID)
	return nil
}

func (s *Service) buildInitiatorsArray(initiators []string, arrayID string) []gopowerstore.InitiatorCreateModify {
	var portType gopowerstore.InitiatorProtocolTypeEnum
	if s.useNVME[arrayID] {
		portType = gopowerstore.InitiatorProtocolTypeEnumNVME
	} else if s.useFC[arrayID] {
		portType = gopowerstore.InitiatorProtocolTypeEnumFC
	} else {
		portType = gopowerstore.InitiatorProtocolTypeEnumISCSI
	}
	initiatorsReq := make([]gopowerstore.InitiatorCreateModify, len(initiators))
	for i, iqn := range initiators {
		iqn := iqn
		if !s.useFC[arrayID] && s.opts.EnableCHAP {
			initiatorsReq[i] = gopowerstore.InitiatorCreateModify{
				ChapSinglePassword: &s.opts.CHAPPassword,
				ChapSingleUsername: &s.opts.CHAPUsername,
				PortName:           &iqn,
				PortType:           &portType,
			}
		} else {
			initiatorsReq[i] = gopowerstore.InitiatorCreateModify{
				PortName: &iqn,
				PortType: &portType,
			}
		}
	}
	return initiatorsReq
}

// create or update host on PowerStore array
func (s *Service) updateHost(ctx context.Context, initiators []string, client gopowerstore.Client, host gopowerstore.Host, arrayID string, connectivity *gopowerstore.HostConnectivityEnum) error {
	initiatorsToAdd, initiatorsToDelete := checkIQNS(initiators, host)
	return s.modifyHostInitiators(ctx, host.ID, client, initiatorsToAdd, initiatorsToDelete, nil, arrayID, connectivity)
}

var (
	getArrayfn = func(s *Service) map[string]*array.PowerStoreArray {
		return s.Arrays()
	}

	getIsHostAlreadyRegistered = func(s *Service, ctx context.Context, client gopowerstore.Client, initiators []string) bool {
		return s.isHostAlreadyRegistered(ctx, client, initiators)
	}

	getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, ctx context.Context) ([]gopowerstore.RemoteSystem, error) {
		return arr.GetClient().GetAllRemoteSystems(ctx)
	}

	getIsRemoteToOtherArray = func(s *Service, ctx context.Context, arr, remoteArr *array.PowerStoreArray) bool {
		return s.isRemoteToOtherArray(ctx, arr, remoteArr)
	}

	registerHostFunc = func(s *Service, ctx context.Context, client gopowerstore.Client, arrayID string, initiators []string, connType gopowerstore.HostConnectivityEnum) error {
		return s.registerHost(ctx, client, arrayID, initiators, connType)
	}
)

// register host
func (s *Service) createHost(
	ctx context.Context,
	initiators []string,
) (string, error) {
	nodeLabels, err := k8sutils.GetNodeLabels(context.Background(), s.opts.KubeConfigPath, s.opts.KubeNodeName)
	if err != nil {
		return "", fmt.Errorf("failed to get node labels for node %s: %v", s.opts.KubeNodeName, err)
	}
	var primaryArrayID string

	// Step 1: Check if this node matches at least one labeled Metro array
	anyLabelMatch := false
	for _, arr := range getArrayfn(s) {
		if strings.ToLower(arr.MetroTopology) == "uniform" && len(arr.Labels) == 1 {
			if labelsMatch(arr.Labels, nodeLabels) {
				anyLabelMatch = true
				break
			}
		}
	}

	for _, arr := range getArrayfn(s) {
		log.Infof("[createHost] Processing array %s (%s)", arr.GlobalID, arr.IP)
		// 1) Skip if already registered
		if getIsHostAlreadyRegistered(s, ctx, arr.GetClient(), initiators) {
			log.Infof("[createHost] Already registered on %s, skipping", arr.GlobalID)
			if primaryArrayID == "" {
				primaryArrayID = arr.GlobalID
			}
			continue
		}

		// 2) Metro vs Non‑Metro
		if strings.ToLower(arr.MetroTopology) != "uniform" {
			log.Infof("[createHost] Non‑Metro array %s → registering LocalOnly", arr.GlobalID)
			if err := s.registerHost(
				ctx, arr.GetClient(), arr.GlobalID, initiators,
				gopowerstore.HostConnectivityEnumLocalOnly,
			); err != nil {
				return "", fmt.Errorf("failed LocalOnly on %s: %v", arr.GlobalID, err)
			}
			if primaryArrayID == "" {
				primaryArrayID = arr.GlobalID
			}
			continue
		}

		if len(arr.Labels) > 1 {
			log.Warnf("[createHost] Skipping Metro array %s: more than one label", arr.GlobalID)
			continue
		}

		// 4) Skip Metro arrays if this node doesn’t match any Metro array label
		if !anyLabelMatch {
			log.Warnf("[createHost] Node does not match any Metro array labels — skipping Metro registration for %s", arr.GlobalID)
			continue
		}

		// 5) Metro: now dispatch to label-match vs no-label-match
		arrayAddedList := make(map[string]bool)

		if labelsMatch(arr.Labels, nodeLabels) {
			// 4a) Labels match
			log.Infof("[createHost] Metro & label match on %s", arr.GlobalID)
			coLocated, err := s.handleLabelMatchRegistration(ctx, arr, initiators, nodeLabels, arrayAddedList)
			if err != nil {
				return "", err
			}
			conn := gopowerstore.HostConnectivityEnumMetroOptimizeLocal
			if coLocated {
				conn = gopowerstore.HostConnectivityEnumMetroOptimizeBoth
			}
			log.Infof("[createHost] Registering %s as %s", arr.GlobalID, conn)
			if err := registerHostFunc(s, ctx, arr.GetClient(), arr.GlobalID, initiators, conn); err != nil {
				return "", fmt.Errorf("failed on %s: %v", arr.GlobalID, err)
			}
			if primaryArrayID == "" {
				primaryArrayID = arr.GlobalID
			}
		} else {
			// 4b) Labels don’t match
			log.Infof("[createHost] Metro & no label match on %s", arr.GlobalID)
			coLocated, err := s.handleNoLabelMatchRegistration(
				ctx, arr, initiators, nodeLabels, arrayAddedList,
			)
			if err != nil {
				return "", err
			}
			conn := gopowerstore.HostConnectivityEnumMetroOptimizeRemote
			if coLocated {
				conn = gopowerstore.HostConnectivityEnumMetroOptimizeBoth
			}

			log.Infof("[createHost] Registering %s as %s", arr.GlobalID, conn)
			if err := s.registerHost(
				ctx, arr.GetClient(), arr.GlobalID, initiators, conn,
			); err != nil {
				return "", fmt.Errorf("failed on %s: %v", arr.GlobalID, err)
			}
			if primaryArrayID == "" {
				primaryArrayID = arr.GlobalID
			}
		}
	}

	if primaryArrayID != "" {
		log.Infof("[createHost] Success. Primary array: %s", primaryArrayID)
		return primaryArrayID, nil
	}
	return "", fmt.Errorf("[createHost] Failed to register host on any array")
}

func (s *Service) handleLabelMatchRegistration(
	ctx context.Context,
	arr *array.PowerStoreArray,
	initiators []string,
	nodeLabels map[string]string,
	arrayAddedList map[string]bool,
) (bool, error) {
	// Early exit if no array labels match the node labels
	anyLabelMatch := false
	for _, configuredArr := range getArrayfn(s) {
		if labelsMatch(configuredArr.Labels, nodeLabels) {
			anyLabelMatch = true
			break
		}
	}
	if !anyLabelMatch {
		log.Infof("[handleLabelMatch] No arrays match node labels — skipping registration")
		return false, nil
	}

	remoteSystems, err := getAllRemoteSystemsFunc(arr, ctx)
	if err != nil {
		log.Warnf("[handleLabelMatch] failed to get remotes for %s: %v", arr.GlobalID, err)
		return false, err
	}

	coLocated := false

	// 1) Determine this array's connectivity based on its label vs. the node's labels
	var arrayConn gopowerstore.HostConnectivityEnum
	if labelsMatch(arr.Labels, nodeLabels) {
		arrayConn = gopowerstore.HostConnectivityEnumMetroOptimizeLocal
	} else {
		arrayConn = gopowerstore.HostConnectivityEnumMetroOptimizeRemote
	}

	for _, remote := range remoteSystems {
		if remote.Name == "" || arrayAddedList[remote.SerialNumber] {
			continue
		}

		for _, remoteArr := range getArrayfn(s) {
			if remoteArr.GlobalID != remote.SerialNumber {
				continue
			}
			if len(remoteArr.Labels) > 1 {
				return false, fmt.Errorf("skipping remote array %s – more than one label", remoteArr.GlobalID)
			}

			// 2) Mutual-remote check
			if !getIsRemoteToOtherArray(s, ctx, arr, remoteArr) {
				log.Infof("[handleLabelMatch] skipping %s↔%s: not mutually remote",
					arr.GlobalID, remoteArr.GlobalID)
				continue
			}

			clientB := remoteArr.GetClient()
			if getIsHostAlreadyRegistered(s, ctx, clientB, initiators) {
				arrayAddedList[remoteArr.GlobalID] = true
				continue
			}

			if !labelsMatch(remoteArr.Labels, arr.Labels) && labelsMatch(remoteArr.Labels, nodeLabels) && labelsMatch(arr.Labels, nodeLabels) {
				log.Info("skipping registration as the node is having all the array labels")
				return false, fmt.Errorf("skipping registration as the node matching all the array labels node label: %s, arr label: %s, remote label: %s", nodeLabels, arr.Labels, remoteArr.Labels)
			}

			// 3) Determine remote's connectivity
			var remoteConn gopowerstore.HostConnectivityEnum
			if labelsMatch(remoteArr.Labels, arr.Labels) {
				remoteConn = gopowerstore.HostConnectivityEnumMetroOptimizeBoth
			} else if labelsMatch(remoteArr.Labels, nodeLabels) {
				remoteConn = gopowerstore.HostConnectivityEnumMetroOptimizeLocal
			} else {
				remoteConn = gopowerstore.HostConnectivityEnumMetroOptimizeRemote
			}

			// 4) Guard: skip if both would end up with the same non‑Both connectivity
			if arrayConn == remoteConn && remoteConn != gopowerstore.HostConnectivityEnumMetroOptimizeBoth {
				log.Infof("[handleLabelMatch] skipping %s: both arrays would be %s",
					arr.GlobalID, arrayConn)
				continue
			}

			// 5) Register
			if remoteConn == gopowerstore.HostConnectivityEnumMetroOptimizeBoth {
				log.Infof("[handleLabelMatch] Full match → MetroOptimizeBoth on %s", remoteArr.GlobalID)
			} else {
				log.Infof("[handleLabelMatch] Partial match → MetroOptimizeRemote on %s", remoteArr.GlobalID)
			}
			if err := registerHostFunc(s, ctx, clientB, remoteArr.GlobalID, initiators, remoteConn); err != nil {
				return false, err
			}
			arrayAddedList[remoteArr.GlobalID] = true

			if remoteConn == gopowerstore.HostConnectivityEnumMetroOptimizeBoth {
				coLocated = true
			}
		}
	}
	return coLocated, nil
}

func (s *Service) handleNoLabelMatchRegistration(
	ctx context.Context,
	arr *array.PowerStoreArray,
	initiators []string,
	nodeLabels map[string]string,
	arrayAddedList map[string]bool,
) (bool, error) {
	// Early exit if no array labels match the node labels
	anyLabelMatch := false
	for _, configuredArr := range getArrayfn(s) {
		if labelsMatch(configuredArr.Labels, nodeLabels) {
			anyLabelMatch = true
			break
		}
	}
	if !anyLabelMatch {
		log.Infof("[handleNoLabelMatch] No arrays match node labels — skipping registration for %s", arr.GlobalID)
		return false, nil
	}

	remoteSystems, err := getAllRemoteSystemsFunc(arr, ctx)
	if err != nil {
		log.Warnf("[handleNoLabelMatch] failed to get remotes for %s: %v", arr.GlobalID, err)
		return false, err
	}

	coLocated := false
	// 1) Determine this array's connectivity based on its label vs. the node's labels
	var arrayConn gopowerstore.HostConnectivityEnum
	if labelsMatch(arr.Labels, nodeLabels) {
		arrayConn = gopowerstore.HostConnectivityEnumMetroOptimizeLocal
	} else {
		arrayConn = gopowerstore.HostConnectivityEnumMetroOptimizeRemote
	}

	for _, remote := range remoteSystems {
		if remote.Name == "" || arrayAddedList[remote.SerialNumber] {
			continue
		}

		for _, remoteArr := range getArrayfn(s) {
			if remoteArr.GlobalID != remote.SerialNumber {
				continue
			}
			// Mutual remote check
			if !getIsRemoteToOtherArray(s, ctx, arr, remoteArr) {
				log.Infof("[handleNoLabelMatch] skipping %s↔%s: not mutually remote",
					arr.GlobalID, remoteArr.GlobalID)
				continue
			}

			clientB := remoteArr.GetClient()
			if getIsHostAlreadyRegistered(s, ctx, clientB, initiators) {
				arrayAddedList[remoteArr.GlobalID] = true
				continue
			}

			if !labelsMatch(remoteArr.Labels, arr.Labels) && labelsMatch(remoteArr.Labels, nodeLabels) && labelsMatch(arr.Labels, nodeLabels) {
				log.Info("skipping registration as the node is having all the array labels")
				return false, fmt.Errorf("skipping registration as the node matching all the array labels node label: %s, arr label: %s, remote label: %s", nodeLabels, arr.Labels, remoteArr.Labels)
			}

			// Determine remote's connectivity
			var remoteConn gopowerstore.HostConnectivityEnum
			if labelsMatch(remoteArr.Labels, arr.Labels) {
				remoteConn = gopowerstore.HostConnectivityEnumMetroOptimizeBoth
			} else if labelsMatch(remoteArr.Labels, nodeLabels) {
				remoteConn = gopowerstore.HostConnectivityEnumMetroOptimizeLocal
			} else {
				remoteConn = gopowerstore.HostConnectivityEnumMetroOptimizeRemote
			}

			// Guard: skip if both would end up with the same non-Both connectivity
			if arrayConn == remoteConn && remoteConn != gopowerstore.HostConnectivityEnumMetroOptimizeBoth {
				log.Infof("[handleNoLabelMatch] skipping %s: both arrays would be %s",
					arr.GlobalID, arrayConn)
				continue
			}

			// Register
			if remoteConn == gopowerstore.HostConnectivityEnumMetroOptimizeBoth {
				log.Infof("[handleNoLabelMatch] Full match → MetroOptimizeBoth on %s", remoteArr.GlobalID)
			} else {
				log.Infof("[handleNoLabelMatch] Partial match → MetroOptimizeRemote on %s", remoteArr.GlobalID)
			}
			if err := registerHostFunc(s, ctx, clientB, remoteArr.GlobalID, initiators, remoteConn); err != nil {
				return false, err
			}
			arrayAddedList[remoteArr.GlobalID] = true

			if remoteConn == gopowerstore.HostConnectivityEnumMetroOptimizeBoth {
				coLocated = true
			}
		}
	}
	return coLocated, nil
}

// isRemoteToOtherArray returns true if arrA and arrB are mutually remote to each other.
func (s *Service) isRemoteToOtherArray(
	ctx context.Context,
	arrA, arrB *array.PowerStoreArray,
) bool {
	// fetch arrA’s remotes
	remotesA, err := getAllRemoteSystemsFunc(arrA, ctx)
	if err != nil {
		log.Warnf("[isRemoteToOtherArray] failed to get remotes for %s: %v", arrA.GlobalID, err)
		return false
	}
	// fetch arrB’s remotes
	remotesB, err := getAllRemoteSystemsFunc(arrB, ctx)
	if err != nil {
		log.Warnf("[isRemoteToOtherArray] failed to get remotes for %s: %v", arrB.GlobalID, err)
		return false
	}

	foundAtoB := false
	for _, r := range remotesA {
		if r.SerialNumber == arrB.GlobalID {
			foundAtoB = true
			break
		}
	}
	if !foundAtoB {
		return false
	}

	for _, r := range remotesB {
		if r.SerialNumber == arrA.GlobalID {
			return true
		}
	}
	return false
}

// Checks if host with given initiators already exists
func (s *Service) isHostAlreadyRegistered(ctx context.Context, client gopowerstore.Client, initiators []string) bool {
	existingHosts, err := client.GetHosts(ctx)
	if err != nil {
		log.Warnf("[isHostAlreadyRegistered] Failed to get hosts: %v", err)
		return false
	}

	for _, host := range existingHosts {
		for _, hInit := range host.Initiators {
			for _, i := range initiators {
				if hInit.PortName == i {
					log.Infof("[isHostAlreadyRegistered] Found existing host with initiator %s", i)
					return true
				}
			}
		}
	}
	return false
}

func (s *Service) registerHost(
	ctx context.Context,
	client gopowerstore.Client,
	arrayID string,
	initiators []string,
	connType gopowerstore.HostConnectivityEnum,
) error {
	description := fmt.Sprintf("k8s node: %s", s.opts.KubeNodeName)
	reqInitiators := s.buildInitiatorsArray(initiators, arrayID)
	osType := gopowerstore.OSTypeEnumLinux

	createParams := gopowerstore.HostCreate{
		Name:             &s.nodeID,
		OsType:           &osType,
		Initiators:       &reqInitiators,
		Description:      &description,
		HostConnectivity: connType,
	}

	if s.opts.KubeNodeName != "" && identifiers.IsK8sMetadataSupported(client) {
		metadata := map[string]string{"k8s_node_name": s.opts.KubeNodeName}
		createParams.Metadata = &metadata

		headers := client.GetCustomHTTPHeaders()
		if headers == nil {
			headers = api.NewSafeHeader().GetHeader()
		}
		headers.Add("DELL-VISIBILITY", "internal")
		client.SetCustomHTTPHeaders(headers)
	}

	log.Infof("[registerHost] Creating host on array %s with connectivity: %s", arrayID, connType)
	resp, err := client.CreateHost(ctx, &createParams)
	client.SetCustomHTTPHeaders(nil)

	if err != nil {
		if connType == gopowerstore.HostConnectivityEnumMetroOptimizeRemote &&
			strings.Contains(err.Error(), "already registered with another host") {
			log.Warnf("[registerHost] Skipping array %s due to duplicate initiator error (remote host): %v", arrayID, err)
			return nil
		}
		log.Errorf("[registerHost] Failed to create host on array %s: %v", arrayID, err)
		return err
	}
	log.Infof("[registerHost] Host successfully registered on array %s with ID: %s", arrayID, resp.ID)
	return nil
}

func labelsMatch(arrayLabels, nodeLabels map[string]string) bool {
	for key, val := range arrayLabels {
		if nodeVal, exists := nodeLabels[key]; !exists || nodeVal != val {
			return false
		}
	}
	return true
}

// add or remove initiators from host
func (s *Service) modifyHostInitiators(ctx context.Context, hostID string, client gopowerstore.Client,
	initiatorsToAdd []string, initiatorsToDelete []string, initiatorsToModify []string, arrayID string, connectivity *gopowerstore.HostConnectivityEnum,
) error {
	if len(initiatorsToDelete) > 0 {
		modifyParams := gopowerstore.HostModify{RemoveInitiators: &initiatorsToDelete}
		_, err := client.ModifyHost(ctx, &modifyParams, hostID)
		if err != nil {
			return fmt.Errorf("failed to remove initiators: %w", err)
		}
	}

	if len(initiatorsToAdd) > 0 {
		modifyParams := gopowerstore.HostModify{}
		initiators := s.buildInitiatorsArray(initiatorsToAdd, arrayID)
		modifyParams.AddInitiators = &initiators

		_, err := client.ModifyHost(ctx, &modifyParams, hostID)
		if err != nil {
			if strings.Contains(err.Error(), "already registered with another host") {
				log.Warnf("Skipping duplicate initiator registration: %v", err)
			} else {
				return fmt.Errorf("failed to add initiators: %w", err)
			}
		}
	}

	if len(initiatorsToModify) > 0 {
		modifyParams := gopowerstore.HostModify{}
		initiators := s.buildInitiatorsArrayModify(initiatorsToModify, arrayID)
		modifyParams.ModifyInitiators = &initiators

		_, err := client.ModifyHost(ctx, &modifyParams, hostID)
		if err != nil {
			return fmt.Errorf("failed to modify initiators: %w", err)
		}
	}

	// Ensure HostConnectivity is updated only if needed
	if connectivity != nil {
		modifyParams := gopowerstore.HostModify{HostConnectivity: *connectivity}
		_, err := client.ModifyHost(ctx, &modifyParams, hostID)
		if err != nil {
			return fmt.Errorf("failed to update host connectivity for %s: %w", hostID, err)
		}
	}

	return nil
}

func checkIQNS(IQNs []string, host gopowerstore.Host) (iqnToAdd, iqnToDelete []string) {
	// create map with initiators which are already exist
	initiatorMap := make(map[string]bool)
	for _, initiator := range host.Initiators {
		initiatorMap[initiator.PortName] = false
	}

	for _, iqn := range IQNs {
		_, ok := initiatorMap[iqn]
		if ok {
			// the iqn should be left in the host
			initiatorMap[iqn] = true
		} else {
			// the iqn should be added to the host
			iqnToAdd = append(iqnToAdd, iqn)
		}
	}

	// find iqns to delete from host
	for iqn, found := range initiatorMap {
		if !found {
			iqnToDelete = append(iqnToDelete, iqn)
		}
	}
	return
}

func (s *Service) buildInitiatorsArrayModify(initiators []string, arrayID string) []gopowerstore.UpdateInitiatorInHost {
	initiatorsReq := make([]gopowerstore.UpdateInitiatorInHost, len(initiators))
	for i, iqn := range initiators {
		iqn := iqn
		if !s.useFC[arrayID] && s.opts.EnableCHAP {
			initiatorsReq[i] = gopowerstore.UpdateInitiatorInHost{
				ChapSinglePassword: &s.opts.CHAPPassword,
				ChapSingleUsername: &s.opts.CHAPUsername,
				PortName:           &iqn,
			}
		} else {
			initiatorsReq[i] = gopowerstore.UpdateInitiatorInHost{
				PortName: &iqn,
			}
		}
	}
	return initiatorsReq
}

func (s *Service) fileExists(filename string) bool {
	_, err := s.Fs.Stat(filename)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		log.WithFields(log.Fields{
			"filename": filename,
			"error":    err,
		}).Error("File doesn't exist")
	} else {
		log.WithFields(log.Fields{
			"filename": filename,
			"error":    err,
		}).Error("Error while checking stat of file")
	}
	return false
}

// splitIPAddress function takes a string in the format "hostname:port"
// and returns a slice containing the hostname and port.
func splitIPAddress(address string) []string {
	return strings.Split(address, ":")
}

// ExtractPort extracts the port from a URL.
func ExtractPort(urlString string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	port := u.Port()
	if port == "" {
		return "", errors.New("port not specified in URL")
	}

	return port, nil
}
