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
	"github.com/dell/gofsutil"
	"github.com/dell/gopowerstore"
	"github.com/rexray/gocsi"
	"io"
	"net"
	"os"
)

// Service is the CSI service provider.
type Service interface {
	csi.ControllerServer
	csi.IdentityServer
	csi.NodeServer
	BeforeServe(context.Context, *gocsi.StoragePlugin, net.Listener) error
	ShutDown(ctx context.Context) error
}

type internalServiceAPI interface {
	nodeProbe(ctx context.Context) (bool, error)
	initPowerStoreClient() error
	initApiThrottle() error
	initCustomInterceptors(sp *gocsi.StoragePlugin, opts Opts)
	runDebugHTTPServer(ctx context.Context, gs gracefulStopper)
	updateNodeID() error
	nodeStartup(ctx context.Context, gs gracefulStopper) error
	nodeHostSetup(initiators []string, useFC bool, maximumStartupDelay int) error
	createOrUpdateHost(ctx context.Context, useFC bool, initiators []string) error
	createHost(ctx context.Context, useFC bool, initiators []string) (string, error)
	modifyHostInitiators(ctx context.Context, hostID string, useFC bool,
		initiatorsToAdd []string, initiatorsToDelete []string, initiatorsToModify []string) error
	buildInitiatorsArray(useFC bool, initiators []string) []gopowerstore.InitiatorCreateModify
	detachVolumeFromAllHosts(ctx context.Context, volumeID string) error
	detachVolumeFromHost(ctx context.Context, hostID string, volumeID string) error
	initNodeFSLib()
	initNodeMountLib()
	initISCSILib()
	initISCSIConnector()
	initFCConnector()
	initNodeVolToDevMapper()
	readSCSIPublishContext(req publishContextGetter) (scsiPublishContextData, error)
	readISCSITargetsFromPublishContext(pc map[string]string) []ISCSITargetInfo
	readFCTargetsFromPublishContext(pc map[string]string) []FCTargetInfo
	getNodeFCPorts(ctx context.Context) ([]string, error)
	readFCPortsFilterFile(ctx context.Context) ([]string, error)
	connectDevice(ctx context.Context, data scsiPublishContextData) (string, error)
	connectISCSIDevice(ctx context.Context, lun int, data scsiPublishContextData) (gobrick.Device, error)
	connectFCDevice(ctx context.Context, lun int, data scsiPublishContextData) (gobrick.Device, error)
}

// wrapperFsLib represent required interface for wrapperFsLib
type wrapperFsLib interface {
	// original gofsutil methods
	GetDiskFormat(ctx context.Context, disk string) (string, error)
	Format(ctx context.Context, source, target, fsType string, options ...string) error
	Mount(ctx context.Context, source, target, fsType string, options ...string) error
	BindMount(ctx context.Context, source, target string, options ...string) error
	Unmount(ctx context.Context, target string) error
	WWNToDevicePath(ctx context.Context, wwn string) (string, string, error)
	RemoveBlockDevice(ctx context.Context, blockDevicePath string) error
	// wrapper methods
	ParseProcMounts(ctx context.Context, content io.Reader) ([]gofsutil.Info, error)
}

type iSCSIConnector interface {
	ConnectVolume(ctx context.Context, info gobrick.ISCSIVolumeInfo) (gobrick.Device, error)
	DisconnectVolumeByDeviceName(ctx context.Context, name string) error
	GetInitiatorName(ctx context.Context) ([]string, error)
}

type fcConnector interface {
	ConnectVolume(ctx context.Context, info gobrick.FCVolumeInfo) (gobrick.Device, error)
	DisconnectVolumeByDeviceName(ctx context.Context, name string) error
	GetInitiatorPorts(ctx context.Context) ([]string, error)
}

// mountLib provide interface for volume mounting
type mountLib interface {
	StageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest, device string) error
	StageVolumeNFS(ctx context.Context, req *csi.NodeStageVolumeRequest, path string) error
	UnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (string, error)
	PublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) error
	PublishVolumeNFS(ctx context.Context, req *csi.NodePublishVolumeRequest) error
	UnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) error
	GetMountsByDev(ctx context.Context, device string) ([]gofsutil.Info, error)
	GetStagingPath(ctx context.Context, req commonReqGetters) string
	IsReadyToPublish(ctx context.Context, stagingPath string) (bool, bool, error)
	IsReadyToPublishNFS(ctx context.Context, stagingPath string) (bool, error)
}

// mountLib internal interfaces
type mountLibStageCheck interface {
	getStagedDev(ctx context.Context, stagePath string) (string, error)
}

type mountLibPublishCheck interface {
	isAlreadyPublished(ctx context.Context, targetPath, rwMode string) (bool, error)
	isReadyToPublish(ctx context.Context, device string) (bool, bool, error)
	isReadyToPublishNFS(ctx context.Context, device string) (bool, error)
}

type mountLibMountsReader interface {
	getMountsByDev(ctx context.Context, device string) ([]gofsutil.Info, error)
	getTargetMount(ctx context.Context, target string) (gofsutil.Info, bool, error)
	getMounts(ctx context.Context) ([]gofsutil.Info, error)
}

type mountLibPublishBlock interface {
	publishBlock(ctx context.Context, req *csi.NodePublishVolumeRequest) error
}

type mountLibPublishMount interface {
	publishMount(ctx context.Context, req *csi.NodePublishVolumeRequest) error
}

type reqHelpers interface {
	isBlock(req volumeCapabilityGetter) bool
	getStagingPath(ctx context.Context, req commonReqGetters) string
}

// wrapper used for file reading
type fileReader interface {
	ReadFile(filename string) ([]byte, error)
}

// wrapper used for file reading
type fileWriter interface {
	WriteFile(filename string, data []byte, perm os.FileMode) error
}

// wrapper used for filepath manipulation
type filePath interface {
	Glob(pattern string) (matches []string, err error)
}

type limitedOSIFace interface {
	OpenFile(name string, flag int, perm os.FileMode) (limitedFileIFace, error)
	Stat(name string) (limitedFileInfoIFace, error)
	Create(name string) (*os.File, error)
	ReadFile(name string) ([]byte, error)
	IsNotExist(err error) bool
	Mkdir(name string, perm os.FileMode) error
	MkdirAll(name string, perm os.FileMode) error
	Remove(name string) error
	WriteString(file *os.File, string string) (int, error)
	ExecCommand(name string, args ...string) ([]byte, error)
}

type limitedFileInfoIFace interface {
	IsDir() bool
}

type limitedFileIFace interface {
	WriteString(s string) (n int, err error)
	Close() error
}

// interface required for driver graceful stop
type gracefulStopper interface {
	GracefulStop(ctx context.Context)
}

type fileCreator interface {
	// mkfile creates a file specified by the path if needed.
	// return pair is a bool flag of whether file was created, and an error
	mkFile(path string) (bool, error)
}

type dirCreator interface {
	// mkDir creates the directory specified by path if needed.
	// return pair is a bool flag of whether dir was created, and an error
	mkDir(path string) (bool, error)
}

type consistentReader interface {
	consistentRead(filename string, retry int) ([]byte, error)
}

type fsCreator interface {
	// format creates the specified file system to by.
	// return an error
	format(ctx context.Context, source, fsType string, opts ...string) error
}

type timeoutSemaphore interface {
	Acquire(ctx context.Context) error
	Release(ctx context.Context)
}

type publishContextGetter interface {
	GetPublishContext() map[string]string
}

type volumeCapabilityGetter interface {
	GetVolumeCapability() *csi.VolumeCapability
}

type volToDevMapper interface {
	CreateMapping(volID, deviceName string) error
	GetMapping(volID string) (string, error)
	DeleteMapping(volID string) error
}
