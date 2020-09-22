// +build test

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
	"errors"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gobrick"
	"github.com/dell/gofsutil"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	validLUNID          = "3"
	validLUNIDINT       = 3
	nodeStagePrivateDir = "test/stage"
	unimplementedErrMsg = "rpc error: code = Unimplemented desc = "
	validNodeID         = "csi-node-1a47a1b91c444a8a90193d8066669603"
	validHostID         = "e8f4c5f8-c2fc-4df4-bd99-c292c12b55be"
	testErrMsg          = "test err"
	validDeviceWWN      = "68ccf09800e23ab798312a05426acae0"
	validDevPath        = "/dev/sdag"
	validDevName        = "sdag"
)

var (
	validFCTargetsWWPN           = []string{"58ccf09348a003a3", "58ccf09348a002a3"}
	validFCTargetsWWPNPowerstore = []string{"58:cc:f0:93:48:a0:03:a3", "58:cc:f0:93:48:a0:02:a3"}
	validFCTargetsInfo           = []FCTargetInfo{{WWPN: validFCTargetsWWPN[0]},
		{WWPN: validFCTargetsWWPN[1]}}
	validISCSIInitiators = []string{"iqn.1994-05.com.redhat:4db86abbe3c", "iqn.1994-05.com.redhat:2950c9ca441b"}
	validISCSIPortals    = []string{"192.168.1.1:3260", "192.168.1.2:3260"}
	validISCSITargets    = []string{"iqn.2015-10.com.dell:dellemc-powerstore-fnm00180700173-a-39f17e0e",
		"iqn.2015-10.com.dell:dellemc-powerstore-fnm00180700173-b-10de15a5"}
	validISCSITargetInfo = []ISCSITargetInfo{
		{Portal: validISCSIPortals[0], Target: validISCSITargets[0]},
		{Portal: validISCSIPortals[1], Target: validISCSITargets[1]}}
	validGobrickISCSIVolumeINFO = gobrick.ISCSIVolumeInfo{
		Targets: []gobrick.ISCSITargetInfo{
			{Portal: validISCSITargetInfo[0].Portal,
				Target: validISCSITargetInfo[0].Target},
			{Portal: validISCSITargetInfo[1].Portal, Target: validISCSITargetInfo[1].Target}},
		Lun: validLUNIDINT}
	validGobrickFCVolumeINFO = gobrick.FCVolumeInfo{
		Targets: []gobrick.FCTargetInfo{
			{WWPN: validFCTargetsWWPN[0]},
			{WWPN: validFCTargetsWWPN[1]}},
		Lun: validLUNIDINT}
	validGobrickDevice = gobrick.Device{Name: validDevName, WWN: validDeviceWWN, MultipathID: validDeviceWWN}
)

func getValidPublishContext() map[string]string {
	return map[string]string{
		PublishContextLUNAddress:               validLUNID,
		PublishContextDeviceWWN:                validDeviceWWN,
		PublishContextISCSIPortalsPrefix + "0": validISCSIPortals[0],
		PublishContextISCSIPortalsPrefix + "1": validISCSIPortals[1],
		PublishContextISCSITargetsPrefix + "0": validISCSITargets[0],
		PublishContextISCSITargetsPrefix + "1": validISCSITargets[1],
		PublishContextFCWWPNPrefix + "0":       validFCTargetsWWPN[0],
		PublishContextFCWWPNPrefix + "1":       validFCTargetsWWPN[1],
	}
}

func getValidPublishContextData() scsiPublishContextData {
	return scsiPublishContextData{
		iscsiTargets:     validISCSITargetInfo,
		deviceWWN:        validDeviceWWN,
		volumeLUNAddress: validLUNID,
		fcTargets:        validFCTargetsInfo,
	}
}

func getCapabilityWithVoltypeAccessFstype(voltype, access, fstype string) *csi.VolumeCapability {
	// Construct the volume capability
	capability := new(csi.VolumeCapability)
	switch voltype {
	case "block":
		blockVolume := new(csi.VolumeCapability_BlockVolume)
		block := new(csi.VolumeCapability_Block)
		block.Block = blockVolume
		capability.AccessType = block
	case "mount":
		mountVolume := new(csi.VolumeCapability_MountVolume)
		mountVolume.FsType = fstype
		mountVolume.MountFlags = make([]string, 0)
		mount := new(csi.VolumeCapability_Mount)
		mount.Mount = mountVolume
		capability.AccessType = mount
	}
	accessMode := new(csi.VolumeCapability_AccessMode)
	switch access {
	case "single-reader":
		accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY
	case "single-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
	case "multiple-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
	case "multiple-reader":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY
	case "multiple-node-single-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER
	}
	capability.AccessMode = accessMode
	return capability
}

func getNodePublishValidRequest() *csi.NodePublishVolumeRequest {
	return &csi.NodePublishVolumeRequest{
		VolumeId:       GoodVolumeID,
		VolumeContext:  map[string]string{"field": "value"},
		PublishContext: getValidPublishContext(),
		VolumeCapability: getCapabilityWithVoltypeAccessFstype(
			"block", "single-writer", "none"),
		TargetPath:        validTargetPath,
		StagingTargetPath: validStagingPath,
	}
}

func getNodeUnpublishValidRequest() *csi.NodeUnpublishVolumeRequest {
	req := csi.NodeUnpublishVolumeRequest{VolumeId: validVolumeID, TargetPath: validTargetPath}
	return &req
}

func getNodeVolumeExpandValidRequest() *csi.NodeExpandVolumeRequest {
	var size int64 = MaxVolumeSizeBytes / 100
	req := csi.NodeExpandVolumeRequest{
		VolumeId:   GoodVolumeID,
		VolumePath: validTargetPath,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: size,
			LimitBytes:    MaxVolumeSizeBytes,
		},
		XXX_NoUnkeyedLiteral: struct{}{},
		XXX_unrecognized:     nil,
		XXX_sizecache:        0,
	}
	return &req
}

func getNodeStageValidRequest() *csi.NodeStageVolumeRequest {
	return &csi.NodeStageVolumeRequest{
		VolumeId:       GoodVolumeID,
		VolumeContext:  map[string]string{"field": "value"},
		PublishContext: getValidPublishContext(),
		VolumeCapability: getCapabilityWithVoltypeAccessFstype(
			"block", "single-writer", "none"),
		StagingTargetPath: filepath.Join(nodeStagePrivateDir, GoodVolumeID),
	}
}

func getNodeUnstageValidRequest() *csi.NodeUnstageVolumeRequest {
	return &csi.NodeUnstageVolumeRequest{
		VolumeId:          GoodVolumeID,
		StagingTargetPath: filepath.Join(nodeStagePrivateDir, GoodVolumeID),
	}
}

const (
	validTargetPath = "/var/lib/kubelet/pods/dac33335-a31d-11e9-b46e-005056917428/" +
		"volumes/kubernetes.io~csi/csi-d91431aba3/mount"
	validStagingPath = "/var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/" +
		"staging/csi-44b46e98ae/c875b4f0-172e-4238-aec7-95b379eb55db"
)

func getValidGofsutilOtherDevInfo() gofsutil.Info {
	return gofsutil.Info{Device: "/dev/loop2",
		Path:   "/snap/core18/1055",
		Source: "/dev/loop2",
		Type:   "squashfs",
		Opts:   []string{"ro", "nodev", "realtime"}}
}

func getValidGofsutilTargetDevInfo() gofsutil.Info {
	return gofsutil.Info{
		Device: validDevPath,
		Path:   validTargetPath,
		Source: validDevPath,
		Type:   "ext4",
		Opts:   []string{"rw", "realtime"}}
}

func TestCheckIQNs(t *testing.T) {
	targetIQNs := []string{"1", "2", "3", "4", "5"}
	currentIQNs := []string{"2", "7", "9", "3"}
	expectedAdd := []string{"1", "4", "5"}
	expectedDelete := []string{"7", "9"}
	initiators := make([]gopowerstore.InitiatorInstance, len(currentIQNs))
	for i, v := range currentIQNs {
		initiators[i] = gopowerstore.InitiatorInstance{PortName: v}
	}
	resultAdd, resultDelete := checkIQNS(targetIQNs, gopowerstore.Host{Initiators: initiators})
	assert.ElementsMatch(t, expectedAdd, resultAdd)
	assert.ElementsMatch(t, expectedDelete, resultDelete)
}

func Test_buildInitiatorsArray(t *testing.T) {
	resp := buildInitiatorsArray(false, validISCSIInitiators)
	assert.Equal(t, len(validISCSIInitiators), len(resp))
	assert.Equal(t, *resp[0].PortType, gopowerstore.InitiatorProtocolTypeEnumISCSI)
}

func Test_readISCSITargetsFromPublishContext(t *testing.T) {
	svc := service{}
	svc.impl = &serviceIMPL{service: &svc}
	tgts := svc.impl.readISCSITargetsFromPublishContext(getValidPublishContext())
	assert.Len(t, tgts, 2)
}

func Test_readFCTargetsFromPublishContext(t *testing.T) {
	svc := service{}
	svc.impl = &serviceIMPL{service: &svc}
	tgts := svc.impl.readFCTargetsFromPublishContext(getValidPublishContext())
	assert.Len(t, tgts, 2)
}

func Test_NodePublish_ProbeFailed(t *testing.T) {
	svc := service{}
	implMock, ctrl := getServiceIMPLMock(t)
	defer ctrl.Finish()
	implMock.EXPECT().nodeProbe(gomock.Any()).Return(true, errors.New("error while probe"))
	svc.impl = implMock
	_, err := svc.NodePublishVolume(context.Background(), getNodePublishValidRequest())
	assert.NotNil(t, err)
}

func Test_NodePublish(t *testing.T) {
	svc := service{}
	implMock, ctrl := getServiceIMPLMock(t)
	defer ctrl.Finish()
	nodeMountLibMock := NewMockmountLib(ctrl)
	svc.nodeMountLib = nodeMountLibMock
	nodeMountLibMock.EXPECT().GetStagingPath(gomock.Any(), gomock.Any()).
		Return(validStagingPath).AnyTimes()
	svc.impl = implMock

	var req *csi.NodePublishVolumeRequest
	var err error

	funcUnderTest := func() (*csi.NodePublishVolumeResponse, error) {
		return svc.NodePublishVolume(context.Background(), req)
	}
	t.Run("node probe error", func(t *testing.T) {
		implMock.EXPECT().nodeProbe(gomock.Any()).Return(false, errors.New(testErrMsg))
		_, err = funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})

	nodeProbeMockOK := func() *gomock.Call {
		return implMock.EXPECT().nodeProbe(gomock.Any()).Return(true, nil)
	}

	t.Run("no volumeID in request", func(t *testing.T) {
		nodeProbeMockOK()
		req = getNodePublishValidRequest()
		req.VolumeId = ""
		_, err = funcUnderTest()
		assert.EqualError(t, err, "rpc error: code = InvalidArgument desc = volume ID is required")
	})

	t.Run("no targetPath in request", func(t *testing.T) {
		nodeProbeMockOK()
		req = getNodePublishValidRequest()
		req.TargetPath = ""
		_, err = funcUnderTest()
		assert.EqualError(t, err, "rpc error: code = InvalidArgument desc = targetPath is required")
	})

	t.Run("no VolumeCapability in request", func(t *testing.T) {
		nodeProbeMockOK()
		req = getNodePublishValidRequest()
		req.VolumeCapability = nil
		_, err = funcUnderTest()
		assert.EqualError(t, err, "rpc error: code = InvalidArgument desc = VolumeCapability is required")
	})

	t.Run("no StagingTargetPath in request", func(t *testing.T) {
		nodeProbeMockOK()
		req = getNodePublishValidRequest()
		req.StagingTargetPath = ""
		_, err = funcUnderTest()
		assert.EqualError(t, err, "rpc error: code = InvalidArgument desc = stagingPath is required")
	})

	req = getNodePublishValidRequest()

	t.Run("publish error", func(t *testing.T) {
		nodeProbeMockOK()
		nodeMountLibMock.EXPECT().PublishVolume(gomock.Any(), gomock.Any()).
			Return(errors.New(testErrMsg))
		_, err = funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})
	t.Run("success", func(t *testing.T) {
		nodeProbeMockOK()
		nodeMountLibMock.EXPECT().PublishVolume(gomock.Any(), gomock.Any()).
			Return(nil)
		_, err = funcUnderTest()
		assert.Nil(t, err)
	})
}

func TestNodeStageVolume(t *testing.T) {
	impl, implMock, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := impl.service
	nodeMountLibMock := NewMockmountLib(ctrl)
	svc.nodeMountLib = nodeMountLibMock
	iscsiConnectorMock := NewMockiSCSIConnector(ctrl)
	svc.iscsiConnector = iscsiConnectorMock

	ctx := context.Background()

	funcUnderTest := func(req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
		if req == nil {
			req = getNodeStageValidRequest()
		}
		return svc.NodeStageVolume(ctx, req)
	}
	getStagingPathMockOK := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().GetStagingPath(gomock.Any(), gomock.Any()).
			Return(validStagingPath)
	}

	isReadyToPublishMock := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().IsReadyToPublish(gomock.Any(), gomock.Any())
	}

	isReadyToPublishMockReady := func() *gomock.Call {
		return isReadyToPublishMock().Return(true, true, nil)
	}

	isReadyToPublishMockNotReadyNotFound := func() *gomock.Call {
		return isReadyToPublishMock().Return(false, false, nil)
	}

	isReadyToPublishMockNotReadyFound := func() *gomock.Call {
		return isReadyToPublishMock().Return(true, false, nil)
	}

	isReadyToPublishMockErr := func() *gomock.Call {
		return isReadyToPublishMock().Return(false, false, errors.New(testErrMsg))
	}

	isReadyToPublishNfsMock := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().IsReadyToPublishNFS(gomock.Any(), gomock.Any())
	}

	isReadyToPublishNfsMockNotFound := func() *gomock.Call {
		return isReadyToPublishNfsMock().Return(false, nil)
	}

	isReadyToPublishNfsMockFound := func() *gomock.Call {
		return isReadyToPublishNfsMock().Return(true, nil)
	}

	isReadyToPublishNfsMockErr := func() *gomock.Call {
		return isReadyToPublishNfsMock().Return(false, errors.New(testErrMsg))
	}

	readPublishContextMockOK := func() *gomock.Call {
		return implMock.EXPECT().readSCSIPublishContext(gomock.Any()).
			Return(getValidPublishContextData(), nil)
	}

	connectDeviceMock := func() *gomock.Call {
		return implMock.EXPECT().connectDevice(gomock.Any(), getValidPublishContextData())
	}

	connectDeviceError := func() {
		connectDeviceMock().Return("", errors.New(testErrMsg))
	}

	nodeMountLibUnstageVolume := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().UnstageVolume(gomock.Any(), gomock.Any())
	}

	nodeMountLibUnstageVolumeOK := func() {
		nodeMountLibUnstageVolume().Return(validDevName, nil)
	}

	nodeMountLibUnstageVolumeErr := func() {
		nodeMountLibUnstageVolume().Return("", errors.New(testErrMsg))
	}

	connectDeviceOK := func() {
		connectDeviceMock().Return(validDevPath, nil)
	}

	stageVolumeMockOK := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().StageVolume(gomock.Any(), gomock.Any(), validDevPath).
			Return(nil)
	}

	stageVolumeNfsMockOK := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().StageVolumeNFS(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)
	}

	stageVolumeNfsMockErr := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().StageVolumeNFS(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New(testErrMsg))
	}

	t.Run("node probe error", func(t *testing.T) {
		implMock.EXPECT().nodeProbe(gomock.Any()).Return(false, errors.New(testErrMsg))
		_, err := funcUnderTest(nil)
		assert.EqualError(t, err, testErrMsg)
	})

	nodeProbeMockOK := func() *gomock.Call {
		return implMock.EXPECT().nodeProbe(gomock.Any()).Return(true, nil)
	}

	t.Run("no VolumeID in request", func(t *testing.T) {
		nodeProbeMockOK()
		req := getNodeStageValidRequest()
		req.VolumeId = ""
		_, err := funcUnderTest(req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument"+
			" desc = volume ID is required")
	})

	t.Run("no StagingPath in request", func(t *testing.T) {
		nodeProbeMockOK()
		req := getNodeStageValidRequest()
		req.StagingTargetPath = ""
		_, err := funcUnderTest(req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument"+
			" desc = staging target path is required")
	})

	t.Run("read publishContext error", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		implMock.EXPECT().readSCSIPublishContext(gomock.Any()).
			Return(scsiPublishContextData{}, errors.New(testErrMsg))
		_, err := funcUnderTest(nil)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("IsReadyToPublish error", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		readPublishContextMockOK()
		isReadyToPublishMockErr()
		_, err := funcUnderTest(nil)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("already staged", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		readPublishContextMockOK()
		isReadyToPublishMockReady()
		_, err := funcUnderTest(nil)
		assert.Nil(t, err)
	})

	t.Run("need unstaging but failed to unstage", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		readPublishContextMockOK()
		isReadyToPublishMockNotReadyFound()
		nodeMountLibUnstageVolumeErr()
		_, err := funcUnderTest(nil)
		assert.EqualError(t, err, "rpc error: code = Internal desc = failed to unmount volume: test err")
	})

	t.Run("connect device error", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		readPublishContextMockOK()
		isReadyToPublishMockNotReadyFound()
		nodeMountLibUnstageVolumeOK()
		connectDeviceError()
		_, err := funcUnderTest(nil)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("StageVolume error", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		readPublishContextMockOK()
		isReadyToPublishMockNotReadyNotFound()
		connectDeviceOK()
		nodeMountLibMock.EXPECT().StageVolume(gomock.Any(), gomock.Any(), validDevPath).
			Return(errors.New(testErrMsg))
		_, err := funcUnderTest(nil)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal "+
			"desc = error during volume staging: %s", testErrMsg))
	})

	t.Run("success", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		readPublishContextMockOK()
		isReadyToPublishMockNotReadyNotFound()
		connectDeviceOK()
		stageVolumeMockOK()
		_, err := funcUnderTest(nil)
		assert.Nil(t, err)
	})

	publishContext := getValidPublishContext()
	publishContext[keyFsType] = "nfs"

	t.Run("publish check err nfs", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		isReadyToPublishNfsMockErr()
		_, err := funcUnderTest(&csi.NodeStageVolumeRequest{
			VolumeId:       GoodVolumeID,
			PublishContext: publishContext,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"mount", "multi-writer", "nfs"),
			StagingTargetPath: filepath.Join(nodeStagePrivateDir, GoodVolumeID),
		})
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("already staged nfs", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		isReadyToPublishNfsMockFound()
		_, err := funcUnderTest(&csi.NodeStageVolumeRequest{
			VolumeId:       GoodVolumeID,
			PublishContext: publishContext,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"mount", "multi-writer", "nfs"),
			StagingTargetPath: filepath.Join(nodeStagePrivateDir, GoodVolumeID),
		})
		assert.Nil(t, err)
	})

	t.Run("stage failure nfs", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		isReadyToPublishNfsMockNotFound()
		stageVolumeNfsMockErr()
		_, err := funcUnderTest(&csi.NodeStageVolumeRequest{
			VolumeId:       GoodVolumeID,
			PublishContext: publishContext,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"mount", "multi-writer", "nfs"),
			StagingTargetPath: filepath.Join(nodeStagePrivateDir, GoodVolumeID),
		})
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal "+
			"desc = error during volume staging: %s", testErrMsg))
	})

	t.Run("success nfs", func(t *testing.T) {
		nodeProbeMockOK()
		getStagingPathMockOK()
		isReadyToPublishNfsMockNotFound()
		stageVolumeNfsMockOK()
		_, err := funcUnderTest(&csi.NodeStageVolumeRequest{
			VolumeId:       GoodVolumeID,
			PublishContext: publishContext,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"mount", "multi-writer", "nfs"),
			StagingTargetPath: filepath.Join(nodeStagePrivateDir, GoodVolumeID),
		})
		assert.Nil(t, err)
	})
}

func TestNodeUnstageVolume(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := impl.service
	volToDevMapperMock := NewMockvolToDevMapper(ctrl)
	nodeMountLibMock := NewMockmountLib(ctrl)
	nodeFsLibMock := NewMockwrapperFsLib(ctrl)
	svc.nodeMountLib = nodeMountLibMock
	svc.nodeFSLib = nodeFsLibMock
	iscisConnectorMock := NewMockiSCSIConnector(ctrl)
	svc.iscsiConnector = iscisConnectorMock
	svc.volToDevMapper = volToDevMapperMock

	funcUnderTest := func(req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
		ctx := context.Background()
		if req == nil {
			req = getNodeUnstageValidRequest()
		}
		return svc.NodeUnstageVolume(ctx, req)
	}

	getStagingPathMockOK := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().GetStagingPath(gomock.Any(), gomock.Any()).
			Return(validStagingPath)
	}

	unstageVolumeMockOK := func() *gomock.Call {
		return nodeMountLibMock.EXPECT().UnstageVolume(gomock.Any(), gomock.Any()).
			Return(validDevName, nil)
	}

	disconnectVolumeByDeviceNameMock := func() *gomock.Call {
		return iscisConnectorMock.EXPECT().DisconnectVolumeByDeviceName(gomock.Any(), validDevName)
	}

	disconnectVolumeByDeviceNameMockError := func() {
		disconnectVolumeByDeviceNameMock().Return(errors.New(testErrMsg))
	}

	disconnectVolumeByDeviceNameMockOK := func() {
		disconnectVolumeByDeviceNameMock().Return(nil)
	}

	volToDevMapperCreateMappingMock := func() *gomock.Call {
		return volToDevMapperMock.EXPECT().CreateMapping(GoodVolumeID, validDevName)
	}

	volToDevMapperCreateMappingErr := func() *gomock.Call {
		return volToDevMapperCreateMappingMock().Return(errors.New(testErrMsg))
	}

	volToDevMapperCreateMappingOK := func() *gomock.Call {
		return volToDevMapperCreateMappingMock().Return(nil)
	}

	volToDevMapperGetMappingMock := func() *gomock.Call {
		return volToDevMapperMock.EXPECT().GetMapping(GoodVolumeID)
	}

	volToDevMapperGetMappingMockErr := func() *gomock.Call {
		return volToDevMapperGetMappingMock().Return("", errors.New(testErrMsg))
	}

	volToDevMapperDeleteMappingMock := func() *gomock.Call {
		return volToDevMapperMock.EXPECT().DeleteMapping(GoodVolumeID)
	}

	volToDevMapperDeleteMappingMockOK := func() *gomock.Call {
		return volToDevMapperDeleteMappingMock().Return(nil)
	}

	volToDevMapperDeleteMappingMockErr := func() *gomock.Call {
		return volToDevMapperDeleteMappingMock().Return(errors.New(testErrMsg))
	}

	t.Run("no VolumdeID in request", func(t *testing.T) {
		req := getNodeUnstageValidRequest()
		req.VolumeId = ""
		_, err := funcUnderTest(req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument"+
			" desc = volume ID is required")
	})

	t.Run("no StagingTargetPath in request", func(t *testing.T) {
		req := getNodeUnstageValidRequest()
		req.StagingTargetPath = ""
		_, err := funcUnderTest(req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument"+
			" desc = staging target path is required")
	})

	t.Run("UnstageVolume error", func(t *testing.T) {
		getStagingPathMockOK()
		nodeMountLibMock.EXPECT().UnstageVolume(gomock.Any(), gomock.Any()).
			Return("", errors.New(testErrMsg))
		_, err := funcUnderTest(nil)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal desc"+
			" = failed to unstage volume: %s", testErrMsg))
	})

	t.Run("UnstageVolume returns empty device no cached value", func(t *testing.T) {
		getStagingPathMockOK()
		nodeMountLibMock.EXPECT().UnstageVolume(gomock.Any(), gomock.Any()).
			Return("", nil)
		volToDevMapperGetMappingMockErr()
		_, err := funcUnderTest(nil)
		assert.Nil(t, err)
	})

	t.Run("gobrick.DisconnectVolumeByDeviceName error", func(t *testing.T) {
		getStagingPathMockOK()
		unstageVolumeMockOK()
		volToDevMapperCreateMappingOK()
		disconnectVolumeByDeviceNameMockError()
		_, err := funcUnderTest(nil)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("success", func(t *testing.T) {
		getStagingPathMockOK()
		unstageVolumeMockOK()
		disconnectVolumeByDeviceNameMockOK()
		volToDevMapperCreateMappingErr()
		volToDevMapperDeleteMappingMockOK()
		_, err := funcUnderTest(nil)
		assert.Nil(t, err)
	})

	t.Run("failed to remove cache file", func(t *testing.T) {
		getStagingPathMockOK()
		unstageVolumeMockOK()
		volToDevMapperCreateMappingOK()
		disconnectVolumeByDeviceNameMockOK()
		volToDevMapperDeleteMappingMockErr()
		_, err := funcUnderTest(nil)
		assert.Nil(t, err)
	})
}

func TestNodeProbe(t *testing.T) {
	impl, implMock, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()

	errMsg := "test err"
	// initClient err
	implMock.EXPECT().initPowerStoreClient().Return(errors.New(errMsg))
	ready, err := impl.nodeProbe(context.Background())
	assert.False(t, ready)
	assert.EqualError(t, err, errMsg)

	// updateNodeID err
	implMock.EXPECT().initPowerStoreClient().Return(nil).AnyTimes()
	implMock.EXPECT().updateNodeID().Return(errors.New(errMsg))
	ready, err = impl.nodeProbe(context.Background())
	assert.False(t, ready)
	assert.EqualError(t, err, errMsg)

	// ok
	implMock.EXPECT().updateNodeID().Return(nil).AnyTimes()
	implMock.EXPECT().initNodeFSLib().MinTimes(1)
	implMock.EXPECT().initNodeMountLib().MinTimes(1)
	implMock.EXPECT().initISCSIConnector().MinTimes(1)
	implMock.EXPECT().initFCConnector().MinTimes(1)
	implMock.EXPECT().initNodeVolToDevMapper().MinTimes(1)
	ready, err = impl.nodeProbe(context.Background())
	assert.False(t, ready)
	assert.Nil(t, err)
}

func TestUpdateNodeID(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := impl.service
	readerMock, ctrl := getFileReaderMock(t)
	defer ctrl.Finish()
	svc.fileReader = readerMock

	testNodeID := "1a47a1b91c444a8a90193d8066669603"

	// node id already set
	svc.nodeID = testNodeID
	err := impl.updateNodeID()
	assert.Nil(t, err)
	assert.Equal(t, testNodeID, svc.nodeID)
	svc.nodeID = ""

	// can't read file
	readerMock.EXPECT().ReadFile(gomock.Any()).Return([]byte{}, errors.New(testErrMsg))
	err = impl.updateNodeID()
	assert.EqualError(t, err,
		"rpc error: code = FailedPrecondition desc = Could not readNode ID file: test err")
	assert.Empty(t, svc.nodeID)

	// too long name
	readerMock.EXPECT().ReadFile(gomock.Any()).Return([]byte(testNodeID), nil).AnyTimes()
	svc.opts.NodeNamePrefix = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	err = impl.updateNodeID()
	assert.EqualError(t, err, "node name prefix is too long")
	assert.Empty(t, svc.nodeID)

	// valid
	testNodeNamePrefix := "test_node"
	svc.opts.NodeNamePrefix = testNodeNamePrefix
	err = impl.updateNodeID()
	assert.Nil(t, err)
	assert.Contains(t, svc.nodeID, fmt.Sprintf("%s-%s", testNodeNamePrefix, testNodeID))
	//assert.Equal(t, fmt.Sprintf("%s-%s", testNodeNamePrefix, testNodeID), svc.nodeID)
}

func TestNodeGetCapabilities(t *testing.T) {
	svc := service{}
	r, err := svc.NodeGetCapabilities(nil, &csi.NodeGetCapabilitiesRequest{})
	assert.Nil(t, err)
	assert.Len(t, r.Capabilities, 2)
}

func TestNodeGetInfo(t *testing.T) {
	impl, implMock, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := impl.service

	// already updated
	svc.nodeID = validNodeID
	r, err := svc.NodeGetInfo(nil, &csi.NodeGetInfoRequest{})
	assert.Nil(t, err)
	assert.Equal(t, r.NodeId, validNodeID)

	// updateNodeID error
	svc.nodeID = ""
	implMock.EXPECT().updateNodeID().Return(errors.New(testErrMsg))
	r, err = svc.NodeGetInfo(nil, &csi.NodeGetInfoRequest{})
	assert.EqualError(t, err, testErrMsg)
	assert.Nil(t, r)

	// updateNodeID success
	svc.nodeID = ""
	implMock.EXPECT().updateNodeID().Do(func() { svc.nodeID = validNodeID }).Return(nil)
	r, err = svc.NodeGetInfo(nil, &csi.NodeGetInfoRequest{})
	assert.Nil(t, err)
	assert.Equal(t, validNodeID, svc.nodeID)
}

func TestNodeGetVolumeStats(t *testing.T) {
	svc := service{}
	r, err := svc.NodeGetVolumeStats(nil, &csi.NodeGetVolumeStatsRequest{})
	assert.Nil(t, r)
	assert.EqualError(t, err, unimplementedErrMsg)
}

func TestInitNodeFSLib(t *testing.T) {
	svc := initService()
	svc.impl.initNodeFSLib()
	assert.NotNil(t, svc.nodeFSLib)
}

func TestInitMountLib(t *testing.T) {
	svc := initService()
	svc.impl.initNodeMountLib()
	assert.NotNil(t, svc.nodeMountLib)
}

func TestNodeStartup(t *testing.T) {
	impl, implMock, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := New().(*service)
	impl.service = svc

	ctx := context.Background()

	gs, ctrl := getGracefulStopperMock(t)
	defer ctrl.Finish()

	funcUnderTest := func() error {
		return impl.nodeStartup(ctx, gs)
	}

	t.Run("node already init", func(t *testing.T) {
		svc.nodeIsInitialized = true
		assert.Nil(t, funcUnderTest())
		svc.nodeIsInitialized = false
	})

	t.Run("no admin client", func(t *testing.T) {
		svc.adminClient = nil
		assert.EqualError(t, funcUnderTest(), "there is no PowerStore connection")
	})

	adminClient, ctrl := getAdminClient(t)
	defer ctrl.Finish()
	svc.adminClient = adminClient

	iscsiConnectorMock := NewMockiSCSIConnector(ctrl)
	svc.iscsiConnector = iscsiConnectorMock

	iscsiConnectorGetInitiatorNameMock := func() *gomock.Call {
		return iscsiConnectorMock.EXPECT().GetInitiatorName(ctx)
	}

	iscsiConnectorGetInitiatorNameMockErr := func() {
		iscsiConnectorGetInitiatorNameMock().Return(nil, errors.New(testErrMsg))
	}

	iscsiConnectorGetInitiatorNameMockEmpty := func() {
		iscsiConnectorGetInitiatorNameMock().Return(nil, nil)
	}

	iscsiConnectorGetInitiatorNameMockNonEmpty := func() {
		iscsiConnectorGetInitiatorNameMock().Return(validISCSIInitiators, nil)
	}

	implProxyGetNodeFCPortsMock := func() *gomock.Call {
		return implMock.EXPECT().getNodeFCPorts(ctx)
	}

	implProxyGetNodeFCPortsMockErr := func() {
		implProxyGetNodeFCPortsMock().Return(nil, errors.New(testErrMsg))
	}

	implProxyGetNodeFCPortsMockEmpty := func() {
		implProxyGetNodeFCPortsMock().Return(nil, nil)
	}

	implProxyGetNodeFCPortsMockNonEmpty := func() {
		implProxyGetNodeFCPortsMock().Return(validFCTargetsWWPNPowerstore, nil)
	}

	nodeHostSetupFC := func() *sync.WaitGroup {
		wg := sync.WaitGroup{}
		wg.Add(1)
		implMock.EXPECT().nodeHostSetup(validFCTargetsWWPNPowerstore, true, gomock.Any()).
			Do(func(args ...interface{}) { wg.Done() }).Return(nil)
		return &wg
	}

	nodeHostSetupISCSI := func() *sync.WaitGroup {
		wg := sync.WaitGroup{}
		wg.Add(1)
		implMock.EXPECT().nodeHostSetup(validISCSIInitiators, false, gomock.Any()).
			Do(func(args ...interface{}) { wg.Done() }).Return(nil)
		return &wg
	}

	unavailableMSG := "FC and iSCSI initiators not found on node"

	t.Run("iscsi and FC unavailable", func(t *testing.T) {
		iscsiConnectorGetInitiatorNameMockEmpty()
		implProxyGetNodeFCPortsMockEmpty()
		assert.EqualError(t, funcUnderTest(), unavailableMSG)
	})

	t.Run("error check for initiators", func(t *testing.T) {
		iscsiConnectorGetInitiatorNameMockErr()
		implProxyGetNodeFCPortsMockErr()
		assert.EqualError(t, funcUnderTest(), unavailableMSG)
	})

	t.Run("prefer FC if both connection types are available", func(t *testing.T) {
		iscsiConnectorGetInitiatorNameMockNonEmpty()
		implProxyGetNodeFCPortsMockNonEmpty()
		wg := nodeHostSetupFC()
		assert.Nil(t, funcUnderTest())
		wg.Wait()
		assert.True(t, svc.useFC)
	})
	t.Run("iscsi explicitly selected but it's unavailable", func(t *testing.T) {
		svc.opts.PreferredTransport = iSCSITransport
		iscsiConnectorGetInitiatorNameMockEmpty()
		implProxyGetNodeFCPortsMockNonEmpty()
		assert.EqualError(t, funcUnderTest(),
			"iSCSI transport was requested but iSCSI initiator is not available")
	})
	t.Run("FC explicitly selected but it's unavailable", func(t *testing.T) {
		svc.opts.PreferredTransport = fcTransport
		iscsiConnectorGetInitiatorNameMockNonEmpty()
		implProxyGetNodeFCPortsMockEmpty()
		assert.EqualError(t, funcUnderTest(),
			"FC transport was requested but FC initiator is not available")
	})

	t.Run("FC explicitly selected when both available", func(t *testing.T) {
		svc.opts.PreferredTransport = fcTransport
		iscsiConnectorGetInitiatorNameMockNonEmpty()
		implProxyGetNodeFCPortsMockNonEmpty()
		wg := nodeHostSetupFC()
		assert.Nil(t, funcUnderTest())
		wg.Wait()
		assert.True(t, svc.useFC)
	})

	t.Run("iscsi explicitly selected when both available", func(t *testing.T) {
		svc.opts.PreferredTransport = iSCSITransport
		iscsiConnectorGetInitiatorNameMockNonEmpty()
		implProxyGetNodeFCPortsMockNonEmpty()
		wg := nodeHostSetupISCSI()
		assert.Nil(t, funcUnderTest())
		wg.Wait()
		assert.False(t, svc.useFC)
		svc.opts.PreferredTransport = autoDetectTransport
	})

	t.Run("nodeHostSetup error", func(t *testing.T) {
		iscsiConnectorGetInitiatorNameMockNonEmpty()
		implProxyGetNodeFCPortsMockNonEmpty()
		wg := sync.WaitGroup{}
		wg.Add(1)
		implMock.EXPECT().nodeHostSetup(validFCTargetsWWPNPowerstore, true, gomock.Any()).
			Do(func(args ...interface{}) { wg.Done() }).Return(errors.New(testErrMsg))
		gs.EXPECT().GracefulStop(ctx).Return().AnyTimes()
		assert.Nil(t, funcUnderTest())
		wg.Wait()
	})
}

func TestNodeHostSetup(t *testing.T) {
	impl, implMock, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := impl.service
	maxStartDelay := 1

	// no nodeID
	err := impl.nodeHostSetup(validISCSIInitiators, false, maxStartDelay)
	assert.EqualError(t, err, "nodeID not set")

	svc.nodeID = validNodeID

	// createOrUpdateHost error
	implMock.EXPECT().createOrUpdateHost(gomock.Any(), false, validISCSIInitiators).Return(errors.New(testErrMsg))
	err = impl.nodeHostSetup(validISCSIInitiators, false, maxStartDelay)
	assert.EqualError(t, err, testErrMsg)

	implMock.EXPECT().createOrUpdateHost(gomock.Any(), false, validISCSIInitiators).Return(nil)
	// ok
	err = impl.nodeHostSetup(validISCSIInitiators, false, maxStartDelay)
	assert.Nil(t, err)
	assert.True(t, svc.nodeIsInitialized)
}

func TestCreateHost(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	adminClientMock, ctrl := getAdminClient(t)
	defer ctrl.Finish()
	svc := impl.service
	svc.adminClient = adminClientMock

	adminClientMock.EXPECT().CreateHost(gomock.Any(), gomock.Any()).
		Return(gopowerstore.CreateResponse{}, errors.New(testErrMsg))
	resp, err := impl.createHost(nil, false, []string{})
	assert.EqualError(t, err, testErrMsg)
	assert.Equal(t, resp, "")

	// valid resp
	cr := gopowerstore.CreateResponse{ID: validHostID}
	adminClientMock.EXPECT().CreateHost(gomock.Any(), gomock.Any()).Return(cr, nil)
	resp, err = impl.createHost(nil, false, []string{})
	assert.Nil(t, err)
	assert.Equal(t, resp, validHostID)
}

func Test_service_NodeUnpublishVolume(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	ctrl.Finish()
	svc := impl.service
	ctx := context.Background()
	nodeMountLibMock := NewMockmountLib(ctrl)
	svc.nodeMountLib = nodeMountLibMock

	t.Run("no targetPath in req", func(t *testing.T) {
		req := getNodeUnpublishValidRequest()
		req.TargetPath = ""
		_, err := svc.NodeUnpublishVolume(ctx, req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument desc"+
			" = target path required")
	})

	t.Run("no volumeID in req", func(t *testing.T) {
		req := getNodeUnpublishValidRequest()
		req.VolumeId = ""
		_, err := svc.NodeUnpublishVolume(ctx, req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument "+
			"desc = volume ID is required")
	})

	t.Run("unpublish error", func(t *testing.T) {
		req := getNodeUnpublishValidRequest()
		nodeMountLibMock.EXPECT().UnpublishVolume(gomock.Any(), gomock.Any()).
			Return(errors.New(testErrMsg))
		_, err := svc.NodeUnpublishVolume(ctx, req)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("unpublish ok", func(t *testing.T) {
		req := getNodeUnpublishValidRequest()
		nodeMountLibMock.EXPECT().UnpublishVolume(gomock.Any(), gomock.Any()).
			Return(nil)
		_, err := svc.NodeUnpublishVolume(ctx, req)
		assert.Nil(t, err)
	})
}

func Test_service_NodeExpandVolume(t *testing.T) {
	impl, implMock, ctrl := getIMPLWitIMPLMock(t)
	ctrl.Finish()
	svc := impl.service
	ctx := context.Background()
	adminClientMock := gopowerstoremock.NewMockClient(ctrl)
	svc.adminClient = adminClientMock
	nodeMountLibMock := NewMockmountLib(ctrl)
	svc.nodeMountLib = nodeMountLibMock
	nodeProbeMockOK := func() *gomock.Call {
		return implMock.EXPECT().nodeProbe(gomock.Any()).Return(true, nil)
	}
	nodeProbeMockBad := func() *gomock.Call {
		return implMock.EXPECT().nodeProbe(gomock.Any()).Return(false, errors.New("Failed"))
	}
	getVolMockBad := func() *gomock.Call {
		return adminClientMock.EXPECT().GetVolume(ctx, gomock.Any()).
			Return(gopowerstore.Volume{ID: GoodVolumeID, Size: 20 * VolumeSizeMultiple}, errors.New(testErrMsg))
	}
	getVolMockOK := func() *gomock.Call {
		return adminClientMock.EXPECT().GetVolume(ctx, gomock.Any()).
			Return(gopowerstore.Volume{ID: GoodVolumeID, Size: 20 * VolumeSizeMultiple}, nil)
	}

	t.Run("node probe bad", func(t *testing.T) {
		nodeProbeMockBad()
		req := getNodeVolumeExpandValidRequest()
		_, err := svc.NodeExpandVolume(ctx, req)
		assert.EqualError(t, err, "Failed")
	})

	t.Run("no targetPath in req", func(t *testing.T) {
		nodeProbeMockOK()
		req := getNodeVolumeExpandValidRequest()
		req.VolumePath = ""
		_, err := svc.NodeExpandVolume(ctx, req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument desc"+
			" = targetPath is required")
	})

	t.Run("no volumeID in req", func(t *testing.T) {
		nodeProbeMockOK()
		req := getNodeVolumeExpandValidRequest()
		req.VolumeId = ""
		_, err := svc.NodeExpandVolume(ctx, req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument "+
			"desc = volume ID is required")
	})

	t.Run("Volume Not Found", func(t *testing.T) {
		nodeProbeMockOK()
		req := getNodeVolumeExpandValidRequest()
		getVolMockBad()
		_, err := svc.NodeExpandVolume(ctx, req)
		assert.EqualError(t, err, "rpc error: code = NotFound desc = Volume not found")
	})

	t.Run("Unable to find mount points. Should try offline and fail again", func(t *testing.T) {
		gofsutil.UseMockFS()

		nodeProbeMockOK()
		req := getNodeVolumeExpandValidRequest()
		getVolMockOK()
		gofsutil.GOFSMock.InduceGetMountInfoFromDeviceError = true
		_, err := svc.NodeExpandVolume(ctx, req)
		gofsutil.GOFSMock.InduceGetMountInfoFromDeviceError = false
		_, staterr := os.Stat(fmt.Sprintf("tmp/%s", req.VolumeId))
		assert.Error(t, staterr)
		assert.EqualError(t, err, "rpc error: code = Internal desc = Failed to find mount info for () with error (getMounts induced error: Failed to find mount information)")
	})

	t.Run("Good scenario", func(t *testing.T) {
		gofsutil.UseMockFS()

		nodeProbeMockOK()
		req := getNodeVolumeExpandValidRequest()
		getVolMockOK()
		_, err := svc.NodeExpandVolume(ctx, req)
		assert.NoError(t, err)
	})
	t.Run("Failed to perform a fake mount ", func(t *testing.T) {
		gofsutil.UseMockFS()

		nodeProbeMockOK()
		req := getNodeVolumeExpandValidRequest()
		getVolMockOK()
		gofsutil.GOFSMock.InduceGetMountInfoFromDeviceError = true
		gofsutil.GOFSMock.InduceMountError = true
		_, err := svc.NodeExpandVolume(ctx, req)
		gofsutil.GOFSMock.InduceGetMountInfoFromDeviceError = false
		gofsutil.GOFSMock.InduceMountError = false
		assert.EqualError(t, err, "rpc error: code = Internal desc = Failed to find mount info for () with error (mount induced error)")
	})

}

func TestNode_readPublishContext(t *testing.T) {
	svc := service{}
	implMock, ctrl := getServiceIMPLMock(t)
	svc.impl = implMock
	impl := serviceIMPL{&svc, implMock}

	defer ctrl.Finish()

	var err error

	buildReq := func(data map[string]string) publishContextGetter {
		reqMock := NewMockpublishContextGetter(ctrl)
		reqMock.EXPECT().GetPublishContext().Return(data)
		return reqMock
	}

	t.Run("no deviceWWN", func(t *testing.T) {
		pc := getValidPublishContext()
		delete(pc, PublishContextDeviceWWN)
		_, err = impl.readSCSIPublishContext(buildReq(pc))
		assert.EqualError(t, err, "rpc error: code = InvalidArgument"+
			" desc = deviceWWN must be in publish context")
	})
	t.Run("no volumeLUNAddress", func(t *testing.T) {
		pc := getValidPublishContext()
		delete(pc, PublishContextLUNAddress)
		_, err = impl.readSCSIPublishContext(buildReq(pc))
		assert.EqualError(t, err, "rpc error: code = InvalidArgument "+
			"desc = volumeLUNAddress must be in publish context")
	})
	t.Run("no target data", func(t *testing.T) {
		svc.useFC = false
		implMock.EXPECT().readISCSITargetsFromPublishContext(gomock.Any()).Return([]ISCSITargetInfo{})
		_, err = impl.readSCSIPublishContext(buildReq(getValidPublishContext()))
		assert.EqualError(t, err, "rpc error: code = InvalidArgument"+
			" desc = iscsiTargets data must be in publish context")
	})
	t.Run("no FC target data", func(t *testing.T) {
		svc.useFC = true
		implMock.EXPECT().readISCSITargetsFromPublishContext(gomock.Any()).Return(validISCSITargetInfo)
		implMock.EXPECT().readFCTargetsFromPublishContext(gomock.Any()).Return([]FCTargetInfo{})
		_, err = impl.readSCSIPublishContext(buildReq(getValidPublishContext()))
		assert.EqualError(t, err, "rpc error: code = InvalidArgument"+
			" desc = fcTargets data must be in publish context")
	})
	t.Run("success", func(t *testing.T) {
		implMock.EXPECT().readISCSITargetsFromPublishContext(gomock.Any()).Return(validISCSITargetInfo)
		implMock.EXPECT().readFCTargetsFromPublishContext(gomock.Any()).Return(validFCTargetsInfo)
		data, err := impl.readSCSIPublishContext(buildReq(getValidPublishContext()))
		assert.Nil(t, err)
		assert.Equal(t, validDeviceWWN, data.deviceWWN)
		assert.Equal(t, validLUNID, data.volumeLUNAddress)
		assert.Equal(t, validISCSITargetInfo, data.iscsiTargets)
		assert.Equal(t, validFCTargetsInfo, data.fcTargets)
	})
}

func TestNode_modifyHostInitiators(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	adminClientMock := gopowerstoremock.NewMockClient(ctrl)
	svc := impl.service
	svc.adminClient = adminClientMock
	ctx := context.Background()

	funcUnderTest := func(iqnToAdd []string, iqnToDel []string) error {
		return impl.modifyHostInitiators(ctx, validHostID, false, iqnToAdd, iqnToDel)
	}
	adminClientModifyHostMock := func() *gomock.Call {
		return adminClientMock.EXPECT().ModifyHost(ctx, gomock.Any(), validHostID)
	}
	adminClientModifyHostMockOK := func() {
		adminClientModifyHostMock().Return(gopowerstore.CreateResponse{}, nil)
	}
	adminClientModifyHostMockErr := func() {
		adminClientModifyHostMock().Return(gopowerstore.CreateResponse{}, errors.New(testErrMsg))
	}

	t.Run("only remove initiators", func(t *testing.T) {
		adminClientModifyHostMockOK()
		assert.Nil(t, funcUnderTest(nil, []string{validISCSIInitiators[0]}))
	})

	t.Run("only add initiators", func(t *testing.T) {
		adminClientModifyHostMockOK()
		assert.Nil(t, funcUnderTest([]string{validISCSIInitiators[0]}, nil))
	})
	t.Run("add and remove", func(t *testing.T) {
		adminClientModifyHostMockOK()
		adminClientModifyHostMockOK()
		assert.Nil(t, funcUnderTest([]string{validISCSIInitiators[0]}, []string{validISCSIInitiators[1]}))
	})
	t.Run("add error", func(t *testing.T) {
		adminClientModifyHostMockErr()
		assert.EqualError(t, funcUnderTest([]string{validISCSIInitiators[0]}, nil), testErrMsg)
	})

	t.Run("del error", func(t *testing.T) {
		adminClientModifyHostMockErr()
		assert.EqualError(t, funcUnderTest(nil, []string{validISCSIInitiators[0]}), testErrMsg)
	})
}

func TestNode_createOrUpdateHost(t *testing.T) {
	impl, implMock, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	adminClientMock := gopowerstoremock.NewMockClient(ctrl)
	svc := impl.service
	svc.nodeID = validNodeID
	svc.adminClient = adminClientMock
	ctx := context.Background()

	funcUnderTest := func(IQNs []string) error {
		return impl.createOrUpdateHost(ctx, false, IQNs)
	}

	getHostByNameMockNotExist := func() *gomock.Call {
		return adminClientMock.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
			Return(gopowerstore.Host{}, gopowerstore.NewHostIsNotExistError())
	}

	getHostByNameMockOK := func() *gomock.Call {
		return adminClientMock.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
			Return(gopowerstore.Host{}, nil)
	}

	modifyHostInitiatorsMockOK := func() *gomock.Call {
		return implMock.EXPECT().modifyHostInitiators(
			gomock.Any(), gomock.Any(), gomock.Any(), []string{validISCSIInitiators[0]}, gomock.Any()).
			Return(nil)
	}

	t.Run("get host info error", func(t *testing.T) {
		adminClientMock.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
			Return(gopowerstore.Host{}, errors.New(testErrMsg))
		err := funcUnderTest([]string{validISCSIInitiators[0]})
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("create host ok", func(t *testing.T) {
		iqns := []string{validISCSIInitiators[0]}
		getHostByNameMockNotExist()
		implMock.EXPECT().createHost(gomock.Any(), false, iqns).Return("", nil)
		err := funcUnderTest(iqns)
		assert.Nil(t, err)
	})

	t.Run("create host error", func(t *testing.T) {
		iqns := []string{validISCSIInitiators[0]}
		getHostByNameMockNotExist()
		implMock.EXPECT().createHost(gomock.Any(), false, iqns).Return("", errors.New(testErrMsg))
		err := funcUnderTest(iqns)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("modifyHostInitiators error", func(t *testing.T) {
		getHostByNameMockOK()
		implMock.EXPECT().modifyHostInitiators(
			gomock.Any(), gomock.Any(), gomock.Any(), []string{validISCSIInitiators[0]}, gomock.Any()).
			Return(errors.New(testErrMsg))
		err := funcUnderTest([]string{validISCSIInitiators[0]})
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("modifyHostInitiators ok", func(t *testing.T) {
		getHostByNameMockOK()
		modifyHostInitiatorsMockOK()
		err := funcUnderTest([]string{validISCSIInitiators[0]})
		assert.Nil(t, err)
	})
}

func TestNode_formatWWPN(t *testing.T) {
	t.Run("test valid data", func(t *testing.T) {
		result, err := formatWWPN(validFCTargetsWWPN[0])
		assert.Nil(t, err)
		assert.Equal(t, validFCTargetsWWPNPowerstore[0], result)
	})
	t.Run("test invalid data", func(t *testing.T) {
		_, err := formatWWPN("111111111")
		// should not panic and don't return err
		assert.Nil(t, err)
	})
}

func TestNode_readFCPortsFilterFile(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := impl.service

	fileReaderMock := NewMockfileReader(ctrl)
	svc.fileReader = fileReaderMock

	osMock := NewMocklimitedOSIFace(ctrl)
	svc.os = osMock

	ctx := context.Background()

	funcUnderTest := func() ([]string, error) {
		return impl.readFCPortsFilterFile(ctx)
	}
	fileReaderReadFileMock := func() *gomock.Call {
		return fileReaderMock.EXPECT().ReadFile(svc.opts.FCPortsFilterFilePath)
	}
	fileReaderReadFileMockErr := func() {
		fileReaderReadFileMock().Return(nil, errors.New(testErrMsg))
	}
	fileReaderReadFileMockEmpty := func() {
		fileReaderReadFileMock().Return(nil, nil)
	}
	fileReaderReadFileMockValidData := func() {
		fileReaderReadFileMock().Return(
			[]byte(strings.Join(validFCTargetsWWPNPowerstore, ",")), nil)
	}
	fileReaderReadFileMockInvalidData := func() {
		fileReaderReadFileMock().Return([]byte("foobar"), nil)
	}
	fileOpenerIsNotExistMock := func() *gomock.Call {
		return osMock.EXPECT().IsNotExist(gomock.Any())
	}
	fileOpenerIsNotExistTrue := func() {
		fileOpenerIsNotExistMock().Return(true)
	}
	fileOpenerIsNotExistFalse := func() {
		fileOpenerIsNotExistMock().Return(false)
	}

	t.Run("FC ports filter file not specified", func(t *testing.T) {
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.Nil(t, err)
	})

	svc.opts.FCPortsFilterFilePath = "/etc/fc-ports-filter"

	t.Run("file read error", func(t *testing.T) {
		fileReaderReadFileMockErr()
		fileOpenerIsNotExistFalse()
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("file not exist", func(t *testing.T) {
		fileReaderReadFileMockErr()
		fileOpenerIsNotExistTrue()
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.Nil(t, err)
	})

	t.Run("file is empty", func(t *testing.T) {
		fileReaderReadFileMockEmpty()
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.Nil(t, err)
	})

	t.Run("invalid data in file", func(t *testing.T) {
		fileReaderReadFileMockInvalidData()
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.Nil(t, err)
	})
	t.Run("valid data in file", func(t *testing.T) {
		fileReaderReadFileMockValidData()
		data, err := funcUnderTest()
		assert.Equal(t, validFCTargetsWWPNPowerstore, data)
		assert.Nil(t, err)
	})
}

func TestNode_getNodeFCPorts(t *testing.T) {
	impl, implProxy, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := impl.service

	ctx := context.Background()

	fcConnectorMock := NewMockfcConnector(ctrl)
	svc.fcConnector = fcConnectorMock

	funcUnderTest := func() ([]string, error) {
		return impl.getNodeFCPorts(ctx)
	}

	fcConnectorMockGetInitiatorPortsMock := func() *gomock.Call {
		return fcConnectorMock.EXPECT().GetInitiatorPorts(ctx)
	}
	fcConnectorMockGetInitiatorPortsMockErr := func() {
		fcConnectorMockGetInitiatorPortsMock().
			Return(nil, errors.New(testErrMsg))
	}

	fcConnectorMockGetInitiatorPortsMockData := func() {
		fcConnectorMockGetInitiatorPortsMock().
			Return(validFCTargetsWWPN, nil)
	}
	fcConnectorMockGetInitiatorPortsMockEmpty := func() {
		fcConnectorMockGetInitiatorPortsMock().
			Return(nil, nil)
	}
	implProxyReadFCPortsFilterFileMock := func() *gomock.Call {
		return implProxy.EXPECT().readFCPortsFilterFile(ctx)
	}

	implProxyReadFCPortsFilterFileMockEmpty := func() {
		implProxyReadFCPortsFilterFileMock().Return(nil, nil)
	}
	implProxyReadFCPortsFilterFileMockFullMatch := func() {
		implProxyReadFCPortsFilterFileMock().
			Return(validFCTargetsWWPNPowerstore, nil)
	}
	implProxyReadFCPortsFilterFileMockSingleMatch := func() {
		implProxyReadFCPortsFilterFileMock().
			Return([]string{validFCTargetsWWPNPowerstore[1]}, nil)
	}
	implProxyReadFCPortsFilterFileMockFilterAll := func() {
		implProxyReadFCPortsFilterFileMock().
			Return([]string{"58:cc:f0:93:40:a0:03:a3", "58:cc:f0:93:41:a0:02:a3"}, nil)
	}

	t.Run("GetInitiatorPorts error", func(t *testing.T) {
		fcConnectorMockGetInitiatorPortsMockErr()
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("GetInitiatorPorts returns no initiators", func(t *testing.T) {
		fcConnectorMockGetInitiatorPortsMockEmpty()
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.Nil(t, err)
	})

	t.Run("GetInitiatorPorts returns initiators, no filter", func(t *testing.T) {
		fcConnectorMockGetInitiatorPortsMockData()
		implProxyReadFCPortsFilterFileMockEmpty()
		data, err := funcUnderTest()
		assert.Equal(t, validFCTargetsWWPNPowerstore, data)
		assert.Nil(t, err)
	})
	t.Run("GetInitiatorPorts returns initiators, match all", func(t *testing.T) {
		fcConnectorMockGetInitiatorPortsMockData()
		implProxyReadFCPortsFilterFileMockFullMatch()
		data, err := funcUnderTest()
		assert.Equal(t, validFCTargetsWWPNPowerstore, data)
		assert.Nil(t, err)
	})
	t.Run("GetInitiatorPorts returns initiators, single match", func(t *testing.T) {
		fcConnectorMockGetInitiatorPortsMockData()
		implProxyReadFCPortsFilterFileMockSingleMatch()
		data, err := funcUnderTest()
		assert.Equal(t, []string{validFCTargetsWWPNPowerstore[1]}, data)
		assert.Nil(t, err)
	})
	t.Run("GetInitiatorPorts returns initiators, filter all", func(t *testing.T) {
		fcConnectorMockGetInitiatorPortsMockData()
		implProxyReadFCPortsFilterFileMockFilterAll()
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.Nil(t, err)
	})
}

func TestNode_connectDevice(t *testing.T) {
	impl, implProxy, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	svc := impl.service
	ctx := context.Background()

	funcUnderTest := func(data scsiPublishContextData) (string, error) {
		return impl.connectDevice(ctx, data)
	}
	implProxyConnectFCDeviceMock := func() *gomock.Call {
		return implProxy.EXPECT().connectFCDevice(ctx, validLUNIDINT, getValidPublishContextData())
	}
	implProxyConnectFCDeviceMockErr := func() {
		implProxyConnectFCDeviceMock().Return(gobrick.Device{}, errors.New(testErrMsg))
	}
	implProxyConnectFCDeviceMockOK := func() {
		implProxyConnectFCDeviceMock().Return(validGobrickDevice, nil)
	}
	implProxyConnectISCSIDeviceMock := func() *gomock.Call {
		return implProxy.EXPECT().connectISCSIDevice(
			ctx, validLUNIDINT, getValidPublishContextData())
	}
	implProxyConnectISCSIDeviceMockErr := func() {
		implProxyConnectISCSIDeviceMock().Return(gobrick.Device{}, errors.New(testErrMsg))
	}
	implProxyConnectISCSIDeviceMockOK := func() {
		implProxyConnectISCSIDeviceMock().Return(validGobrickDevice, nil)
	}

	t.Run("can't convert LUN id to integer", func(t *testing.T) {
		pcData := getValidPublishContextData()
		pcData.volumeLUNAddress = "a"
		data, err := funcUnderTest(pcData)
		assert.Empty(t, data)
		assert.EqualError(t, err, "strconv.Atoi: parsing \"a\": invalid syntax")
	})

	t.Run("use FC", func(t *testing.T) {
		svc.useFC = true
		implProxyConnectFCDeviceMockOK()
		data, err := funcUnderTest(getValidPublishContextData())
		assert.Nil(t, err)
		assert.Equal(t, validDevPath, data)
	})

	t.Run("use iSCSI", func(t *testing.T) {
		svc.useFC = false
		implProxyConnectISCSIDeviceMockOK()
		data, err := funcUnderTest(getValidPublishContextData())
		assert.Nil(t, err)
		assert.Equal(t, validDevPath, data)
	})

	t.Run("FC error", func(t *testing.T) {
		svc.useFC = true
		implProxyConnectFCDeviceMockErr()
		_, err := funcUnderTest(getValidPublishContextData())
		assert.NotNil(t, err)
	})

	t.Run("iSCSI error", func(t *testing.T) {
		svc.useFC = false
		implProxyConnectISCSIDeviceMockErr()
		_, err := funcUnderTest(getValidPublishContextData())
		assert.NotNil(t, err)
	})
}

func TestNode_connectFCDevice(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	ctx := context.Background()

	svc := impl.service
	fcConnectorMock := NewMockfcConnector(ctrl)
	svc.fcConnector = fcConnectorMock

	fcConnectorConnectVolumeMock := func() *gomock.Call {
		return fcConnectorMock.EXPECT().ConnectVolume(gomock.Any(), validGobrickFCVolumeINFO)
	}

	fcConnectorConnectVolumeMockOK := func() {
		fcConnectorConnectVolumeMock().Return(validGobrickDevice, nil)
	}

	fcConnectorConnectVolumeMockErr := func() {
		fcConnectorConnectVolumeMock().Return(gobrick.Device{}, errors.New(testErrMsg))
	}

	funcUnderTest := func() (gobrick.Device, error) {
		return impl.connectFCDevice(ctx, validLUNIDINT, getValidPublishContextData())
	}

	t.Run("error", func(t *testing.T) {
		fcConnectorConnectVolumeMockErr()
		_, err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("ok", func(t *testing.T) {
		fcConnectorConnectVolumeMockOK()
		data, err := funcUnderTest()
		assert.Equal(t, validGobrickDevice, data)
		assert.Nil(t, err)
	})
}

func TestNode_connectISCSIDevice(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	ctx := context.Background()

	svc := impl.service
	iscsiConnector := NewMockiSCSIConnector(ctrl)
	svc.iscsiConnector = iscsiConnector

	iscsiConnectorConnectVolumeMock := func() *gomock.Call {
		return iscsiConnector.EXPECT().ConnectVolume(gomock.Any(), validGobrickISCSIVolumeINFO)
	}

	iscsiConnectorConnectVolumeMockOK := func() {
		iscsiConnectorConnectVolumeMock().Return(validGobrickDevice, nil)
	}

	iscsiConnectorConnectVolumeMockErr := func() {
		iscsiConnectorConnectVolumeMock().Return(gobrick.Device{}, errors.New(testErrMsg))
	}

	funcUnderTest := func() (gobrick.Device, error) {
		return impl.connectISCSIDevice(ctx, validLUNIDINT, getValidPublishContextData())
	}

	t.Run("error", func(t *testing.T) {
		iscsiConnectorConnectVolumeMockErr()
		_, err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("ok", func(t *testing.T) {
		iscsiConnectorConnectVolumeMockOK()
		data, err := funcUnderTest()
		assert.Equal(t, validGobrickDevice, data)
		assert.Nil(t, err)
	})
}

func TestNode_volToDevFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	wMock := NewMockfileWriter(ctrl)
	rMock := NewMockfileReader(ctrl)
	osMock := NewMocklimitedOSIFace(ctrl)

	vtd := &volToDevFile{W: wMock, R: rMock, OS: osMock, DataDir: "foo"}

	t.Run("CreateMapping", func(t *testing.T) {
		wMock.EXPECT().WriteFile(
			path.Join(vtd.DataDir, validVolumeID), []byte(validDevName), gomock.Any()).
			Return(errors.New(testErrMsg))
		err := vtd.CreateMapping(validVolumeID, validDevName)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("GetMapping - read error", func(t *testing.T) {
		rMock.EXPECT().ReadFile(path.Join(vtd.DataDir, validVolumeID)).
			Return(nil, errors.New(testErrMsg))
		_, err := vtd.GetMapping(validVolumeID)
		assert.EqualError(t, err, testErrMsg)
	})
	t.Run("GetMapping - empty data", func(t *testing.T) {
		rMock.EXPECT().ReadFile(path.Join(vtd.DataDir, validVolumeID)).
			Return(nil, nil)
		_, err := vtd.GetMapping(validVolumeID)
		assert.EqualError(t, err, "no device name in mapping")
	})
	t.Run("GetMapping - valid data", func(t *testing.T) {
		rMock.EXPECT().ReadFile(path.Join(vtd.DataDir, validVolumeID)).
			Return([]byte(validDevName), nil)
		result, err := vtd.GetMapping(validVolumeID)
		assert.Nil(t, err)
		assert.Equal(t, validDevName, result)
	})

	t.Run("DeleteMapping - error", func(t *testing.T) {
		osMock.EXPECT().Remove(path.Join(vtd.DataDir, validVolumeID)).
			Return(errors.New(testErrMsg))
		osMock.EXPECT().IsNotExist(gomock.Any()).
			Return(false)
		err := vtd.DeleteMapping(validVolumeID)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("DeleteMapping - not exist", func(t *testing.T) {
		osMock.EXPECT().Remove(path.Join(vtd.DataDir, validVolumeID)).
			Return(errors.New(testErrMsg))
		osMock.EXPECT().IsNotExist(gomock.Any()).
			Return(true)
		err := vtd.DeleteMapping(validVolumeID)
		assert.Nil(t, err)
	})
}
