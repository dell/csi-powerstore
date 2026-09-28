/*
 *
 * Copyright © 2021-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	log "github.com/dell/csmlog"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"k8s.io/client-go/tools/record"

	"github.com/dell/gobrick"
	"github.com/dell/gofsutil"
	"github.com/golang/mock/gomock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var validBaseVolID = "39bb1b5f-5624-490d-9ece-18f7b28a904e"

func getValidPublishContext() map[string]string {
	return map[string]string{
		identifiers.TargetMapLUNAddress:                 validLUNID,
		identifiers.TargetMapDeviceWWN:                  validDeviceWWN,
		identifiers.TargetMapISCSIPortalsPrefix + "0":   validISCSIPortals[0],
		identifiers.TargetMapISCSIPortalsPrefix + "1":   validISCSIPortals[1],
		identifiers.TargetMapISCSITargetsPrefix + "0":   validISCSITargets[0],
		identifiers.TargetMapISCSITargetsPrefix + "1":   validISCSITargets[1],
		identifiers.TargetMapNVMEFCPortalsPrefix + "0":  validNVMEFCPortals[0],
		identifiers.TargetMapNVMEFCPortalsPrefix + "1":  validNVMEFCPortals[1],
		identifiers.TargetMapNVMEFCTargetsPrefix + "0":  validNVMEFCTargets[0],
		identifiers.TargetMapNVMEFCTargetsPrefix + "1":  validNVMEFCTargets[1],
		identifiers.TargetMapNVMETCPPortalsPrefix + "0": validNVMETCPPortals[0],
		identifiers.TargetMapNVMETCPPortalsPrefix + "1": validNVMETCPPortals[1],
		identifiers.TargetMapNVMETCPTargetsPrefix + "0": validNVMETCPTargets[0],
		identifiers.TargetMapNVMETCPTargetsPrefix + "1": validNVMETCPTargets[1],
		identifiers.TargetMapFCWWPNPrefix + "0":         validFCTargetsWWPN[0],
		identifiers.TargetMapFCWWPNPrefix + "1":         validFCTargetsWWPN[1],
	}
}

func getValidUniformMetroPublishContext() map[string]string {
	publishContext := getValidPublishContext()
	publishContext[identifiers.TargetMapRemoteLUNAddress] = validLUNID
	publishContext[identifiers.TargetMapRemoteDeviceWWN] = validDeviceWWN
	publishContext[identifiers.TargetMapRemoteISCSIPortalsPrefix+"0"] = validRemoteISCSIPortals[0]
	publishContext[identifiers.TargetMapRemoteISCSIPortalsPrefix+"1"] = validRemoteISCSIPortals[1]
	publishContext[identifiers.TargetMapRemoteISCSITargetsPrefix+"0"] = validRemoteISCSITargets[0]
	publishContext[identifiers.TargetMapRemoteISCSITargetsPrefix+"1"] = validRemoteISCSITargets[1]
	publishContext[identifiers.TargetMapRemoteFCWWPNPrefix+"0"] = validRemoteFCTargetsWWPN[0]
	publishContext[identifiers.TargetMapRemoteFCWWPNPrefix+"1"] = validRemoteFCTargetsWWPN[1]

	return publishContext
}

// getValidRemoteMetroPublishContext contains an empty local publish context
// and a populated remote publish context.
func getValidRemoteMetroPublishContext() map[string]string {
	publishContext := make(map[string]string)
	publishContext[identifiers.TargetMapRemoteLUNAddress] = validLUNID
	publishContext[identifiers.TargetMapRemoteDeviceWWN] = validDeviceWWN
	publishContext[identifiers.TargetMapRemoteISCSIPortalsPrefix+"0"] = validRemoteISCSIPortals[0]
	publishContext[identifiers.TargetMapRemoteISCSIPortalsPrefix+"1"] = validRemoteISCSIPortals[1]
	publishContext[identifiers.TargetMapRemoteISCSITargetsPrefix+"0"] = validRemoteISCSITargets[0]
	publishContext[identifiers.TargetMapRemoteISCSITargetsPrefix+"1"] = validRemoteISCSITargets[1]
	publishContext[identifiers.TargetMapRemoteFCWWPNPrefix+"0"] = validRemoteFCTargetsWWPN[0]
	publishContext[identifiers.TargetMapRemoteFCWWPNPrefix+"1"] = validRemoteFCTargetsWWPN[1]

	return publishContext
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

func scsiStageVolumeOK(util *mocks.UtilInterface, fs *mocks.FsInterface) {
	util.On("BindMount", mock.Anything, "/dev", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(nil)
	fs.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
	fs.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)
	fs.On("MkFileIdempotent", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(true, nil)
	fs.On("GetUtil").Return(util)
}

func scsiStageVolumeFail(util *mocks.UtilInterface, fs *mocks.FsInterface) {
	util.On("BindMount", mock.Anything, "/dev", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(nil)
	fs.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, errors.New("mock staging failure")).Once()
}

func scsiStageRemoteMetroVolumeOK(util *mocks.UtilInterface, fs *mocks.FsInterface) {
	util.On("BindMount", mock.Anything, "/dev", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(nil)
	fs.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
	fs.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)
	fs.On("MkFileIdempotent", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(true, nil)
	fs.On("GetUtil").Return(util)
}

// setDefaultClientMocks sets default mock values for gopowerstore client, no matter what protocol is used, the mocks needed are the same
func setDefaultClientMocks() {
	clientMock.On("GetVolume", mock.Anything, validBaseVolID).
		Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

	clientMock.On("GetVolume", mock.Anything, validRemoteVolID).
		Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

	clientMock.On("GetCluster", mock.Anything).
		Return(gopowerstore.Cluster{Name: validClusterName}, nil)

	clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
		Return([]gopowerstore.IPPoolAddress{
			{
				Address: "192.168.1.1",
				IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
			},
		}, nil)
	clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
		Return([]gopowerstore.IPPoolAddress{
			{
				Address: "192.168.1.1",
				IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
			},
		}, nil)
	clientMock.On("GetFCPorts", mock.Anything).
		Return([]gopowerstore.FcPort{
			{
				IsLinkUp: true,
				Wwn:      "58:cc:f0:93:48:a0:03:a3",
				WwnNVMe:  "58ccf091492b0c22",
				WwnNode:  "58ccf090c9200c22",
			},
		}, nil)
}

func setCustomClientMocks(iscsiTargets string, wwn string, nvmeTCPTargets string, nvmeNqn string) {
	// for any given item, return an error if the item is not set
	if iscsiTargets == "" {
		clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return(nil, errors.New("error"))
	} else {
		clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "192.168.1.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: iscsiTargets},
				},
			}, nil)
	}

	if wwn == "" {
		clientMock.On("GetFCPorts", mock.Anything).
			Return(nil, errors.New("error"))
	} else {
		clientMock.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{
				{
					IsLinkUp: true,
					Wwn:      wwn,
					WwnNVMe:  wwn,
					WwnNode:  wwn,
				},
			}, nil)
	}

	if nvmeTCPTargets == "" {
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return(nil, errors.New("error"))
	} else {
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "192.168.1.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: nvmeTCPTargets},
				},
			}, nil)
	}

	// always set the cluster value
	clientMock.On("GetCluster", mock.Anything).
		Return(gopowerstore.Cluster{Name: validClusterName, NVMeNQN: nvmeNqn}, nil)
}

func TestSCSIStager_Stage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("iscsi -- success test", func(t *testing.T) {
		setVariables()
		setDefaultClientMocks()
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          false,
			useNVME:        false,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		iscsiConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything).Return(gobrick.Device{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, false, clientMock)
		assert.Nil(t, err)
	})

	t.Run("nvmefc -- success test", func(t *testing.T) {
		setVariables()
		setDefaultClientMocks()
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          true,
			useNVME:        true,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		nvmeConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything, true).Return(gobrick.Device{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)

		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, false, clientMock)

		assert.Nil(t, err)
	})

	t.Run("nvmetcp -- success test", func(t *testing.T) {
		setVariables()
		setDefaultClientMocks()
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          false,
			useNVME:        true,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		nvmeConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything, false).Return(gobrick.Device{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, false, clientMock)

		assert.Nil(t, err)
	})

	// originally a test for publisher, the logic and corresponding test for checking targets is now in the stager, so this test has been moved here
	t.Run("no protocols can be used", func(t *testing.T) {
		setVariables()
		client := new(gopowerstoremock.Client)
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          false,
			useNVME:        false,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		e := errors.New("unable to get targets for any protocol")
		client.On("GetVolume", mock.Anything, validBaseVolID).
			Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)
		client.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		iscsiConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything).Return(gobrick.Device{}, nil)
		client.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, e)
		client.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, e)
		client.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, false, client)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "unable to get targets for any protocol")
	})
	t.Run("nvmeFC is specified but cannot be used", func(t *testing.T) {
		setVariables()
		client := new(gopowerstoremock.Client)
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          true,
			useNVME:        true,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		e := errors.New("unable to get targets for any protocol")
		client.On("GetVolume", mock.Anything, validBaseVolID).
			Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)
		client.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		nvmeConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything).Return(gobrick.Device{}, nil)
		client.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, e)
		client.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "192.168.1.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
				},
			}, nil)
		client.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, false, client)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "NVMeFC Targets data must be in publish context")
	})
	t.Run("nvmeTCP is specified but cannot be used", func(t *testing.T) {
		setVariables()
		client := new(gopowerstoremock.Client)
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          false,
			useNVME:        true,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		e := errors.New("unable to get targets for any protocol")
		client.On("GetVolume", mock.Anything, validBaseVolID).
			Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)
		client.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		nvmeConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything).Return(gobrick.Device{}, nil)
		client.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, e)
		client.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, e)
		client.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{
				{
					IsLinkUp: true,
					Wwn:      "58:cc:f0:93:48:a0:03:a3",
					WwnNVMe:  "58ccf091492b0c22",
					WwnNode:  "58ccf090c9200c22",
				},
			}, nil)
		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, false, client)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "NVMeTCP Targets data must be in publish context")
	})
	t.Run("iscsi is specified but cannot be used", func(t *testing.T) {
		setVariables()
		client := new(gopowerstoremock.Client)
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          false,
			useNVME:        false,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		e := errors.New("unable to get targets for any protocol")
		client.On("GetVolume", mock.Anything, validBaseVolID).
			Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)
		client.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		iscsiConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything).Return(gobrick.Device{}, nil)
		client.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, e)
		client.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, e)
		client.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{
				{
					IsLinkUp: true,
					Wwn:      "58:cc:f0:93:48:a0:03:a3",
					WwnNVMe:  "58ccf091492b0c22",
					WwnNode:  "58ccf090c9200c22",
				},
			}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, false, client)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "iscsiTargets data must be in publish context")
	})
	t.Run("fc is specified but cannot be used", func(t *testing.T) {
		setVariables()
		client := new(gopowerstoremock.Client)
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          true,
			useNVME:        false,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		e := errors.New("unable to get targets for any protocol")
		client.On("GetVolume", mock.Anything, validBaseVolID).
			Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)
		client.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		nvmeConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything).Return(gobrick.Device{}, nil)
		client.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, e)
		client.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "192.168.1.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
				},
			}, nil)
		client.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, false, client)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "fcTargets data must be in publish context")
	})

	t.Run("remote device already staged - should connect device but skip bind-mount", func(t *testing.T) {
		setVariables()
		setDefaultClientMocks()
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          false,
			useNVME:        false,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		// Mock connectDevice to be called for remote device connection
		iscsiConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything).Return(gobrick.Device{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		// Mock the scenario where device is already staged (ready=true)
		// This simulates the isReadyToPublish returning found=true, ready=true
		stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
		fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
		fsMock.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{
			{
				Source: "/dev/sdx",  // Valid device path (not "deleted")
				Path:   stagingPath, // The staging path is already mounted
			},
		}, nil)
		fsMock.On("GetUtil").Return(utilMock)
		// Mock GetDiskFormat to return something other than "mpath_member" to indicate ready=true
		utilMock.On("GetDiskFormat", mock.Anything, mock.Anything).Return("ext4", nil)

		// Call Stage with isRemote=true
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidRemoteMetroPublishContext(), // Use remote publish context
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, true, clientMock) // isRemote=true

		assert.Nil(t, err)
		// Verify that connectDevice was called (this is the key behavior we're testing)
		iscsiConnectorMock.AssertCalled(t, "ConnectVolume", mock.Anything, mock.Anything)
		// Verify that BindMount was NOT called (should be skipped for remote already staged devices)
		utilMock.AssertNotCalled(t, "BindMount", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("remote device connection failure - should return error", func(t *testing.T) {
		setVariables()
		setDefaultClientMocks()
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmeConnectorMock := new(mocks.NVMEConnector)

		stager := &SCSIStager{
			useFC:          false,
			useNVME:        false,
			iscsiConnector: iscsiConnectorMock,
			nvmeConnector:  nvmeConnectorMock,
			fcConnector:    fcConnectorMock,
		}

		// Mock connectDevice to fail for remote device connection
		connectErr := errors.New("failed to connect remote device")
		iscsiConnectorMock.On("ConnectVolume", mock.Anything, mock.Anything).Return(gobrick.Device{}, connectErr)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		// Mock the scenario where device is already staged (ready=true)
		stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
		fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
		fsMock.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{
			{
				Source: "/dev/sdx",  // Valid device path (not "deleted")
				Path:   stagingPath, // The staging path is already mounted
			},
		}, nil)
		fsMock.On("GetUtil").Return(utilMock)
		// Mock GetDiskFormat to return something other than "mpath_member" to indicate ready=true
		utilMock.On("GetDiskFormat", mock.Anything, mock.Anything).Return("ext4", nil)

		// Call Stage with isRemote=true
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeHandle,
			PublishContext:    getValidRemoteMetroPublishContext(), // Use remote publish context
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none",
			),
		}, filepath.Join(nodeStagePrivateDir, validBaseVolumeID), "node-1", log.Fields{}, fsMock, validBaseVolumeID, true, clientMock) // isRemote=true

		// Should now return error when remote device connection fails
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to connect remote device")
		// Verify that connectDevice was called and failed
		iscsiConnectorMock.AssertCalled(t, "ConnectVolume", mock.Anything, mock.Anything)
		// Verify that BindMount was NOT called (should be skipped for remote already staged devices)
		utilMock.AssertNotCalled(t, "BindMount", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestSCSIStager_getLunAddressFromArray(t *testing.T) {
	tests := []struct {
		name                     string
		getHostByNameFunc        func(ctx context.Context, name string) (gopowerstore.Host, error)
		getHostVolumeMappingFunc func(ctx context.Context, volumeID string) ([]gopowerstore.HostVolumeMapping, error)
		volumeID                 string
		nodeID                   string
		want                     string
		wantErr                  bool
	}{
		{
			name: "valid array and volume",
			getHostByNameFunc: func(_ context.Context, _ string) (gopowerstore.Host, error) {
				return gopowerstore.Host{
					ID:         validHostID,
					Initiators: []gopowerstore.InitiatorInstance{},
					Name:       "host-name",
				}, nil
			},
			getHostVolumeMappingFunc: func(_ context.Context, _ string) ([]gopowerstore.HostVolumeMapping, error) {
				return []gopowerstore.HostVolumeMapping{
					{HostID: validHostID, LogicalUnitNumber: validLUNIDINT},
				}, nil
			},
			volumeID: "valid-volume-id",
			nodeID:   validHostID,
			want:     validLUNID,
			wantErr:  false,
		},
		{
			name: "invalid volume ID",
			getHostByNameFunc: func(_ context.Context, _ string) (gopowerstore.Host, error) {
				return gopowerstore.Host{
					ID:         validHostID,
					Initiators: []gopowerstore.InitiatorInstance{},
					Name:       "host-name",
				}, nil
			},
			getHostVolumeMappingFunc: func(_ context.Context, _ string) ([]gopowerstore.HostVolumeMapping, error) {
				return nil, errors.New("invalid volume ID")
			},
			volumeID: "invalid-volume-id",
			nodeID:   "valid-node-id",
			want:     "",
			wantErr:  true,
		},
		{
			name: "host not found",
			getHostByNameFunc: func(_ context.Context, _ string) (gopowerstore.Host, error) {
				return gopowerstore.Host{}, errors.New("invalid host")
			},
			getHostVolumeMappingFunc: func(_ context.Context, _ string) ([]gopowerstore.HostVolumeMapping, error) {
				return []gopowerstore.HostVolumeMapping{
					{HostID: validHostID, LogicalUnitNumber: validLUNIDINT},
				}, nil
			},
			volumeID: "valid-volume-id",
			nodeID:   "valid-node-id",
			want:     "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientMock.ExpectedCalls = nil // reset previous expectations

			// Mock GetHostByName using closures
			clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
				Return(func(ctx context.Context, name string) gopowerstore.Host {
					host, _ := tt.getHostByNameFunc(ctx, name)
					return host
				}, func(ctx context.Context, name string) error {
					_, err := tt.getHostByNameFunc(ctx, name)
					return err
				})

			// Mock GetHostVolumeMappingByVolumeID using closures
			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, mock.AnythingOfType("string")).
				Return(func(ctx context.Context, volumeID string) []gopowerstore.HostVolumeMapping {
					mapping, _ := tt.getHostVolumeMappingFunc(ctx, volumeID)
					return mapping
				}, func(ctx context.Context, volumeID string) error {
					_, err := tt.getHostVolumeMappingFunc(ctx, volumeID)
					return err
				})

			// Call the method under test
			got, err := getLunAddressFromArray(context.Background(), clientMock, tt.volumeID, tt.nodeID)

			// Validate error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("getLunAddressFromArray() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Validate result
			if got != tt.want {
				t.Errorf("getLunAddressFromArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSCSIStager_AddTargetsInfoToMap(t *testing.T) {
	tests := []struct {
		name               string
		isRemote           bool
		volumeApplianceID  string
		iscsiTargetsInfo   string
		fcWwn              string
		nvmeNqn            string
		nvmeTCPTargetsInfo string
		expectedTargetMap  map[string]string
		expectErr          bool
	}{
		{
			name:               "local targets - all",
			isRemote:           false,
			volumeApplianceID:  "", // should be empty in most cases
			iscsiTargetsInfo:   "test",
			fcWwn:              "testWwn",
			nvmeNqn:            "testNqn",
			nvmeTCPTargetsInfo: "test2", // only determines if NVME TCP will be added to mock/error out, value will be nvmeNqn
			expectedTargetMap: map[string]string{
				identifiers.TargetMapISCSIPortalsPrefix + "0":   "192.168.1.1",
				identifiers.TargetMapISCSITargetsPrefix + "0":   "test",
				identifiers.TargetMapFCWWPNPrefix + "0":         "testWwn",
				identifiers.TargetMapNVMEFCPortalsPrefix + "0":  "nn-0xtestWwn:pn-0xtestWwn",
				identifiers.TargetMapNVMEFCTargetsPrefix + "0":  "testNqn",
				identifiers.TargetMapNVMETCPPortalsPrefix + "0": "192.168.1.1",
				identifiers.TargetMapNVMETCPTargetsPrefix + "0": "testNqn",
			},
			expectErr: false,
		},
		{
			name:              "fail to get NVME and FC targets but ISCSI succeeds",
			isRemote:          false,
			volumeApplianceID: "", // should be empty in most cases
			iscsiTargetsInfo:  "test",
			fcWwn:             "",
			nvmeNqn:           "",
			expectedTargetMap: map[string]string{
				identifiers.TargetMapISCSIPortalsPrefix + "0": "192.168.1.1",
				identifiers.TargetMapISCSITargetsPrefix + "0": "test",
			},
			expectErr: false,
		},
		{
			name:              "fail to get all targets",
			isRemote:          false,
			volumeApplianceID: "", // should be empty in most cases
			iscsiTargetsInfo:  "",
			fcWwn:             "",
			nvmeNqn:           "",
			expectedTargetMap: map[string]string{},
			expectErr:         true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// set the variables before each run
			setVariables()

			// put test-specificvalues into the client mock
			setCustomClientMocks(test.iscsiTargetsInfo, test.fcWwn, test.nvmeTCPTargetsInfo, test.nvmeNqn)

			// fill any values that are not set by custom
			// note: mock.On will not override previous values with mock.anything
			setDefaultClientMocks()

			targetMap := make(map[string]string)
			stager := &SCSIStager{}
			err := stager.AddTargetsInfoToMap(targetMap, test.volumeApplianceID, clientMock, test.isRemote)
			fmt.Println("Actual map: ")
			fmt.Println(targetMap)

			// if there was an error and we expected none, fail
			if err != nil && test.expectErr == false {
				t.Errorf("AddTargetsInfoToMap returned unexpected error: %v", err)
			}

			// if there was no error and we expected one, fail
			if test.expectErr {
				assert.NotNil(t, err)
			}

			// if the returned map doesn't match what was expected, fail
			if !reflect.DeepEqual(targetMap, test.expectedTargetMap) {
				t.Errorf("AddTargetsInfoToMap returned unexpected target map. Expected: %+v, Actual: %+v", test.expectedTargetMap, targetMap)
			}
		})
	}
}

// --- NFS Auto-Select Tests (Phase 2: NodeStage) ---

// nfsAutoSelectTestHelper creates a standard NFSStager with auto-select enabled,
// sets up common mock expectations, and returns everything needed for a test.
func nfsAutoSelectTestHelper(t *testing.T) (
	*NFSStager, *mocks.FsInterface, *mocks.UtilInterface, *gopowerstoremock.Client,
) {
	t.Helper()
	setVariables()

	testClient := new(gopowerstoremock.Client)
	testFsMock := new(mocks.FsInterface)
	testUtilMock := new(mocks.UtilInterface)

	testArr := &array.PowerStoreArray{
		Endpoint: "https://192.168.0.2/api/rest",
		GlobalID: secondGlobalID,
		Client:   testClient,
		IP:       "192.168.0.2",
	}

	stager := &NFSStager{
		array:         testArr,
		nfsAutoSelect: true,
		nodeID:        validNodeID,
		managementIP:  "192.168.0.2",
	}
	return stager, testFsMock, testUtilMock, testClient
}

// nfsStageRequest builds a standard NodeStageVolumeRequest for NFS auto-select tests.
func nfsStageRequest(publishCtx map[string]string) *csi.NodeStageVolumeRequest {
	return &csi.NodeStageVolumeRequest{
		VolumeId:          validNfsVolumeID,
		PublishContext:    publishCtx,
		StagingTargetPath: nodeStagePrivateDir,
		VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "multiple-writer", "nfs"),
	}
}

// setupNFSMountMocks sets up standard mock expectations for a successful NFS mount.
func setupNFSMountMocks(fsMock *mocks.FsInterface, utilMock *mocks.UtilInterface, stagingPath, nfsExportPath string) {
	fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
	fsMock.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)
	fsMock.On("MkdirAll", stagingPath, mock.Anything).Return(nil).Once()
	fsMock.On("MkdirAll", filepath.Join(stagingPath, commonNfsVolumeFolder), mock.Anything).Return(nil).Once()
	fsMock.On("Chmod", filepath.Join(stagingPath, commonNfsVolumeFolder), os.ModeSticky|os.ModePerm).Return(nil)
	utilMock.On("Mount", mock.Anything, nfsExportPath, stagingPath, "").Return(nil)
	fsMock.On("GetUtil").Return(utilMock)
}

func TestNFSStager_AutoSelect_HappyPath(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	// Mock getOutboundIP — NetDial returns a connection with a different IP (storage NIC)
	conn, _ := net.Dial("udp", "10.20.30.40:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	// Mock GetNFSExport for host-limit check
	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID:          "export-1",
			RWRootHosts: []string{},
			RWHosts:     []string{},
			ROHosts:     []string{},
			RORootHosts: []string{},
		}, nil)

	// Mock ModifyNFSExport for adding discovered IP
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)

	// Mock WriteFile for metadata persistence
	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)

	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	// Verify ModifyNFSExport was called with AddRWRootHosts (default when allowRoot != "false")
	testClient.AssertCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, "export-1")
	// Verify metadata file was written
	fsMock.AssertCalled(t, "WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything)
}

func TestNFSStager_AutoSelect_IPv6HostEntry(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)
	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "[2001:db8::16]:/test-export"

	conn, err := net.Dial("udp", "[::1]:80")
	assert.NoError(t, err)
	defer func() { _ = conn.Close() }()
	fsMock.On("NetDial", "2001:db8::16").Return(conn, nil)
	testClient.On("GetNFSExport", mock.Anything, "export-1").Return(gopowerstore.NFSExport{ID: "export-1"}, nil)
	testClient.On("ModifyNFSExport", mock.Anything, mock.MatchedBy(func(req *gopowerstore.NFSExportModify) bool {
		return len(req.AddRWRootHosts) == 1 && req.AddRWRootHosts[0] == "::1/128"
	}), "export-1").Return(gopowerstore.CreateResponse{}, nil)
	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}
	_, err = stager.Stage(context.Background(), nfsStageRequest(publishCtx), stagingPath,
		validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)
	assert.NoError(t, err)
}

func TestNFSStager_AutoSelect_AllowRootFalse(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	conn, _ := net.Dial("udp", "10.20.30.40:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID:          "export-1",
			RWRootHosts: []string{},
			RWHosts:     []string{},
			ROHosts:     []string{},
			RORootHosts: []string{},
		}, nil)

	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)

	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "false",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)

	// Verify the FIRST ModifyNFSExport call (auto-select) used AddRWHosts, not AddRWRootHosts
	foundAutoSelectCall := false
	for _, call := range testClient.Calls {
		if call.Method == "ModifyNFSExport" && !foundAutoSelectCall {
			modifyArg := call.Arguments.Get(1).(*gopowerstore.NFSExportModify)
			assert.NotEmpty(t, modifyArg.AddRWHosts, "auto-select should add to RWHosts when allowRoot=false")
			assert.Empty(t, modifyArg.AddRWRootHosts, "auto-select should NOT add to RWRootHosts when allowRoot=false")
			foundAutoSelectCall = true
		}
	}
	assert.True(t, foundAutoSelectCall, "expected at least one ModifyNFSExport call from auto-select")
}

func TestNFSStager_AutoSelect_ExclusiveAccessSkipped(t *testing.T) {
	// When exclusiveAccess=true, the controller does NOT set NfsAutoSelect=true in
	// publishContext. This test verifies the node skips auto-select when that key is absent.
	stager, testFsMock, testUtilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	setupNFSMountMocks(testFsMock, testUtilMock, stagingPath, nfsExportPath)

	// Note: NfsAutoSelect is NOT in publishContext (controller suppressed it)
	publishCtx := map[string]string{
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
		identifiers.KeyHostIP:        "127.0.0.1",
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, testFsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	// No auto-select operations should have occurred
	testClient.AssertNotCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, mock.Anything)
	testClient.AssertNotCalled(t, "GetNFSExport", mock.Anything, mock.Anything)
	testFsMock.AssertNotCalled(t, "NetDial", mock.Anything)
}

func TestNFSStager_AutoSelect_MissingNfsExportPath(t *testing.T) {
	stager, fsMock, _, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)

	fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
	fsMock.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)

	// Missing NfsExportPath key
	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
	}

	_, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "NfsExportPath")
}

func TestNFSStager_AutoSelect_EmptyIPInExportPath(t *testing.T) {
	stager, fsMock, _, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)

	fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
	fsMock.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)

	// NfsExportPath with empty IP component
	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: ":/test-export",
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
	}

	_, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "empty IP")
}

func TestNFSStager_AutoSelect_HostAlreadyPresent(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	conn, _ := net.Dial("udp", "10.20.30.40:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID:          "export-1",
			RWRootHosts: []string{},
			RWHosts:     []string{},
			ROHosts:     []string{},
			RORootHosts: []string{},
		}, nil)

	// ModifyNFSExport returns HostAlreadyPresent error (HTTP 400)
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
			ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
		})

	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	// HostAlreadyPresent should be treated as success
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	// Metadata should still be written
	fsMock.AssertCalled(t, "WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything)
}

func TestNFSStager_AutoSelect_HardErrorFallback(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	// NetDial fails — triggers hard-error fallback to kubeNodeID IP
	fsMock.On("NetDial", mock.Anything).Return(nil, errors.New("network unreachable"))

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID:          "export-1",
			RWRootHosts: []string{},
			RWHosts:     []string{},
			ROHosts:     []string{},
			RORootHosts: []string{},
		}, nil)

	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)

	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	// Should succeed via fallback
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	// ModifyNFSExport should still have been called (with fallback IP)
	testClient.AssertCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, "export-1")
}

func TestNFSStager_AutoSelect_ExportHostLimitWarning(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	conn, _ := net.Dial("udp", "10.20.30.40:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	// Create an export with >100 host entries to trigger the warning
	hosts := make([]string, 101)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("10.0.0.%d/255.255.255.255", i)
	}

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID:          "export-1",
			RWRootHosts: hosts,
			RWHosts:     []string{},
			ROHosts:     []string{},
			RORootHosts: []string{},
		}, nil)

	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)

	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	// Should succeed — warning doesn't block the operation
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	testClient.AssertCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, "export-1")
}

func TestNFSStager_AutoSelect_MetadataWriteFailure(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	conn, _ := net.Dial("udp", "10.20.30.40:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID:          "export-1",
			RWRootHosts: []string{},
			RWHosts:     []string{},
			ROHosts:     []string{},
			RORootHosts: []string{},
		}, nil)

	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)

	// WriteFile fails — should log WARN but still proceed with mount
	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).
		Return(errors.New("disk full"))
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	// Should succeed despite metadata write failure
	assert.Nil(t, err)
	assert.NotNil(t, resp)
}

func TestNFSStager_AutoSelect_DisabledMode(t *testing.T) {
	setVariables()

	testClient := new(gopowerstoremock.Client)
	testFsMock := new(mocks.FsInterface)
	testUtilMock := new(mocks.UtilInterface)

	testArr := &array.PowerStoreArray{
		Endpoint: "https://192.168.0.2/api/rest",
		GlobalID: secondGlobalID,
		Client:   testClient,
		IP:       "192.168.0.2",
	}

	// nfsAutoSelect is false — disabled mode
	stager := &NFSStager{
		array:         testArr,
		nfsAutoSelect: false,
		nodeID:        validNodeID,
		managementIP:  "192.168.0.2",
	}

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	setupNFSMountMocks(testFsMock, testUtilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
		identifiers.KeyHostIP:        "127.0.0.1",
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, testFsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	// No auto-select operations should have occurred
	testFsMock.AssertNotCalled(t, "NetDial", mock.Anything)
	testClient.AssertNotCalled(t, "GetNFSExport", mock.Anything, mock.Anything)
	testFsMock.AssertNotCalled(t, "WriteFile", mock.Anything, mock.Anything, mock.Anything)
}

// --- NFS Auto-Select Cleanup Tests (Phase 3: NodeUnstage) ---

func TestNFSAutoSelectCleanup_HappyPath(t *testing.T) {
	setVariables()

	testClient := new(gopowerstoremock.Client)
	testFsMock := new(mocks.FsInterface)
	testArr := &array.PowerStoreArray{
		Endpoint: "https://192.168.0.2/api/rest",
		GlobalID: secondGlobalID,
		Client:   testClient,
		IP:       "192.168.0.2",
	}

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	metadataPath := stagingPath + ".nfs-autoselect.json"

	// Metadata file exists with valid content
	metadata := `{"nasIP":"10.20.30.40","exportID":"export-1","discoveredNodeIP":"10.247.97.234","nasName":"my-nas-name","hostsListType":"RWRootHosts"}`
	testFsMock.On("ReadFile", metadataPath).Return([]byte(metadata), nil)

	// ModifyNFSExport to remove the discovered IP
	testClient.On("ModifyNFSExport", mock.Anything, mock.MatchedBy(func(req *gopowerstore.NFSExportModify) bool {
		return len(req.RemoveRWRootHosts) == 1 && req.RemoveRWRootHosts[0] == "10.247.97.234/255.255.255.255"
	}), "export-1").Return(gopowerstore.CreateResponse{}, nil)

	// Remove metadata file
	testFsMock.On("Remove", metadataPath).Return(nil)

	handleNFSAutoSelectCleanup(context.Background(), stagingPath, testArr, testFsMock, log.Fields{})

	testClient.AssertCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, "export-1")
	testFsMock.AssertCalled(t, "Remove", metadataPath)
}

func TestNFSAutoSelectCleanup_NoMetadataFile(t *testing.T) {
	setVariables()

	testFsMock := new(mocks.FsInterface)
	testArr := &array.PowerStoreArray{
		Endpoint: "https://192.168.0.2/api/rest",
		GlobalID: secondGlobalID,
		Client:   new(gopowerstoremock.Client),
		IP:       "192.168.0.2",
	}

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	metadataPath := stagingPath + ".nfs-autoselect.json"

	// Metadata file does not exist
	testFsMock.On("ReadFile", metadataPath).Return(nil, os.ErrNotExist)

	handleNFSAutoSelectCleanup(context.Background(), stagingPath, testArr, testFsMock, log.Fields{})

	// No export modification should occur
	testArr.Client.(*gopowerstoremock.Client).AssertNotCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, mock.Anything)
}

func TestNFSAutoSelectCleanup_RWHostsListType(t *testing.T) {
	setVariables()

	testClient := new(gopowerstoremock.Client)
	testFsMock := new(mocks.FsInterface)
	testArr := &array.PowerStoreArray{
		Endpoint: "https://192.168.0.2/api/rest",
		GlobalID: secondGlobalID,
		Client:   testClient,
		IP:       "192.168.0.2",
	}

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	metadataPath := stagingPath + ".nfs-autoselect.json"

	// Metadata with RWHosts (root squashing was enabled)
	metadata := `{"nasIP":"10.20.30.40","exportID":"export-1","discoveredNodeIP":"10.247.97.234","nasName":"my-nas-name","hostsListType":"RWHosts"}`
	testFsMock.On("ReadFile", metadataPath).Return([]byte(metadata), nil)

	// Verify ModifyNFSExport uses RemoveRWHosts (not RemoveRWRootHosts)
	testClient.On("ModifyNFSExport", mock.Anything, mock.MatchedBy(func(req *gopowerstore.NFSExportModify) bool {
		return len(req.RemoveRWHosts) == 1 && req.RemoveRWHosts[0] == "10.247.97.234/255.255.255.255"
	}), "export-1").Return(gopowerstore.CreateResponse{}, nil)

	testFsMock.On("Remove", metadataPath).Return(nil)

	handleNFSAutoSelectCleanup(context.Background(), stagingPath, testArr, testFsMock, log.Fields{})
	testClient.AssertCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, "export-1")
}

func TestNFSAutoSelectCleanup_ExportModifyFails(t *testing.T) {
	setVariables()

	testClient := new(gopowerstoremock.Client)
	testFsMock := new(mocks.FsInterface)
	testArr := &array.PowerStoreArray{
		Endpoint: "https://192.168.0.2/api/rest",
		GlobalID: secondGlobalID,
		Client:   testClient,
		IP:       "192.168.0.2",
	}

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	metadataPath := stagingPath + ".nfs-autoselect.json"

	metadata := `{"nasIP":"10.20.30.40","exportID":"export-1","discoveredNodeIP":"10.247.97.234","nasName":"my-nas-name","hostsListType":"RWRootHosts"}`
	testFsMock.On("ReadFile", metadataPath).Return([]byte(metadata), nil)

	// ModifyNFSExport fails with a non-NotFound error
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, errors.New("connection refused"))

	// Metadata file should still be removed on best-effort
	testFsMock.On("Remove", metadataPath).Return(nil)

	handleNFSAutoSelectCleanup(context.Background(), stagingPath, testArr, testFsMock, log.Fields{})
	testFsMock.AssertCalled(t, "Remove", metadataPath)
}

func TestNFSAutoSelectCleanup_ExportNotFound(t *testing.T) {
	setVariables()

	testClient := new(gopowerstoremock.Client)
	testFsMock := new(mocks.FsInterface)
	testArr := &array.PowerStoreArray{
		Endpoint: "https://192.168.0.2/api/rest",
		GlobalID: secondGlobalID,
		Client:   testClient,
		IP:       "192.168.0.2",
	}

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	metadataPath := stagingPath + ".nfs-autoselect.json"

	metadata := `{"nasIP":"10.20.30.40","exportID":"export-1","discoveredNodeIP":"10.247.97.234","nasName":"my-nas-name","hostsListType":"RWRootHosts"}`
	testFsMock.On("ReadFile", metadataPath).Return([]byte(metadata), nil)

	// Export was already deleted — NotFound error
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
			ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound},
		})

	testFsMock.On("Remove", metadataPath).Return(nil)

	handleNFSAutoSelectCleanup(context.Background(), stagingPath, testArr, testFsMock, log.Fields{})
	testFsMock.AssertCalled(t, "Remove", metadataPath)
}

func TestNFSAutoSelectCleanup_MalformedMetadata(t *testing.T) {
	setVariables()

	testFsMock := new(mocks.FsInterface)
	testArr := &array.PowerStoreArray{
		Endpoint: "https://192.168.0.2/api/rest",
		GlobalID: secondGlobalID,
		Client:   new(gopowerstoremock.Client),
		IP:       "192.168.0.2",
	}

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	metadataPath := stagingPath + ".nfs-autoselect.json"

	// Malformed JSON
	testFsMock.On("ReadFile", metadataPath).Return([]byte("{{not json"), nil)
	testFsMock.On("Remove", metadataPath).Return(nil)

	handleNFSAutoSelectCleanup(context.Background(), stagingPath, testArr, testFsMock, log.Fields{})
	// Metadata file should still be removed
	testFsMock.AssertCalled(t, "Remove", metadataPath)
}

// G-3: Flat-network fallback test
func TestNFSStager_AutoSelect_FlatNetworkFallback(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"
	metadataPath := stagingPath + ".nfs-autoselect.json"

	managementIP := "192.168.0.2"

	// Mock NetDial to return management IP (flat network)
	conn, _ := net.Dial("udp", managementIP+":80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	// Mock GetNFSExport for host-limit check
	testClient.On("GetNFSExport", mock.Anything, "export-1").
		Return(gopowerstore.NFSExport{
			ID:          "export-1",
			RWRootHosts: []string{},
			RWHosts:     []string{},
			ROHosts:     []string{},
			RORootHosts: []string{},
		}, nil)

	// Mock ModifyNFSExport for adding fallback IP
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)

	// Mock WriteFile for metadata persistence
	fsMock.On("WriteFile", metadataPath, mock.Anything, mock.Anything).Return(nil)

	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	// Verify ModifyNFSExport was called with fallback IP
	testClient.AssertCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, "export-1")
	// Verify metadata file was written
	fsMock.AssertCalled(t, "WriteFile", metadataPath, mock.Anything, mock.Anything)
}

// G-5: ModifyNFSExport 500 error test
func TestNFSStager_AutoSelect_ModifyExportFatalError(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"
	metadataPath := stagingPath + ".nfs-autoselect.json"

	// Mock NetDial to return discovered IP
	conn, _ := net.Dial("udp", "10.20.30.103:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	// Mock GetNFSExport for host-limit check
	testClient.On("GetNFSExport", mock.Anything, "export-1").
		Return(gopowerstore.NFSExport{
			ID:          "export-1",
			RWRootHosts: []string{},
			RWHosts:     []string{},
			ROHosts:     []string{},
			RORootHosts: []string{},
		}, nil)

	// Mock ModifyNFSExport to return 500 error (not HostAlreadyPresent)
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, errors.New("internal server error"))

	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	// Should return error for fatal ModifyNFSExport failure
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "internal server error")
	// Metadata file should NOT be written on error
	fsMock.AssertNotCalled(t, "WriteFile", metadataPath, mock.Anything, mock.Anything)
}

// G-6: GetNFSExport failure test
func TestNFSStager_AutoSelect_ExportCheckFailure(t *testing.T) {
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"
	metadataPath := stagingPath + ".nfs-autoselect.json"

	// Mock NetDial to return discovered IP
	conn, _ := net.Dial("udp", "10.20.30.103:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	// Mock GetNFSExport to fail (host-limit check)
	testClient.On("GetNFSExport", mock.Anything, "export-1").
		Return(gopowerstore.NFSExport{}, errors.New("export not found"))

	// Mock ModifyNFSExport should still be called (host-limit check is best-effort)
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)

	// Mock WriteFile for metadata persistence
	fsMock.On("WriteFile", metadataPath, mock.Anything, mock.Anything).Return(nil)

	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect: "true",
		identifiers.KeyNfsExportPath: nfsExportPath,
		identifiers.KeyExportID:      "export-1",
		identifiers.KeyAllowRoot:     "true",
		identifiers.KeyNasName:       validNasName,
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	// Should succeed despite export check failure (best-effort)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	// ModifyNFSExport should still be called
	testClient.AssertCalled(t, "ModifyNFSExport", mock.Anything, mock.Anything, "export-1")
	// Metadata file should be written
	fsMock.AssertCalled(t, "WriteFile", metadataPath, mock.Anything, mock.Anything)
}

// --- NFS Auto-Select K8s Event Emission Tests (FR-6.1) ---

// nfsAutoSelectTestHelperWithRecorder creates a standard NFSStager with a fake event recorder.
func nfsAutoSelectTestHelperWithRecorder(t *testing.T) (
	*NFSStager, *mocks.FsInterface, *mocks.UtilInterface, *gopowerstoremock.Client, *record.FakeRecorder,
) {
	t.Helper()
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)
	fakeRecorder := record.NewFakeRecorder(10)
	stager.eventRecorder = fakeRecorder
	return stager, fsMock, utilMock, testClient, fakeRecorder
}

func TestNFSStager_AutoSelect_EmitsNFSAutoSelectIPEvent(t *testing.T) {
	stager, fsMock, utilMock, testClient, fakeRecorder := nfsAutoSelectTestHelperWithRecorder(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	conn, _ := net.Dial("udp", "10.20.30.40:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID: "export-1", RWRootHosts: []string{}, RWHosts: []string{},
			ROHosts: []string{}, RORootHosts: []string{},
		}, nil)
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)
	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect:  "true",
		identifiers.KeyNfsExportPath:  nfsExportPath,
		identifiers.KeyExportID:       "export-1",
		identifiers.KeyAllowRoot:      "true",
		identifiers.KeyNasName:        validNasName,
		controller.KeyCSIPVCName:      "test-pvc",
		controller.KeyCSIPVCNamespace: "test-ns",
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)

	// Verify NFSAutoSelectIP Normal event was emitted
	select {
	case event := <-fakeRecorder.Events:
		assert.Contains(t, event, EventReasonNFSAutoSelectIP)
		assert.Contains(t, event, "Normal")
		assert.Contains(t, event, "NAS=")
	default:
		t.Error("expected NFSAutoSelectIP event to be emitted")
	}
}

func TestNFSStager_AutoSelect_EmitsNFSAutoSelectFallbackOnFlatNetwork(t *testing.T) {
	stager, fsMock, utilMock, testClient, fakeRecorder := nfsAutoSelectTestHelperWithRecorder(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	// Determine actual outbound IP — same IP the test host would discover via NetDial.
	// Set managementIP to that so the flat-network condition triggers reliably.
	conn, dialErr := net.Dial("udp", "10.20.30.40:80")
	if dialErr != nil {
		t.Skipf("cannot dial UDP to determine local IP: %v", dialErr)
	}
	localIP := conn.LocalAddr().(*net.UDPAddr).IP.String()
	stager.managementIP = localIP // flat-network: discovered == management
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID: "export-1", RWRootHosts: []string{}, RWHosts: []string{},
			ROHosts: []string{}, RORootHosts: []string{},
		}, nil)
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)
	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect:  "true",
		identifiers.KeyNfsExportPath:  nfsExportPath,
		identifiers.KeyExportID:       "export-1",
		identifiers.KeyAllowRoot:      "true",
		identifiers.KeyNasName:        validNasName,
		controller.KeyCSIPVCName:      "test-pvc",
		controller.KeyCSIPVCNamespace: "test-ns",
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)

	// Should emit NFSAutoSelectFallback Warning first, then NFSAutoSelectIP Normal
	foundFallback := false
	foundAutoSelect := false
	for i := 0; i < 2; i++ {
		select {
		case event := <-fakeRecorder.Events:
			if assert.NotEmpty(t, event) {
				if strings.Contains(event, EventReasonNFSAutoSelectFallback) {
					foundFallback = true
					assert.Contains(t, event, "Warning")
				} else if strings.Contains(event, EventReasonNFSAutoSelectIP) {
					foundAutoSelect = true
				}
			}
		default:
		}
	}
	assert.True(t, foundFallback, "expected NFSAutoSelectFallback event for flat network")
	assert.True(t, foundAutoSelect, "expected NFSAutoSelectIP event after flat network fallback")
}

func TestNFSStager_AutoSelect_EmitsNFSAutoSelectFallbackOnHardError(t *testing.T) {
	stager, fsMock, utilMock, testClient, fakeRecorder := nfsAutoSelectTestHelperWithRecorder(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	// NetDial fails — triggers hard-error fallback
	fsMock.On("NetDial", mock.Anything).Return(nil, errors.New("network unreachable"))

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID: "export-1", RWRootHosts: []string{}, RWHosts: []string{},
			ROHosts: []string{}, RORootHosts: []string{},
		}, nil)
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)
	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect:  "true",
		identifiers.KeyNfsExportPath:  nfsExportPath,
		identifiers.KeyExportID:       "export-1",
		identifiers.KeyAllowRoot:      "true",
		identifiers.KeyNasName:        validNasName,
		controller.KeyCSIPVCName:      "test-pvc",
		controller.KeyCSIPVCNamespace: "test-ns",
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)

	// Should emit NFSAutoSelectFallback Warning, then NFSAutoSelectIP Normal
	foundFallback := false
	for i := 0; i < 2; i++ {
		select {
		case event := <-fakeRecorder.Events:
			if strings.Contains(event, EventReasonNFSAutoSelectFallback) {
				foundFallback = true
				assert.Contains(t, event, "Warning")
				assert.Contains(t, event, "routing query failed")
			}
		default:
		}
	}
	assert.True(t, foundFallback, "expected NFSAutoSelectFallback event on hard-error fallback")
}

func TestNFSStager_AutoSelect_EmitsNFSExportHostLimitEvent(t *testing.T) {
	stager, fsMock, utilMock, testClient, fakeRecorder := nfsAutoSelectTestHelperWithRecorder(t)

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	conn, _ := net.Dial("udp", "10.20.30.40:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	// Create an export with >100 host entries to trigger the host-limit event
	hosts := make([]string, 101)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("10.0.0.%d/255.255.255.255", i)
	}

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID: "export-1", RWRootHosts: hosts, RWHosts: []string{},
			ROHosts: []string{}, RORootHosts: []string{},
		}, nil)
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)
	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect:  "true",
		identifiers.KeyNfsExportPath:  nfsExportPath,
		identifiers.KeyExportID:       "export-1",
		identifiers.KeyAllowRoot:      "true",
		identifiers.KeyNasName:        validNasName,
		controller.KeyCSIPVCName:      "test-pvc",
		controller.KeyCSIPVCNamespace: "test-ns",
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	assert.Nil(t, err)
	assert.NotNil(t, resp)

	// Should emit NFSExportHostLimit Warning and NFSAutoSelectIP Normal
	foundHostLimit := false
	for i := 0; i < 3; i++ {
		select {
		case event := <-fakeRecorder.Events:
			if strings.Contains(event, EventReasonNFSExportHostLimit) {
				foundHostLimit = true
				assert.Contains(t, event, "Warning")
				assert.Contains(t, event, "80%")
			}
		default:
		}
	}
	assert.True(t, foundHostLimit, "expected NFSExportHostLimit event when export has >100 hosts")
}

func TestNFSStager_AutoSelect_NoEventWhenRecorderNil(t *testing.T) {
	// Verify the nil-safe no-op behavior of emitNFSAutoSelectEvent
	stager, fsMock, utilMock, testClient := nfsAutoSelectTestHelper(t)
	// eventRecorder is nil by default from helper

	stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
	nfsExportPath := "10.20.30.40:/test-export"

	conn, _ := net.Dial("udp", "10.20.30.40:80")
	fsMock.On("NetDial", mock.Anything).Return(conn, nil)

	testClient.On("GetNFSExport", mock.Anything, mock.Anything).
		Return(gopowerstore.NFSExport{
			ID: "export-1", RWRootHosts: []string{}, RWHosts: []string{},
			ROHosts: []string{}, RORootHosts: []string{},
		}, nil)
	testClient.On("ModifyNFSExport", mock.Anything, mock.Anything, "export-1").
		Return(gopowerstore.CreateResponse{}, nil)
	fsMock.On("WriteFile", stagingPath+".nfs-autoselect.json", mock.Anything, mock.Anything).Return(nil)
	setupNFSMountMocks(fsMock, utilMock, stagingPath, nfsExportPath)

	publishCtx := map[string]string{
		identifiers.KeyNfsAutoSelect:  "true",
		identifiers.KeyNfsExportPath:  nfsExportPath,
		identifiers.KeyExportID:       "export-1",
		identifiers.KeyAllowRoot:      "true",
		identifiers.KeyNasName:        validNasName,
		controller.KeyCSIPVCName:      "test-pvc",
		controller.KeyCSIPVCNamespace: "test-ns",
	}

	resp, err := stager.Stage(context.Background(), nfsStageRequest(publishCtx),
		stagingPath, validNodeID, log.Fields{}, fsMock, validBaseVolumeID, false, testClient)

	// Should succeed without panicking when eventRecorder is nil
	assert.Nil(t, err)
	assert.NotNil(t, resp)
}
