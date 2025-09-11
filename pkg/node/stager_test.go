/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"path/filepath"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"

	"github.com/dell/gobrick"
	"github.com/dell/gofsutil"
	"github.com/golang/mock/gomock"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var validBaseVolID = "39bb1b5f-5624-490d-9ece-18f7b28a904e"

func getValidPublishContext() map[string]string {
	return map[string]string{
		identifiers.PublishContextLUNAddress:                 validLUNID,
		identifiers.PublishContextDeviceWWN:                  validDeviceWWN,
		identifiers.PublishContextISCSIPortalsPrefix + "0":   validISCSIPortals[0],
		identifiers.PublishContextISCSIPortalsPrefix + "1":   validISCSIPortals[1],
		identifiers.PublishContextISCSITargetsPrefix + "0":   validISCSITargets[0],
		identifiers.PublishContextISCSITargetsPrefix + "1":   validISCSITargets[1],
		identifiers.PublishContextNVMEFCPortalsPrefix + "0":  validNVMEFCPortals[0],
		identifiers.PublishContextNVMEFCPortalsPrefix + "1":  validNVMEFCPortals[1],
		identifiers.PublishContextNVMEFCTargetsPrefix + "0":  validNVMEFCTargets[0],
		identifiers.PublishContextNVMEFCTargetsPrefix + "1":  validNVMEFCTargets[1],
		identifiers.PublishContextNVMETCPPortalsPrefix + "0": validNVMETCPPortals[0],
		identifiers.PublishContextNVMETCPPortalsPrefix + "1": validNVMETCPPortals[1],
		identifiers.PublishContextNVMETCPTargetsPrefix + "0": validNVMETCPTargets[0],
		identifiers.PublishContextNVMETCPTargetsPrefix + "1": validNVMETCPTargets[1],
		identifiers.PublishContextFCWWPNPrefix + "0":         validFCTargetsWWPN[0],
		identifiers.PublishContextFCWWPNPrefix + "1":         validFCTargetsWWPN[1],
	}
}

func getValidRemoteMetroPublishContext() map[string]string {
	publishContext := getValidPublishContext()
	publishContext[identifiers.PublishContextRemoteLUNAddress] = validLUNID
	publishContext[identifiers.PublishContextRemoteDeviceWWN] = validDeviceWWN
	publishContext[identifiers.PublishContextRemoteISCSIPortalsPrefix+"0"] = validRemoteISCSIPortals[0]
	publishContext[identifiers.PublishContextRemoteISCSIPortalsPrefix+"1"] = validRemoteISCSIPortals[1]
	publishContext[identifiers.PublishContextRemoteISCSITargetsPrefix+"0"] = validRemoteISCSITargets[0]
	publishContext[identifiers.PublishContextRemoteISCSITargetsPrefix+"1"] = validRemoteISCSITargets[1]
	publishContext[identifiers.PublishContextRemoteFCWWPNPrefix+"0"] = validRemoteFCTargetsWWPN[0]
	publishContext[identifiers.PublishContextRemoteFCWWPNPrefix+"1"] = validRemoteFCTargetsWWPN[1]

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
	fs.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
	fs.On("MkFileIdempotent", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(true, nil)
	fs.On("GetUtil").Return(util)
}

func scsiStageRemoteMetroVolumeOK(util *mocks.UtilInterface, fs *mocks.FsInterface) {
	util.On("BindMount", mock.Anything, "/dev", filepath.Join(nodeStagePrivateDir, validRemoteVolID)).Return(nil)
	fs.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
	fs.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
	fs.On("MkFileIdempotent", filepath.Join(nodeStagePrivateDir, validRemoteVolID)).Return(true, nil)
	fs.On("GetUtil").Return(util)
}

// setClientMocks sets mocks for gopowerstore client, no matter what protocol is used, the mocks needed are the same
func setClientMocks() {
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

func TestSCSIStager_Stage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("iscsi -- success test", func(t *testing.T) {
		setVariables()
		setClientMocks()
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
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false, clientMock)
		assert.Nil(t, err)
	})

	t.Run("nvmefc -- success test", func(t *testing.T) {
		setVariables()
		setClientMocks()
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
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false, clientMock)

		assert.Nil(t, err)
	})

	t.Run("nvmetcp -- success test", func(t *testing.T) {
		setVariables()
		setClientMocks()
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
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false, clientMock)

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
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false, client)
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
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false, client)
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
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false, client)
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
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false, client)
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
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false, client)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "fcTargets data must be in publish context")
	})
}
