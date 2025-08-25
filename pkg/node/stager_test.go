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
	"path/filepath"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gobrick"
	"github.com/dell/gofsutil"
	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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

func TestSCSIStager_Stage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("iscsi -- success test", func(t *testing.T) {
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

		iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
			Targets: []gobrick.ISCSITargetInfo{
				{
					Portal: validISCSIPortals[0],
					Target: validISCSITargets[0],
				},
				{
					Portal: validISCSIPortals[1],
					Target: validISCSITargets[1],
				},
			},
			Lun: validLUNIDINT,
		}).Return(gobrick.Device{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)

		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false)

		assert.Nil(t, err)
	})

	t.Run("nvmefc -- success test", func(t *testing.T) {
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

		nvmeConnectorMock.On("ConnectVolume", mock.Anything, gobrick.NVMeVolumeInfo{
			Targets: []gobrick.NVMeTargetInfo{
				{
					Portal: validNVMEFCPortals[0],
					Target: validNVMEFCTargets[0],
				},
				{
					Portal: validNVMEFCPortals[1],
					Target: validNVMEFCTargets[1],
				},
			},
			WWN: validDeviceWWN,
		}, true).Return(gobrick.Device{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)

		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false)

		assert.Nil(t, err)
	})

	t.Run("nvmetcp -- success test", func(t *testing.T) {
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

		nvmeConnectorMock.On("ConnectVolume", mock.Anything, gobrick.NVMeVolumeInfo{
			Targets: []gobrick.NVMeTargetInfo{
				{
					Portal: validNVMETCPPortals[0],
					Target: validNVMETCPTargets[0],
				},
				{
					Portal: validNVMETCPPortals[1],
					Target: validNVMETCPTargets[1],
				},
			},
			WWN: validDeviceWWN,
		}, false).Return(gobrick.Device{}, nil)

		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		scsiStageVolumeOK(utilMock, fsMock)
		_, err := stager.Stage(context.Background(), &csi.NodeStageVolumeRequest{
			VolumeId:          validBlockVolumeID,
			PublishContext:    getValidPublishContext(),
			StagingTargetPath: nodeStagePrivateDir,
			VolumeCapability: getCapabilityWithVoltypeAccessFstype(
				"block", "single-writer", "none"),
		}, log.Fields{}, fsMock, validBaseVolumeID, false)

		assert.Nil(t, err)
	})
}
