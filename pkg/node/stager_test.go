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
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/mocks"
	"github.com/dell/csi-powerstore/pkg/common"
	"github.com/dell/gobrick"
	"github.com/dell/gofsutil"
	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"path/filepath"
	"testing"
)

func getValidPublishContext() map[string]string {
	return map[string]string{
		common.PublishContextLUNAddress:               validLUNID,
		common.PublishContextDeviceWWN:                validDeviceWWN,
		common.PublishContextISCSIPortalsPrefix + "0": validISCSIPortals[0],
		common.PublishContextISCSIPortalsPrefix + "1": validISCSIPortals[1],
		common.PublishContextISCSITargetsPrefix + "0": validISCSITargets[0],
		common.PublishContextISCSITargetsPrefix + "1": validISCSITargets[1],
		common.PublishContextFCWWPNPrefix + "0":       validFCTargetsWWPN[0],
		common.PublishContextFCWWPNPrefix + "1":       validFCTargetsWWPN[1],
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

func scsiStageVolumeOK(util *mocks.UtilInterface, fs *mocks.FsInterface) {
	util.On("BindMount", mock.Anything, "/dev", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(nil)
	fs.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
	fs.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
	fs.On("MkFileIdempotent", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(true, nil)
	fs.On("GetUtil").Return(util)
}

func TestSCSIStager_Stage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("iscsi -- success test", func(t *testing.T) {
		iscsiConnectorMock := new(mocks.ISCSIConnector)
		fcConnectorMock := new(mocks.FcConnector)
		nvmetcpConnectorMock := new(mocks.NVMETCPConnector)

		stager := &SCSIStager{
			useFC:            false,
			useISCSI:         true,
			iscsiConnector:   iscsiConnectorMock,
			nvmetcpConnector: nvmetcpConnectorMock,
			fcConnector:      fcConnectorMock,
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
		}, log.Fields{}, fsMock, validBaseVolumeID)

		assert.Nil(t, err)
	})
}
