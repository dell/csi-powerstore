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

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestVolumeCreator_CheckSize(t *testing.T) {
	t.Run("scsi creator", func(t *testing.T) {
		sc := &SCSICreator{}
		t.Run("zeroes", func(t *testing.T) {
			cr := &csi.CapacityRange{
				RequiredBytes: 0,
				LimitBytes:    0,
			}

			res, err := sc.CheckSize(context.Background(), cr, false)
			assert.NoError(t, err)
			assert.Equal(t, res, int64(MinVolumeSizeBytes))
		})

		t.Run("mod != 0", func(t *testing.T) {
			cr := &csi.CapacityRange{
				RequiredBytes: MinVolumeSizeBytes + 1,
				LimitBytes:    0,
			}

			res, err := sc.CheckSize(context.Background(), cr, false)
			assert.NoError(t, err)
			assert.Equal(t, res, int64(MinVolumeSizeBytes+VolumeSizeMultiple))
		})
	})

	t.Run("nfs creator", func(t *testing.T) {
		nc := &NfsCreator{}
		t.Run("zeroes", func(t *testing.T) {
			cr := &csi.CapacityRange{
				RequiredBytes: 0,
				LimitBytes:    0,
			}

			res, err := nc.CheckSize(context.Background(), cr, false)
			assert.NoError(t, err)
			assert.Equal(t, res, int64(MinVolumeSizeBytes))
		})

		t.Run("mod != 0", func(t *testing.T) {
			cr := &csi.CapacityRange{
				RequiredBytes: MinVolumeSizeBytes + 1,
				LimitBytes:    0,
			}

			res, err := nc.CheckSize(context.Background(), cr, false)
			assert.NoError(t, err)
			assert.Equal(t, res, int64(MinVolumeSizeBytes+VolumeSizeMultiple))
		})
	})
}

func TestVolumeCreator_CheckIfAlreadyExists(t *testing.T) {
	t.Run("can't find volume [block]", func(t *testing.T) {
		sc := &SCSICreator{}
		name := "test"
		clientMock := new(mocks.Client)
		clientMock.On("GetVolumeByName", context.Background(), name).
			Return(gopowerstore.Volume{}, errors.New("error"))

		_, err := sc.CheckIfAlreadyExists(context.Background(), name, 0, clientMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't find volume")
	})

	t.Run("can't find volume [nfs]", func(t *testing.T) {
		nc := &NfsCreator{}
		name := "test"
		clientMock := new(mocks.Client)
		clientMock.On("GetFSByName", context.Background(), name).
			Return(gopowerstore.FileSystem{}, errors.New("error"))

		_, err := nc.CheckIfAlreadyExists(context.Background(), name, 0, clientMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't find filesystem")
	})

	t.Run("volume already exists [nfs]", func(t *testing.T) {
		nc := &NfsCreator{nfsAutoSelect: false}
		name := "test"
		sizeInBytes := int64(1610612736)
		validNodeID = strings.Join([]string{validHostName, "127.0.0.1"}, "-")
		clientMock := new(mocks.Client)
		clientMock.On("GetFSByName", context.Background(), name).
			Return(gopowerstore.FileSystem{SizeTotal: 3221225472}, nil)

		clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{
			CurrentNodeID:                   validNodeID,
			CurrentPreferredIPv4InterfaceID: "intf-1",
		}, nil)
		vol, err := nc.CheckIfAlreadyExists(context.Background(), name, sizeInBytes, clientMock)
		assert.NoError(t, err)
		assert.Equal(t, sizeInBytes, vol.CapacityBytes)
		// When auto-select is disabled, GetFileInterface should NOT be called
		clientMock.AssertNotCalled(t, "GetFileInterface", mock.Anything, mock.Anything)
		assert.Empty(t, nc.nasInterfaceIP)
	})
	t.Run("volume already exists [nfs] with auto-select resolves interface IP", func(t *testing.T) {
		nc := &NfsCreator{nfsAutoSelect: true}
		name := "test"
		sizeInBytes := int64(1610612736)
		validNodeID = strings.Join([]string{validHostName, "127.0.0.1"}, "-")
		clientMock := new(mocks.Client)
		clientMock.On("GetFSByName", context.Background(), name).
			Return(gopowerstore.FileSystem{SizeTotal: 3221225472}, nil)

		clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{
			Name:                            "nas-1",
			CurrentNodeID:                   validNodeID,
			CurrentPreferredIPv4InterfaceID: "intf-1",
		}, nil)
		clientMock.On("GetFileInterface", context.Background(), "intf-1").Return(gopowerstore.FileInterface{
			IPAddress: "10.20.30.40",
		}, nil)
		vol, err := nc.CheckIfAlreadyExists(context.Background(), name, sizeInBytes, clientMock)
		assert.NoError(t, err)
		assert.Equal(t, sizeInBytes, vol.CapacityBytes)
		clientMock.AssertCalled(t, "GetFileInterface", context.Background(), "intf-1")
		assert.Equal(t, "10.20.30.40", nc.nasInterfaceIP)
	})
	t.Run("volume with same name exists, but is wrong size [nfs]", func(t *testing.T) {
		nc := &NfsCreator{}
		name := "test"
		sizeInBytes := int64(3221225472)
		clientMock := new(mocks.Client)
		clientMock.On("GetFSByName", context.Background(), name).
			Return(gopowerstore.FileSystem{SizeTotal: 1610612736}, nil)

		_, err := nc.CheckIfAlreadyExists(context.Background(), name, sizeInBytes, clientMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists but is incompatible volume size")
	})
}

func TestVolumeCreator_Clone(t *testing.T) {
	t.Run("scsi creator", func(t *testing.T) {
		sc := &SCSICreator{}
		name := "test"
		t.Run("failed to lookup volume", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{}, errors.New("error"))

			_, err := sc.Clone(context.Background(), &csi.VolumeContentSource_VolumeSource{VolumeId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "volume not found")
		})

		t.Run("incorrect size", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{
					Name: name,
					Size: 1024,
					ID:   validBaseVolID,
				}, nil)

			_, err := sc.Clone(context.Background(), &csi.VolumeContentSource_VolumeSource{VolumeId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "volume "+validBaseVolID+" has incompatible size")
		})

		t.Run("clone failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{
					Name: name,
					Size: validVolSize,
					ID:   validBaseVolID,
				}, nil)
			clientMock.On("CloneVolume", context.Background(), mock.Anything, validBaseVolID).
				Return(gopowerstore.CreateResponse{}, errors.New("error"))

			_, err := sc.Clone(context.Background(), &csi.VolumeContentSource_VolumeSource{VolumeId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't clone volume")
		})
	})

	t.Run("nfs creator", func(t *testing.T) {
		nc := &NfsCreator{}
		name := "test"
		t.Run("failed to lookup filesystem", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{}, errors.New("error"))

			_, err := nc.Clone(context.Background(), &csi.VolumeContentSource_VolumeSource{VolumeId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "fs not found")
		})

		t.Run("incorrect size", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{
					Name:      name,
					SizeTotal: 1024,
					ID:        validBaseVolID,
				}, nil)

			_, err := nc.Clone(context.Background(), &csi.VolumeContentSource_VolumeSource{VolumeId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "fs "+validBaseVolID+" has incompatible size")
		})

		t.Run("clone failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{
					Name:      name,
					SizeTotal: validVolSize + ReservedSize,
					ID:        validBaseVolID,
				}, nil)
			clientMock.On("CloneFS", context.Background(), mock.Anything, validBaseVolID).
				Return(gopowerstore.CreateResponse{}, errors.New("error"))

			_, err := nc.Clone(context.Background(), &csi.VolumeContentSource_VolumeSource{VolumeId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't clone fs")
		})
	})
}

func TestVolumeCreator_CreateFromSnapshot(t *testing.T) {
	t.Run("scsi creator", func(t *testing.T) {
		sc := &SCSICreator{}
		name := "test"
		t.Run("failed to lookup volume", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{}, errors.New("error"))

			_, err := sc.CreateVolumeFromSnapshot(context.Background(),
				&csi.VolumeContentSource_SnapshotSource{SnapshotId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "volume snapshot not found")
		})

		t.Run("incorrect size", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{
					Name: name,
					Size: 1024,
					ID:   validBaseVolID,
				}, nil)

			_, err := sc.CreateVolumeFromSnapshot(context.Background(),
				&csi.VolumeContentSource_SnapshotSource{SnapshotId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "snapshot "+validBaseVolID+" has incompatible size")
		})

		t.Run("create failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{
					Name: name,
					Size: validVolSize,
					ID:   validBaseVolID,
				}, nil)
			clientMock.On("CreateVolumeFromSnapshot", context.Background(), mock.Anything, validBaseVolID).
				Return(gopowerstore.CreateResponse{}, errors.New("error"))

			_, err := sc.CreateVolumeFromSnapshot(context.Background(),
				&csi.VolumeContentSource_SnapshotSource{SnapshotId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't create volume")
		})
	})

	t.Run("nfs creator", func(t *testing.T) {
		nc := &NfsCreator{}
		name := "test"
		t.Run("failed to lookup filesystem snapshot", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{}, errors.New("error"))

			_, err := nc.CreateVolumeFromSnapshot(context.Background(),
				&csi.VolumeContentSource_SnapshotSource{SnapshotId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "fs snapshot not found")
		})

		t.Run("incorrect size", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{
					Name:      name,
					SizeTotal: 1024,
					ID:        validBaseVolID,
				}, nil)

			_, err := nc.CreateVolumeFromSnapshot(context.Background(),
				&csi.VolumeContentSource_SnapshotSource{SnapshotId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "snapshot "+validBaseVolID+" has incompatible size")
		})

		t.Run("create failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{
					Name:      name,
					SizeTotal: validVolSize + ReservedSize,
					ID:        validBaseVolID,
				}, nil)
			clientMock.On("CreateFsFromSnapshot", context.Background(), mock.Anything, validBaseVolID).
				Return(gopowerstore.CreateResponse{}, errors.New("error"))

			_, err := nc.CreateVolumeFromSnapshot(context.Background(),
				&csi.VolumeContentSource_SnapshotSource{SnapshotId: validBaseVolID},
				name, validVolSize, map[string]string{}, clientMock)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't create fs")
		})
	})
}

func TestCreator_SetAttributes(t *testing.T) {
	t.Run("setVolumeCreateAttributes", func(t *testing.T) {
		params := map[string]string{
			identifiers.KeyApplianceID:         "app-1",
			identifiers.KeyVolumeDescription:   "my-desc",
			identifiers.KeyProtectionPolicyID:  "prot-1",
			identifiers.KeyPerformancePolicyID: "perf-1",
			identifiers.KeyAppType:             "Oracle",
			identifiers.KeyAppTypeOther:        "custom-oracle",
		}
		vc := &gopowerstore.VolumeCreate{}
		setVolumeCreateAttributes(params, vc)
		assert.Equal(t, "app-1", vc.ApplianceID)
		assert.Equal(t, "my-desc", vc.Description)
		assert.Equal(t, "prot-1", vc.ProtectionPolicyID)
		assert.Equal(t, "perf-1", vc.PerformancePolicyID)
		assert.Equal(t, gopowerstore.AppTypeEnum("Oracle"), vc.AppType)
		assert.Equal(t, "custom-oracle", vc.AppTypeOther)
	})

	t.Run("validateHostIOSize", func(t *testing.T) {
		assert.Equal(t, gopowerstore.VMware8K, validateHostIOSize(gopowerstore.VMware8K))
		assert.Equal(t, gopowerstore.VMware16K, validateHostIOSize(gopowerstore.VMware16K))
		assert.Equal(t, gopowerstore.VMware32K, validateHostIOSize(gopowerstore.VMware32K))
		assert.Equal(t, gopowerstore.VMware64K, validateHostIOSize(gopowerstore.VMware64K))
		assert.Equal(t, gopowerstore.VMware8K, validateHostIOSize("invalid_size"))
	})

	t.Run("setFLRAttributes", func(t *testing.T) {
		params := map[string]string{
			identifiers.KeyFlrCreateMode:       "Enterprise",
			identifiers.KeyFlrDefaultRetention: "1d",
			identifiers.KeyFlrMinRetention:     "1h",
			identifiers.KeyFlrMaxRetention:     "1y",
		}
		fc := &gopowerstore.FsCreate{}
		setFLRAttributes(params, fc)
		flr, ok := fc.FlrCreate.(gopowerstore.FLRCreate)
		assert.True(t, ok)
		assert.Equal(t, "Enterprise", flr.Mode)
		assert.Equal(t, "1d", flr.DefaultRetention)
		assert.Equal(t, "1h", flr.MinimumRetention)
		assert.Equal(t, "1y", flr.MaximumRetention)
	})

	t.Run("setNFSCreateAttributes", func(t *testing.T) {
		params := map[string]string{
			identifiers.KeyVolumeDescription:        "nfs-desc",
			identifiers.KeyConfigType:               "General",
			identifiers.KeyAccessPolicy:             "Native",
			identifiers.KeyLockingPolicy:            "Mandatory",
			identifiers.KeyFolderRenamePolicy:       "AllAllowed",
			identifiers.KeyIsAsyncMtimeEnabled:      "true",
			identifiers.KeyProtectionPolicyID:       "prot-nfs",
			identifiers.KeyPerformancePolicyID:      "perf-nfs",
			identifiers.KeyFileEventsPublishingMode: "None",
			identifiers.KeyHostIoSize:               gopowerstore.VMware32K,
		}
		fc := &gopowerstore.FsCreate{}
		setNFSCreateAttributes(params, fc)
		assert.Equal(t, "nfs-desc", fc.Description)
		assert.Equal(t, "General", fc.ConfigType)
		assert.Equal(t, "Native", fc.AccessPolicy)
		assert.Equal(t, "Mandatory", fc.LockingPolicy)
		assert.Equal(t, "AllAllowed", fc.FolderRenamePolicy)
		assert.True(t, fc.IsAsyncMTimeEnabled)
		assert.Equal(t, "prot-nfs", fc.ProtectionPolicyID)
		assert.Equal(t, "perf-nfs", fc.PerformancePolicyID)
		assert.Equal(t, "None", fc.FileEventsPublishingMode)
		assert.Equal(t, gopowerstore.VMware32K, fc.HostIOSize)
	})
}

func TestNfsCreator_Create(t *testing.T) {
	t.Run("create with auto-select disabled does not call GetFileInterface", func(t *testing.T) {
		nc := &NfsCreator{
			nasName:       "nas-1",
			nfsAutoSelect: false,
		}
		clientMock := new(mocks.Client)
		clientMock.On("GetNASByName", context.Background(), "nas-1").Return(gopowerstore.NAS{
			ID:                              "nas-id-1",
			Name:                            "nas-1",
			CurrentPreferredIPv4InterfaceID: "intf-1",
		}, nil)
		clientMock.On("CreateFS", context.Background(), mock.Anything).Return(gopowerstore.CreateResponse{ID: "fs-1"}, nil)

		req := &csi.CreateVolumeRequest{
			Name:       "vol-1",
			Parameters: map[string]string{},
		}
		resp, err := nc.Create(context.Background(), req, 1073741824, clientMock)
		assert.NoError(t, err)
		assert.Equal(t, "fs-1", resp.ID)
		clientMock.AssertNotCalled(t, "GetFileInterface", mock.Anything, mock.Anything)
		assert.Empty(t, nc.nasInterfaceIP)
	})

	t.Run("create with auto-select enabled resolves NAS interface IP", func(t *testing.T) {
		nc := &NfsCreator{
			nasName:       "nas-1",
			nfsAutoSelect: true,
		}
		clientMock := new(mocks.Client)
		clientMock.On("GetNASByName", context.Background(), "nas-1").Return(gopowerstore.NAS{
			ID:                              "nas-id-1",
			Name:                            "nas-1",
			CurrentPreferredIPv4InterfaceID: "intf-1",
		}, nil)
		clientMock.On("GetFileInterface", context.Background(), "intf-1").Return(gopowerstore.FileInterface{
			IPAddress: "10.20.30.40",
		}, nil)
		clientMock.On("CreateFS", context.Background(), mock.Anything).Return(gopowerstore.CreateResponse{ID: "fs-1"}, nil)

		req := &csi.CreateVolumeRequest{
			Name:       "vol-1",
			Parameters: map[string]string{},
		}
		resp, err := nc.Create(context.Background(), req, 1073741824, clientMock)
		assert.NoError(t, err)
		assert.Equal(t, "fs-1", resp.ID)
		clientMock.AssertCalled(t, "GetFileInterface", context.Background(), "intf-1")
		assert.Equal(t, "10.20.30.40", nc.nasInterfaceIP)
	})

	t.Run("create with auto-select enabled handles GetFileInterface failure gracefully", func(t *testing.T) {
		nc := &NfsCreator{
			nasName:       "nas-1",
			nfsAutoSelect: true,
		}
		clientMock := new(mocks.Client)
		clientMock.On("GetNASByName", context.Background(), "nas-1").Return(gopowerstore.NAS{
			ID:                              "nas-id-1",
			Name:                            "nas-1",
			CurrentPreferredIPv4InterfaceID: "intf-1",
		}, nil)
		clientMock.On("GetFileInterface", context.Background(), "intf-1").Return(gopowerstore.FileInterface{}, errors.New("network error"))
		clientMock.On("CreateFS", context.Background(), mock.Anything).Return(gopowerstore.CreateResponse{ID: "fs-1"}, nil)

		req := &csi.CreateVolumeRequest{
			Name:       "vol-1",
			Parameters: map[string]string{},
		}
		resp, err := nc.Create(context.Background(), req, 1073741824, clientMock)
		assert.NoError(t, err)
		assert.Equal(t, "fs-1", resp.ID)
		assert.Empty(t, nc.nasInterfaceIP)
	})
}
