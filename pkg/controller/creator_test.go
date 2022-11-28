/*
 *
 * Copyright © 2021-2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package controller_test

import (
	"context"
	"errors"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/pkg/controller"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestVolumeCreator_CheckSize(t *testing.T) {
	t.Run("scsi creator", func(t *testing.T) {
		sc := &controller.SCSICreator{}
		t.Run("zeroes", func(t *testing.T) {
			cr := &csi.CapacityRange{
				RequiredBytes: 0,
				LimitBytes:    0,
			}

			res, err := sc.CheckSize(context.Background(), cr, false)
			assert.NoError(t, err)
			assert.Equal(t, res, int64(controller.MinVolumeSizeBytes))
		})

		t.Run("mod != 0", func(t *testing.T) {
			cr := &csi.CapacityRange{
				RequiredBytes: controller.MinVolumeSizeBytes + 1,
				LimitBytes:    0,
			}

			res, err := sc.CheckSize(context.Background(), cr, false)
			assert.NoError(t, err)
			assert.Equal(t, res, int64(controller.MinVolumeSizeBytes+controller.VolumeSizeMultiple))
		})
	})

	t.Run("nfs creator", func(t *testing.T) {
		nc := &controller.NfsCreator{}
		t.Run("zeroes", func(t *testing.T) {
			cr := &csi.CapacityRange{
				RequiredBytes: 0,
				LimitBytes:    0,
			}

			res, err := nc.CheckSize(context.Background(), cr, false)
			assert.NoError(t, err)
			assert.Equal(t, res, int64(controller.MinVolumeSizeBytes))
		})

		t.Run("mod != 0", func(t *testing.T) {
			cr := &csi.CapacityRange{
				RequiredBytes: controller.MinVolumeSizeBytes + 1,
				LimitBytes:    0,
			}

			res, err := nc.CheckSize(context.Background(), cr, false)
			assert.NoError(t, err)
			assert.Equal(t, res, int64(controller.MinVolumeSizeBytes+controller.VolumeSizeMultiple))
		})
	})
}

func TestVolumeCreator_CheckIfAlreadyExists(t *testing.T) {
	t.Run("can't find volume [block]", func(t *testing.T) {
		sc := &controller.SCSICreator{}
		name := "test"
		clientMock := new(mocks.Client)
		clientMock.On("GetVolumeByName", context.Background(), name).
			Return(gopowerstore.Volume{}, errors.New("error"))

		_, err := sc.CheckIfAlreadyExists(context.Background(), name, 0, clientMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't find volume")
	})

	t.Run("can't find volume [nfs]", func(t *testing.T) {
		nc := &controller.NfsCreator{}
		name := "test"
		clientMock := new(mocks.Client)
		clientMock.On("GetFSByName", context.Background(), name).
			Return(gopowerstore.FileSystem{}, errors.New("error"))

		_, err := nc.CheckIfAlreadyExists(context.Background(), name, 0, clientMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't find filesystem")
	})
}

func TestVolumeCreator_Clone(t *testing.T) {
	t.Run("scsi creator", func(t *testing.T) {
		sc := &controller.SCSICreator{}
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
		nc := &controller.NfsCreator{}
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
					SizeTotal: validVolSize + controller.ReservedSize,
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
		sc := &controller.SCSICreator{}
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
		nc := &controller.NfsCreator{}
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
					SizeTotal: validVolSize + controller.ReservedSize,
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
