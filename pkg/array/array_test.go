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

package array_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/common/fs"
	"github.com/dell/gopowerstore"

	"github.com/dell/gopowerstore/api"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"

	"github.com/dell/gofsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	validPowerStoreIP = "127.0.0.1"

	validBlockVolumeUUID       = "39bb1b5f-5624-490d-9ece-18f7b28a904e"
	validRemoteBlockVolumeUUID = "9f840c56-96e6-4de9-b5a3-27e7c20eaa77"

	validFileSystemUUID = "66d815e3-52c2-126f-e29f-3e95021dcb9b"

	validGlobalID       = "globalvolid1"
	validRemoteGlobalID = "globalvolid2"

	scsi = "scsi"
	nfs  = "nfs"
)

var (
	validBlockVolumeNameSCSI      = buildVolumeName(validBlockVolumeUUID, validGlobalID, scsi)
	validMetroBlockVolumeNameSCSI = buildMetroVolumeName(validBlockVolumeUUID, validGlobalID, scsi, validRemoteBlockVolumeUUID, validRemoteGlobalID)
)

func buildVolumeName(uuid, globalID, transport string) string {
	return uuid + "/" + globalID + "/" + transport
}

func buildMetroVolumeName(uuid, globalID, transport, remoteUUID, remoteGlobalID string) string {
	return buildVolumeName(uuid, globalID, transport) + ":" + remoteUUID + "/" + remoteGlobalID
}

func TestGetPowerStoreArrays(t *testing.T) {
	type args struct {
		fs   fs.Interface
		data string
	}
	_ = os.Setenv(common.EnvThrottlingRateLimit, "1000")

	tests := []struct {
		name    string
		args    args
		want    map[string]*array.PowerStoreArray
		wantErr bool
	}{
		{
			name:    "two arrays",
			args:    args{data: "./testdata/two-arr.yaml", fs: &fs.Fs{Util: &gofsutil.FS{}}},
			wantErr: false,
			want: map[string]*array.PowerStoreArray{
				"gid1": {
					Endpoint:      "https://127.0.0.1/api/rest",
					Username:      "admin",
					Password:      "password",
					Insecure:      true,
					IsDefault:     true,
					BlockProtocol: common.ISCSITransport,
				},
				"gid2": {
					Endpoint:      "https://127.0.0.2/api/rest",
					Username:      "user",
					Password:      "password",
					Insecure:      true,
					IsDefault:     false,
					BlockProtocol: common.AutoDetectTransport,
				},
			},
		},
		{
			name:    "one array",
			args:    args{data: "./testdata/one-arr.yaml", fs: &fs.Fs{Util: &gofsutil.FS{}}},
			wantErr: false,
			want: map[string]*array.PowerStoreArray{
				"gid1": {
					Endpoint:      "https://127.0.0.1/api/rest",
					Username:      "admin",
					Password:      "password",
					Insecure:      true,
					IsDefault:     true,
					BlockProtocol: common.AutoDetectTransport,
				},
			},
		},
		{
			name:    "empty arrays",
			args:    args{data: "./testdata/no-arr.yaml", fs: &fs.Fs{Util: &gofsutil.FS{}}},
			wantErr: false,
			want:    map[string]*array.PowerStoreArray{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _, err := array.GetPowerStoreArrays(tt.args.fs, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPowerStoreArrays() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for k, v1 := range tt.want {
				assert.Equal(t, v1.Password, got[k].Password)
				assert.Equal(t, v1.Username, got[k].Username)
				assert.Equal(t, v1.Endpoint, got[k].Endpoint)
				assert.Equal(t, v1.Insecure, got[k].Insecure)
				assert.Equal(t, v1.IsDefault, got[k].IsDefault)
				assert.Equal(t, v1.BlockProtocol, got[k].BlockProtocol)
			}
		})
	}

	t.Run("failed to read file", func(t *testing.T) {
		e := errors.New("some-error")
		path := "some-path"
		fsMock := new(mocks.FsInterface)
		fsMock.On("ReadFile", path).Return([]byte{}, e)

		_, _, _, err := array.GetPowerStoreArrays(fsMock, path)
		assert.Error(t, err)
		assert.Equal(t, e, err)
	})

	t.Run("can't unmarshal data", func(t *testing.T) {
		path := "some-path"
		fsMock := new(mocks.FsInterface)
		fsMock.On("ReadFile", path).Return([]byte("some12frandomgtqxt\nhere"), nil)

		_, _, _, err := array.GetPowerStoreArrays(fsMock, path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot unmarshal")
	})

	t.Run("incorrect endpoint", func(t *testing.T) {
		f := &fs.Fs{Util: &gofsutil.FS{}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/incorrect-endpoint.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't get ips from endpoint")
	})

	t.Run("invalid endpoint", func(t *testing.T) {
		f := &fs.Fs{Util: &gofsutil.FS{}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/invalid-endpoint.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't get ips from endpoint")
	})
	t.Run("no global ID", func(t *testing.T) {
		f := &fs.Fs{Util: &gofsutil.FS{}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/no-globalID.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no GlobalID field found in config.yaml")
	})

	t.Run("incorrect throttling limit", func(t *testing.T) {
		_ = os.Setenv(common.EnvThrottlingRateLimit, "abc")
		f := &fs.Fs{Util: &gofsutil.FS{}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/one-arr.yaml")
		assert.NoError(t, err)
	})
}

func TestParseVolumeID(t *testing.T) {
	t.Run("parse volume name", func(t *testing.T) {
		id, globalID, protocol, _, _, err := array.ParseVolumeID(context.Background(), validBlockVolumeNameSCSI, nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, validBlockVolumeUUID, id)
		assert.Equal(t, validGlobalID, globalID)
		assert.Equal(t, scsi, protocol)
	})

	t.Run("incorrect volume id", func(t *testing.T) {
		_, _, _, _, _, err := array.ParseVolumeID(context.Background(), "", nil, nil)
		assert.Error(t, err)
	})

	t.Run("parse metro volume name", func(t *testing.T) {
		id, globalID, protocol, remoteID, remoteGlobalID, err := array.ParseVolumeID(context.Background(), validMetroBlockVolumeNameSCSI, nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, validBlockVolumeUUID, id)
		assert.Equal(t, validRemoteBlockVolumeUUID, remoteID)
		assert.Equal(t, validGlobalID, globalID)
		assert.Equal(t, remoteGlobalID, validRemoteGlobalID)
		assert.Equal(t, scsi, protocol)
	})

	t.Run("parse bad metro volume name", func(t *testing.T) {
		invalidMetroVolumeName := buildMetroVolumeName(validBlockVolumeUUID, validGlobalID, scsi, "", "")
		_, _, _, _, _, err := array.ParseVolumeID(context.Background(), invalidMetroVolumeName, nil, nil)
		assert.Error(t, err)
	})

	t.Run("parse metro volume with missing source volume", func(t *testing.T) {
		invalidMetroVolumeName := buildMetroVolumeName("", "", "", validRemoteBlockVolumeUUID, validRemoteGlobalID)
		_, _, _, _, _, err := array.ParseVolumeID(context.Background(), invalidMetroVolumeName, nil, nil)
		assert.Error(t, err)
	})

	t.Run("volume capability nfs", func(t *testing.T) {
		id := "1cd254s"
		ip := "gid1"
		getVolCap := func() *csi.VolumeCapability {
			accessMode := new(csi.VolumeCapability_AccessMode)
			accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
			accessType := new(csi.VolumeCapability_Mount)
			mountVolume := new(csi.VolumeCapability_MountVolume)
			mountVolume.FsType = "nfs"
			accessType.Mount = mountVolume
			capability := new(csi.VolumeCapability)
			capability.AccessMode = accessMode
			capability.AccessType = accessType
			return capability
		}

		volCap := getVolCap()
		gotID, gotIP, protocol, _, _, err := array.ParseVolumeID(context.Background(), id, &array.PowerStoreArray{IP: ip, GlobalID: "gid1"}, volCap)
		assert.NoError(t, err)
		assert.Equal(t, id, gotID)
		assert.Equal(t, ip, gotIP)
		assert.Equal(t, protocol, "nfs")
	})

	t.Run("volume capability scsi", func(t *testing.T) {
		id := validBlockVolumeUUID
		ip := validPowerStoreIP
		getVolCap := func() *csi.VolumeCapability {
			accessMode := new(csi.VolumeCapability_AccessMode)
			accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
			accessType := new(csi.VolumeCapability_Mount)
			mountVolume := new(csi.VolumeCapability_MountVolume)
			mountVolume.FsType = scsi
			accessType.Mount = mountVolume
			capability := new(csi.VolumeCapability)
			capability.AccessMode = accessMode
			capability.AccessType = accessType
			return capability
		}

		volCap := getVolCap()
		gotID, gotGlobalID, protocol, _, _, err := array.ParseVolumeID(context.Background(), id, &array.PowerStoreArray{IP: ip, GlobalID: validGlobalID}, volCap)
		assert.NoError(t, err)
		assert.Equal(t, id, gotID)
		assert.Equal(t, validGlobalID, gotGlobalID)
		assert.Equal(t, scsi, protocol)
	})

	t.Run("legacy missing scsi protocol", func(t *testing.T) {
		// if GetVolume returns without error, the protocol should be scsi
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{ID: validBlockVolumeUUID}, nil)

		defaultArray := &array.PowerStoreArray{Client: clientMock, IP: validPowerStoreIP, GlobalID: validGlobalID}

		id, globalID, protocol, _, _, err := array.ParseVolumeID(context.Background(), validBlockVolumeUUID, defaultArray, nil)
		assert.NoError(t, err)
		assert.Equal(t, validBlockVolumeUUID, id)
		assert.Equal(t, validGlobalID, globalID)
		assert.Equal(t, protocol, scsi)
	})

	t.Run("legacy get nfs protocol from API client", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{}, errors.New(""))
		clientMock.On("GetFS", mock.Anything, mock.Anything).Return(gopowerstore.FileSystem{ID: validFileSystemUUID}, nil)

		defaultArray := &array.PowerStoreArray{Client: clientMock, IP: validPowerStoreIP, GlobalID: validGlobalID}

		id, globalID, protocol, _, _, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, defaultArray, nil)
		assert.NoError(t, err)
		assert.Equal(t, validFileSystemUUID, id)
		assert.Equal(t, validGlobalID, globalID)
		assert.Equal(t, protocol, nfs)
	})

	t.Run("legacy volume not found", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{}, errors.New(""))
		apiError := gopowerstore.APIError{
			ErrorMsg: &api.ErrorMsg{
				StatusCode: http.StatusNotFound,
				Message:    "volume not found",
			},
		}

		clientMock.On("GetFS", mock.Anything, mock.Anything).Return(gopowerstore.FileSystem{}, error(apiError))

		defaultArray := &array.PowerStoreArray{Client: clientMock, IP: validPowerStoreIP, GlobalID: validGlobalID}

		_, _, _, _, _, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, defaultArray, nil)
		assert.ErrorIs(t, err, error(apiError))
	})

	t.Run("legacy volume unknown error", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{}, errors.New(""))
		apiError := gopowerstore.APIError{
			ErrorMsg: &api.ErrorMsg{
				StatusCode: http.StatusBadRequest,
				Message:    "bad request",
			},
		}

		clientMock.On("GetFS", mock.Anything, mock.Anything).Return(gopowerstore.FileSystem{}, error(apiError))

		defaultArray := &array.PowerStoreArray{Client: clientMock, IP: validPowerStoreIP, GlobalID: validGlobalID}

		_, _, _, _, _, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, defaultArray, nil)
		assert.ErrorContains(t, err, apiError.ErrorMsg.Message)
	})
}

func TestLocker_UpdateArrays(t *testing.T) {
	lck := array.Locker{}
	err := lck.UpdateArrays("./testdata/one-arr.yaml", &fs.Fs{Util: &gofsutil.FS{}})
	assert.NoError(t, err)
	assert.Equal(t, lck.DefaultArray().Endpoint, "https://127.0.0.1/api/rest")
}

func TestLocker_GetOneArray(t *testing.T) {
	lck := array.Locker{}
	arrayMap := make(map[string]*array.PowerStoreArray)
	array := &array.PowerStoreArray{GlobalID: "globalId1"}
	arrayMap["globalId1"] = array
	lck.SetArrays(arrayMap)
	fetched, err := lck.GetOneArray("globalId1")
	assert.NoError(t, err)
	assert.Equal(t, fetched, array)
	fetched, err = lck.GetOneArray("globalId2")
	assert.Error(t, err)
	assert.NotEqual(t, fetched, array)
}
