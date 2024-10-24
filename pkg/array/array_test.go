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
	"github.com/stretchr/testify/suite"
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
			args:    args{data: "./testdata/two-arr.yaml", fs: &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}},
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
			args:    args{data: "./testdata/one-arr.yaml", fs: &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}},
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
			args:    args{data: "./testdata/no-arr.yaml", fs: &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}},
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
		f := &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/incorrect-endpoint.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't get ips from endpoint")
	})

	t.Run("invalid endpoint", func(t *testing.T) {
		f := &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/invalid-endpoint.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't get ips from endpoint")
	})
	t.Run("no global ID", func(t *testing.T) {
		f := &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/no-globalID.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no GlobalID field found in config.yaml")
	})

	t.Run("incorrect throttling limit", func(t *testing.T) {
		_ = os.Setenv(common.EnvThrottlingRateLimit, "abc")
		f := &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/one-arr.yaml")
		assert.NoError(t, err)
	})
}

type LegacyParseVolumeTestSuite struct {
	suite.Suite

	// Used to mock gopowerstore
	mockAPI struct {
		APIError gopowerstore.APIError
		Client   *gopowerstoremock.Client

		GetVolume *mock.Call
		GetFS     *mock.Call
	}

	psArray *array.PowerStoreArray
}

func TestLegacyParseVolumeSuite(t *testing.T) {
	suite.Run(t, new(LegacyParseVolumeTestSuite))
}

func (s *LegacyParseVolumeTestSuite) SetupSuite() {
	s.mockAPI.Client = new(gopowerstoremock.Client)
	s.psArray = &array.PowerStoreArray{Client: s.mockAPI.Client, IP: validPowerStoreIP, GlobalID: validGlobalID}
}

func (s *LegacyParseVolumeTestSuite) SetupTest() {
	// A standard setup for mocking these API functions for these tests.
	// Functions can be modified in the test implementation if needed.
	s.mockAPI.GetVolume = s.mockAPI.Client.On("GetVolume", mock.Anything, mock.Anything)
	s.mockAPI.GetFS = s.mockAPI.Client.On("GetFS", mock.Anything, mock.Anything)
}

func (s *LegacyParseVolumeTestSuite) TearDownTest() {
	// Unset any mocks that were configured during the test.
	s.mockAPI.GetVolume.Unset()
	s.mockAPI.GetFS.Unset()

	// Reset the API error for the next test run.
	s.mockAPI.APIError = *gopowerstore.NewAPIError()
}

func (s *LegacyParseVolumeTestSuite) TestVolumeCapabilityNFS() {
	// When VolumeCapability (with mountVolume.FsType = "nfs") and default PowerStore array are passed to ParseVolumeID,
	// use the capability to get the protocol and default array to get the PowerStore Global ID.
	id := "1cd254s"
	ip := "gid1"
	getVolCap := func() *csi.VolumeCapability {
		accessMode := new(csi.VolumeCapability_AccessMode)
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
		accessType := new(csi.VolumeCapability_Mount)
		mountVolume := new(csi.VolumeCapability_MountVolume)
		mountVolume.FsType = nfs
		accessType.Mount = mountVolume
		capability := new(csi.VolumeCapability)
		capability.AccessMode = accessMode
		capability.AccessType = accessType
		return capability
	}

	volCap := getVolCap()
	gotID, gotIP, protocol, _, _, err := array.ParseVolumeID(context.Background(), id, &array.PowerStoreArray{IP: ip, GlobalID: "gid1"}, volCap)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), id, gotID)
	assert.Equal(s.T(), ip, gotIP)
	assert.Equal(s.T(), protocol, "nfs")
}

func (s *LegacyParseVolumeTestSuite) TestVolumeCapabilitySCSI() {
	// When VolumeCapability (with mountVolume.FsType = "scsi") and default PowerStore array are passed to ParseVolumeID,
	// use the capability to get the protocol and default array to get the PowerStore Global ID.
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
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), id, gotID)
	assert.Equal(s.T(), validGlobalID, gotGlobalID)
	assert.Equal(s.T(), scsi, protocol)
}

func (s *LegacyParseVolumeTestSuite) TestMissingSCSIProtocol() {
	// When the protocol is not included in the volume name,
	// if GetVolume returns without error, the protocol should be scsi.
	s.mockAPI.GetVolume.Return(gopowerstore.Volume{ID: validBlockVolumeUUID}, nil)

	id, globalID, protocol, _, _, err := array.ParseVolumeID(context.Background(), validBlockVolumeUUID, s.psArray, nil)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), validBlockVolumeUUID, id)
	assert.Equal(s.T(), s.psArray.GlobalID, globalID)
	assert.Equal(s.T(), protocol, scsi)
}

func (s *LegacyParseVolumeTestSuite) TestGetNFSProtocolFromAPIClient() {
	// When the protocol is not included in the volume name,
	// if GetVolume returns an error and GetFS returns without error,
	// the protocol should be nfs.
	s.mockAPI.GetVolume.Return(gopowerstore.Volume{}, errors.New("error"))
	s.mockAPI.GetFS.Return(gopowerstore.FileSystem{ID: validFileSystemUUID}, nil)

	id, globalID, protocol, _, _, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, s.psArray, nil)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), validFileSystemUUID, id)
	assert.Equal(s.T(), validGlobalID, globalID)
	assert.Equal(s.T(), protocol, nfs)
}

func (s *LegacyParseVolumeTestSuite) TestVolumeNotFound() {
	// When the protocol is not included in the volume name,
	// and both GetVolume and GetFS return with errors,
	// and the error returned by GetFS is http.StatusNotFound (404),
	// then ParseVolumeID should return a related error.
	s.mockAPI.GetVolume.Return(gopowerstore.Volume{}, errors.New("error"))
	s.mockAPI.APIError = gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusNotFound,
			Message:    "volume not found",
		},
	}

	s.mockAPI.GetFS.Return(gopowerstore.FileSystem{}, error(s.mockAPI.APIError))

	_, _, _, _, _, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, s.psArray, nil)
	assert.ErrorIs(s.T(), err, error(s.mockAPI.APIError))
}

func (s *LegacyParseVolumeTestSuite) TestVolumeUnknownError() {
	// When the protocol is not included in the volume name,
	// and both GetVolume and GetFS return with errors,
	// and the error returned by GetFS is NOT http.StatusNotFound (404),
	// then ParseVolumeID should return a related error.
	s.mockAPI.GetVolume.Return(gopowerstore.Volume{}, errors.New("error"))
	s.mockAPI.APIError = gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusBadRequest,
			Message:    "bad request",
		},
	}

	s.mockAPI.GetFS.Return(gopowerstore.FileSystem{}, error(s.mockAPI.APIError))

	_, _, _, _, _, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, s.psArray, nil)
	assert.ErrorContains(s.T(), err, s.mockAPI.APIError.ErrorMsg.Message)
}

func (s *LegacyParseVolumeTestSuite) TestIPAsArrayID() {
	// When a volume name contains an IP as the second element delimited by a forward slash,
	// ParseVolumeID should get the PowerStore Global ID from the IP.

	// Map the PowerStore IP to a valid Global ID
	array.IPToArray = map[string]string{validPowerStoreIP: validGlobalID}

	// Build a volume ID using an IP in place of a PowerStore Global ID
	volID := buildVolumeName(validBlockVolumeUUID, validPowerStoreIP, scsi)

	id, globalID, protocol, _, _, err := array.ParseVolumeID(context.Background(), volID, nil, nil)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), validBlockVolumeUUID, id)
	assert.Equal(s.T(), globalID, validGlobalID)
	assert.Equal(s.T(), protocol, scsi)
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
}

func TestLocker_UpdateArrays(t *testing.T) {
	lck := array.Locker{}
	err := lck.UpdateArrays("./testdata/one-arr.yaml", &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}})
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
