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
	"reflect"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/powerstorecommon"
	"github.com/dell/csi-powerstore/v2/pkg/powerstorecommon/fs"
	sharednfs "github.com/dell/csm-sharednfs/nfs"
	"github.com/dell/gofsutil"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
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
	_ = os.Setenv(powerstorecommon.EnvThrottlingRateLimit, "1000")
	_ = os.Setenv(powerstorecommon.EnvMultiNASFailureThreshold, "10")
	_ = os.Setenv(powerstorecommon.EnvMultiNASCooldownPeriod, "2m")

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
					BlockProtocol: powerstorecommon.ISCSITransport,
				},
				"gid2": {
					Endpoint:      "https://127.0.0.2/api/rest",
					Username:      "user",
					Password:      "password",
					Insecure:      true,
					IsDefault:     false,
					BlockProtocol: powerstorecommon.AutoDetectTransport,
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
					BlockProtocol: powerstorecommon.AutoDetectTransport,
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
				got[k].NASCooldownTracker.(*array.NASCooldown).GetCooldownPeriod()
				assert.Equal(t, 10, got[k].NASCooldownTracker.(*array.NASCooldown).GetThreshold())
				assert.Equal(t, 2*time.Minute, got[k].NASCooldownTracker.(*array.NASCooldown).GetCooldownPeriod())
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
		_ = os.Setenv(powerstorecommon.EnvThrottlingRateLimit, "abc")
		f := &fs.Fs{Util: &gofsutil.FS{}}
		_, _, _, err := array.GetPowerStoreArrays(f, "./testdata/one-arr.yaml")
		assert.NoError(t, err)
	})

	t.Run("incorrect EnvMultiNASFailureThreshold & EnvMultiNASCooldownPeriod value", func(t *testing.T) {
		_ = os.Setenv(powerstorecommon.EnvMultiNASFailureThreshold, "0")
		_ = os.Setenv(powerstorecommon.EnvMultiNASCooldownPeriod, "0m")
		f := &fs.Fs{Util: &gofsutil.FS{}}
		got, _, _, err := array.GetPowerStoreArrays(f, "./testdata/one-arr.yaml")
		assert.NoError(t, err)
		assert.Equal(t, 5, got["gid1"].NASCooldownTracker.(*array.NASCooldown).GetThreshold())
		assert.Equal(t, 5*time.Minute, got["gid1"].NASCooldownTracker.(*array.NASCooldown).GetCooldownPeriod())
	})

	t.Run("invalid format EnvMultiNASFailureThreshold & EnvMultiNASCooldownPeriod", func(t *testing.T) {
		_ = os.Setenv(powerstorecommon.EnvMultiNASFailureThreshold, "abc")
		_ = os.Setenv(powerstorecommon.EnvMultiNASCooldownPeriod, "abc")

		f := &fs.Fs{Util: &gofsutil.FS{}}
		got, _, _, err := array.GetPowerStoreArrays(f, "./testdata/one-arr.yaml")
		assert.NoError(t, err)
		assert.Equal(t, 5, got["gid1"].NASCooldownTracker.(*array.NASCooldown).GetThreshold())
		assert.Equal(t, 5*time.Minute, got["gid1"].NASCooldownTracker.(*array.NASCooldown).GetCooldownPeriod())
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
	gotID, err := array.ParseVolumeID(context.Background(), id, &array.PowerStoreArray{IP: ip, GlobalID: "gid1"}, volCap)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), id, gotID.LocalUUID)
	assert.Equal(s.T(), ip, gotID.LocalArrayGlobalID)
	assert.Equal(s.T(), "nfs", gotID.Protocol)
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
	gotID, err := array.ParseVolumeID(context.Background(), id, &array.PowerStoreArray{IP: ip, GlobalID: validGlobalID}, volCap)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), id, gotID.LocalUUID)
	assert.Equal(s.T(), validGlobalID, gotID.LocalArrayGlobalID)
	assert.Equal(s.T(), scsi, gotID.Protocol)
}

func (s *LegacyParseVolumeTestSuite) TestMissingSCSIProtocol() {
	// When the protocol is not included in the volume name,
	// if GetVolume returns without error, the protocol should be scsi.
	s.mockAPI.GetVolume.Return(gopowerstore.Volume{ID: validBlockVolumeUUID}, nil)

	gotID, err := array.ParseVolumeID(context.Background(), validBlockVolumeUUID, s.psArray, nil)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), validBlockVolumeUUID, gotID.LocalUUID)
	assert.Equal(s.T(), s.psArray.GlobalID, gotID.LocalArrayGlobalID)
	assert.Equal(s.T(), scsi, gotID.Protocol)
}

func (s *LegacyParseVolumeTestSuite) TestGetNFSProtocolFromAPIClient() {
	// When the protocol is not included in the volume name,
	// if GetVolume returns an error and GetFS returns without error,
	// the protocol should be nfs.
	s.mockAPI.GetVolume.Return(gopowerstore.Volume{}, errors.New("error"))
	s.mockAPI.GetFS.Return(gopowerstore.FileSystem{ID: validFileSystemUUID}, nil)

	id, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, s.psArray, nil)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), validFileSystemUUID, id.LocalUUID)
	assert.Equal(s.T(), validGlobalID, id.LocalArrayGlobalID)
	assert.Equal(s.T(), nfs, id.Protocol)
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

	_, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, s.psArray, nil)
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

	_, err := array.ParseVolumeID(context.Background(), validFileSystemUUID, s.psArray, nil)
	assert.ErrorContains(s.T(), err, s.mockAPI.APIError.ErrorMsg.Message)
}

func (s *LegacyParseVolumeTestSuite) TestIPAsArrayID() {
	// When a volume name contains an IP as the second element delimited by a forward slash,
	// ParseVolumeID should get the PowerStore Global ID from the IP.

	// Map the PowerStore IP to a valid Global ID
	array.IPToArray = map[string]string{validPowerStoreIP: validGlobalID}

	// Build a volume ID using an IP in place of a PowerStore Global ID
	volID := buildVolumeName(validBlockVolumeUUID, validPowerStoreIP, scsi)

	id, err := array.ParseVolumeID(context.Background(), volID, nil, nil)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), validBlockVolumeUUID, id.LocalUUID)
	assert.Equal(s.T(), validGlobalID, id.LocalArrayGlobalID)
	assert.Equal(s.T(), scsi, id.Protocol)
}

func TestParseVolumeID(t *testing.T) {
	t.Run("parse volume name", func(t *testing.T) {
		id, err := array.ParseVolumeID(context.Background(), validBlockVolumeNameSCSI, nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, validBlockVolumeUUID, id.LocalUUID)
		assert.Equal(t, validGlobalID, id.LocalArrayGlobalID)
		assert.Equal(t, scsi, id.Protocol)
	})

	t.Run("incorrect volume id", func(t *testing.T) {
		_, err := array.ParseVolumeID(context.Background(), "", nil, nil)
		assert.Error(t, err)
	})

	t.Run("parse metro volume name", func(t *testing.T) {
		id, err := array.ParseVolumeID(context.Background(), validMetroBlockVolumeNameSCSI, nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, validBlockVolumeUUID, id.LocalUUID)
		assert.Equal(t, validRemoteBlockVolumeUUID, id.RemoteUUID)
		assert.Equal(t, validGlobalID, id.LocalArrayGlobalID)
		assert.Equal(t, validRemoteGlobalID, id.RemoteArrayGlobalID)
		assert.Equal(t, scsi, id.Protocol)
	})

	localVolUUID := "aaaaaaaa-0000-bbbb-1111-cccccccccccc"
	powerstoreLocalSystemID := "PS000000000001"
	SharedNFSVolumeID := sharednfs.CsiNfsPrefixDash + localVolUUID + "/" + powerstoreLocalSystemID + "/" + scsi
	type args struct {
		ctx          context.Context
		volumeHandle string
		defaultArray *array.PowerStoreArray
		vc           *csi.VolumeCapability
	}
	tests := []struct {
		name    string
		args    args
		want    array.VolumeHandle
		wantErr bool
	}{
		{
			name: "parse volume handle for a host-based nfs volume",
			args: args{
				ctx:          context.Background(),
				volumeHandle: SharedNFSVolumeID,
				defaultArray: nil,
				vc:           nil,
			},
			want: array.VolumeHandle{
				LocalUUID:           sharednfs.CsiNfsPrefixDash + localVolUUID,
				LocalArrayGlobalID:  powerstoreLocalSystemID,
				RemoteUUID:          "",
				RemoteArrayGlobalID: "",
				Protocol:            scsi,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := array.ParseVolumeID(tt.args.ctx, tt.args.volumeHandle, tt.args.defaultArray, tt.args.vc)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseVolumeID() got = %v, want %v", got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVolumeID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
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

func TestGetLeastUsedActiveNAS(t *testing.T) {
	ctx := context.Background()
	clientMock := new(gopowerstoremock.Client)

	// Define NAS servers for different test cases
	validNAS1 := gopowerstore.NAS{
		Name:              "nasA",
		OperationalStatus: gopowerstore.Started,
		HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Info},
		FileSystems:       make([]gopowerstore.FileSystem, 3), // 3 FS
	}

	validNAS2 := gopowerstore.NAS{
		Name:              "nasB",
		OperationalStatus: gopowerstore.Started,
		HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.None},
		FileSystems:       make([]gopowerstore.FileSystem, 2), // 2 FS (should be chosen)
	}

	validNAS3 := gopowerstore.NAS{
		Name:              "nasC",
		OperationalStatus: gopowerstore.Started,
		HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Info},
		FileSystems:       make([]gopowerstore.FileSystem, 2), // 2 FS, but lexicographically larger
	}

	validNAS4 := gopowerstore.NAS{
		Name:              "nasD",
		OperationalStatus: gopowerstore.Started,
		HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Info},
		FileSystems:       make([]gopowerstore.FileSystem, 1),
	}

	invalidNAS1 := gopowerstore.NAS{
		Name:              "nasX",
		OperationalStatus: gopowerstore.Stopped, // Inactive NAS
		HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Info},
		FileSystems:       make([]gopowerstore.FileSystem, 1),
	}

	invalidNAS2 := gopowerstore.NAS{
		Name:              "nasY",
		OperationalStatus: gopowerstore.Started,
		HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Critical}, // Invalid state
		FileSystems:       make([]gopowerstore.FileSystem, 1),
	}

	invalidNAS3 := gopowerstore.NAS{
		Name:              "nasZ",
		OperationalStatus: gopowerstore.Started,
		HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Info},
		FileSystems:       make([]gopowerstore.FileSystem, 1),
	}

	tests := []struct {
		name           string
		nasList        []gopowerstore.NAS
		expectedNAS    *gopowerstore.NAS
		markForFailure []string
		nasServersInSc []string

		expectedErrMsg string
	}{
		{
			name:           "Valid NAS selection (least FS count wins)",
			nasList:        []gopowerstore.NAS{validNAS1, validNAS2, validNAS3, validNAS4, invalidNAS1, invalidNAS2},
			expectedNAS:    &validNAS4, // nasD has the least FS count (1)
			nasServersInSc: []string{"nasA", "nasD"},
		},
		{
			name:           "NAS not in nasServers map",
			nasList:        []gopowerstore.NAS{invalidNAS3},
			expectedErrMsg: "no suitable NAS server found",
			nasServersInSc: []string{"nasA", "nasD"},
		},
		{
			name:           "NAS not active",
			nasList:        []gopowerstore.NAS{invalidNAS1},
			expectedErrMsg: "no suitable NAS server found",
			nasServersInSc: []string{"nasA", "nasD", "nasX"},
		},
		{
			name:           "NAS with invalid health state",
			nasList:        []gopowerstore.NAS{invalidNAS2},
			expectedErrMsg: "no suitable NAS server found",
			nasServersInSc: []string{"nasA", "nasD", "nasY"},
		},
		{
			name:           "All NAS servers inactive or unhealthy",
			nasList:        []gopowerstore.NAS{invalidNAS1, invalidNAS2},
			expectedErrMsg: "no suitable NAS server found",
			nasServersInSc: []string{"nasA", "nasB", "nasC", "nasD", "nasX", "nasY", "nasZ"},
		},
		{
			name:           "All NAS servers are in cooldown 1",
			nasList:        []gopowerstore.NAS{validNAS1, validNAS2, validNAS3, validNAS4, invalidNAS1, invalidNAS2},
			expectedNAS:    &validNAS4, // nasD has the least Failure count (1)
			markForFailure: []string{"nasA", "nasD"},
			nasServersInSc: []string{"nasD", "nasA"},
		},
		{
			name:           "All NAS servers are in cooldown 2",
			nasList:        []gopowerstore.NAS{validNAS1, validNAS2, validNAS3, validNAS4, invalidNAS1, invalidNAS2},
			expectedNAS:    &validNAS1, // nasA has the least Failure count (1)
			markForFailure: []string{"nasA", "nasD", "nasD"},
			nasServersInSc: []string{"nasD", "nasA"},
		},
		{
			name:           "Few NAS servers inactive or unhealthy and rest are in cooldown",
			nasList:        []gopowerstore.NAS{invalidNAS1, invalidNAS2, validNAS3, validNAS4},
			expectedNAS:    &validNAS3, // nasC has the least Failure count (1)
			markForFailure: []string{"nasC", "nasD", "nasD"},
			nasServersInSc: []string{"nasA", "nasB", "nasC", "nasD", "nasX", "nasY", "nasZ"},
		},
		{
			name:           "Empty NAS list",
			nasList:        []gopowerstore.NAS{},
			expectedErrMsg: "no suitable NAS server found",
		},
		{
			name:           "Error fetching NAS servers",
			nasList:        nil,
			expectedErrMsg: "failed to fetch NAS servers",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock expectations
			if tc.nasList == nil {
				clientMock.On("GetNASServers", ctx).Return(nil, errors.New("failed to fetch NAS servers")).Once()
			} else {
				clientMock.On("GetNASServers", ctx).Return(tc.nasList, nil).Once()
			}

			arr := &array.PowerStoreArray{Client: clientMock, NASCooldownTracker: array.NewNASCooldown(30*time.Minute, 1)}
			for _, nas := range tc.markForFailure {
				arr.NASCooldownTracker.MarkFailure(nas)
			}

			// Call the function
			result, err := array.GetLeastUsedActiveNAS(ctx, arr, tc.nasServersInSc)

			// Assertions
			if tc.expectedErrMsg != "" {
				assert.Empty(t, result)
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.expectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.expectedNAS.Name, result)
			}

			clientMock.AssertExpectations(t)
		})
	}
}

func TestIsLessUsed(t *testing.T) {
	makeFS := func(count int) []gopowerstore.FileSystem {
		return make([]gopowerstore.FileSystem, count)
	}

	tests := []struct {
		name     string
		nas      *gopowerstore.NAS
		current  *gopowerstore.NAS
		expected bool
	}{
		{
			name:     "NAS has fewer filesystems than current",
			nas:      &gopowerstore.NAS{Name: "nasA", FileSystems: makeFS(2)},
			current:  &gopowerstore.NAS{Name: "nasB", FileSystems: makeFS(3)},
			expected: true,
		},
		{
			name:     "NAS has more filesystems than current",
			nas:      &gopowerstore.NAS{Name: "nasA", FileSystems: makeFS(4)},
			current:  &gopowerstore.NAS{Name: "nasB", FileSystems: makeFS(3)},
			expected: false,
		},
		{
			name:     "NAS and current have same FS count, NAS name is lexicographically smaller",
			nas:      &gopowerstore.NAS{Name: "nasA", FileSystems: makeFS(2)},
			current:  &gopowerstore.NAS{Name: "nasB", FileSystems: makeFS(2)},
			expected: true,
		},
		{
			name:     "NAS and current have same FS count, NAS name is lexicographically larger",
			nas:      &gopowerstore.NAS{Name: "nasC", FileSystems: makeFS(2)},
			current:  &gopowerstore.NAS{Name: "nasB", FileSystems: makeFS(2)},
			expected: false,
		},
		{
			name:     "NAS and current are identical",
			nas:      &gopowerstore.NAS{Name: "nasA", FileSystems: makeFS(2)},
			current:  &gopowerstore.NAS{Name: "nasA", FileSystems: makeFS(2)},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := array.IsLessUsed(tc.nas, tc.current)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestResetFailure(t *testing.T) {
	tests := []struct {
		name             string
		nasList          []string
		markForFailure   []string
		expectedFailures int
		expectedCooldown time.Duration
		expectedMapLen   int
	}{
		{
			name:             "1 failure",
			markForFailure:   []string{"nas1"},
			expectedFailures: 1,
			expectedCooldown: 1 * time.Minute,
		},
		{
			name:             "2 failures",
			markForFailure:   []string{"nas1", "nas1"},
			expectedFailures: 2,
			expectedCooldown: 1 * time.Minute,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nas := array.NewNASCooldown(tc.expectedCooldown, 1)
			for _, nasName := range tc.markForFailure {
				nas.MarkFailure(nasName)
			}
			assert.Equal(t, tc.expectedFailures, nas.GetStatusMap()["nas1"].Failures)
			assert.WithinDuration(t, time.Now(), nas.GetStatusMap()["nas1"].CooldownUntil, tc.expectedCooldown)

			nas.ResetFailure("nas1")
			assert.Empty(t, nas.GetStatusMap()["nas1"])
		})
	}
}

func TestFallbackRetry(t *testing.T) {
	nas := array.NewNASCooldown(1*time.Minute, 1)
	nas.MarkFailure("nas1")
	nas.MarkFailure("nas1")
	nas.MarkFailure("nas3")

	tests := []struct {
		name    string
		nasList []string
		want    string
	}{
		{
			name:    "Test FallbackRetry with nas1, nas2, nas3",
			nasList: []string{"nas1", "nas2", "nas3"},
			want:    "nas2",
		},
		{
			name:    "Test FallbackRetry with nas1, nas2",
			nasList: []string{"nas1", "nas2"},
			want:    "nas2",
		},
		{
			name:    "Test FallbackRetry with nas1",
			nasList: []string{"nas1"},
			want:    "nas1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nas.FallbackRetry(tt.nasList)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getVolumeIDPrefix(t *testing.T) {
	legacyVolumeID := "1cd254s"

	type args struct {
		ID string
	}
	tests := []struct {
		name       string
		args       args
		wantPrefix string
	}{
		{
			name: "legacy volume ID",
			args: args{
				ID: legacyVolumeID,
			},
			wantPrefix: "",
		},
		{
			name: "volume UUID with no prefix",
			args: args{
				ID: validBlockVolumeUUID,
			},
			wantPrefix: "",
		},
		{
			name: "volume UUID with host-based nfs prefix",
			args: args{
				ID: sharednfs.CsiNfsPrefixDash + validBlockVolumeUUID,
			},
			wantPrefix: sharednfs.CsiNfsPrefixDash,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrefix := array.GetVolumeUUIDPrefix(tt.args.ID)
			if gotPrefix != tt.wantPrefix {
				t.Errorf("getVolumeIDPrefix() gotPrefix = %v, want %v", gotPrefix, tt.wantPrefix)
			}
		})
	}
}
