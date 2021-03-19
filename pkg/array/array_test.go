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

package array_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/mocks"
	"github.com/dell/csi-powerstore/pkg/array"
	"github.com/dell/csi-powerstore/pkg/common"
	"github.com/dell/csi-powerstore/pkg/common/fs"
	"github.com/dell/gofsutil"
	"github.com/stretchr/testify/assert"
)

func TestGetPowerStoreArrays(t *testing.T) {
	type args struct {
		fs   fs.FsInterface
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
				"127.0.0.1": {
					Endpoint:      "https://127.0.0.1/api/rest",
					Username:      "admin",
					Password:      "password",
					Insecure:      true,
					IsDefault:     true,
					BlockProtocol: common.ISCSITransport,
				},
				"127.0.0.2": {
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
				"127.0.0.1": {
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
			got, _, err := array.GetPowerStoreArrays(tt.args.fs, tt.args.data)
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

		_, _, err := array.GetPowerStoreArrays(fsMock, path)
		assert.Error(t, err)
		assert.Equal(t, e, err)
	})

	t.Run("can't unmarshal data", func(t *testing.T) {
		path := "some-path"
		fsMock := new(mocks.FsInterface)
		fsMock.On("ReadFile", path).Return([]byte("some12frandomgtqxt\nhere"), nil)

		_, _, err := array.GetPowerStoreArrays(fsMock, path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot unmarshal")
	})

	t.Run("incorrect endpoint", func(t *testing.T) {
		f := &fs.Fs{Util: &gofsutil.FS{}}
		_, _, err := array.GetPowerStoreArrays(f, "./testdata/incorrect-endpoint.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can't get ips from endpoint")
	})

	t.Run("incorrect throttling limit", func(t *testing.T) {
		_ = os.Setenv(common.EnvThrottlingRateLimit, "abc")
		f := &fs.Fs{Util: &gofsutil.FS{}}
		_, _, err := array.GetPowerStoreArrays(f, "./testdata/one-arr.yaml")
		assert.NoError(t, err)
	})
}

func TestParseVolumeID(t *testing.T) {
	t.Run("incorrect volume id", func(t *testing.T) {
		_, _, _, err := array.ParseVolumeID(context.Background(), "", nil, nil)
		assert.Error(t, err)
	})

	t.Run("volume capability", func(t *testing.T) {
		id := "1cd254s"
		ip := "192.168.0.1"
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
		gotId, gotIp, protocol, err := array.ParseVolumeID(context.Background(), id, &array.PowerStoreArray{IP: ip}, volCap)
		assert.NoError(t, err)
		assert.Equal(t, id, gotId)
		assert.Equal(t, ip, gotIp)
		assert.Equal(t, protocol, "nfs")
	})
}

func TestLocker_UpdateArrays(t *testing.T) {
	lck := array.Locker{}
	err := lck.UpdateArrays("./testdata/one-arr.yaml", &fs.Fs{Util: &gofsutil.FS{}})
	assert.NoError(t, err)
	assert.Equal(t, lck.DefaultArray().Endpoint, "https://127.0.0.1/api/rest")
}
