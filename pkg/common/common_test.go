/*
 *
 * Copyright © 2021-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package common_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gocsi/utils"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCustomLogger(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	lg := &common.CustomLogger{}
	ctx := context.Background()
	lg.Info(ctx, "foo")
	lg.Debug(ctx, "bar")
	lg.Error(ctx, "spam")
}

func TestRmSockFile(t *testing.T) {
	sockPath := "unix:///var/run/csi/csi.sock"
	trimmedSockPath := "/var/run/csi/csi.sock"
	_ = os.Setenv(utils.CSIEndpoint, sockPath)

	t.Run("removed socket", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, nil)
		fsMock.On("RemoveAll", trimmedSockPath).Return(nil)

		common.RmSockFile(fsMock)
	})

	t.Run("failed to remove socket", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, nil)
		fsMock.On("RemoveAll", trimmedSockPath).Return(fmt.Errorf("some error"))

		common.RmSockFile(fsMock)
	})

	t.Run("not found", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, os.ErrNotExist)

		common.RmSockFile(fsMock)
	})

	t.Run("may or may not exist", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, fmt.Errorf("some other error"))

		common.RmSockFile(fsMock)
	})

	t.Run("no endpoint set", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		_ = os.Setenv(utils.CSIEndpoint, "")

		common.RmSockFile(fsMock)
	})

}

func TestSetLogFields(t *testing.T) {
	t.Run("empty context", func(t *testing.T) {
		common.SetLogFields(nil, log.Fields{})
	})
}

func TestGetLogFields(t *testing.T) {
	t.Run("empty context", func(t *testing.T) {
		fields := common.GetLogFields(nil)
		assert.Equal(t, log.Fields{}, fields)
	})

	t.Run("req id", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), csictx.RequestIDKey, "1")
		fields := common.GetLogFields(ctx)
		assert.Equal(t, log.Fields{"RequestID": "1"}, fields)
	})
}

func TestGetISCSITargetsInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetStorageISCSITargetAddresses", context.Background()).Return([]gopowerstore.IPPoolAddress{}, e)
		_, err := common.GetISCSITargetsInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})
}

func TestGetFCTargetsInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetFCPorts", context.Background()).Return([]gopowerstore.FcPort{}, e)
		_, err := common.GetFCTargetsInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})
}

func TestIsK8sMetadataSupported(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(0.0), e)
		version := common.IsK8sMetadataSupported(clientMock)
		assert.Equal(t, version, false)
	})
}

func TestGetNVMEFCTargetInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{}, e)
		clientMock.On("GetFCPorts", context.Background()).Return([]gopowerstore.FcPort{}, e)
		_, err := common.GetNVMEFCTargetInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})
}

func TestHasRequiredTopology(t *testing.T) {
	nfsTopology := &csi.Topology{Segments: map[string]string{"csi-powerstore.dellemc.com/10.0.0.0-nfs": "true"}}
	iscsiTopology := &csi.Topology{Segments: map[string]string{"csi-powerstore.dellemc.com/10.0.0.0-iscsi": "true"}}

	type args struct {
		topologies       []*csi.Topology
		arrIP            string
		requiredTopology string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "only nfs is present in topologies",
			args: args{topologies: []*csi.Topology{nfsTopology}, arrIP: "10.0.0.0", requiredTopology: "nfs"},
			want: true,
		},
		{
			name: "nfs & iscsi is present in topologies",
			args: args{topologies: []*csi.Topology{iscsiTopology, nfsTopology}, arrIP: "10.0.0.0", requiredTopology: "nfs"},
			want: true,
		},
		{
			name: "nfs is not present in topologies",
			args: args{topologies: []*csi.Topology{iscsiTopology}, arrIP: "10.0.0.0", requiredTopology: "nfs"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, common.HasRequiredTopology(tt.args.topologies, tt.args.arrIP, tt.args.requiredTopology), "HasRequiredTopology(%v, %v, %v)", tt.args.topologies, tt.args.arrIP, tt.args.requiredTopology)
		})
	}
}

func TestGetNfsTopology(t *testing.T) {
	t.Run("nfs topology is true", func(t *testing.T) {
		topology := common.GetNfsTopology("10.0.0.0")
		assert.Equal(t, topology, []*csi.Topology{{Segments: map[string]string{"csi-powerstore.dellemc.com/10.0.0.0-nfs": "true"}}})
	})

	t.Run("nfs topology should not be false", func(t *testing.T) {
		topology := common.GetNfsTopology("10.0.0.0")
		assert.NotEqual(t, topology, []*csi.Topology{{Segments: map[string]string{"csi-powerstore.dellemc.com/10.0.0.0-nfs": "false"}}})
	})
}

func Test_contains(t *testing.T) {
	type args struct {
		slice   []string
		element string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"elementPresent", args{slice: []string{"firstElement", "secondElement"}, element: "secondElement"}, true},
		{"elementNotPresent", args{slice: []string{"firstElement", "secondElement"}, element: "thirdElement"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := common.Contains(tt.args.slice, tt.args.element); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExternalAccessAlreadyAdded(t *testing.T) {
	type args struct {
		export         gopowerstore.NFSExport
		externalAccess string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"externalAccessPresentInRWHosts", args{export: gopowerstore.NFSExport{RWHosts: []string{"10.0.0.0/255.255.255.255"}}, externalAccess: "10.0.0.0"}, true},
		{"externalAccessNotPresentInRWHosts", args{export: gopowerstore.NFSExport{RWHosts: []string{"10.232.0.0/255.255.255.255"}}, externalAccess: "10.10.0.0"}, false},
		{"externalAccessPresentInROHosts", args{export: gopowerstore.NFSExport{ROHosts: []string{"10.0.0.0/255.255.255.255"}}, externalAccess: "10.0.0.0"}, true},
		{"externalAccessNotPresentInROHosts", args{export: gopowerstore.NFSExport{ROHosts: []string{"10.232.0.0/255.255.255.255"}}, externalAccess: "10.10.0.0"}, false},
		{"externalAccessPresentInRWRootHosts", args{export: gopowerstore.NFSExport{RWRootHosts: []string{"10.0.0.0/255.255.255.255"}}, externalAccess: "10.0.0.0"}, true},
		{"externalAccessNotPresentInRWRootHosts", args{export: gopowerstore.NFSExport{RWRootHosts: []string{"10.232.0.0/255.255.255.255"}}, externalAccess: "10.10.0.0"}, false},
		{"externalAccessPresentInRORootHosts", args{export: gopowerstore.NFSExport{RORootHosts: []string{"10.0.0.0/255.255.255.255"}}, externalAccess: "10.0.0.0"}, true},
		{"externalAccessNotPresentInRORootHosts", args{export: gopowerstore.NFSExport{RORootHosts: []string{"10.232.0.0/255.255.255.255"}}, externalAccess: "10.10.0.0"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := common.ExternalAccessAlreadyAdded(tt.args.export, tt.args.externalAccess); got != tt.want {
				t.Errorf("ExternalAccessAlreadyAdded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	type args struct {
		externalAccessCIDR string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"Valid IP with net mask", args{externalAccessCIDR: "10.232.58.2/16"}, "10.232.0.0/255.255.0.0", false},
		{"Valid IP without net mask", args{externalAccessCIDR: "10.232.58.2"}, "10.232.58.2/255.255.255.255", false},
		{"InValid IP without net mask", args{externalAccessCIDR: "10.232.58"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := common.ParseCIDR(tt.args.externalAccessCIDR)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetPollingFrequency(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{"Setting environament variable", args{ctx: context.TODO()}, 100},
		{"Expecting default value to be set", args{ctx: context.TODO()}, 60},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if i == 0 {
				os.Setenv("X_CSI_PODMON_ARRAY_CONNECTIVITY_POLL_RATE", "100")
			}
			// need to import this function because the package name in this file is not common
			// @TO-DO rename package name to common
			if got := common.SetPollingFrequency(tt.args.ctx); got != tt.want {
				t.Errorf("SetPollingFrequency() = %v, want %v", got, tt.want)
			}
			os.Unsetenv("X_CSI_PODMON_ARRAY_CONNECTIVITY_POLL_RATE")
		})
	}
}

func Test_setAPIPort(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{"Fetching port number from Environment variable", args{ctx: context.TODO()}},
		{"Fetching & setting default port number", args{ctx: context.TODO()}},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if i == 0 {
				os.Setenv("X_CSI_PODMON_API_PORT", "8090")
				common.SetAPIPort(tt.args.ctx)
				if common.APIPort != ":8090" {
					t.Errorf("setAPIPort() error, want 8090 port found %v", common.APIPort)
				}
				os.Unsetenv("X_CSI_PODMON_API_PORT")
			}
			common.SetAPIPort(tt.args.ctx)
			if common.APIPort != ":8083" {
				t.Errorf("setAPIPort() error, want 8083 port found %v", common.APIPort)
			}
		})
	}
}

func TestRandomString(t *testing.T) {
	type args struct {
		len int
	}
	tests := []struct {
		name string
		args args
	}{
		{"Generating some random string", args{len: 5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since each byte in the slice is represented by two hex characters in the resulting string, the length of the string returned by the function will be len * 2.
			if got := common.RandomString(tt.args.len); len(got) != 5*2 {
				t.Errorf("RandomString() = %v, have len %d and want 5*2", got, len(got))
			}
		})
	}
}

func TestGetIPListWithMaskFromString(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"Valid IP without subnet mask, Test 1", args{input: "10.1.1.2"}, "10.1.1.2", false},
		{"Invalid IP without subnet maskTest 2", args{input: "10.256.1.2"}, "", true},
		{"Invalid IP with subnet mask, Test 3", args{input: "10.256.1.2/24"}, "", true},
		{"Valid IP with subnet mask, Test 4", args{input: "10.1.1.2/24"}, "10.1.1.2/255.255.255.0", false},
		{"Invalid IP with subnet maskTest 5", args{input: "10.256.1.2/24/25"}, "", true},
		{"Invalid IP with Invalid subnet mask, Test 6", args{input: "10.255.1.2/24/25"}, "", true},
		{"Invalid IP with Invalid subnet mask, Test 7", args{input: "10.255.1.2/38"}, "", true},
		{"Invalid IP with Invalid subnet mask, Test 8", args{input: "10.255.1.2/x"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := common.GetIPListWithMaskFromString(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetIPListWithMaskFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetIPListWithMaskFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetIPListFromString(t *testing.T) {
	type args struct {
		input string
	}
	x := []string{}
	x = nil
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"Valid IP, Test 1", args{input: "10.255.1.2"}, []string{"10.255.1.2"}},
		{"InValid IP, Test 2", args{input: "10.256.1.2"}, x},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := common.GetIPListFromString(tt.args.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIPListFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReachableEndPoint(t *testing.T) {
	type args struct {
		endpoint string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"Unreachable IP, ", args{endpoint: "10.255.1.2:100"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := common.ReachableEndPoint(tt.args.endpoint); got != tt.want {
				t.Errorf("ReachableEndPoint() = %v, want %v", got, tt.want)
			}
		})
	}
}
