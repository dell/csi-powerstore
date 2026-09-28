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

package identifiers_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/mocks"
	identifiers "github.com/dell/csi-powerstore/v2/pkg/identifiers"
	csiutils "github.com/dell/gocsi/utils/csi"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRmSockFile(t *testing.T) {
	sockPath := "unix:///var/run/csi/csi.sock"
	trimmedSockPath := "/var/run/csi/csi.sock"
	_ = os.Setenv(csiutils.CSIEndpoint, sockPath)

	t.Run("removed socket", func(_ *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, nil)
		fsMock.On("RemoveAll", trimmedSockPath).Return(nil)

		identifiers.RmSockFile(fsMock)
	})

	t.Run("failed to remove socket", func(_ *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, nil)
		fsMock.On("RemoveAll", trimmedSockPath).Return(fmt.Errorf("some error"))

		identifiers.RmSockFile(fsMock)
	})

	t.Run("not found", func(_ *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, os.ErrNotExist)

		identifiers.RmSockFile(fsMock)
	})

	t.Run("may or may not exist", func(_ *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, fmt.Errorf("some other error"))

		identifiers.RmSockFile(fsMock)
	})

	t.Run("no endpoint set", func(_ *testing.T) {
		fsMock := new(mocks.FsInterface)
		_ = os.Setenv(csiutils.CSIEndpoint, "")

		identifiers.RmSockFile(fsMock)
	})
}

func TestGetISCSITargetsInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetStorageISCSITargetAddresses", context.Background()).Return([]gopowerstore.IPPoolAddress{}, e)
		_, err := identifiers.GetISCSITargetsInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})

	t.Run("no error", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetStorageISCSITargetAddresses", context.Background()).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "192.168.1.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
				},
			}, nil)
		iscsiTargetsInfo, err := identifiers.GetISCSITargetsInfoFromStorage(clientMock, "")
		assert.NotNil(t, iscsiTargetsInfo)
		assert.NoError(t, err)
	})

	// FR-1.2: IPv6 address must be passed as bare address (no brackets, no port).
	// goiscsi.validateIPAddress uses net.ParseIP which accepts bare IPv6 but rejects
	// "[IPv6]:port". gobrick skips port-append when ":" is present; iscsiadm uses
	// default port 3260. See DEPENDENCIES.md §goiscsi.
	t.Run("IPv6 address produces bare iSCSI portal", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetStorageISCSITargetAddresses", context.Background()).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "2001:db8::1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn.ipv6.example"},
				},
			}, nil)
		targets, err := identifiers.GetISCSITargetsInfoFromStorage(clientMock, "")
		assert.NoError(t, err)
		assert.Len(t, targets, 1)
		assert.Equal(t, "2001:db8::1", targets[0].Portal, "IPv6 iSCSI portal must be bare address (gobrick appends port for IPv4, skips for IPv6)")
	})

	// FR-1.2 regression: IPv4 portal must be bare address; gobrick appends ":3260".
	t.Run("IPv4 address iSCSI portal is bare address", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetStorageISCSITargetAddresses", context.Background()).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "10.0.0.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn.ipv4.example"},
				},
			}, nil)
		targets, err := identifiers.GetISCSITargetsInfoFromStorage(clientMock, "")
		assert.NoError(t, err)
		assert.Len(t, targets, 1)
		assert.Equal(t, "10.0.0.1", targets[0].Portal, "IPv4 iSCSI portal is bare address; gobrick appends :3260 before passing to goiscsi")
	})

	// FR-1.4: dual-purpose address (Storage_Iscsi_Target + Storage_NVMe_TCP_Port) — iSCSI path.
	// Same bare-address convention applies.
	t.Run("dual-purpose IPv6 address produces bare iSCSI portal", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetStorageISCSITargetAddresses", context.Background()).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "2001:db8::2",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn.dual.example"},
					Purposes: []gopowerstore.IPPurposeTypeEnum{
						gopowerstore.IPPurposeTypeEnumStorageIscsiTarget,
						gopowerstore.IPPurposeTypeEnumStorageNVMETCPPort,
					},
				},
			}, nil)
		targets, err := identifiers.GetISCSITargetsInfoFromStorage(clientMock, "")
		assert.NoError(t, err)
		assert.Len(t, targets, 1)
		assert.Equal(t, "2001:db8::2", targets[0].Portal, "dual-purpose IPv6 iSCSI portal must be bare address")
	})
}

func TestGetNVMETCPTargetsInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{}, e)
		clientMock.On("GetStorageNVMETCPTargetAddresses", context.Background()).Return([]gopowerstore.IPPoolAddress{}, e)
		_, err := identifiers.GetNVMETCPTargetsInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})

	t.Run("no error", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{}, nil)
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "192.168.1.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
				},
			}, nil)
		nvmetcpTargetInfo, err := identifiers.GetNVMETCPTargetsInfoFromStorage(clientMock, "")
		assert.NotNil(t, nvmetcpTargetInfo)
		assert.NoError(t, err)
	})

	// FR-1.3: IPv6 address must be passed as bare address. gonvme passes
	// "-a <portal> -s 4420" as separate args; bracketed form is unnecessary.
	// gobrick skips port-append when ":" is present. See DEPENDENCIES.md §gonvme.
	t.Run("IPv6 address produces bare NVMe portal", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{NVMeNQN: "nqn.ipv6.example"}, nil)
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{Address: "2001:db8::1"},
			}, nil)
		targets, err := identifiers.GetNVMETCPTargetsInfoFromStorage(clientMock, "")
		assert.NoError(t, err)
		assert.Len(t, targets, 1)
		assert.Equal(t, "2001:db8::1", targets[0].Portal, "IPv6 NVMe portal must be bare address (gobrick appends port for IPv4, skips for IPv6)")
	})

	// FR-1.3 regression: IPv4 portal is bare address; gobrick appends ":4420".
	t.Run("IPv4 address NVMe portal is bare address", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{NVMeNQN: "nqn.ipv4.example"}, nil)
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{Address: "10.0.0.1"},
			}, nil)
		targets, err := identifiers.GetNVMETCPTargetsInfoFromStorage(clientMock, "")
		assert.NoError(t, err)
		assert.Len(t, targets, 1)
		assert.Equal(t, "10.0.0.1", targets[0].Portal, "IPv4 NVMe portal is bare address; gobrick appends :4420 before passing to gonvme")
	})

	// FR-1.4: dual-purpose address (Storage_Iscsi_Target + Storage_NVMe_TCP_Port) — NVMe path.
	// Same bare-address convention applies.
	t.Run("dual-purpose IPv6 address produces bare NVMe portal", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{NVMeNQN: "nqn.dual.example"}, nil)
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "2001:db8::2",
					Purposes: []gopowerstore.IPPurposeTypeEnum{
						gopowerstore.IPPurposeTypeEnumStorageIscsiTarget,
						gopowerstore.IPPurposeTypeEnumStorageNVMETCPPort,
					},
				},
			}, nil)
		targets, err := identifiers.GetNVMETCPTargetsInfoFromStorage(clientMock, "")
		assert.NoError(t, err)
		assert.Len(t, targets, 1)
		assert.Equal(t, "2001:db8::2", targets[0].Portal, "dual-purpose IPv6 NVMe portal must be bare address")
	})
}

func TestGetFCTargetsInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetFCPorts", context.Background()).Return([]gopowerstore.FcPort{}, e)
		_, err := identifiers.GetFCTargetsInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})

	t.Run("no error", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{
				{
					Wwn:         "58:cc:f0:93:48:a0:03:a3",
					ApplianceID: "A1",
					IsLinkUp:    true,
				},
			}, nil)
		fcTargetInfo, err := identifiers.GetFCTargetsInfoFromStorage(clientMock, "A1")
		assert.NotNil(t, fcTargetInfo)
		assert.NoError(t, err)
	})
}

func TestIsK8sMetadataSupported(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(0.0), e)
		version := identifiers.IsK8sMetadataSupported(clientMock)
		assert.Equal(t, version, false)
	})

	t.Run("no error", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
		version := identifiers.IsK8sMetadataSupported(clientMock)
		assert.Equal(t, version, true)
	})
}

func TestGetNVMEFCTargetInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{}, e)
		clientMock.On("GetFCPorts", context.Background()).Return([]gopowerstore.FcPort{}, e)
		_, err := identifiers.GetNVMEFCTargetInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})

	t.Run("no error", func(t *testing.T) {
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{}, nil)
		clientMock.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{
				{
					Wwn:      "58:cc:f0:93:48:a0:03:a3",
					IsLinkUp: true,
				},
			}, nil)
		nvmefcTargetInfo, err := identifiers.GetNVMEFCTargetInfoFromStorage(clientMock, "")
		assert.NotNil(t, nvmefcTargetInfo)
		assert.NoError(t, err)
	})
}

func TestHasRequiredTopology(t *testing.T) {
	nfsTopology := &csi.Topology{Segments: map[string]string{"csi-powerstore.dellemc.com/10.0.0.0-nfs": "true"}}
	iscsiTopology := &csi.Topology{Segments: map[string]string{"csi-powerstore.dellemc.com/10.0.0.0-iscsi": "true"}}
	// FR-4.1: IPv6 topology key uses colon-encoded form "2001-db8--1"
	nfsTopologyIPv6 := &csi.Topology{Segments: map[string]string{"csi-powerstore.dellemc.com/2001-db8--1-nfs": "true"}}
	nfsTopologyLinkLocal := &csi.Topology{Segments: map[string]string{"csi-powerstore.dellemc.com/fe80--1-eth0-nfs": "true"}}

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
		// FR-4.1: IPv6 arrIP must be colon-encoded in the topology key lookup
		{
			name: "IPv6 arrIP matches encoded topology key",
			args: args{topologies: []*csi.Topology{nfsTopologyIPv6}, arrIP: "2001:db8::1", requiredTopology: "nfs"},
			want: true,
		},
		{
			name: "IPv6 arrIP does not match raw-colon topology key",
			args: args{topologies: []*csi.Topology{
				{Segments: map[string]string{"csi-powerstore.dellemc.com/2001:db8::1-nfs": "true"}},
			}, arrIP: "2001:db8::1", requiredTopology: "nfs"},
			want: false,
		},
		{
			name: "link-local arrIP matches encoded zone topology key",
			args: args{topologies: []*csi.Topology{nfsTopologyLinkLocal}, arrIP: "fe80::1%eth0", requiredTopology: "nfs"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, identifiers.HasRequiredTopology(tt.args.topologies, tt.args.arrIP, tt.args.requiredTopology), "HasRequiredTopology(%v, %v, %v)", tt.args.topologies, tt.args.arrIP, tt.args.requiredTopology)
		})
	}
}

func TestGetNfsTopology(t *testing.T) {
	t.Run("nfs topology is true", func(t *testing.T) {
		topology := identifiers.GetNfsTopology("10.0.0.0")
		assert.Equal(t, topology, []*csi.Topology{{Segments: map[string]string{"csi-powerstore.dellemc.com/10.0.0.0-nfs": "true"}}})
	})

	t.Run("nfs topology should not be false", func(t *testing.T) {
		topology := identifiers.GetNfsTopology("10.0.0.0")
		assert.NotEqual(t, topology, []*csi.Topology{{Segments: map[string]string{"csi-powerstore.dellemc.com/10.0.0.0-nfs": "false"}}})
	})

	// FR-4.1: IPv6 arrIP must produce encoded key (no raw colons in label keys)
	t.Run("IPv6 arrIP produces encoded topology key", func(t *testing.T) {
		topology := identifiers.GetNfsTopology("2001:db8::1")
		assert.Equal(t, topology, []*csi.Topology{{Segments: map[string]string{"csi-powerstore.dellemc.com/2001-db8--1-nfs": "true"}}})
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
			if got := identifiers.Contains(tt.args.slice, tt.args.element); got != tt.want {
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
			if got := identifiers.ExternalAccessAlreadyAdded(tt.args.export, tt.args.externalAccess); got != tt.want {
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
		// FR-7.2: bare IPv6 gets /128; IPv6 CIDR passes through
		{"IPv6 with prefix length", args{externalAccessCIDR: "fd12:3456::/64"}, "fd12:3456::/64", false},
		{"IPv6 bare address gets /128", args{externalAccessCIDR: "2001:db8::1"}, "2001:db8::1/128", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identifiers.ParseCIDR(tt.args.externalAccessCIDR)
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
				_ = os.Setenv("X_CSI_PODMON_ARRAY_CONNECTIVITY_POLL_RATE", "100")
			}
			// need to import this function because the package name in this file is not common
			// @TO-DO rename package name to common
			if got := identifiers.SetPollingFrequency(tt.args.ctx); got != tt.want {
				t.Errorf("SetPollingFrequency() = %v, want %v", got, tt.want)
			}
			_ = os.Unsetenv("X_CSI_PODMON_ARRAY_CONNECTIVITY_POLL_RATE")
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
				_ = os.Setenv("X_CSI_PODMON_API_PORT", "8090")
				identifiers.SetAPIPort(tt.args.ctx)
				if identifiers.APIPort != ":8090" {
					t.Errorf("setAPIPort() error, want 8090 port found %v", identifiers.APIPort)
				}
				_ = os.Unsetenv("X_CSI_PODMON_API_PORT")
			}
			identifiers.SetAPIPort(tt.args.ctx)
			if identifiers.APIPort != ":8083" {
				t.Errorf("setAPIPort() error, want 8083 port found %v", identifiers.APIPort)
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
			if got := identifiers.RandomString(tt.args.len); len(got) != 5*2 {
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
		// FR-7.1: IPv6 prefix lengths > 32 must not be rejected
		{"Valid IPv6 with /64 prefix length", args{input: "fd12:3456::/64"}, "fd12:3456::/64", false},
		{"Valid IPv6 with /128 prefix length", args{input: "2001:db8::1/128"}, "2001:db8::1/128", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identifiers.GetIPListWithMaskFromString(tt.args.input)
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

func TestFormatNFSHostEntry(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "IPv4", input: "10.0.0.35", want: "10.0.0.35/255.255.255.255"},
		{name: "IPv6", input: "2607:f2b1:f1d0:770::35", want: "2607:f2b1:f1d0:770::35/128"},
		{name: "bracketed IPv6", input: "[2607:f2b1:f1d0:770::35]", want: "2607:f2b1:f1d0:770::35/128"},
		{name: "invalid address", input: "not-an-ip", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identifiers.FormatNFSHostEntry(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FormatNFSHostEntry() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHostEntryMatchesIPWithCIDRTarget(t *testing.T) {
	assert.True(t, identifiers.HostEntryMatchesIP("[2001:db8::10]/64", "2001:db8::10/128"))
}

func TestHostAlreadyPresentInNFSExportIPv6(t *testing.T) {
	export := gopowerstore.NFSExport{RWRootHosts: []string{"2607:f2b1:f1d0:770::35/128"}}
	assert.True(t, identifiers.HostAlreadyPresentInNFSExport(export, "2607:f2b1:f1d0:770::35"))
	assert.False(t, identifiers.HostAlreadyPresentInNFSExport(export, "2607:f2b1:f1d0:770::36"))
}

func TestParseNFSExportPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "IPv4", input: "10.0.0.10:/export", want: "10.0.0.10"},
		{name: "bracketed IPv6", input: "[2607:f2b1:f1d0:770::16]:/export", want: "2607:f2b1:f1d0:770::16"},
		{name: "missing path separator", input: "[2607:f2b1:f1d0:770::16]/export", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identifiers.ParseNFSExportPath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseNFSExportPath() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEncodeIPForKubernetes(t *testing.T) {
	assert.Equal(t, "fe80--1-eth0", identifiers.EncodeIPForKubernetes("fe80::1%eth0"))
	assert.Equal(t, "2001-db8--1", identifiers.EncodeIPForKubernetes("2001:db8::1"))
}

func TestGetIPListFromString(t *testing.T) {
	type args struct {
		input string
	}
	var x []string
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"Valid IP, Test 1", args{input: "10.255.1.2"}, []string{"10.255.1.2"}},
		{"InValid IP, Test 2", args{input: "10.256.1.2"}, x},
		{"Valid Localhost", args{input: "https://localhost:9400"}, []string{"localhost"}},
		{"Valid Domain", args{input: "https://example.com:9443"}, []string{"example.com"}},
		{"Valid CSI NodeID", args{input: "csi-node-b61220be1acc441abdd8b00e34542e5d-1.1.1.1"}, []string{"1.1.1.1"}},
		{"Valid CSI NodeID", args{input: "csi-node-tar2222.infralab.ptec-2.2.2.2"}, []string{"2.2.2.2"}},
		{"Valid Multi-Segment Domain", args{input: "https://abc.example.com/page"}, []string{"abc.example.com"}},
		// FR-2.1: IPv6 support
		{"IPv6 in HTTPS URL (bracketed)", args{input: "https://[2001:db8::1]/api/rest"}, []string{"2001:db8::1"}},
		{"IPv6 in CSI NodeID suffix", args{input: "csi-node-hostname-2001:db8::1"}, []string{"2001:db8::1"}},
		{"IPv4-mapped IPv6 URL", args{input: "https://[::ffff:192.0.2.1]/api/rest"}, []string{"::ffff:192.0.2.1"}},
		// FR-3.1: Dash-encoded IPv6 in CSI NodeID (colons replaced with dashes)
		{"Dash-encoded IPv6 with full address", args{input: "csi-node-6e42639baa1b452c88e0cb7e60ca1839-2607-f2b1-f1d0-770--36"}, []string{"2607:f2b1:f1d0:770::36"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identifiers.GetIPListFromString(tt.args.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIPListFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReachableEndPoint(t *testing.T) {
	// Spin up a local listener to verify reachable cases
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer func() { _ = l.Close() }()
	_, port, err := net.SplitHostPort(l.Addr().String())
	assert.NoError(t, err)

	type args struct {
		endpoint string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"Unreachable IP with custom port", args{endpoint: "10.255.1.2:100"}, false},
		{"Unreachable bare IPv4", args{endpoint: "10.255.1.2"}, false},
		{"Unreachable bare IPv6", args{endpoint: "2001:db8::1"}, false},
		{"Unreachable bracketed IPv6 with port", args{endpoint: "[2001:db8::1]:3260"}, false},
		{"Unreachable IPv4 with portal group tag", args{endpoint: "10.255.1.2:3260,1"}, false},
		{"Reachable local listener", args{endpoint: fmt.Sprintf("127.0.0.1:%s", port)}, true},
		{"Reachable local listener with portal group tag", args{endpoint: fmt.Sprintf("127.0.0.1:%s,1", port)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identifiers.ReachableEndPoint(tt.args.endpoint); got != tt.want {
				t.Errorf("ReachableEndPoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetMountFlags(t *testing.T) {
	tests := []struct {
		name     string
		vc       *csi.VolumeCapability
		expected []string
	}{
		{
			name:     "Nil VolumeCapability",
			vc:       nil,
			expected: nil,
		},
		{
			name:     "Nil Mount",
			vc:       &csi.VolumeCapability{},
			expected: nil,
		},
		{
			name: "With Mount Flags",
			vc: &csi.VolumeCapability{
				AccessType: &csi.VolumeCapability_Mount{
					Mount: &csi.VolumeCapability_MountVolume{
						MountFlags: []string{"ro", "noexec"},
					},
				},
			},
			expected: []string{"ro", "noexec"},
		},
		{
			name: "Empty Mount Flags",
			vc: &csi.VolumeCapability{
				AccessType: &csi.VolumeCapability_Mount{
					Mount: &csi.VolumeCapability_MountVolume{
						MountFlags: []string{},
					},
				},
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := identifiers.GetMountFlags(tt.vc)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsNFSServiceEnabled(t *testing.T) {
	// Define mock client
	clientMock := new(gopowerstoremock.Client)
	// Initialise variable for nas servers
	nasServers := []gopowerstore.NAS{
		{
			NfsServers: []gopowerstore.NFSServerInstance{
				{
					ID:             "4444",
					IsNFSv4Enabled: true,
				},
			},
		},
	}

	// Test cases
	t.Run("nfs service is enabled", func(t *testing.T) {
		clientMock.On("GetNASServers", mock.Anything, mock.Anything).Return(nasServers, nil)
		result, err := identifiers.IsNFSServiceEnabled(context.Background(), clientMock)
		assert.NoError(t, err)
		assert.True(t, result, "Expected result to be true")
	})

	t.Run("nfs service is not enabled", func(t *testing.T) {
		nasServers[0].NfsServers[0].IsNFSv4Enabled = false
		clientMock.On("GetNASServers", mock.Anything, mock.Anything).Return(nasServers, nil)
		result, err := identifiers.IsNFSServiceEnabled(context.Background(), clientMock)
		assert.NoError(t, err)
		assert.False(t, result, "Expected result to be false")
	})
}

func TestGetPowerStoreAPITimeout(t *testing.T) {
	tests := []struct {
		name         string
		expected     time.Duration
		setupFunc    func()
		teardownFunc func()
	}{
		{
			name:     "env variable is not set",
			expected: 120 * time.Second,
		},
		{
			name:         "env variable is set to valid value",
			expected:     10 * time.Second,
			setupFunc:    func() { _ = os.Setenv("X_CSI_POWERSTORE_API_TIMEOUT", "10s") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_POWERSTORE_API_TIMEOUT") },
		},
		{
			name:         "env variable is set to invalid value",
			expected:     120 * time.Second,
			setupFunc:    func() { _ = os.Setenv("X_CSI_POWERSTORE_API_TIMEOUT", "abc") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_POWERSTORE_API_TIMEOUT") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
				defer tt.teardownFunc()
			}
			actual := identifiers.GetPowerStoreRESTApiTimeout()
			if actual != tt.expected {
				t.Errorf("GetTimeout() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestGetPodmonArrayConnectivityTimeout(t *testing.T) {
	tests := []struct {
		name         string
		expected     time.Duration
		setupFunc    func()
		teardownFunc func()
	}{
		{
			name:     "env variable is not set",
			expected: 10 * time.Second,
		},
		{
			name:         "env variable is set to valid value",
			expected:     25 * time.Second,
			setupFunc:    func() { _ = os.Setenv("X_CSI_PODMON_ARRAY_CONNECTIVITY_TIMEOUT", "25s") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_PODMON_ARRAY_CONNECTIVITY_TIMEOUT") },
		},
		{
			name:         "env variable is set to invalid value",
			expected:     10 * time.Second,
			setupFunc:    func() { _ = os.Setenv("X_CSI_PODMON_ARRAY_CONNECTIVITY_TIMEOUT", "abc") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_PODMON_ARRAY_CONNECTIVITY_TIMEOUT") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
				defer tt.teardownFunc()
			}

			actual := identifiers.GetPodmonArrayConnectivityTimeout()
			if actual != tt.expected {
				t.Errorf("GetTimeout() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestGetVolumeDisconnectTimeout(t *testing.T) {
	tests := []struct {
		name         string
		expected     time.Duration
		setupFunc    func()
		teardownFunc func()
	}{
		{
			name:     "env variable is not set",
			expected: 120 * time.Second, // DefaultVolumeDisconnectTimeout
		},
		{
			name:         "env variable is set to valid value",
			expected:     45 * time.Second,
			setupFunc:    func() { _ = os.Setenv("X_CSI_VOLUME_DISCONNECT_TIMEOUT_SECONDS", "45s") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_VOLUME_DISCONNECT_TIMEOUT_SECONDS") },
		},
		{
			name:         "env variable is set to invalid value",
			expected:     120 * time.Second,
			setupFunc:    func() { _ = os.Setenv("X_CSI_VOLUME_DISCONNECT_TIMEOUT_SECONDS", "invalid") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_VOLUME_DISCONNECT_TIMEOUT_SECONDS") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
				defer tt.teardownFunc()
			}

			actual := identifiers.GetVolumeDisconnectTimeout()
			if actual != tt.expected {
				t.Errorf("GetVolumeDisconnectTimeout() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestGetVolumeDisconnectRetryInterval(t *testing.T) {
	tests := []struct {
		name         string
		expected     time.Duration
		setupFunc    func()
		teardownFunc func()
	}{
		{
			name:     "env variable is not set",
			expected: 5 * time.Second, // DefaultVolumeDisconnectRetryInterval
		},
		{
			name:         "env variable is set to valid value",
			expected:     15 * time.Second,
			setupFunc:    func() { _ = os.Setenv("X_CSI_VOLUME_DISCONNECT_RETRY_INTERVAL", "15s") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_VOLUME_DISCONNECT_RETRY_INTERVAL") },
		},
		{
			name:         "env variable is set to invalid value",
			expected:     5 * time.Second,
			setupFunc:    func() { _ = os.Setenv("X_CSI_VOLUME_DISCONNECT_RETRY_INTERVAL", "invalid") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_VOLUME_DISCONNECT_RETRY_INTERVAL") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
				defer tt.teardownFunc()
			}

			actual := identifiers.GetVolumeDisconnectRetryInterval()
			if actual != tt.expected {
				t.Errorf("GetVolumeDisconnectRetryInterval() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestGetVolumeDisconnectMaxRetries(t *testing.T) {
	tests := []struct {
		name         string
		expected     int
		setupFunc    func()
		teardownFunc func()
	}{
		{
			name:     "env variable is not set",
			expected: 5, // DefaultVolumeDisconnectMaxRetries
		},
		{
			name:         "env variable is set to valid value",
			expected:     7,
			setupFunc:    func() { _ = os.Setenv("X_CSI_VOLUME_DISCONNECT_MAX_RETRIES", "7") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_VOLUME_DISCONNECT_MAX_RETRIES") },
		},
		{
			name:         "env variable is set to invalid value",
			expected:     5,
			setupFunc:    func() { _ = os.Setenv("X_CSI_VOLUME_DISCONNECT_MAX_RETRIES", "invalid") },
			teardownFunc: func() { _ = os.Unsetenv("X_CSI_VOLUME_DISCONNECT_MAX_RETRIES") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
				defer tt.teardownFunc()
			}

			actual := identifiers.GetVolumeDisconnectMaxRetries()
			if actual != tt.expected {
				t.Errorf("GetVolumeDisconnectMaxRetries() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestHostAlreadyPresentInNFSExport(t *testing.T) {
	tests := []struct {
		name   string
		export gopowerstore.NFSExport
		ip     string
		want   bool
	}{
		{
			name:   "present_in_RWHosts",
			export: gopowerstore.NFSExport{RWHosts: []string{"10.0.0.1/255.255.255.255"}},
			ip:     "10.0.0.1",
			want:   true,
		},
		{
			name:   "present_in_RWRootHosts",
			export: gopowerstore.NFSExport{RWRootHosts: []string{"192.168.0.5/255.255.255.255"}},
			ip:     "192.168.0.5",
			want:   true,
		},
		{
			name:   "present_in_ROHosts",
			export: gopowerstore.NFSExport{ROHosts: []string{"172.16.10.10/255.255.255.255"}},
			ip:     "172.16.10.10",
			want:   true,
		},
		{
			name:   "present_in_RORootHosts",
			export: gopowerstore.NFSExport{RORootHosts: []string{"10.10.10.10/255.255.255.255"}},
			ip:     "10.10.10.10",
			want:   true,
		},
		{
			name:   "not_present_different_ip",
			export: gopowerstore.NFSExport{RWHosts: []string{"10.0.0.2/255.255.255.255"}, ROHosts: []string{"10.0.0.3/255.255.255.255"}},
			ip:     "10.0.0.1",
			want:   false,
		},
		{
			name:   "not_present_empty_lists",
			export: gopowerstore.NFSExport{},
			ip:     "10.0.0.1",
			want:   false,
		},
		{
			name:   "present_in_multiple_lists",
			export: gopowerstore.NFSExport{RWHosts: []string{"1.2.3.4/255.255.255.255"}, RORootHosts: []string{"5.6.7.8/255.255.255.255"}},
			ip:     "1.2.3.4",
			want:   true,
		},
		{
			name:   "ip_with_trailing_spaces_not_present",
			export: gopowerstore.NFSExport{RWHosts: []string{"8.8.8.8/255.255.255.255"}},
			ip:     "8.8.8.8 ",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identifiers.HostAlreadyPresentInNFSExport(tt.export, tt.ip)
			if got != tt.want {
				t.Errorf("HostAlreadyPresentInNFSExport() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetEligibleNfsAccessibleTopologies(t *testing.T) {
	driverPrefix := identifiers.Name
	arrIP := "10.0.0.1"
	nfsKey := driverPrefix + "/" + arrIP + "-nfs"

	t.Run("Preferred has NFS entries - uses Preferred", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
				"custom-label":                "custom-value",
			}},
		}
		requisite := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-b",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, requisite, arrIP)
		assert.Len(t, result, 1)
		assert.Equal(t, "zone-a", result[0].Segments["topology.kubernetes.io/zone"])
		assert.Equal(t, "custom-value", result[0].Segments["custom-label"])
		assert.Equal(t, "true", result[0].Segments[nfsKey])
	})

	t.Run("Preferred empty, Requisite has NFS - uses Requisite", func(t *testing.T) {
		preferred := []*csi.Topology{}
		requisite := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, requisite, arrIP)
		assert.Len(t, result, 1)
		assert.Equal(t, "zone-a", result[0].Segments["topology.kubernetes.io/zone"])
		assert.Equal(t, "true", result[0].Segments[nfsKey])
	})

	t.Run("Both Preferred and Requisite have NFS - uses Preferred", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
		}
		requisite := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-b",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, requisite, arrIP)
		assert.Len(t, result, 1)
		assert.Equal(t, "zone-a", result[0].Segments["topology.kubernetes.io/zone"])
	})

	t.Run("Custom-only entries are dropped", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				"topology.kubernetes.io/zone": "zone-a",
			}},
		}
		requisite := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, requisite, arrIP)
		assert.Len(t, result, 1)
		assert.Equal(t, "true", result[0].Segments[nfsKey])
		assert.Equal(t, "zone-a", result[0].Segments["topology.kubernetes.io/zone"])
	})

	t.Run("Block protocol keys are stripped", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                                "true",
				driverPrefix + "/" + arrIP + "-fc":    "true",
				driverPrefix + "/" + arrIP + "-iscsi": "true",
				"topology.kubernetes.io/zone":         "zone-a",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, nil, arrIP)
		assert.Len(t, result, 1)
		assert.NotContains(t, result[0].Segments, driverPrefix+"/"+arrIP+"-fc")
		assert.NotContains(t, result[0].Segments, driverPrefix+"/"+arrIP+"-iscsi")
		assert.Contains(t, result[0].Segments, nfsKey)
		assert.Contains(t, result[0].Segments, "topology.kubernetes.io/zone")
	})

	t.Run("Fallback to legacy NFS topology when no eligible entries", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				"topology.kubernetes.io/zone": "zone-a",
			}},
		}
		requisite := []*csi.Topology{
			{Segments: map[string]string{
				"topology.kubernetes.io/zone": "zone-b",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, requisite, arrIP)
		assert.Len(t, result, 1)
		assert.Equal(t, "true", result[0].Segments[nfsKey])
		assert.Len(t, result[0].Segments, 1) // Only NFS key
	})

	t.Run("Deduplicates identical entries", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, nil, arrIP)
		assert.Len(t, result, 1) // Deduplicated
		assert.Equal(t, "zone-a", result[0].Segments["topology.kubernetes.io/zone"])
	})

	t.Run("Mixed valid and invalid entries", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
			{Segments: map[string]string{
				"topology.kubernetes.io/zone": "zone-b", // No NFS key
			}},
			{Segments: map[string]string{
				nfsKey:                             "true",
				driverPrefix + "/" + arrIP + "-fc": "true",
				"topology.kubernetes.io/zone":      "zone-c",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, nil, arrIP)
		assert.Len(t, result, 2)
		// Both should have NFS key and zone, but no FC
		for _, topo := range result {
			assert.Contains(t, topo.Segments, nfsKey)
			assert.NotContains(t, topo.Segments, driverPrefix+"/"+arrIP+"-fc")
		}
	})

	t.Run("Nil Preferred and Requisite - fallback to legacy", func(t *testing.T) {
		result := identifiers.GetEligibleNfsAccessibleTopologies(nil, nil, arrIP)
		assert.Len(t, result, 1)
		assert.Equal(t, "true", result[0].Segments[nfsKey])
		assert.Len(t, result[0].Segments, 1) // Only NFS key
	})
}

func TestGetEligibleNfsAccessibleTopologies_ReviewerScenarios(t *testing.T) {
	driverPrefix := identifiers.Name
	arrIP := "10.0.0.1"
	nfsKey := driverPrefix + "/" + arrIP + "-nfs"

	t.Run("custom-only Preferred plus NFS-containing Requisite", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				"topology.kubernetes.io/zone": "zone-a", // No NFS key
			}},
		}
		requisite := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, requisite, arrIP)
		assert.Len(t, result, 1)
		assert.Equal(t, "true", result[0].Segments[nfsKey])
		assert.Equal(t, "zone-a", result[0].Segments["topology.kubernetes.io/zone"])
	})

	t.Run("mixed-case NFS values remain eligible and preserve custom labels", func(t *testing.T) {
		tests := []struct {
			name         string
			preferred    []*csi.Topology
			requisite    []*csi.Topology
			expectedZone string
		}{
			{
				name: "mixed-case Preferred value",
				preferred: []*csi.Topology{{Segments: map[string]string{
					nfsKey:                        "TRUE",
					"topology.kubernetes.io/zone": "zone-a",
				}}},
				expectedZone: "zone-a",
			},
			{
				name: "mixed-case Requisite value",
				preferred: []*csi.Topology{{Segments: map[string]string{
					"topology.kubernetes.io/zone": "zone-a",
				}}},
				requisite: []*csi.Topology{{Segments: map[string]string{
					nfsKey:                        "TrUe",
					"topology.kubernetes.io/zone": "zone-b",
				}}},
				expectedZone: "zone-b",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				result := identifiers.GetEligibleNfsAccessibleTopologies(test.preferred, test.requisite, arrIP)
				assert.Len(t, result, 1)
				assert.Equal(t, "true", result[0].Segments[nfsKey])
				assert.Equal(t, test.expectedZone, result[0].Segments["topology.kubernetes.io/zone"])
			})
		}
	})

	t.Run("mixed valid NFS and custom-only Preferred entries", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
			{Segments: map[string]string{
				"topology.kubernetes.io/zone": "zone-b", // No NFS key
			}},
		}
		requisite := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-c",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, requisite, arrIP)
		assert.Len(t, result, 1)
		assert.Equal(t, "true", result[0].Segments[nfsKey])
		assert.Equal(t, "zone-a", result[0].Segments["topology.kubernetes.io/zone"])
	})

	t.Run("assertion that every returned AccessibleTopology entry contains the selected-array NFS key", func(t *testing.T) {
		preferred := []*csi.Topology{
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-a",
			}},
			{Segments: map[string]string{
				nfsKey:                        "true",
				"topology.kubernetes.io/zone": "zone-b",
			}},
		}
		result := identifiers.GetEligibleNfsAccessibleTopologies(preferred, nil, arrIP)
		assert.Len(t, result, 2)
		// Assert EVERY returned entry contains the NFS key
		for _, topo := range result {
			assert.Contains(t, topo.Segments, nfsKey, "Every returned entry must contain the selected-array NFS key")
		}
	})
}
