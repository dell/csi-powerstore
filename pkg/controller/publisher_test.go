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
	"fmt"
	"net/http"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	"github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestFormatNFSExportPath(t *testing.T) {
	tests := map[string]struct {
		ipAddress  string
		exportName string
		expected   string
	}{
		"IPv4 address": {
			ipAddress:  "10.0.0.1",
			exportName: "export",
			expected:   "10.0.0.1:/export",
		},
		"IPv6 address": {
			ipAddress:  "2607:f2b1:f1d0:770::16",
			exportName: "export",
			expected:   "[2607:f2b1:f1d0:770::16]:/export",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatNFSExportPath(tt.ipAddress, tt.exportName))
		})
	}
}

func TestPreferredFileInterfaceID(t *testing.T) {
	tests := map[string]struct {
		nas      gopowerstore.NAS
		expected string
	}{
		"prefers IPv4 interface": {
			nas: gopowerstore.NAS{
				CurrentPreferredIPv4InterfaceID: "ipv4-interface",
				CurrentPreferredIPv6InterfaceID: "ipv6-interface",
			},
			expected: "ipv4-interface",
		},
		"falls back to IPv6 interface": {
			nas: gopowerstore.NAS{
				CurrentPreferredIPv6InterfaceID: "ipv6-interface",
			},
			expected: "ipv6-interface",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, preferredFileInterfaceID(tt.nas))
		})
	}
}

func TestVolumePublisher_Publish(t *testing.T) {
	t.Run("scsi publisher", func(t *testing.T) {
		sp := &SCSIPublisher{}
		getVolumeOK := func(clientMock *mocks.Client) {
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).
				Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)
		}

		getHostByNameOK := func(clientMock *mocks.Client) {
			clientMock.On("GetHostByName", mock.Anything, validNodeID).Return(gopowerstore.Host{ID: validHostID}, nil)
		}

		t.Run("getVolume failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{}, errors.New("error"))
			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure checking volume status for volume publishing")
		})

		t.Run("no volume found", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				})
			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("volume with ID '%s' not found", validBaseVolID))
		})

		t.Run("can't find ip in node id", func(t *testing.T) {
			nodeID := "some-random-text"
			clientMock := new(mocks.Client)

			getVolumeOK(clientMock)

			clientMock.On("GetHostByName", mock.Anything, nodeID).
				Return(gopowerstore.Host{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				}).Once()

			_, err := sp.Publish(context.Background(), nil, nil, clientMock, nodeID, validBaseVolID, true)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't find IP in node ID")
		})

		t.Run("host unknown api error", func(t *testing.T) {
			e := errors.New("random-api-error")

			clientMock := new(mocks.Client)

			getVolumeOK(clientMock)

			clientMock.On("GetHostByName", mock.Anything, validNodeID).
				Return(gopowerstore.Host{}, e).Once()

			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(),
				fmt.Sprintf("failure checking host '%s' status for volume publishing: %s", validNodeID, e.Error()))
		})

		t.Run("failed to get mapping", func(t *testing.T) {
			e := errors.New("random-api-error")

			clientMock := new(mocks.Client)

			getVolumeOK(clientMock)
			getHostByNameOK(clientMock)

			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{}, e).Once()

			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(),
				fmt.Sprintf("failed to get mapping for volume with ID '%s': %s", validBaseVolID, e.Error()))
		})

		t.Run("failed to get iscsiTargets", func(t *testing.T) {
			e := errors.New("unable to get targets for any protocol")

			clientMock := new(mocks.Client)

			getVolumeOK(clientMock)
			getHostByNameOK(clientMock)

			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{}, nil).Once()
			clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
				Return([]gopowerstore.IPPoolAddress{}, e)
			clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
				Return([]gopowerstore.IPPoolAddress{}, e)
			clientMock.On("GetFCPorts", mock.Anything).
				Return([]gopowerstore.FcPort{}, nil)
			clientMock.On("GetCluster", mock.Anything).
				Return(gopowerstore.Cluster{Name: validClusterName, NVMeNQN: "nqn"}, nil)
			clientMock.On("AttachVolumeToHost", mock.Anything, validHostID, mock.Anything).
				Return(gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil).Once()

			_, err := sp.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Nil(t, err)
		})

		t.Run("host not found after stripping IP", func(t *testing.T) {
			clientMock := new(mocks.Client)
			getVolumeOK(clientMock)
			clientMock.On("GetHostByName", mock.Anything, validNodeID).
				Return(gopowerstore.Host{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}}).Once()
			clientMock.On("GetHostByName", mock.Anything, mock.Anything).
				Return(gopowerstore.Host{}, errors.New("host lookup error")).Once()
			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})

		t.Run("single node writer conflict", func(t *testing.T) {
			clientMock := new(mocks.Client)
			getVolumeOK(clientMock)
			getHostByNameOK(clientMock)
			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{{HostID: "different-host-id"}}, nil)
			req := &csi.ControllerPublishVolumeRequest{
				VolumeCapability: &csi.VolumeCapability{
					AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER},
				},
			}
			_, err := sp.Publish(context.Background(), make(map[string]string), req, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "volume already present in a different lun mapping")
		})

		t.Run("AttachVolumeToHost error", func(t *testing.T) {
			clientMock := new(mocks.Client)
			getVolumeOK(clientMock)
			getHostByNameOK(clientMock)
			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{}, nil).Once()
			clientMock.On("AttachVolumeToHost", mock.Anything, validHostID, mock.Anything).
				Return(gopowerstore.EmptyResponse(""), errors.New("attach failure"))
			_, err := sp.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to attach volume")
		})

		t.Run("remote scsi volume publish", func(t *testing.T) {
			clientMock := new(mocks.Client)
			getVolumeOK(clientMock)
			getHostByNameOK(clientMock)
			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 5}}, nil).Once()
			pubCtx := make(map[string]string)
			resp, err := sp.Publish(context.Background(), pubCtx, nil, clientMock, validNodeID, validBaseVolID, true)
			assert.NoError(t, err)
			assert.Equal(t, "68ccf098003ceb5e4577a20be6d11bf9", resp.PublishContext[identifiers.TargetMapRemoteDeviceWWN])
			assert.Equal(t, "5", resp.PublishContext[identifiers.TargetMapRemoteLUNAddress])
		})
	})

	t.Run("nfs publisher", func(t *testing.T) {
		np := &NfsPublisher{}

		getFSOK := func(clientMock *mocks.Client) {
			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)
		}

		getExportOK := func(clientMock *mocks.Client, times int) {
			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
				Return(gopowerstore.NFSExport{ID: "some-export-id"}, nil).Times(times)
		}

		t.Run("getFS failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{}, errors.New("error"))
			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure checking volume status for volume publishing")
		})

		t.Run("no volume found", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				})
			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("volume with ID '%s' not found", validBaseVolID))
		})

		t.Run("can't find ip in node id", func(t *testing.T) {
			nodeID := "some-random-text"
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)

			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, nodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't find IP in node ID")
		})

		t.Run("can't check nfs export status", func(t *testing.T) {
			e := errors.New("random-api-error")
			clientMock := new(mocks.Client)

			getFSOK(clientMock)

			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
				Return(gopowerstore.NFSExport{}, e).Once()

			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure checking nfs export status for volume publishing")
		})

		t.Run("failed to get existing nfs export", func(t *testing.T) {
			e := errors.New("random-api-error")
			clientMock := new(mocks.Client)

			getFSOK(clientMock)
			getExportOK(clientMock, 1)

			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
				Return(gopowerstore.NFSExport{}, e).Once()

			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure getting nfs export")
		})

		t.Run("failed to add hosts", func(t *testing.T) {
			e := errors.New("random-api-error")
			clientMock := new(mocks.Client)

			getFSOK(clientMock)
			getExportOK(clientMock, 2)

			clientMock.On("ModifyNFSExport", mock.Anything, mock.Anything, mock.Anything).
				Return(gopowerstore.CreateResponse{}, e).Once()

			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure when adding new host to nfs export")
		})

		t.Run("creates export when not found", func(t *testing.T) {
			clientMock := new(mocks.Client)
			getFSOK(clientMock)
			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
				Return(gopowerstore.NFSExport{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}}).Once()
			clientMock.On("CreateNFSExport", mock.Anything, mock.Anything).
				Return(gopowerstore.CreateResponse{ID: "created-export-id"}, nil).Once()
			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
				Return(gopowerstore.NFSExport{ID: "created-export-id", Name: "export-name"}, nil).Once()
			clientMock.On("ModifyNFSExport", mock.Anything, mock.Anything, "created-export-id").
				Return(gopowerstore.CreateResponse{}, nil).Once()
			clientMock.On("GetNAS", mock.Anything, mock.Anything).
				Return(gopowerstore.NAS{CurrentPreferredIPv4InterfaceID: "intf-1"}, nil).Once()
			clientMock.On("GetFileInterface", mock.Anything, "intf-1").
				Return(gopowerstore.FileInterface{IPAddress: "10.0.0.1"}, nil).Once()

			req := &csi.ControllerPublishVolumeRequest{VolumeContext: map[string]string{}}
			resp, err := np.Publish(context.Background(), make(map[string]string), req, clientMock, validNodeID, validBaseVolID, false)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
		})
	})
}

func TestNfsPublisher_AutoSelect(t *testing.T) {
	const (
		testNasServerID    = "nas-server-id-1"
		testNasName        = "test-nas"
		testFileIntfID     = "file-intf-id-1"
		testFileIntfIP     = "10.20.30.40"
		testExportID       = "export-id-1"
		testExportName     = "test-export"
		testPVCName        = "my-pvc"
		testPVCNamespace   = "default"
		testPVName         = "pv-001"
		testExternalAccess = "192.168.1.0/24"
	)

	// Helper: set up a full successful NFS publish mock chain
	setupFullNFSPublishMocks := func(clientMock *mocks.Client) {
		clientMock.On("GetFS", mock.Anything, validBaseVolID).
			Return(gopowerstore.FileSystem{ID: validBaseVolID, Name: testExportName, NasServerID: testNasServerID}, nil)
		clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
			Return(gopowerstore.NFSExport{ID: testExportID, Name: testExportName}, nil)
		clientMock.On("ModifyNFSExport", mock.Anything, mock.Anything, testExportID).
			Return(gopowerstore.CreateResponse{}, nil)
		clientMock.On("GetNAS", mock.Anything, testNasServerID).
			Return(gopowerstore.NAS{ID: testNasServerID, Name: testNasName, CurrentPreferredIPv4InterfaceID: testFileIntfID}, nil)
		clientMock.On("GetFileInterface", mock.Anything, testFileIntfID).
			Return(gopowerstore.FileInterface{ID: testFileIntfID, IPAddress: testFileIntfIP}, nil)
	}

	makeReq := func() *csi.ControllerPublishVolumeRequest {
		return &csi.ControllerPublishVolumeRequest{
			VolumeContext: map[string]string{
				identifiers.KeyAllowRoot: "true",
				identifiers.KeyNfsACL:    "A::OWNER@:RWX",
				KeyCSIPVCName:            testPVCName,
				KeyCSIPVCNamespace:       testPVCNamespace,
				KeyCSIPVName:             testPVName,
			},
		}
	}

	t.Run("auto-select enabled skips node IP and enriches publishContext", func(t *testing.T) {
		clientMock := new(mocks.Client)
		setupFullNFSPublishMocks(clientMock)

		np := &NfsPublisher{NfsAutoSelect: true}
		publishContext := make(map[string]string)
		req := makeReq()

		resp, err := np.Publish(context.Background(), publishContext, req, clientMock, validNodeID, validBaseVolID, false)
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// FR-2: publishContext[identifiers.KeyNfsAutoSelect] should be "true"
		assert.Equal(t, "true", resp.PublishContext[identifiers.KeyNfsAutoSelect])

		// FR-2: NAS metadata should be present
		assert.Equal(t, testNasName, resp.PublishContext[identifiers.KeyNasName])
		assert.Equal(t, testFileIntfIP, resp.PublishContext[identifiers.KeyNasInterfaceIP])

		// FR-2: PVC/PV identifiers should be forwarded
		assert.Equal(t, testPVCName, resp.PublishContext[KeyCSIPVCName])
		assert.Equal(t, testPVCNamespace, resp.PublishContext[KeyCSIPVCNamespace])
		assert.Equal(t, testPVName, resp.PublishContext[KeyCSIPVName])

		// FR-2: Node host IP should NOT be in publishContext when auto-select is enabled
		assert.Empty(t, resp.PublishContext[identifiers.KeyHostIP])

		// FR-2: NfsExportPath and ExportID should still be set
		expectedPath := testFileIntfIP + ":/" + testExportName
		assert.Equal(t, expectedPath, resp.PublishContext[identifiers.KeyNfsExportPath])
		assert.Equal(t, testExportID, resp.PublishContext[identifiers.KeyExportID])

		// FR-2: ModifyNFSExport should NOT have been called with node IP
		// (the ipWithNat list should be empty since auto-select skips node IP)
		modifyCalls := clientMock.Calls
		for _, call := range modifyCalls {
			if call.Method == "ModifyNFSExport" {
				modifyArg := call.Arguments.Get(1).(*gopowerstore.NFSExportModify)
				for _, host := range modifyArg.AddRWRootHosts {
					assert.NotEqual(t, "127.0.0.1", host, "node IP should not be added when auto-select is enabled")
				}
			}
		}
	})

	t.Run("auto-select disabled preserves existing behavior", func(t *testing.T) {
		clientMock := new(mocks.Client)
		setupFullNFSPublishMocks(clientMock)

		np := &NfsPublisher{NfsAutoSelect: false}
		publishContext := make(map[string]string)
		req := makeReq()

		resp, err := np.Publish(context.Background(), publishContext, req, clientMock, validNodeID, validBaseVolID, false)
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// FR-1 regression: NfsAutoSelect key should NOT be in publishContext when disabled
		_, hasAutoSelect := resp.PublishContext[identifiers.KeyNfsAutoSelect]
		assert.False(t, hasAutoSelect, "NfsAutoSelect should not be in publishContext when disabled")

		// FR-1 regression: Host IP should be present (existing behavior)
		assert.NotEmpty(t, resp.PublishContext[identifiers.KeyHostIP])

		// Auto-select metadata keys should NOT be present when disabled
		_, hasNasInterfaceIP := resp.PublishContext[identifiers.KeyNasInterfaceIP]
		assert.False(t, hasNasInterfaceIP, "nasInterfaceIP should not be in publishContext when auto-select is disabled")
	})

	t.Run("auto-select enabled with externalAccess still adds CIDR", func(t *testing.T) {
		clientMock := new(mocks.Client)
		setupFullNFSPublishMocks(clientMock)

		np := &NfsPublisher{
			NfsAutoSelect:  true,
			ExternalAccess: testExternalAccess,
		}
		publishContext := make(map[string]string)
		req := makeReq()

		resp, err := np.Publish(context.Background(), publishContext, req, clientMock, validNodeID, validBaseVolID, false)
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// FR-2: externalAccess should still be applied (NatIP in publishContext)
		assert.NotEmpty(t, resp.PublishContext[identifiers.KeyNatIP])

		// FR-2: NfsAutoSelect should be set
		assert.Equal(t, "true", resp.PublishContext[identifiers.KeyNfsAutoSelect])

		// ModifyNFSExport should have been called with externalAccess CIDR but NOT node IP
		modifyCalls := clientMock.Calls
		for _, call := range modifyCalls {
			if call.Method == "ModifyNFSExport" {
				modifyArg := call.Arguments.Get(1).(*gopowerstore.NFSExportModify)
				// Should contain the external access CIDR
				assert.NotEmpty(t, modifyArg.AddRWRootHosts, "externalAccess should be in modify request")
				// Should NOT contain node IP 127.0.0.1
				for _, host := range modifyArg.AddRWRootHosts {
					assert.NotEqual(t, "127.0.0.1", host, "node IP should not be added when auto-select is enabled")
				}
			}
		}
	})

	t.Run("auto-select enabled publishContext carries PVC/PV identifiers from VolumeContext", func(t *testing.T) {
		clientMock := new(mocks.Client)
		setupFullNFSPublishMocks(clientMock)

		np := &NfsPublisher{NfsAutoSelect: true}
		publishContext := make(map[string]string)
		req := makeReq()

		resp, err := np.Publish(context.Background(), publishContext, req, clientMock, validNodeID, validBaseVolID, false)
		assert.NoError(t, err)

		// Verify all PVC/PV identifiers are forwarded from req.VolumeContext to publishContext
		assert.Equal(t, testPVCName, resp.PublishContext[KeyCSIPVCName])
		assert.Equal(t, testPVCNamespace, resp.PublishContext[KeyCSIPVCNamespace])
		assert.Equal(t, testPVName, resp.PublishContext[KeyCSIPVName])
	})

	t.Run("exclusiveAccess takes precedence over auto-select", func(t *testing.T) {
		clientMock := new(mocks.Client)
		setupFullNFSPublishMocks(clientMock)

		np := &NfsPublisher{
			NfsAutoSelect:   true,
			ExclusiveAccess: true,
			ExternalAccess:  testExternalAccess,
		}
		publishContext := make(map[string]string)
		req := makeReq()

		resp, err := np.Publish(context.Background(), publishContext, req, clientMock, validNodeID, validBaseVolID, false)
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// When exclusiveAccess=true, NfsAutoSelect metadata must NOT be set in publishContext
		_, hasAutoSelect := resp.PublishContext[identifiers.KeyNfsAutoSelect]
		assert.False(t, hasAutoSelect, "NfsAutoSelect should be suppressed when exclusiveAccess=true")
		_, hasNasInterfaceIP := resp.PublishContext[identifiers.KeyNasInterfaceIP]
		assert.False(t, hasNasInterfaceIP, "nasInterfaceIP should be suppressed when exclusiveAccess=true")
	})

	t.Run("publish error branches", func(t *testing.T) {
		t.Run("invalid node ID with no IP", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{ID: validBaseVolID, Name: testExportName, NasServerID: testNasServerID}, nil)

			np := &NfsPublisher{NfsAutoSelect: true}
			_, err := np.Publish(context.Background(), make(map[string]string), makeReq(), clientMock, "invalid-node-no-ip", validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't find IP in node ID")
		})

		t.Run("GetNAS failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{ID: validBaseVolID, Name: testExportName, NasServerID: testNasServerID}, nil)
			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
				Return(gopowerstore.NFSExport{ID: testExportID, Name: testExportName}, nil)
			clientMock.On("ModifyNFSExport", mock.Anything, mock.Anything, testExportID).
				Return(gopowerstore.CreateResponse{}, nil)
			clientMock.On("GetNAS", mock.Anything, testNasServerID).
				Return(gopowerstore.NAS{}, errors.New("nas connection failed"))

			np := &NfsPublisher{NfsAutoSelect: true}
			_, err := np.Publish(context.Background(), make(map[string]string), makeReq(), clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure getting nas")
		})

		t.Run("GetFileInterface failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{ID: validBaseVolID, Name: testExportName, NasServerID: testNasServerID}, nil)
			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
				Return(gopowerstore.NFSExport{ID: testExportID, Name: testExportName}, nil)
			clientMock.On("ModifyNFSExport", mock.Anything, mock.Anything, testExportID).
				Return(gopowerstore.CreateResponse{}, nil)
			clientMock.On("GetNAS", mock.Anything, testNasServerID).
				Return(gopowerstore.NAS{ID: testNasServerID, Name: testNasName, CurrentPreferredIPv4InterfaceID: testFileIntfID}, nil)
			clientMock.On("GetFileInterface", mock.Anything, testFileIntfID).
				Return(gopowerstore.FileInterface{}, errors.New("file interface query failed"))

			np := &NfsPublisher{NfsAutoSelect: true}
			_, err := np.Publish(context.Background(), make(map[string]string), makeReq(), clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure getting file interface")
		})
	})
}

func TestCheckIfVolumeExists(t *testing.T) {
	ctx := context.Background()

	t.Run("scsi publisher CheckIfVolumeExists", func(t *testing.T) {
		sp := &SCSIPublisher{}

		t.Run("success", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", ctx, validBaseVolID).
				Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
			err := sp.CheckIfVolumeExists(ctx, clientMock, validBaseVolID)
			assert.NoError(t, err)
		})

		t.Run("not found", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", ctx, validBaseVolID).
				Return(gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound},
				})
			err := sp.CheckIfVolumeExists(ctx, clientMock, validBaseVolID)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})

		t.Run("internal error", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", ctx, validBaseVolID).
				Return(gopowerstore.Volume{}, errors.New("database connection down"))
			err := sp.CheckIfVolumeExists(ctx, clientMock, validBaseVolID)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure checking volume status")
		})
	})

	t.Run("nfs publisher CheckIfVolumeExists", func(t *testing.T) {
		np := &NfsPublisher{}

		t.Run("success", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", ctx, validBaseVolID).
				Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)
			err := np.CheckIfVolumeExists(ctx, clientMock, validBaseVolID)
			assert.NoError(t, err)
		})

		t.Run("not found", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", ctx, validBaseVolID).
				Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound},
				})
			err := np.CheckIfVolumeExists(ctx, clientMock, validBaseVolID)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})

		t.Run("internal error", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", ctx, validBaseVolID).
				Return(gopowerstore.FileSystem{}, errors.New("array unreachable"))
			err := np.CheckIfVolumeExists(ctx, clientMock, validBaseVolID)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure checking volume status")
		})
	})
}

func TestBuildFSModify(t *testing.T) {
	currentFS := gopowerstore.FileSystem{
		Description:         "old-desc",
		ProtectionPolicyID:  "old-prot",
		PerformancePolicyID: "old-perf",
	}

	t.Run("all unchanged returns nil", func(t *testing.T) {
		res := buildFSModify(currentFS, map[string]string{})
		assert.Nil(t, res)
	})

	t.Run("same values unchanged returns nil", func(t *testing.T) {
		res := buildFSModify(currentFS, map[string]string{
			"Description":         "old-desc",
			"ProtectionPolicyID":  "old-prot",
			"PerformancePolicyID": "old-perf",
		})
		assert.Nil(t, res)
	})

	t.Run("description changed", func(t *testing.T) {
		res := buildFSModify(currentFS, map[string]string{"Description": "new-desc"})
		assert.NotNil(t, res)
		assert.NotNil(t, res.Description)
		assert.Equal(t, "new-desc", *res.Description)
	})

	t.Run("protection policy changed", func(t *testing.T) {
		res := buildFSModify(currentFS, map[string]string{"ProtectionPolicyID": "new-prot"})
		assert.NotNil(t, res)
		assert.NotNil(t, res.ProtectionPolicyID)
		assert.Equal(t, "new-prot", *res.ProtectionPolicyID)
	})

	t.Run("performance policy changed", func(t *testing.T) {
		res := buildFSModify(currentFS, map[string]string{"PerformancePolicyID": "new-perf"})
		assert.NotNil(t, res)
		assert.NotNil(t, res.PerformancePolicyID)
		assert.Equal(t, "new-perf", *res.PerformancePolicyID)
	})

	t.Run("all fields changed", func(t *testing.T) {
		res := buildFSModify(currentFS, map[string]string{
			"Description":         "new-desc",
			"ProtectionPolicyID":  "new-prot",
			"PerformancePolicyID": "new-perf",
		})
		assert.NotNil(t, res)
		assert.Equal(t, "new-desc", *res.Description)
		assert.Equal(t, "new-prot", *res.ProtectionPolicyID)
		assert.Equal(t, "new-perf", *res.PerformancePolicyID)
	})
}

func TestGetServiceTag(t *testing.T) {
	ctx := context.Background()

	t.Run("appliance_id parameter present", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetAppliance", ctx, "app-1").Return(gopowerstore.ApplianceInstance{ServiceTag: "STAG123"}, nil)
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{"appliance_id": "app-1"}}
		tag := GetServiceTag(ctx, req, arr, "vol-1", "scsi")
		assert.Equal(t, "STAG123", tag)
	})

	t.Run("appliance_id parameter with error", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetAppliance", ctx, "app-err").Return(gopowerstore.ApplianceInstance{}, errors.New("appliance not found"))
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{"appliance_id": "app-err"}}
		tag := GetServiceTag(ctx, req, arr, "vol-1", "scsi")
		assert.Equal(t, "", tag)
	})

	t.Run("scsi volume with appliance ID", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetVolume", ctx, "vol-1").Return(gopowerstore.Volume{ApplianceID: "app-2"}, nil)
		clientMock.On("GetAppliance", ctx, "app-2").Return(gopowerstore.ApplianceInstance{ServiceTag: "STAG456"}, nil)
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{}}
		tag := GetServiceTag(ctx, req, arr, "vol-1", "scsi")
		assert.Equal(t, "STAG456", tag)
	})

	t.Run("scsi volume without appliance ID", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetVolume", ctx, "vol-no-app").Return(gopowerstore.Volume{ApplianceID: ""}, nil)
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{}}
		tag := GetServiceTag(ctx, req, arr, "vol-no-app", "scsi")
		assert.Equal(t, "", tag)
	})

	t.Run("scsi volume GetVolume error", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetVolume", ctx, "vol-err").Return(gopowerstore.Volume{}, errors.New("vol error"))
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{}}
		tag := GetServiceTag(ctx, req, arr, "vol-err", "scsi")
		assert.Equal(t, "", tag)
	})

	t.Run("nfs filesystem with valid NAS and currentNodeID", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetFS", ctx, "fs-1").Return(gopowerstore.FileSystem{NasServerID: "nas-1"}, nil)
		clientMock.On("GetNAS", ctx, "nas-1").Return(gopowerstore.NAS{CurrentNodeID: "appl1-node-A"}, nil)
		clientMock.On("GetApplianceByName", ctx, "appl1").Return(gopowerstore.ApplianceInstance{ServiceTag: "STAG789"}, nil)
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{}}
		tag := GetServiceTag(ctx, req, arr, "fs-1", "nfs")
		assert.Equal(t, "STAG789", tag)
	})

	t.Run("nfs filesystem with empty NasServerID", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetFS", ctx, "fs-no-nas").Return(gopowerstore.FileSystem{NasServerID: ""}, nil)
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{}}
		tag := GetServiceTag(ctx, req, arr, "fs-no-nas", "nfs")
		assert.Equal(t, "", tag)
	})

	t.Run("nfs filesystem with GetFS error", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetFS", ctx, "fs-err").Return(gopowerstore.FileSystem{}, errors.New("fs error"))
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{}}
		tag := GetServiceTag(ctx, req, arr, "fs-err", "nfs")
		assert.Equal(t, "", tag)
	})

	t.Run("nfs filesystem with empty CurrentNodeID", func(t *testing.T) {
		clientMock := new(mocks.Client)
		clientMock.On("GetFS", ctx, "fs-no-node").Return(gopowerstore.FileSystem{NasServerID: "nas-no-node"}, nil)
		clientMock.On("GetNAS", ctx, "nas-no-node").Return(gopowerstore.NAS{CurrentNodeID: ""}, nil)
		arr := &array.PowerStoreArray{Client: clientMock}

		req := &csi.CreateVolumeRequest{Parameters: map[string]string{}}
		tag := GetServiceTag(ctx, req, arr, "fs-no-node", "nfs")
		assert.Equal(t, "", tag)
	})
}
