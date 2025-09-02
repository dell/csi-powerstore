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

/*
 *
 * Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csm-sharednfs/nfs"
	nfsmock "github.com/dell/csm-sharednfs/nfs/mocks"
	commonext "github.com/dell/dell-csi-extensions/common"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCreateVolume(t *testing.T) {
	c := gomock.NewController(t)
	svc := service{}
	volumeUUID := uuid.New().String()
	arrayGlobalID := "PS000000000001"
	volumeHandle := volumeUUID + "/" + arrayGlobalID + "/scsi"
	nfsVolumeHandle := nfs.CsiNfsPrefixDash + volumeHandle

	type args struct {
		ctx context.Context
		req *csi.CreateVolumeRequest
	}
	type testCase struct {
		name        string
		args        args
		mockSetup   func(mock *mocks.ControllerInterface, mockNode *mocks.MockInterface, mockNfs *nfsmock.MockService)
		expectedErr error
	}

	testCases := []testCase{
		{
			name: "nfs volume",
			args: args{
				ctx: context.Background(),
				req: &csi.CreateVolumeRequest{
					Parameters: map[string]string{CsiNfsParameter: "RWX"},
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
						},
					},
				},
			},
			mockSetup: func(mockController *mocks.ControllerInterface, _ *mocks.MockInterface, mockNfs *nfsmock.MockService) {
				mockController.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{}, nil)
				mockNfs.EXPECT().CreateVolume(gomock.Any(), gomock.Any()).Times(1).Return(&csi.CreateVolumeResponse{}, nil)
			},
			expectedErr: nil,
		},
		{
			name: "normal volume",
			args: args{
				ctx: context.Background(),
				req: &csi.CreateVolumeRequest{
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
						},
					},
				},
			},
			mockSetup: func(mockController *mocks.ControllerInterface, _ *mocks.MockInterface, mockNfs *nfsmock.MockService) {
				mockController.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{}, nil)
				mockNfs.EXPECT().CreateVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.CreateVolumeResponse{}, nil)
			},
			expectedErr: nil,
		},
		{
			name: "clone a host-based NFS volume",
			args: args{
				ctx: context.Background(),
				req: &csi.CreateVolumeRequest{
					Parameters: map[string]string{CsiNfsParameter: "RWX"},
					// provide a host-based nfs volume as content source, signifying a clone request
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
						},
					},
					VolumeContentSource: &csi.VolumeContentSource{
						Type: &csi.VolumeContentSource_Volume{
							Volume: &csi.VolumeContentSource_VolumeSource{
								VolumeId: nfsVolumeHandle,
							},
						},
					},
				},
			},
			mockSetup: func(mockController *mocks.ControllerInterface, _ *mocks.MockInterface, mockNfs *nfsmock.MockService) {
				mockController.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{}, nil)
				mockNfs.EXPECT().CreateVolume(gomock.Any(), gomock.Any()).Times(1).Return(&csi.CreateVolumeResponse{}, nil)
			},
			expectedErr: nil,
		},
		{
			name: "clone a raw block volume with host-based NFS storage class",
			args: args{
				ctx: context.Background(),
				req: &csi.CreateVolumeRequest{
					// CsiNfsParameter denotes a host-based NFS storage class
					Parameters: map[string]string{CsiNfsParameter: "RWX"},
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
						},
					},
					// provide a regular volume ID as content source
					VolumeContentSource: &csi.VolumeContentSource{
						Type: &csi.VolumeContentSource_Volume{
							Volume: &csi.VolumeContentSource_VolumeSource{
								VolumeId: volumeHandle,
							},
						},
					},
				},
			},
			mockSetup: func(_ *mocks.ControllerInterface, _ *mocks.MockInterface, _ *nfsmock.MockService) {
			},
			expectedErr: status.Error(codes.InvalidArgument,
				"the volume ID of the volume to be cloned must be of the host-based NFS type"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockController := new(mocks.ControllerInterface)
			mockNode := mocks.NewMockInterface(c)
			mockNfs := nfsmock.NewMockService(c)

			tc.mockSetup(mockController, mockNode, mockNfs)

			PutControllerService(mockController)
			PutNodeService(mockNode)
			PutNfsService(mockNfs)

			resp, err := svc.CreateVolume(tc.args.ctx, tc.args.req)

			if tc.expectedErr == nil {
				assert.Nil(t, err)
				assert.Empty(t, resp)
			} else {
				assert.Equal(t, tc.expectedErr, err)
			}
		})
	}
}

func TestDeleteVolume(t *testing.T) {
	c := gomock.NewController(t)
	svc := service{}
	ctx := context.Background()
	mockController := new(mocks.ControllerInterface)
	mockNode := mocks.NewMockInterface(c)
	mockNfs := nfsmock.NewMockService(c)

	t.Run("nfs volume", func(t *testing.T) {
		mockController.On("DeleteVolume", mock.Anything, mock.Anything).Return(&csi.DeleteVolumeResponse{}, nil)
		mockNfs.EXPECT().DeleteVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.DeleteVolumeResponse{}, nil)
		PutControllerService(mockController)
		PutNodeService(mockNode)
		PutNfsService(mockNfs)

		req := &csi.DeleteVolumeRequest{
			VolumeId: "nfs-123",
		}
		resp, err := svc.DeleteVolume(ctx, req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
}

func TestProbeController(t *testing.T) {
	svc := service{}
	ctx := context.Background()
	mockController := new(mocks.ControllerInterface)

	t.Run("success", func(t *testing.T) {
		PutControllerService(mockController)

		req := &commonext.ProbeControllerRequest{}
		mockController.On("ProbeController", mock.Anything, mock.Anything).Return(&commonext.ProbeControllerResponse{}, nil)

		resp, err := svc.ProbeController(ctx, req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
}

func TestControllerGetVolume(t *testing.T) {
	svc := service{}
	ctx := context.Background()
	mockController := new(mocks.ControllerInterface)

	t.Run("success", func(t *testing.T) {
		PutControllerService(mockController)

		req := &csi.ControllerGetVolumeRequest{
			VolumeId: "nfs-12345",
		}
		mockController.On("ControllerGetVolume", mock.Anything, mock.Anything).
			Return(&csi.ControllerGetVolumeResponse{}, nil)

		resp, err := svc.ControllerGetVolume(ctx, req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
}

func TestControllerExpandVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	svc := service{}
	req := &csi.ControllerExpandVolumeRequest{
		VolumeId: "nfs-volume",
	}
	mockController.On("ControllerExpandVolume", mock.Anything, req).Return(&csi.ControllerExpandVolumeResponse{}, nil)
	PutControllerService(mockController)
	resp, err := svc.ControllerExpandVolume(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestControllerListSnapshots(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	svc := service{}
	req := &csi.ListSnapshotsRequest{
		SourceVolumeId: "nfs-volume",
	}
	mockController.On("ListSnapshots", mock.Anything, req).Return(&csi.ListSnapshotsResponse{}, nil)
	PutControllerService(mockController)
	resp, err := svc.ListSnapshots(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestDeleteSnapshot(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	svc := service{}
	req := &csi.DeleteSnapshotRequest{
		SnapshotId: "nfs-snapshot",
	}
	mockController.On("DeleteSnapshot", mock.Anything, req).Return(&csi.DeleteSnapshotResponse{}, nil)
	PutControllerService(mockController)
	resp, err := svc.DeleteSnapshot(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestCreateSnapshot(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	svc := service{}
	req := &csi.CreateSnapshotRequest{
		SourceVolumeId: "nfs-volume",
		Name:           "snapshot-name",
	}
	mockController.On("CreateSnapshot", mock.Anything, req).Return(&csi.CreateSnapshotResponse{
		Snapshot: &csi.Snapshot{
			SnapshotId:     "nfs-snapshot",
			SourceVolumeId: "nfs-volume",
			CreationTime:   nil,
			SizeBytes:      int64(1024),
			ReadyToUse:     true,
		},
	}, nil)
	PutControllerService(mockController)
	resp, err := svc.CreateSnapshot(context.Background(), req)
	assert.Nil(t, err)
	assert.NotEmpty(t, resp)
	assert.Equal(t, "nfs-snapshot", resp.GetSnapshot().GetSnapshotId())
	assert.Equal(t, "nfs-volume", resp.GetSnapshot().GetSourceVolumeId())
	assert.Equal(t, int64(1024), resp.GetSnapshot().GetSizeBytes())
	assert.True(t, resp.GetSnapshot().GetReadyToUse())
}

func TestControllerGetCapabilities(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	svc := service{}
	req := &csi.ControllerGetCapabilitiesRequest{}
	mockController.On("ControllerGetCapabilities", mock.Anything, req).Return(&csi.ControllerGetCapabilitiesResponse{}, nil)
	PutControllerService(mockController)
	resp, err := svc.ControllerGetCapabilities(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestControllerGetCapacity(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	svc := service{}
	req := &csi.GetCapacityRequest{}
	mockController.On("GetCapacity", mock.Anything, req).Return(&csi.GetCapacityResponse{
		AvailableCapacity: int64(1024),
	}, nil)
	PutControllerService(mockController)
	resp, err := svc.GetCapacity(context.Background(), req)
	assert.Nil(t, err)
	assert.NotEmpty(t, resp)
	assert.Equal(t, int64(1024), resp.GetAvailableCapacity())
}

func TestControllerListVolumes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	svc := service{}
	req := &csi.ListVolumesRequest{}
	mockController.On("ListVolumes", mock.Anything, req).Return(&csi.ListVolumesResponse{
		Entries: []*csi.ListVolumesResponse_Entry{
			{
				Volume: &csi.Volume{
					VolumeId:      "nfs-123",
					VolumeContext: map[string]string{"fsType": "nfs"},
					CapacityBytes: int64(1024),
				},
			},
		},
	}, nil)
	PutControllerService(mockController)
	resp, err := svc.ListVolumes(context.Background(), req)
	assert.Nil(t, err)
	assert.NotEmpty(t, resp)
	assert.Equal(t, "nfs-123", resp.GetEntries()[0].GetVolume().GetVolumeId())
	assert.Equal(t, "nfs", resp.GetEntries()[0].GetVolume().GetVolumeContext()["fsType"])
	assert.Equal(t, int64(1024), resp.GetEntries()[0].GetVolume().GetCapacityBytes())
}

func TestControllerValidateVolumeCapabilities(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	svc := service{}
	req := &csi.ValidateVolumeCapabilitiesRequest{
		VolumeId: "nfs-123",
	}
	mockController.On("ValidateVolumeCapabilities", mock.Anything, req).Return(&csi.ValidateVolumeCapabilitiesResponse{}, nil)
	PutControllerService(mockController)
	resp, err := svc.ValidateVolumeCapabilities(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestControllerUnpublishVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	mockNfs := nfsmock.NewMockService(ctrl)
	svc := service{}
	t.Run("nfs volume", func(t *testing.T) {
		req := &csi.ControllerUnpublishVolumeRequest{
			VolumeId: "nfs-123",
			NodeId:   "node-123",
		}
		mockController.On("ControllerUnpublishVolume", mock.Anything, req).Return(&csi.ControllerUnpublishVolumeResponse{}, nil)
		mockNfs.EXPECT().ControllerUnpublishVolume(gomock.Any(), req).AnyTimes().Return(&csi.ControllerUnpublishVolumeResponse{}, nil)
		PutControllerService(mockController)
		PutNfsService(mockNfs)
		resp, err := svc.ControllerUnpublishVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
	t.Run("normal volume", func(t *testing.T) {
		req := &csi.ControllerUnpublishVolumeRequest{
			VolumeId: "vid-123",
			NodeId:   "node-123",
		}
		mockController.On("ControllerUnpublishVolume", mock.Anything, req).Return(&csi.ControllerUnpublishVolumeResponse{}, nil)
		PutControllerService(mockController)
		resp, err := svc.ControllerUnpublishVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
}

func TestControllerPublishVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		name       string
		req        *csi.ControllerPublishVolumeRequest
		expectResp *csi.ControllerPublishVolumeResponse
		expectErr  error
	}{
		{
			name: "empty volume id",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeContext: map[string]string{"fsType": "nfs"},
				VolumeId:      "",
			},
			expectErr: errors.New("volume ID is required"),
		},
		{
			name: "nfs volume",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeId: "nfs-123",
			},
			expectResp: &csi.ControllerPublishVolumeResponse{},
		},
		{
			name: "normal volume",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeId: "vid-123",
			},
			expectResp: &csi.ControllerPublishVolumeResponse{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockController := new(mocks.ControllerInterface)
			mockNfs := nfsmock.NewMockService(ctrl)
			svc := service{}

			if tc.name == "nfs volume" {
				mockController.On("ControllerPublishVolume", mock.Anything, tc.req).Return(tc.expectResp, tc.expectErr)
				mockNfs.EXPECT().ControllerPublishVolume(gomock.Any(), tc.req).AnyTimes().Return(tc.expectResp, tc.expectErr)

				PutControllerService(mockController)
				PutNfsService(mockNfs)
			} else {
				mockController.On("ControllerPublishVolume", mock.Anything, tc.req).Return(tc.expectResp, tc.expectErr)

				PutControllerService(mockController)
			}

			resp, err := svc.ControllerPublishVolume(context.Background(), tc.req)
			assert.Equal(t, tc.expectResp, resp)
			if tc.expectErr != nil {
				assert.Contains(t, err.Error(), tc.expectErr.Error())
			}
		})
	}
}

func Test_removeNFSPrefixFromSourceID(t *testing.T) {
	arrayGlobalID := "PS000000000001"
	volumeUUID := uuid.New().String()
	volumeHandle := volumeUUID + "/" + arrayGlobalID + "/scsi"
	nfsVolumeHandle := nfs.CsiNfsPrefixDash + volumeHandle

	type args struct {
		source *csi.VolumeContentSource
	}
	tests := []struct {
		name    string
		args    args
		expect  *csi.VolumeContentSource
		wantErr bool
		errMsg  string
	}{
		{
			name: "remove the nfs prefix from a host-based nfs source volume",
			args: args{
				source: &csi.VolumeContentSource{
					Type: &csi.VolumeContentSource_Volume{
						Volume: &csi.VolumeContentSource_VolumeSource{
							VolumeId: nfsVolumeHandle,
						},
					},
				},
			},
			expect: &csi.VolumeContentSource{
				Type: &csi.VolumeContentSource_Volume{
					Volume: &csi.VolumeContentSource_VolumeSource{
						VolumeId: volumeHandle,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "snapshots are not affected",
			args: args{
				source: &csi.VolumeContentSource{
					Type: &csi.VolumeContentSource_Snapshot{
						Snapshot: &csi.VolumeContentSource_SnapshotSource{
							SnapshotId: volumeUUID,
						},
					},
				},
			},
			expect: &csi.VolumeContentSource{
				Type: &csi.VolumeContentSource_Snapshot{
					Snapshot: &csi.VolumeContentSource_SnapshotSource{
						SnapshotId: volumeUUID,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "source volume ID is empty",
			args: args{
				source: &csi.VolumeContentSource{
					Type: &csi.VolumeContentSource_Volume{
						Volume: &csi.VolumeContentSource_VolumeSource{
							VolumeId: "",
						},
					},
				},
			},
			expect: &csi.VolumeContentSource{
				Type: &csi.VolumeContentSource_Volume{
					Volume: &csi.VolumeContentSource_VolumeSource{
						VolumeId: "",
					},
				},
			},
			wantErr: true,
			errMsg:  "the volume ID of the volume to be cloned cannot be empty",
		},
		{
			name: "source volume is not a host-based NFS volume",
			args: args{
				source: &csi.VolumeContentSource{
					Type: &csi.VolumeContentSource_Volume{
						Volume: &csi.VolumeContentSource_VolumeSource{
							VolumeId: volumeHandle,
						},
					},
				},
			},
			expect: &csi.VolumeContentSource{
				Type: &csi.VolumeContentSource_Volume{
					Volume: &csi.VolumeContentSource_VolumeSource{
						VolumeId: volumeHandle,
					},
				},
			},
			wantErr: true,
			errMsg:  "the volume ID of the volume to be cloned must be of the host-based NFS type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := removeNFSPrefixFromSourceID(tt.args.source)
			if (err != nil) != tt.wantErr {
				t.Errorf("removeNFSPrefixFromSourceID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				assert.Contains(t, err.Error(), tt.errMsg)
			}
			assert.Equal(t, *tt.expect, *tt.args.source)
		})
	}
}
