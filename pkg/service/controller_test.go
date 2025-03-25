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
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	nfsmock "github.com/dell/csm-hbnfs/nfs/mocks"
	commonext "github.com/dell/dell-csi-extensions/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/mock/gomock"
)

func TestCreateVolume(t *testing.T) {
	c := gomock.NewController(t)
	svc := service{}
	ctx := context.Background()
	mockController := new(mocks.ControllerInterface)
	mockNode := mocks.NewMockInterface(c)
	mockNfs := nfsmock.NewMockService(c)

	t.Run("nfs volume", func(t *testing.T) {
		mockController.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{}, nil)
		mockNfs.EXPECT().CreateVolume(gomock.Any(), gomock.Any()).Times(1).Return(&csi.CreateVolumeResponse{}, nil)
		PutControllerService(mockController)
		PutNodeService(mockNode)
		PutNfsService(mockNfs)

		req := &csi.CreateVolumeRequest{
			Parameters: map[string]string{"csi-nfs": "RWXW"},
		}
		resp, err := svc.CreateVolume(ctx, req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})

	t.Run("normal volume", func(t *testing.T) {
		mockController.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{}, nil)
		mockNfs.EXPECT().CreateVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.CreateVolumeResponse{}, nil)
		PutControllerService(mockController)
		PutNodeService(mockNode)
		PutNfsService(mockNfs)

		req := &csi.CreateVolumeRequest{}
		resp, err := svc.CreateVolume(ctx, req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
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
	mockController := new(mocks.ControllerInterface)
	mockNfs := nfsmock.NewMockService(ctrl)
	svc := service{}

	t.Run("empty volume id", func(t *testing.T) {
		req := &csi.ControllerPublishVolumeRequest{
			VolumeContext: map[string]string{"fsType": "nfs"},
			VolumeId:      "",
		}
		resp, err := svc.ControllerPublishVolume(context.Background(), req)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "volume ID is required")
	})

	t.Run("nfs volume", func(t *testing.T) {
		mockController.On("ControllerPublishVolume", mock.Anything, mock.Anything).Return(&csi.ControllerPublishVolumeResponse{}, nil)
		mockNfs.EXPECT().ControllerPublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.ControllerPublishVolumeResponse{}, nil)

		PutControllerService(mockController)
		PutNfsService(mockNfs)

		req := &csi.ControllerPublishVolumeRequest{
			VolumeContext: map[string]string{"fsType": "nfs"},
			VolumeId:      "nfs-123",
		}

		resp, err := svc.ControllerPublishVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})

	t.Run("normal volume", func(t *testing.T) {
		mockController.On("ControllerPublishVolume", mock.Anything, mock.Anything).Return(&csi.ControllerPublishVolumeResponse{}, nil)
		PutControllerService(mockController)
		req := &csi.ControllerPublishVolumeRequest{
			VolumeContext: map[string]string{"fsType": "nfs"},
			VolumeId:      "vid-123",
		}
		resp, err := svc.ControllerPublishVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
}
