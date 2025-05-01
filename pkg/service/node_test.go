/*
 *
 * Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
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

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	nfsmock "github.com/dell/csm-hbnfs/nfs/mocks"
	"github.com/dell/gofsutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNodeGetInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockInterface(ctrl)
	svc := service{}
	mockNode.EXPECT().NodeGetInfo(gomock.Any(), gomock.Any()).Return(&csi.NodeGetInfoResponse{}, nil)
	PutNodeService(mockNode)
	req := &csi.NodeGetInfoRequest{}
	resp, err := svc.NodeGetInfo(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestNodeGetCapabilities(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockInterface(ctrl)
	svc := service{}
	mockNode.EXPECT().NodeGetCapabilities(gomock.Any(), gomock.Any()).Return(&csi.NodeGetCapabilitiesResponse{}, nil)
	PutNodeService(mockNode)
	req := &csi.NodeGetCapabilitiesRequest{}
	resp, err := svc.NodeGetCapabilities(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestNodeExpandVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockInterface(ctrl)
	svc := service{}
	mockNode.EXPECT().NodeExpandVolume(gomock.Any(), gomock.Any()).Return(&csi.NodeExpandVolumeResponse{}, nil)
	PutNodeService(mockNode)
	req := &csi.NodeExpandVolumeRequest{}
	resp, err := svc.NodeExpandVolume(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestNodeGetVolumeStats(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockInterface(ctrl)
	svc := service{}
	mockNode.EXPECT().NodeGetVolumeStats(gomock.Any(), gomock.Any()).Return(&csi.NodeGetVolumeStatsResponse{}, nil)
	PutNodeService(mockNode)
	req := &csi.NodeGetVolumeStatsRequest{
		VolumeId: "nfs-123",
	}
	resp, err := svc.NodeGetVolumeStats(context.Background(), req)
	assert.Nil(t, err)
	assert.Empty(t, resp)
}

func TestNodeUnpublishVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockInterface(ctrl)
	svc := service{}
	mockNode.EXPECT().NodeUnpublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeUnpublishVolumeResponse{}, nil)
	PutNodeService(mockNode)

	t.Run("nfs volume", func(t *testing.T) {
		mockNfs := nfsmock.NewMockService(ctrl)
		mockNfs.EXPECT().NodeUnpublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeUnpublishVolumeResponse{}, nil)
		PutNfsService(mockNfs)
		req := &csi.NodeUnpublishVolumeRequest{
			VolumeId: "nfs-123",
		}
		resp, err := svc.NodeUnpublishVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})

	t.Run("normal volume", func(t *testing.T) {
		req := &csi.NodeUnpublishVolumeRequest{
			VolumeId: "123",
		}
		resp, err := svc.NodeUnpublishVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
}

func TestNodePublishVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockInterface(ctrl)
	svc := service{}
	mockNode.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, nil)
	PutNodeService(mockNode)

	t.Run("nfs volume", func(t *testing.T) {
		mockNfs := nfsmock.NewMockService(ctrl)
		mockNfs.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, nil)
		PutNfsService(mockNfs)
		req := &csi.NodePublishVolumeRequest{
			VolumeId: "nfs-123",
		}
		resp, err := svc.NodePublishVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})

	t.Run("normal volume", func(t *testing.T) {
		req := &csi.NodePublishVolumeRequest{
			VolumeId: "123",
		}
		resp, err := svc.NodePublishVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})
}

func TestNodeUnstageVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockInterface(ctrl)
	svc := service{}
	mockNode.EXPECT().NodeUnstageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeUnstageVolumeResponse{
		XXX_sizecache: 10,
	}, nil)
	PutNodeService(mockNode)
	t.Run("nfs volume", func(t *testing.T) {
		req := &csi.NodeUnstageVolumeRequest{
			VolumeId: "nfs-123",
		}
		resp, err := svc.NodeUnstageVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})

	t.Run("normal volume", func(t *testing.T) {
		req := &csi.NodeUnstageVolumeRequest{}
		resp, err := svc.NodeUnstageVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Equal(t, resp.XXX_sizecache, int32(10))
	})
}

func TestNodeStageVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockInterface(ctrl)
	svc := service{}
	mockNode.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{
		XXX_sizecache: 10,
	}, nil)
	PutNodeService(mockNode)
	t.Run("nfs volume", func(t *testing.T) {
		req := &csi.NodeStageVolumeRequest{
			VolumeId: "nfs-123",
		}
		resp, err := svc.NodeStageVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})

	t.Run("normal volume", func(t *testing.T) {
		req := &csi.NodeStageVolumeRequest{
			VolumeId: "123",
		}
		resp, err := svc.NodeStageVolume(context.Background(), req)
		assert.Nil(t, err)
		assert.NotEmpty(t, resp)
	})
}

func TestMountVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	svc := service{}
	ctx := context.Background()

	t.Run("no volume id", func(t *testing.T) {
		resp, err := svc.MountVolume(ctx, "", "", "", map[string]string{})
		assert.Empty(t, resp)
		assert.Equal(t, err.Error(), "MountVolume: volumeId was empty")
	})

	t.Run("success", func(t *testing.T) {
		mockNode := mocks.NewMockInterface(ctrl)
		mockNfs := nfsmock.NewMockService(ctrl)
		mockNode.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, nil)
		mockNfs.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, nil)
		mockNode.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{}, nil)
		mockNfs.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{}, nil)
		PutNfsService(mockNfs)
		PutNodeService(mockNode)
		resp, err := svc.MountVolume(ctx, "123", "", "test", map[string]string{})
		assert.Nil(t, err)
		assert.Contains(t, resp, "test")
		resp, err = svc.MountVolume(ctx, "123", "", "", map[string]string{})
		assert.Nil(t, err)
		assert.Empty(t, resp)
	})

	t.Run("stage error", func(t *testing.T) {
		mockNode := mocks.NewMockInterface(ctrl)
		mockNfs := nfsmock.NewMockService(ctrl)
		mockNode.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, nil)
		mockNfs.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, nil)
		mockNode.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{}, errors.New("stage error"))
		mockNfs.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{}, errors.New("stage error"))
		PutNfsService(mockNfs)
		PutNodeService(mockNode)
		resp, err := svc.MountVolume(ctx, "123", "", "", map[string]string{})
		assert.Empty(t, resp)
		assert.Contains(t, err.Error(), "stage error")
	})

	t.Run("publish error", func(t *testing.T) {
		mockNode := mocks.NewMockInterface(ctrl)
		mockNfs := nfsmock.NewMockService(ctrl)
		mockNode.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, errors.New("publish error"))
		mockNfs.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, errors.New("publish error"))
		mockNode.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{}, nil)
		mockNfs.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{}, nil)
		PutNfsService(mockNfs)
		PutNodeService(mockNode)
		resp, err := svc.MountVolume(ctx, "123", "", "", map[string]string{})
		assert.Empty(t, resp)
		assert.Contains(t, err.Error(), "could not publish volume")
	})
}

func TestUnmountVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx := context.Background()

	t.Run("Umount fail", func(t *testing.T) {
		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		defaultSysUnmount := sysUnmount
		sysUnmount = func(_ string, _ int) error {
			return errors.New("operation not permitted")
		}
		defer func() {
			sysUnmount = defaultSysUnmount
		}()

		utilMock.On("GetMounts", ctx).Return([]gofsutil.Info{
			{
				Path: "/var/lib/dell/nfs/myNfsMount",
			},
		}, nil)
		fsMock.On("GetUtil").Return(utilMock)

		svc := service{
			fs: fsMock,
		}

		err := svc.UnmountVolume(ctx, "", "/var/lib/dell/nfs/", map[string]string{
			"ServiceName": "myNfsMount",
		})
		assert.NotNil(t, err)
	})

	t.Run("success", func(t *testing.T) {
		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		mockNode := mocks.NewMockInterface(ctrl)
		oldRemove := osRemove
		oldUnmount := sysUnmount
		defer func() {
			osRemove = oldRemove
			sysUnmount = oldUnmount
		}()

		utilMock.On("GetMounts", ctx).Return([]gofsutil.Info{
			{
				Path: "/var/lib/dell/nfs/myNfsMount",
			},
		}, nil)
		fsMock.On("GetUtil").Return(utilMock)

		osRemove = func(_ string) error {
			return nil
		}
		sysUnmount = func(_ string, _ int) error {
			return nil
		}

		mockNode.EXPECT().NodeUnstageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeUnstageVolumeResponse{}, nil)
		PutNodeService(mockNode)

		svc := service{
			fs: fsMock,
		}

		err := svc.UnmountVolume(ctx, "123", "/var/lib/dell/nfs/", map[string]string{
			"ServiceName": "myNfsMount",
		})
		assert.Nil(t, err)
	})

	t.Run("remove fail", func(t *testing.T) {
		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		mockNode := mocks.NewMockInterface(ctrl)
		oldRemove := osRemove
		oldUnmount := sysUnmount
		defer func() {
			osRemove = oldRemove
			sysUnmount = oldUnmount
		}()

		utilMock.On("GetMounts", ctx).Return([]gofsutil.Info{
			{
				Path: "/var/lib/dell/nfs/myNfsMount",
			},
		}, nil)
		fsMock.On("GetUtil").Return(utilMock)

		osRemove = func(_ string) error {
			return errors.New("remove error")
		}
		sysUnmount = func(_ string, _ int) error {
			return nil
		}

		mockNode.EXPECT().NodeUnstageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeUnstageVolumeResponse{}, nil)
		PutNodeService(mockNode)

		svc := service{
			fs: fsMock,
		}

		err := svc.UnmountVolume(ctx, "123", "/var/lib/dell/nfs/", map[string]string{
			"ServiceName": "myNfsMount",
		})
		assert.Contains(t, err.Error(), "remove error")
	})

	t.Run("unstage error", func(t *testing.T) {
		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		mockNode := mocks.NewMockInterface(ctrl)
		oldRemove := osRemove
		oldUnmount := sysUnmount
		defer func() {
			osRemove = oldRemove
			sysUnmount = oldUnmount
		}()

		utilMock.On("GetMounts", ctx).Return([]gofsutil.Info{
			{
				Path: "/var/lib/dell/nfs/myNfsMount",
			},
		}, nil)
		fsMock.On("GetUtil").Return(utilMock)

		osRemove = func(_ string) error {
			return nil
		}
		sysUnmount = func(_ string, _ int) error {
			return nil
		}

		mockNode.EXPECT().NodeUnstageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeUnstageVolumeResponse{}, errors.New("unstage error"))
		PutNodeService(mockNode)

		svc := service{
			fs: fsMock,
		}

		err := svc.UnmountVolume(ctx, "123", "/var/lib/dell/nfs/", map[string]string{
			"ServiceName": "myNfsMount",
		})
		assert.Contains(t, err.Error(), "unstage error")
	})

	t.Run("unable to determine mounts", func(t *testing.T) {
		utilMock := new(mocks.UtilInterface)
		fsMock := new(mocks.FsInterface)

		oldRemove := osRemove
		oldUnmount := sysUnmount
		defer func() {
			osRemove = oldRemove
			sysUnmount = oldUnmount
		}()

		utilMock.On("GetMounts", ctx).Return([]gofsutil.Info{}, errors.New("get mounts error"))
		fsMock.On("GetUtil").Return(utilMock)

		osRemove = func(_ string) error {
			return nil
		}
		sysUnmount = func(_ string, _ int) error {
			return nil
		}

		svc := service{
			fs: fsMock,
		}

		err := svc.UnmountVolume(ctx, "123", "/var/lib/dell/nfs/", map[string]string{
			"ServiceName": "myNfsMount",
		})
		assert.Contains(t, err.Error(), "get mounts error")
	})
}
