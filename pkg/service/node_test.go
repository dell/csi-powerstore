package service

import (
	"context"
	"testing"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	nfsmock "github.com/dell/csm-hbnfs/nfs/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNodeGetInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockNodeInterface(ctrl)
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
	mockNode := mocks.NewMockNodeInterface(ctrl)
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
	mockNode := mocks.NewMockNodeInterface(ctrl)
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
	mockNode := mocks.NewMockNodeInterface(ctrl)
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
	mockNode := mocks.NewMockNodeInterface(ctrl)
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
	mockNode := mocks.NewMockNodeInterface(ctrl)
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
	mockNode := mocks.NewMockNodeInterface(ctrl)
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
	mockNode := mocks.NewMockNodeInterface(ctrl)
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
	mockNode := mocks.NewMockNodeInterface(ctrl)
	mockNfs := nfsmock.NewMockService(ctrl)
	svc := service{}
	ctx := context.Background()

	t.Run("no volume id", func(t *testing.T) {
		resp, err := svc.MountVolume(ctx, "", "", "", map[string]string{})
		assert.Empty(t, resp)
		assert.Equal(t, err.Error(), "MountVolume: volumeId was empty")
	})

	t.Run("success", func(t *testing.T) {
		mockNode.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, nil)
		mockNfs.EXPECT().NodePublishVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodePublishVolumeResponse{}, nil)
		mockNode.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{}, nil)
		mockNfs.EXPECT().NodeStageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeStageVolumeResponse{}, nil)
		PutNfsService(mockNfs)
		PutNodeService(mockNode)
		resp, err := svc.MountVolume(ctx, "123", "", "test", map[string]string{})
		assert.Nil(t, err)
		assert.Contains(t, resp, "test")
	})
}

func TestUnmountVolume(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNode := mocks.NewMockNodeInterface(ctrl)
	///mockNfs := nfsmock.NewMockService(ctrl)
	svc := service{}
	ctx := context.Background()

	t.Run("Umount fail", func(t *testing.T) {
		err := svc.UnmountVolume(ctx, "", "", map[string]string{})
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("sunccess", func(t *testing.T) {
		oldRemove := osRemove
		oldUnmount := sysUnmount
		defer func() {
			osRemove = oldRemove
			sysUnmount = oldUnmount
		}()

		osRemove = func(name string) error {
			return nil
		}
		sysUnmount = func(target string, flags int) error {
			return nil
		}

		mockNode.EXPECT().NodeUnstageVolume(gomock.Any(), gomock.Any()).AnyTimes().Return(&csi.NodeUnstageVolumeResponse{}, nil)
		PutNodeService(mockNode)

		err := svc.UnmountVolume(ctx, "123", "", map[string]string{})
		assert.Nil(t, err)
	})
}
