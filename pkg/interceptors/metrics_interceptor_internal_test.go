/*
 *
 * Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package interceptors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/dell/csi-metadata-retriever/retriever"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	controller "github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	"github.com/akutz/gosync"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type errorLockerProvider struct{}

func (errorLockerProvider) GetLockWithID(context.Context, string) (gosync.TryLocker, error) {
	return nil, errors.New("lock failure")
}

func (errorLockerProvider) GetLockWithName(context.Context, string) (gosync.TryLocker, error) {
	return nil, errors.New("lock failure")
}

type nilMetadataClient struct{}

func (nilMetadataClient) GetPVCLabels(context.Context, *retriever.GetPVCLabelsRequest) (*retriever.GetPVCLabelsResponse, error) {
	return nil, nil
}

func (nilMetadataClient) GetPVCLabelsByPVName(context.Context, *retriever.GetPVCLabelsByPVNameRequest) (*retriever.GetPVCLabelsByPVNameResponse, error) {
	return nil, nil
}

type testProtocolResolver map[string]string

func (r testProtocolResolver) GetProtocol(_ context.Context, volumeID string) string {
	return r[volumeID]
}

func (r testProtocolResolver) RefreshCache(_ context.Context) error {
	return nil
}

func TestNormalizeProtocol(t *testing.T) {
	tests := map[string]string{
		"iscsi":    "iSCSI",
		"fc":       "FC",
		"nvmeof":   "NVMeFC",
		"nvme_fc":  "NVMeFC",
		"nvme-fc":  "NVMeFC",
		"nvmefc":   "NVMeFC",
		"nvme_tcp": "NVMeTCP",
		"nvme-tcp": "NVMeTCP",
		"nvmetcp":  "NVMeTCP",
		"nfs":      "NFS",
		"scsi":     "unknown",
		"other":    "unknown",
		"  fc  ":   "FC",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, normalizeProtocol(input))
		})
	}
}

func TestExtractProtocolForMetrics(t *testing.T) {
	array.IPToArray = map[string]string{"192.168.0.1": "mapped-global"}

	tests := []struct {
		name      string
		req       interface{}
		resp      interface{}
		operation string
		resolver  testProtocolResolver
		want      string
	}{
		{
			name: "create volume from response context",
			req:  &csi.CreateVolumeRequest{},
			resp: &csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					VolumeContext: map[string]string{"Protocol": "iSCSI"},
				},
			},
			operation: "CreateVolume",
			want:      "iSCSI",
		},
		{
			name: "create volume fallback to volume id",
			req:  &csi.CreateVolumeRequest{},
			resp: &csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					VolumeId:      "vol-1/global-1/nfs",
					VolumeContext: map[string]string{}, // Empty VolumeContext
				},
			},
			operation: "CreateVolume",
			want:      "NFS",
		},
		{
			name: "create volume derives generic scsi from response topology",
			req:  &csi.CreateVolumeRequest{},
			resp: &csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					VolumeId:      "vol-1/global-1/scsi",
					VolumeContext: map[string]string{"Protocol": "scsi"},
					AccessibleTopology: []*csi.Topology{
						{Segments: map[string]string{"csi-powerstore.dellemc.com/10.247.27.44-iscsi": "true"}},
					},
				},
			},
			operation: "CreateVolume",
			want:      "iSCSI",
		},
		{
			name: "create volume derives generic scsi from request topology",
			req: &csi.CreateVolumeRequest{
				AccessibilityRequirements: &csi.TopologyRequirement{
					Preferred: []*csi.Topology{
						{Segments: map[string]string{"csi-powerstore.dellemc.com/10.247.27.44-nvmetcp": "true"}},
					},
				},
			},
			resp: &csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					VolumeId:      "vol-1/global-1/scsi",
					VolumeContext: map[string]string{"Protocol": "scsi"},
				},
			},
			operation: "CreateVolume",
			want:      "NVMeTCP",
		},
		{
			name: "create volume with unknown protocol in context",
			req:  &csi.CreateVolumeRequest{},
			resp: &csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					VolumeContext: map[string]string{"Protocol": "unknown"},
				},
			},
			operation: "CreateVolume",
			want:      "unknown",
		},
		{
			name: "create volume with nil volume",
			req:  &csi.CreateVolumeRequest{},
			resp: &csi.CreateVolumeResponse{
				Volume: nil,
			},
			operation: "CreateVolume",
			want:      "unknown",
		},
		{
			name:      "create volume with nil response",
			req:       &csi.CreateVolumeRequest{},
			resp:      nil,
			operation: "CreateVolume",
			want:      "unknown",
		},
		{
			name: "delete volume from id",
			req: &csi.DeleteVolumeRequest{
				VolumeId: "vol-1/global-1/nfs",
			},
			resp:      nil,
			operation: "DeleteVolume",
			want:      "NFS",
		},
		{
			name: "controller publish from id",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeId: "vol-1/global-1/iscsi",
			},
			resp:      nil,
			operation: "ControllerPublishVolume",
			want:      "iSCSI",
		},
		{
			name: "controller publish from volume context",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeContext: map[string]string{"Protocol": "FC"},
			},
			resp:      nil,
			operation: "ControllerPublishVolume",
			want:      "FC",
		},
		{
			name: "controller publish with unknown protocol in context",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeContext: map[string]string{"Protocol": "unknown"},
			},
			resp:      nil,
			operation: "ControllerPublishVolume",
			want:      "unknown",
		},
		{
			name: "controller publish resolves generic scsi from resolver",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeId:      "vol-1/global-1/scsi",
				VolumeContext: map[string]string{"Protocol": "scsi"},
			},
			resp:      nil,
			operation: "ControllerPublishVolume",
			resolver:  testProtocolResolver{"vol-1/global-1/scsi": "iSCSI"},
			want:      "iSCSI",
		},
		{
			name: "controller publish with nil volume context",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeContext: nil,
			},
			resp:      nil,
			operation: "ControllerPublishVolume",
			want:      "unknown",
		},
		{
			name: "node stage from volume context",
			req: &csi.NodeStageVolumeRequest{
				VolumeId:      "vol-1/global-1/nvme_tcp",
				VolumeContext: map[string]string{"Protocol": "NVMeTCP"},
			},
			resp:      nil,
			operation: "NodeStageVolume",
			want:      "NVMeTCP",
		},
		{
			name: "node stage resolves generic scsi from resolver",
			req: &csi.NodeStageVolumeRequest{
				VolumeId:      "vol-1/global-1/scsi",
				VolumeContext: map[string]string{"Protocol": "scsi"},
			},
			resp:      nil,
			operation: "NodeStageVolume",
			resolver:  testProtocolResolver{"vol-1/global-1/scsi": "FC"},
			want:      "FC",
		},
		{
			name: "node publish from id",
			req: &csi.NodePublishVolumeRequest{
				VolumeId: "vol-1/global-1/nvme_fc",
			},
			resp:      nil,
			operation: "NodePublishVolume",
			want:      "NVMeFC",
		},
		{
			name: "node publish from volume context",
			req: &csi.NodePublishVolumeRequest{
				VolumeContext: map[string]string{"Protocol": "NFS"},
			},
			resp:      nil,
			operation: "NodePublishVolume",
			want:      "NFS",
		},
		{
			name: "node publish resolves generic scsi from resolver",
			req: &csi.NodePublishVolumeRequest{
				VolumeId:      "vol-1/global-1/scsi",
				VolumeContext: map[string]string{"Protocol": "scsi"},
			},
			resp:      nil,
			operation: "NodePublishVolume",
			resolver:  testProtocolResolver{"vol-1/global-1/scsi": "NVMeFC"},
			want:      "NVMeFC",
		},
		{
			name:      "unknown request",
			req:       struct{}{},
			resp:      nil,
			operation: "UnknownOperation",
			want:      "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractProtocolForMetrics(context.Background(), tt.req, tt.resp, tt.operation, tt.resolver))
		})
	}
}

func TestExtractProtocolFromVolumeID(t *testing.T) {
	array.IPToArray = map[string]string{"192.168.0.1": "mapped-global"}

	tests := []struct {
		name string
		req  interface{}
		want string
	}{
		{
			name: "delete volume",
			req: &csi.DeleteVolumeRequest{
				VolumeId: "vol-1/global-1/nfs",
			},
			want: "NFS",
		},
		{
			name: "controller publish",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeId: "vol-1/global-1/iscsi",
			},
			want: "iSCSI",
		},
		{
			name: "controller unpublish",
			req: &csi.ControllerUnpublishVolumeRequest{
				VolumeId: "vol-1/global-1/nvme_fc",
			},
			want: "NVMeFC",
		},
		{
			name: "node stage",
			req: &csi.NodeStageVolumeRequest{
				VolumeId: "vol-1/global-1/nvme_tcp",
			},
			want: "NVMeTCP",
		},
		{
			name: "node unstage",
			req: &csi.NodeUnstageVolumeRequest{
				VolumeId: "vol-1/global-1/fc",
			},
			want: "FC",
		},
		{
			name: "node publish",
			req: &csi.NodePublishVolumeRequest{
				VolumeId: "vol-1/global-1/nvmeof",
			},
			want: "NVMeFC",
		},
		{
			name: "node unpublish",
			req: &csi.NodeUnpublishVolumeRequest{
				VolumeId: "vol-1/global-1/scsi",
			},
			want: "unknown",
		},
		{
			name: "unknown request",
			req:  struct{}{},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractProtocolFromVolumeID(tt.req))
		})
	}
}

func TestExtractGlobalIDFromRequest(t *testing.T) {
	tests := []struct {
		name string
		req  interface{}
		want string
	}{
		{
			name: "delete volume",
			req: &csi.DeleteVolumeRequest{
				VolumeId: "vol-1/global-9/scsi",
			},
			want: "global-9",
		},
		{
			name: "controller publish",
			req: &csi.ControllerPublishVolumeRequest{
				VolumeId: "vol-1/global-8/nfs",
			},
			want: "global-8",
		},
		{
			name: "node publish",
			req: &csi.NodePublishVolumeRequest{
				VolumeId: "vol-1/global-7/scsi",
			},
			want: "global-7",
		},
		{
			name: "unknown request",
			req:  struct{}{},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractGlobalIDFromRequest(tt.req))
		})
	}
}

func TestExtractGlobalIDAndProtocolFromVolumeID(t *testing.T) {
	array.IPToArray = map[string]string{"192.168.0.1": "mapped-global"}

	globalID, protocol := extractGlobalIDAndProtocolFromVolumeID("vol-1/192.168.0.1/nvme_tcp")
	assert.Equal(t, "mapped-global", globalID)
	assert.Equal(t, "NVMeTCP", protocol)

	globalID, protocol = extractGlobalIDAndProtocolFromVolumeID("vol-1/global-2/iscsi")
	assert.Equal(t, "global-2", globalID)
	assert.Equal(t, "iSCSI", protocol)

	globalID, protocol = extractGlobalIDAndProtocolFromVolumeID("bad-format")
	assert.Equal(t, "unknown", globalID)
	assert.Equal(t, "unknown", protocol)
}

func TestExtractResponseHelpers(t *testing.T) {
	resp := &csi.CreateVolumeResponse{
		Volume: &csi.Volume{VolumeId: "vol-1/global-3/nfs"},
	}
	assert.Equal(t, "global-3", extractGlobalIDAndProtocolFromResponse(resp))
	assert.Equal(t, "unknown", extractGlobalIDAndProtocolFromResponse(&csi.CreateVolumeResponse{}))
}

func TestExtractPSTOperation(t *testing.T) {
	assert.Equal(t, "CreateVolume", extractPSTOperation("/csi.v1.Controller/CreateVolume"))
	assert.Equal(t, "", extractPSTOperation(""))
}

func TestShouldSkipOperation(t *testing.T) {
	// Test operations that should NOT be skipped (core volume lifecycle operations)
	nonSkipOps := []string{
		"CreateVolume", "DeleteVolume",
		"ControllerPublishVolume", "ControllerUnpublishVolume",
		"NodeStageVolume", "NodeUnstageVolume",
		"NodePublishVolume", "NodeUnpublishVolume",
	}
	for _, op := range nonSkipOps {
		t.Run(op+" should not skip", func(t *testing.T) {
			assert.False(t, shouldSkipOperation(op))
		})
	}

	// Test operations that should be skipped
	skipOps := []string{
		"GetCapacity", "ListVolumes", "ValidateVolumeCapabilities",
		"ControllerGetCapabilities", "NodeGetCapabilities",
		"NodeGetVolumeStats", "ExpandVolume", "GetPluginInfo",
		"Probe", "UnknownOperation", "",
	}
	for _, op := range skipOps {
		t.Run(op+" should skip", func(t *testing.T) {
			assert.True(t, shouldSkipOperation(op))
		})
	}
}

func TestClassifyPSTError(t *testing.T) {
	assert.Equal(t, "none", classifyPSTError(nil))
	assert.Equal(t, "unknown", classifyPSTError(errors.New("plain")))
	assert.Equal(t, "timeout", classifyPSTError(status.Error(codes.DeadlineExceeded, "deadline")))
	assert.Equal(t, "auth_failure", classifyPSTError(status.Error(codes.PermissionDenied, "denied")))
	assert.Equal(t, "auth_failure", classifyPSTError(status.Error(codes.Unauthenticated, "unauth")))
	assert.Equal(t, "not_found", classifyPSTError(status.Error(codes.NotFound, "missing")))
	assert.Equal(t, "internal_error", classifyPSTError(status.Error(codes.Internal, "other")))
}

func TestClassifyPSTError_PowerStoreAPIError(t *testing.T) {
	t.Run("401 Unauthorized returns auth_failure", func(t *testing.T) {
		apiErr := gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusUnauthorized,
			Message:    "unauthorized",
		}}
		assert.Equal(t, "auth_failure", classifyPSTError(apiErr))
	})

	t.Run("403 Forbidden returns auth_failure", func(t *testing.T) {
		apiErr := gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusForbidden,
			Message:    "forbidden",
		}}
		assert.Equal(t, "auth_failure", classifyPSTError(apiErr))
	})

	t.Run("404 NotFound does not return auth_failure", func(t *testing.T) {
		apiErr := gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusNotFound,
			Message:    "not found",
		}}
		// APIError does not satisfy status.FromError, so falls through to "unknown"
		assert.Equal(t, "unknown", classifyPSTError(apiErr))
	})

	t.Run("500 InternalServerError does not return auth_failure", func(t *testing.T) {
		apiErr := gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal error",
		}}
		assert.Equal(t, "unknown", classifyPSTError(apiErr))
	})

	t.Run("401 wrapped with fmt.Errorf %w returns auth_failure", func(t *testing.T) {
		apiErr := gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusUnauthorized,
			Message:    "unauthorized",
		}}
		wrapped := fmt.Errorf("volume operation failed: %w", apiErr)
		assert.Equal(t, "auth_failure", classifyPSTError(wrapped))
	})

	t.Run("403 wrapped with fmt.Errorf %w returns auth_failure", func(t *testing.T) {
		apiErr := gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusForbidden,
			Message:    "forbidden",
		}}
		wrapped := fmt.Errorf("publish failed: %w", apiErr)
		assert.Equal(t, "auth_failure", classifyPSTError(wrapped))
	})

	t.Run("401 wrapped in gRPC Internal status returns auth_failure", func(t *testing.T) {
		grpcErr := status.Errorf(codes.Internal, "can't publish volume: HTTP 401: unauthorized")
		assert.Equal(t, "auth_failure", classifyPSTError(grpcErr))
	})

	t.Run("403 wrapped in gRPC Internal status returns auth_failure", func(t *testing.T) {
		grpcErr := status.Errorf(codes.Internal, "can't create volume: HTTP 403: forbidden")
		assert.Equal(t, "auth_failure", classifyPSTError(grpcErr))
	})

	t.Run("403 wrapped in gRPC ResourceExhausted status returns auth_failure", func(t *testing.T) {
		grpcErr := status.Errorf(codes.ResourceExhausted, "can't create fs: HTTP 403: forbidden")
		assert.Equal(t, "auth_failure", classifyPSTError(grpcErr))
	})

	t.Run("403 wrapped in gRPC Unknown status returns auth_failure", func(t *testing.T) {
		grpcErr := status.Errorf(codes.Unknown, "detach failed: HTTP 403: forbidden")
		assert.Equal(t, "auth_failure", classifyPSTError(grpcErr))
	})

	t.Run("non-auth error in gRPC Internal status returns internal_error", func(t *testing.T) {
		grpcErr := status.Errorf(codes.Internal, "can't publish volume: HTTP 500: server error")
		assert.Equal(t, "internal_error", classifyPSTError(grpcErr))
	})
}

func TestIsPSTContextCancelled(t *testing.T) {
	assert.True(t, isPSTContextCancelled(context.Canceled))
	assert.True(t, isPSTContextCancelled(status.Error(codes.Canceled, "cancelled")))
	assert.False(t, isPSTContextCancelled(errors.New("plain")))
}

func TestNodeStageAndUnstageVolumeErrors(t *testing.T) {
	t.Run("node stage lock error", func(t *testing.T) {
		i := &interceptor{opts: opts{locker: errorLockerProvider{}}}
		_, err := i.nodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{VolumeId: "vol-1"}, nil, func(context.Context, interface{}) (interface{}, error) {
			return nil, nil
		})
		assert.Error(t, err)
	})

	t.Run("node unstage lock error", func(t *testing.T) {
		i := &interceptor{opts: opts{locker: errorLockerProvider{}}}
		_, err := i.nodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{VolumeId: "vol-1"}, nil, func(context.Context, interface{}) (interface{}, error) {
			return nil, nil
		})
		assert.Error(t, err)
	})
}

func TestCreateVolumeMetadataBranches(t *testing.T) {
	req := &csi.CreateVolumeRequest{
		Name: "vol-1",
		Parameters: map[string]string{
			controller.KeyCSIPVCName:      "pvc-1",
			controller.KeyCSIPVCNamespace: "default",
		},
	}
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "ok", nil
	}

	t.Run("no metadata client", func(t *testing.T) {
		mockLocker := &MockLocker{}
		mockLock := &MockLock{}
		mockLocker.On("GetLockWithID", context.Background(), req.Name).Return(mockLock, nil)
		mockLock.On("TryLock", time.Duration(0)).Return(true)
		mockLock.On("Unlock").Return()
		mockLock.On("Close").Return(nil)

		i := &interceptor{opts: opts{locker: mockLocker, timeout: 0}}
		res, err := i.createVolume(context.Background(), req, nil, handler)
		assert.NoError(t, err)
		assert.Equal(t, "ok", res)
		mockLocker.AssertExpectations(t)
		mockLock.AssertExpectations(t)
	})

	t.Run("nil metadata response", func(t *testing.T) {
		mockLocker := &MockLocker{}
		mockLock := &MockLock{}
		mockLocker.On("GetLockWithID", context.Background(), req.Name).Return(mockLock, nil)
		mockLock.On("TryLock", time.Duration(0)).Return(true)
		mockLock.On("Unlock").Return()
		mockLock.On("Close").Return(nil)

		i := &interceptor{opts: opts{
			locker:                mockLocker,
			timeout:               0,
			MetadataSidecarClient: nilMetadataClient{},
		}}
		res, err := i.createVolume(context.Background(), req, nil, handler)
		assert.NoError(t, err)
		assert.Equal(t, "ok", res)
		mockLocker.AssertExpectations(t)
		mockLock.AssertExpectations(t)
	})
}
