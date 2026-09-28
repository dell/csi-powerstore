/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package interceptors_test

import (
	"context"
	"strings"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/collectors"
	"github.com/dell/csi-powerstore/v2/pkg/interceptors"
	"github.com/dell/csm-metrics-common/pkg/naming"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockProtocolResolver is a simple mock for testing
type mockProtocolResolver struct {
	protocol  string
	protocols map[string]string // volumeID -> protocol override
}

var _ collectors.ProtocolResolver = (*mockProtocolResolver)(nil)

func extractVolumeIDFromFullID(volumeHandle string) string {
	// volumeHandle format is typically: "volumeID/arrayID" or just "volumeID"
	// Split on "/" and take the first part
	parts := []string{}
	for _, p := range strings.Split(volumeHandle, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func (m *mockProtocolResolver) GetProtocol(_ context.Context, volumeID string) string {
	// Extract volume ID from full volume ID if needed
	shortVolumeID := extractVolumeIDFromFullID(volumeID)

	// Check for volume-specific protocol override
	if m.protocols != nil {
		if p, ok := m.protocols[shortVolumeID]; ok {
			return p
		}
	}
	return m.protocol
}

func (m *mockProtocolResolver) RefreshCache(_ context.Context) error {
	return nil
}

func gatherPSTIntMetric(t *testing.T, reg prometheus.Gatherer, name string) *dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

func counterPSTInt(mf *dto.MetricFamily, labels map[string]string) float64 {
	if mf == nil {
		return 0
	}
	for _, m := range mf.GetMetric() {
		got := make(map[string]string)
		for _, lp := range m.GetLabel() {
			got[lp.GetName()] = lp.GetValue()
		}
		match := true
		for k, v := range labels {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

// U-PST-01: CreateVolume success with protocol=iSCSI label
func TestMetricsInterceptor_CreateVolume_Success_iSCSI(t *testing.T) {
	reg := prometheus.NewRegistry()
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", &mockProtocolResolver{protocol: "unknown"})

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/CreateVolume"}
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return &csi.CreateVolumeResponse{
			Volume: &csi.Volume{
				VolumeId:      "vol-1/global-1/iscsi",
				VolumeContext: map[string]string{"Protocol": "iSCSI"},
			},
		}, nil
	}

	_, err := interceptor(ctx, &csi.CreateVolumeRequest{}, info, handler)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf, "dell_csi_operation_total must be registered")

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "CreateVolume",
		"status":    "success",
		"protocol":  "iSCSI",
	})
	assert.Equal(t, 1.0, v)
}

// U-PST-02: NodePublishVolume uses protocol normalization from volume ID.
func TestMetricsInterceptor_NodePublishVolume_ProtocolLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", &mockProtocolResolver{protocol: "unknown"})

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Node/NodePublishVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.NodePublishVolumeRequest{VolumeId: "vol-2/global-1/nvme_fc"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "NodePublishVolume",
		"status":    "success",
		"protocol":  "NVMeFC",
	})
	assert.Equal(t, 1.0, v, "operation=NodePublishVolume should be tracked")
}

func TestMetricsInterceptor_CreateVolume_UsesResponseVolumeID(t *testing.T) {
	reg := prometheus.NewRegistry()
	interceptor := interceptors.NewMetricsInterceptor(reg, "unknown", &mockProtocolResolver{protocol: "unknown"})

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/CreateVolume"}
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return &csi.CreateVolumeResponse{
			Volume: &csi.Volume{
				VolumeId:      "vol-123/array-9/nfs",
				VolumeContext: map[string]string{"Protocol": "NFS"},
			},
		}, nil
	}

	_, err := interceptor(ctx, &csi.CreateVolumeRequest{}, info, handler)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "array-9",
		"operation": "CreateVolume",
		"status":    "success",
		"protocol":  "NFS",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_DeleteVolume_UsesRequestVolumeID(t *testing.T) {
	reg := prometheus.NewRegistry()
	resolver := &mockProtocolResolver{
		protocol: "unknown",
		protocols: map[string]string{
			"vol-456": "NFS", // Return "NFS" for this specific volume ID
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "unknown", resolver)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/DeleteVolume"}
	handler := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.DeleteVolumeRequest{VolumeId: "vol-456/array-7/nfs"}, info, handler)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "array-7",
		"operation": "DeleteVolume",
		"status":    "success",
		"protocol":  "NFS",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_DeleteVolume_Failure(t *testing.T) {
	reg := prometheus.NewRegistry()
	resolver := &mockProtocolResolver{
		protocol: "unknown",
		protocols: map[string]string{
			"vol-456": "iSCSI", // Return "iSCSI" for this specific volume ID
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "unknown", resolver)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/DeleteVolume"}
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}

	_, err := interceptor(ctx, &csi.DeleteVolumeRequest{VolumeId: "vol-456/array-7/iscsi"}, info, handler)
	require.Error(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)
	assert.Equal(t, 1.0, counterPSTInt(mf, map[string]string{
		"global_id": "array-7",
		"operation": "DeleteVolume",
		"status":    "failure",
		"protocol":  "iSCSI",
	}))

	failureMF := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationFailureTotal)
	require.NotNil(t, failureMF)
	assert.Equal(t, 1.0, counterPSTInt(failureMF, map[string]string{
		"global_id":  "array-7",
		"operation":  "DeleteVolume",
		"error_code": "auth_failure",
		"protocol":   "iSCSI",
	}))
}

func TestMetricsInterceptor_NodePublishVolume_Canceled(t *testing.T) {
	reg := prometheus.NewRegistry()
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", &mockProtocolResolver{protocol: "unknown"})

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Node/NodePublishVolume"}
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, context.Canceled
	}

	_, err := interceptor(ctx, &csi.NodePublishVolumeRequest{VolumeId: "vol-1/global-1/fc"}, info, handler)
	require.ErrorIs(t, err, context.Canceled)

	// Context-canceled operations should not be recorded, and metrics are not pre-created.
	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	assert.Nil(t, mf)
}

func TestMetricsInterceptor_NoRegistry(t *testing.T) {
	interceptor := interceptors.NewMetricsInterceptor(nil, "global-1", &mockProtocolResolver{protocol: "unknown"})

	_, err := interceptor(context.Background(), &csi.CreateVolumeRequest{}, &grpc.UnaryServerInfo{
		FullMethod: "/csi.v1.Controller/CreateVolume",
	}, func(_ context.Context, _ interface{}) (interface{}, error) {
		return &csi.CreateVolumeResponse{
			Volume: &csi.Volume{
				VolumeId:      "vol-1/global-1/nfs",
				VolumeContext: map[string]string{"Protocol": "NFS"},
			},
		}, nil
	})
	require.NoError(t, err)
}

func TestMetricsInterceptor_SingleInterceptorUsage(t *testing.T) {
	reg := prometheus.NewRegistry()

	// Test the actual production usage pattern: single interceptor creation
	resolver := &mockProtocolResolver{
		protocol: "unknown",
		protocols: map[string]string{
			"vol-9": "NFS", // Return "NFS" for this specific volume ID
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", resolver)

	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/DeleteVolume"}
	req := &csi.DeleteVolumeRequest{VolumeId: "vol-9/global-9/nfs"}

	// Call the interceptor multiple times (simulating multiple CSI operations)
	_, err := interceptor(context.Background(), req, info, func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, nil
	})
	require.NoError(t, err)

	_, err = interceptor(context.Background(), req, info, func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, nil
	})
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)
	assert.Equal(t, 2.0, counterPSTInt(mf, map[string]string{
		"global_id": "global-9",
		"operation": "DeleteVolume",
		"status":    "success",
		"protocol":  "NFS",
	}))
}

// Additional tests for complete operation coverage
func TestMetricsInterceptor_ControllerPublishVolume_ProtocolLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", &mockProtocolResolver{protocol: "unknown"})

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/ControllerPublishVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.ControllerPublishVolumeRequest{VolumeId: "vol-1/global-1/iscsi"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "ControllerPublishVolume",
		"status":    "success",
		"protocol":  "iSCSI",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_ControllerUnpublishVolume_ProtocolLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	resolver := &mockProtocolResolver{
		protocol: "unknown",
		protocols: map[string]string{
			"vol-1": "FC", // Return "FC" for this specific volume ID
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", resolver)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/ControllerUnpublishVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.ControllerUnpublishVolumeRequest{VolumeId: "vol-1/global-1/fc"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "ControllerUnpublishVolume",
		"status":    "success",
		"protocol":  "FC",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_NodeStageVolume_ProtocolLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", &mockProtocolResolver{protocol: "unknown"})

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Node/NodeStageVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.NodeStageVolumeRequest{VolumeId: "vol-1/global-1/nvme_tcp"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "NodeStageVolume",
		"status":    "success",
		"protocol":  "NVMeTCP",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_NodeUnstageVolume_ProtocolLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	resolver := &mockProtocolResolver{
		protocol: "unknown",
		protocols: map[string]string{
			"vol-1": "NFS", // Return "NFS" for this specific volume ID
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", resolver)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Node/NodeUnstageVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.NodeUnstageVolumeRequest{VolumeId: "vol-1/global-1/nfs"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "NodeUnstageVolume",
		"status":    "success",
		"protocol":  "NFS",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_NodeUnpublishVolume_ProtocolLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	resolver := &mockProtocolResolver{
		protocol: "unknown",
		protocols: map[string]string{
			"vol-1": "SCSI", // Resolver returns a generic block value, not a concrete transport.
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", resolver)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Node/NodeUnpublishVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.NodeUnpublishVolumeRequest{VolumeId: "vol-1/global-1/scsi"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "NodeUnpublishVolume",
		"status":    "success",
		"protocol":  "unknown",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_DeleteVolume_WithPendingDeletionResolver(t *testing.T) {
	reg := prometheus.NewRegistry()
	resolver := &mockProtocolResolver{
		protocol: "unknown", // Default fallback
		protocols: map[string]string{
			"vol-1": "NVMeTCP", // Simulate protocol from pending deletion cache
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", resolver)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/DeleteVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.DeleteVolumeRequest{VolumeId: "vol-1/global-1/nvmetcp"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "DeleteVolume",
		"status":    "success",
		"protocol":  "NVMeTCP",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_DeleteVolume_ISCSIWithPendingDeletionResolver(t *testing.T) {
	reg := prometheus.NewRegistry()
	resolver := &mockProtocolResolver{
		protocol: "unknown", // Default fallback
		protocols: map[string]string{
			"vol-1": "iSCSI", // Simulate protocol from pending deletion cache
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", resolver)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/DeleteVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.DeleteVolumeRequest{VolumeId: "vol-1/global-1/iscsi"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "DeleteVolume",
		"status":    "success",
		"protocol":  "iSCSI",
	})
	assert.Equal(t, 1.0, v)
}

func TestMetricsInterceptor_DeleteVolume_NFSWithPendingDeletionResolver(t *testing.T) {
	reg := prometheus.NewRegistry()
	resolver := &mockProtocolResolver{
		protocol: "unknown", // Default fallback
		protocols: map[string]string{
			"vol-1": "NFS", // Simulate protocol from pending deletion cache
		},
	}
	interceptor := interceptors.NewMetricsInterceptor(reg, "global-1", resolver)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Controller/DeleteVolume"}
	noopH := func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil }

	_, err := interceptor(ctx, &csi.DeleteVolumeRequest{VolumeId: "vol-1/global-1/nfs"}, info, noopH)
	require.NoError(t, err)

	mf := gatherPSTIntMetric(t, reg, naming.MetricCSIOperationTotal)
	require.NotNil(t, mf)

	v := counterPSTInt(mf, map[string]string{
		"global_id": "global-1",
		"operation": "DeleteVolume",
		"status":    "success",
		"protocol":  "NFS",
	})
	assert.Equal(t, 1.0, v)
}
