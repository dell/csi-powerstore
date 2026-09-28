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

package interceptors

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/collectors"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	metricsprotocol "github.com/dell/csi-powerstore/v2/pkg/metrics/protocol"
	csmnamed "github.com/dell/csm-metrics-common/pkg/naming"
	"github.com/dell/gopowerstore"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewMetricsInterceptor returns a gRPC UnaryServerInterceptor that records
// dell_csi_operation_* metrics for all CSI operations using global_id label.
func NewMetricsInterceptor(reg prometheus.Registerer, _ string, resolver collectors.ProtocolResolver) grpc.UnaryServerInterceptor {
	// Create metrics on each call (no singleton pattern - follows CSI PowerScale pattern)
	opTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: csmnamed.MetricCSIOperationTotal,
		Help: "Total CSI operations.",
	}, []string{csmnamed.LabelGlobalID, csmnamed.LabelOperation, csmnamed.LabelStatus, "protocol"})

	opDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    csmnamed.MetricCSIOperationDurationSeconds,
		Help:    "CSI operation duration.",
		Buckets: csmnamed.HistogramBuckets,
	}, []string{csmnamed.LabelGlobalID, csmnamed.LabelOperation, "protocol"})

	opFailure := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: csmnamed.MetricCSIOperationFailureTotal,
		Help: "Total CSI operation failures.",
	}, []string{csmnamed.LabelGlobalID, csmnamed.LabelOperation, csmnamed.LabelErrorCode, "protocol"})

	// Register metrics immediately if registry is provided
	if reg != nil {
		reg.MustRegister(opTotal, opDuration, opFailure)
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		operation := extractPSTOperation(info.FullMethod)
		if shouldSkipOperation(operation) {
			return handler(ctx, req)
		}

		resp, err := handler(ctx, req)

		// After operation completes, mark cache cleanup for successful DeleteVolume
		if operation == "DeleteVolume" && err == nil {
			if checker, ok := resolver.(interface{ MarkDeleteComplete(string) }); ok {
				volumeID := extractVolumeIDFromRequest(req)
				checker.MarkDeleteComplete(volumeID)
			}
		}

		requestGlobalID := extractGlobalIDFromRequest(req)
		if requestGlobalID == "unknown" {
			requestGlobalID = extractGlobalIDAndProtocolFromResponse(resp)
		}
		protocol := extractProtocolForMetrics(ctx, req, resp, operation, resolver)

		duration := time.Since(start).Seconds()
		opDuration.WithLabelValues(requestGlobalID, operation, protocol).Observe(duration)

		if err != nil {
			if isPSTContextCancelled(err) {
				return resp, err
			}
			opTotal.WithLabelValues(requestGlobalID, operation, csmnamed.LabelStatusFailure, protocol).Inc()
			opFailure.WithLabelValues(requestGlobalID, operation, classifyPSTError(err), protocol).Inc()
		} else {
			opTotal.WithLabelValues(requestGlobalID, operation, csmnamed.LabelStatusSuccess, protocol).Inc()
		}
		return resp, err
	}
}

// extractProtocolForMetrics extracts protocol for metrics using simplified logic
func extractProtocolForMetrics(ctx context.Context, req interface{}, resp interface{}, operation string, resolver collectors.ProtocolResolver) string {
	// For CreateVolume: use response VolumeContext.Protocol when it is specific.
	// Block volumes use generic "scsi" in VolumeContext and volume handles, so
	// fall back to topology to derive the real transport protocol.
	if operation == "CreateVolume" {
		if r, ok := resp.(*csi.CreateVolumeResponse); ok {
			if r.GetVolume() != nil && r.GetVolume().VolumeContext != nil {
				if protocol, ok := r.GetVolume().VolumeContext["Protocol"]; ok {
					if normalized := normalizeProtocol(protocol); normalized != "unknown" {
						return normalized
					}
				}
			}
			if r.GetVolume() != nil && r.GetVolume().VolumeId != "" {
				_, protocol := extractGlobalIDAndProtocolFromVolumeID(r.GetVolume().VolumeId)
				if protocol != "unknown" {
					return protocol
				}
			}
			if r.GetVolume() != nil {
				if protocol := metricsprotocol.FromCSITopologies(r.GetVolume().GetAccessibleTopology()); protocol != metricsprotocol.Unknown {
					return protocol
				}
			}
		}
		if r, ok := req.(*csi.CreateVolumeRequest); ok {
			if protocol := metricsprotocol.FromCSIRequirements(r.GetAccessibilityRequirements()); protocol != metricsprotocol.Unknown {
				return protocol
			}
		}
		return "unknown" // Failed CreateVolume won't have protocol set
	}

	// For ControllerPublishVolume, NodeStageVolume, NodePublishVolume:
	// Use request VolumeContext (CSI spec passes VolumeContext in these requests)
	switch r := req.(type) {
	case *csi.ControllerPublishVolumeRequest:
		if r.VolumeContext != nil {
			if protocol, ok := r.VolumeContext["Protocol"]; ok {
				if normalized := normalizeProtocol(protocol); normalized != "unknown" {
					return normalized
				}
			}
		}
	case *csi.NodeStageVolumeRequest:
		if r.VolumeContext != nil {
			if protocol, ok := r.VolumeContext["Protocol"]; ok {
				if normalized := normalizeProtocol(protocol); normalized != "unknown" {
					return normalized
				}
			}
		}
	case *csi.NodePublishVolumeRequest:
		if r.VolumeContext != nil {
			if protocol, ok := r.VolumeContext["Protocol"]; ok {
				if normalized := normalizeProtocol(protocol); normalized != "unknown" {
					return normalized
				}
			}
		}
	}

	// For ControllerUnpublishVolume, NodeUnstageVolume, NodeUnpublishVolume:
	// Use the resolver (K8s PV lookup) - PV should still exist at this point
	volumeID := extractVolumeIDFromRequest(req)
	if volumeID != "" && resolver != nil {
		if protocol := normalizeProtocol(resolver.GetProtocol(ctx, volumeID)); protocol != "unknown" {
			return protocol
		}
	}

	// Fallback to volume ID parsing
	return extractProtocolFromVolumeID(req)
}

// extractVolumeIDFromRequest extracts the volume ID from various CSI requests
func extractVolumeIDFromRequest(req interface{}) string {
	switch r := req.(type) {
	case *csi.DeleteVolumeRequest:
		return r.VolumeId
	case *csi.ControllerPublishVolumeRequest:
		return r.VolumeId
	case *csi.ControllerUnpublishVolumeRequest:
		return r.VolumeId
	case *csi.NodeStageVolumeRequest:
		return r.VolumeId
	case *csi.NodeUnstageVolumeRequest:
		return r.VolumeId
	case *csi.NodePublishVolumeRequest:
		return r.VolumeId
	case *csi.NodeUnpublishVolumeRequest:
		return r.VolumeId
	}
	return ""
}

// extractProtocolFromVolumeID extracts protocol from volume ID for non-CreateVolume operations
func extractProtocolFromVolumeID(req interface{}) string {
	var volumeID string

	switch r := req.(type) {
	case *csi.DeleteVolumeRequest:
		volumeID = r.VolumeId
	case *csi.ControllerPublishVolumeRequest:
		volumeID = r.VolumeId
	case *csi.ControllerUnpublishVolumeRequest:
		volumeID = r.VolumeId
	case *csi.NodeStageVolumeRequest:
		volumeID = r.VolumeId
	case *csi.NodeUnstageVolumeRequest:
		volumeID = r.VolumeId
	case *csi.NodePublishVolumeRequest:
		volumeID = r.VolumeId
	case *csi.NodeUnpublishVolumeRequest:
		volumeID = r.VolumeId
	default:
		return "unknown"
	}

	_, protocol := extractGlobalIDAndProtocolFromVolumeID(volumeID)
	return protocol
}

// extractGlobalIDFromRequest attempts to extract the global_id from CSI requests
// Volume ID format is typically: "volume_id/global_id"
func extractGlobalIDFromRequest(req interface{}) string {
	if req == nil {
		return "unknown"
	}

	// Try to extract global_id from volume IDs in various CSI request types
	switch r := req.(type) {
	case *csi.DeleteVolumeRequest:
		if globalID, _ := extractGlobalIDAndProtocolFromVolumeID(r.VolumeId); globalID != "unknown" {
			return globalID
		}
	case *csi.ControllerPublishVolumeRequest:
		if globalID, _ := extractGlobalIDAndProtocolFromVolumeID(r.VolumeId); globalID != "unknown" {
			return globalID
		}
	case *csi.ControllerUnpublishVolumeRequest:
		if globalID, _ := extractGlobalIDAndProtocolFromVolumeID(r.VolumeId); globalID != "unknown" {
			return globalID
		}
	case *csi.NodeStageVolumeRequest:
		if globalID, _ := extractGlobalIDAndProtocolFromVolumeID(r.VolumeId); globalID != "unknown" {
			return globalID
		}
	case *csi.NodeUnstageVolumeRequest:
		if globalID, _ := extractGlobalIDAndProtocolFromVolumeID(r.VolumeId); globalID != "unknown" {
			return globalID
		}
	case *csi.NodePublishVolumeRequest:
		if globalID, _ := extractGlobalIDAndProtocolFromVolumeID(r.VolumeId); globalID != "unknown" {
			return globalID
		}
	case *csi.NodeUnpublishVolumeRequest:
		if globalID, _ := extractGlobalIDAndProtocolFromVolumeID(r.VolumeId); globalID != "unknown" {
			return globalID
		}
	}

	return "unknown"
}

func extractGlobalIDAndProtocolFromResponse(resp interface{}) string {
	switch r := resp.(type) {
	case *csi.CreateVolumeResponse:
		if r != nil && r.GetVolume() != nil {
			globalID, _ := extractGlobalIDAndProtocolFromVolumeID(r.GetVolume().GetVolumeId())
			return globalID
		}
	}
	return "unknown"
}

func extractGlobalIDAndProtocolFromVolumeID(volumeID string) (string, string) {
	if volumeID == "" {
		return "unknown", "unknown"
	}

	// Volume ID format: "uuid/global_id/protocol" or "uuid/global_id/protocol:..."
	// Example: "d419debd-6a20-40f3-bea6-89188de51d1b/PSc26835c9a0ba/scsi"
	// We need to extract the protocol from the last segment

	// Split by ":" first to handle any suffix after protocol
	parts := strings.Split(volumeID, ":")
	baseID := parts[0]

	// Split by "/" to get segments
	segments := strings.Split(baseID, "/")
	if len(segments) < 3 {
		return "unknown", "unknown"
	}

	globalID := segments[1]
	protocol := segments[len(segments)-1] // Last segment is the protocol

	// Map IP-based global IDs to array names if needed
	if ips := identifiers.GetIPListFromString(globalID); len(ips) > 0 {
		if mappedGlobalID, ok := array.IPToArray[ips[0]]; ok && mappedGlobalID != "" {
			globalID = mappedGlobalID
		}
	}

	normalizedProtocol := normalizeProtocol(protocol)
	return globalID, normalizedProtocol
}

// shouldSkipOperation returns true for CSI operations that should not have metrics recorded.
// Only the 8 core volume lifecycle operations are instrumented:
// CreateVolume, DeleteVolume, ControllerPublishVolume, ControllerUnpublishVolume,
// NodeStageVolume, NodeUnstageVolume, NodePublishVolume, NodeUnpublishVolume
func shouldSkipOperation(operation string) bool {
	switch operation {
	case "CreateVolume", "DeleteVolume",
		"ControllerPublishVolume", "ControllerUnpublishVolume",
		"NodeStageVolume", "NodeUnstageVolume",
		"NodePublishVolume", "NodeUnpublishVolume":
		return false
	}
	return true
}

func normalizeProtocol(protocol string) string {
	return metricsprotocol.Normalize(protocol)
}

func extractPSTOperation(fullMethod string) string {
	parts := strings.Split(fullMethod, "/")
	if len(parts) == 0 {
		return "unknown"
	}
	return parts[len(parts)-1]
}

func classifyPSTError(err error) string {
	if err == nil {
		return "none"
	}
	// Check for PowerStore REST API authentication/authorization errors.
	// Direct type assertion handles raw gopowerstore.APIError values returned
	// by handlers that pass errors through without wrapping.
	// errors.As traverses error chains from fmt.Errorf("...: %w", err).
	var apiErr gopowerstore.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
			return "auth_failure"
		}
	}
	s, ok := status.FromError(err)
	if !ok {
		return "unknown"
	}
	switch s.Code() {
	case codes.DeadlineExceeded:
		return "timeout"
	case codes.Unauthenticated, codes.PermissionDenied:
		return "auth_failure"
	case codes.NotFound:
		return "not_found"
	case codes.InvalidArgument:
		return "invalid_argument"
	case codes.Internal:
		if isWrappedAuthError(s.Message()) {
			return "auth_failure"
		}
		return "internal_error"
	case codes.FailedPrecondition:
		return "failed_precondition"
	case codes.AlreadyExists:
		return "already_exists"
	case codes.ResourceExhausted:
		if isWrappedAuthError(s.Message()) {
			return "auth_failure"
		}
		return "resource_exhausted"
	case codes.Unknown:
		if isWrappedAuthError(s.Message()) {
			return "auth_failure"
		}
		return "unknown"
	default:
		return "unknown"
	}
}

// isWrappedAuthError checks if a gRPC status message contains a PowerStore REST API
// authentication/authorization error. The gopowerstore ErrorMsg.Error() format is
// "HTTP <code>: <message>", so we look for "HTTP 401:" or "HTTP 403:" substrings.
func isWrappedAuthError(msg string) bool {
	return strings.Contains(msg, "HTTP 401:") || strings.Contains(msg, "HTTP 403:")
}

func isPSTContextCancelled(err error) bool {
	if err == context.Canceled {
		return true
	}
	s, ok := status.FromError(err)
	return ok && s.Code() == codes.Canceled
}
