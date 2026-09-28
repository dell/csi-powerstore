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

package controller

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/dell/csmlog"
	"github.com/dell/gopowerstore"
)

// NAA resolution constants
const (
	// KeyAffinitySourceNAA is the PVC label key for MTV source volume NAA ID
	// This label is merged directly into req.Parameters by csi-metadata-retriever sidecar
	KeyAffinitySourceNAA = "volume.csi.k8s.io/affinity-source-naa"

	// NAAPrefix is the standard NAA ID prefix
	NAAPrefix = "naa."

	// MinFirmwareVersionForNAA is the minimum PowerStore firmware version for NAA resolution (5.1)
	MinFirmwareVersionForNAA float32 = 5.1

	// NAAResolutionMaxRetries is the maximum number of retry attempts for NAA resolution
	NAAResolutionMaxRetries = 3

	// NAAResolutionInitialBackoff is the initial backoff duration for retries
	NAAResolutionInitialBackoff = 100 * time.Millisecond
)

// PlacementOutcome represents the result of placement verification
type PlacementOutcome string

const (
	// PlacementXCOPYSuccess indicates target is on same appliance as source (XCOPY eligible)
	PlacementXCOPYSuccess PlacementOutcome = "XCOPYSuccess"
	// PlacementHostCopyFallback indicates target is on different appliance (host-copy required)
	PlacementHostCopyFallback PlacementOutcome = "HostCopyFallback"
	// PlacementVerificationFailed indicates placement verification query failed
	PlacementVerificationFailed PlacementOutcome = "PlacementVerificationFailed"
)

// PlacementVerificationResult contains the result of placement verification
type PlacementVerificationResult struct {
	Outcome           PlacementOutcome
	TargetApplianceID string
	SourceApplianceID string
	Error             error
}

// NAAResolutionResult contains the result of NAA ID resolution
type NAAResolutionResult struct {
	SourceVolumeID    string
	SourceApplianceID string
	Success           bool
	FailureReason     string
}

// extractNAALabelFromParams extracts the NAA ID label value from request parameters
// The csi-metadata-retriever sidecar merges PVC labels directly into req.Parameters
func extractNAALabelFromParams(params map[string]string) string {
	naaValue, ok := params[KeyAffinitySourceNAA]
	if !ok {
		return ""
	}

	return strings.TrimSpace(naaValue)
}

// normalizeNAAID normalizes the NAA ID by ensuring the "naa." prefix is present
// The hex portion of the NAA ID is preserved as-is since PowerStore API handles case
func normalizeNAAID(naaID string) string {
	if naaID == "" {
		return ""
	}

	// Check if prefix already exists (case-insensitive)
	lowerNAA := strings.ToLower(naaID)
	if strings.HasPrefix(lowerNAA, NAAPrefix) {
		// Replace any case variant of "naa." with lowercase "naa."
		return NAAPrefix + naaID[len(NAAPrefix):]
	}

	return NAAPrefix + naaID
}

// isTransientError checks if the HTTP status code indicates a transient error that should be retried
func isTransientError(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}

// resolveNAAToVolumeID resolves a NAA ID to source volume ID and appliance ID
func resolveNAAToVolumeID(ctx context.Context, client gopowerstore.Client, naaID string) (*NAAResolutionResult, error) {
	if naaID == "" {
		return &NAAResolutionResult{
			Success:       false,
			FailureReason: "empty NAA ID",
		}, nil
	}

	normalizedNAA := normalizeNAAID(naaID)
	log.Debugf("Resolving NAA ID: %s (normalized)", normalizedNAA)

	var lastErr error
	backoff := NAAResolutionInitialBackoff

	for attempt := 1; attempt <= NAAResolutionMaxRetries; attempt++ {
		volumes, err := client.GetVolumesWithFilter(ctx, map[string]string{
			"wwn": "eq." + normalizedNAA,
		})

		if err == nil {
			if len(volumes) == 0 {
				log.WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  "NAAResolution",
					"resolution_status": "failure",
				}).Warnf("NAA ID not found; provisioning without affinity hint")
				return &NAAResolutionResult{
					Success:       false,
					FailureReason: "NAA ID not found",
				}, nil
			}

			// Use first matching volume
			vol := volumes[0]
			log.WithFields(log.Fields{
				log.FieldComponent:    "controller",
				log.FieldOperation:    "NAAResolution",
				"source_volume_id":    vol.ID,
				"source_appliance_id": vol.ApplianceID,
				"resolution_status":   "success",
			}).Infof("NAA ID resolution succeeded")
			return &NAAResolutionResult{
				SourceVolumeID:    vol.ID,
				SourceApplianceID: vol.ApplianceID,
				Success:           true,
			}, nil
		}

		// Check if error is retryable
		apiErr, ok := err.(gopowerstore.APIError)
		if ok {
			statusCode := apiErr.StatusCode
			if !isTransientError(statusCode) {
				// Permanent error - don't retry
				log.WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  "NAAResolution",
					"resolution_status": "failure",
					"error_details":     err.Error(),
				}).Warnf("NAA ID resolution failed (HTTP %d); provisioning without affinity hint", statusCode)
				return &NAAResolutionResult{
					Success:       false,
					FailureReason: err.Error(),
				}, nil
			}
		}

		lastErr = err
		if attempt < NAAResolutionMaxRetries {
			log.Debugf("NAA ID resolution attempt %d failed, retrying after %v", attempt, backoff)
			select {
			case <-time.After(backoff):
				// backoff elapsed, proceed to retry
			case <-ctx.Done():
				log.WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  "NAAResolution",
					"resolution_status": "failure",
					"error_details":     ctx.Err().Error(),
				}).Warnf("NAA ID resolution cancelled during backoff")
				return &NAAResolutionResult{
					Success:       false,
					FailureReason: ctx.Err().Error(),
				}, nil
			}
			backoff *= 2 // Exponential backoff
		}
	}

	log.WithFields(log.Fields{
		log.FieldComponent:  "controller",
		log.FieldOperation:  "NAAResolution",
		"resolution_status": "failure",
		"error_details":     lastErr.Error(),
	}).Warnf("NAA ID resolution failed after %d attempts; provisioning without affinity hint", NAAResolutionMaxRetries)
	return &NAAResolutionResult{
		Success:       false,
		FailureReason: lastErr.Error(),
	}, nil
}

// NAAResolutionConfig tracks NAA resolution enablement state per array
type NAAResolutionConfig struct {
	enabled        bool
	checkedVersion bool
}

var (
	naaConfigMu  sync.Mutex
	naaConfigMap = make(map[string]*NAAResolutionConfig)
)

// CheckFirmwareVersion checks if the PowerStore firmware supports NAA resolution.
// Results are cached per arrayID to support multi-array deployments correctly.
func CheckFirmwareVersion(ctx context.Context, client gopowerstore.Client, arrayID string) bool {
	naaConfigMu.Lock()
	defer naaConfigMu.Unlock()

	cfg, exists := naaConfigMap[arrayID]
	if exists && cfg.checkedVersion {
		return cfg.enabled
	}

	if cfg == nil {
		cfg = &NAAResolutionConfig{}
		naaConfigMap[arrayID] = cfg
	}

	version, err := client.GetSoftwareMajorMinorVersion(ctx)
	if err != nil {
		log.WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "FirmwareVersionCheck",
			log.FieldArrayID:   arrayID,
			"error_details":    err.Error(),
		}).Warnf("Firmware version detection failed; multi-appliance NAA resolution disabled")
		cfg.enabled = false
		cfg.checkedVersion = true
		return false
	}

	// Compare version (float32)
	if version >= MinFirmwareVersionForNAA {
		log.WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "FirmwareVersionCheck",
			log.FieldArrayID:   arrayID,
		}).Infof("PowerStore firmware %.1f detected; multi-appliance NAA resolution enabled", version)
		cfg.enabled = true
	} else {
		log.WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "FirmwareVersionCheck",
			log.FieldArrayID:   arrayID,
		}).Warnf("PowerStore firmware %.1f detected (< %.1f required); multi-appliance NAA resolution disabled",
			version, MinFirmwareVersionForNAA)
		cfg.enabled = false
	}
	cfg.checkedVersion = true
	return cfg.enabled
}

// ResetNAAConfig resets the NAA configuration for all arrays (for testing)
func ResetNAAConfig() {
	naaConfigMu.Lock()
	defer naaConfigMu.Unlock()
	naaConfigMap = make(map[string]*NAAResolutionConfig)
}

// resolveNAAForColocation is the main entry point for NAA resolution in CreateVolume
// It extracts NAA label, checks firmware version, and resolves NAA to volume ID.
// The arrayID parameter is used to cache firmware version results per array.
func resolveNAAForColocation(ctx context.Context, params map[string]string, client gopowerstore.Client, arrayID string) *NAAResolutionResult {
	pvcName := params[KeyCSIPVCName]

	// Extract NAA label from PVC labels
	naaID := extractNAALabelFromParams(params)
	if naaID == "" {
		// Check if label key exists but value is empty
		if _, exists := params[KeyAffinitySourceNAA]; exists {
			log.WithFields(log.Fields{
				log.FieldComponent:  "controller",
				log.FieldOperation:  "NAAResolution",
				"pvc_name":          pvcName,
				"resolution_status": "failure",
			}).Warnf("NAA label present but empty; provisioning without affinity hint")
			return &NAAResolutionResult{
				Success:       false,
				FailureReason: "empty NAA ID",
			}
		}
		// No NAA label present - this is normal for non-MTV volumes
		return nil
	}

	// Check firmware version (cached per array after first check)
	if !CheckFirmwareVersion(ctx, client, arrayID) {
		log.WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  "NAAResolution",
			"pvc_name":          pvcName,
			log.FieldArrayID:    arrayID,
			"resolution_status": "failure",
		}).Warnf("NAA label present but firmware < %.1f; provisioning without affinity hint", MinFirmwareVersionForNAA)
		return &NAAResolutionResult{
			Success:       false,
			FailureReason: "firmware version too old",
		}
	}

	// Resolve NAA to volume ID
	result, err := resolveNAAToVolumeID(ctx, client, naaID)
	if err != nil {
		log.WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  "NAAResolution",
			"pvc_name":          pvcName,
			"resolution_status": "failure",
			"error_details":     err.Error(),
		}).Warnf("NAA resolution error; provisioning without affinity hint")
		return &NAAResolutionResult{
			Success:       false,
			FailureReason: err.Error(),
		}
	}

	return result
}

// verifyPlacement queries the created target volume to determine actual appliance placement
// and compares it with the source appliance ID to determine if XCOPY is possible
func verifyPlacement(ctx context.Context, client gopowerstore.Client, targetVolumeID, sourceApplianceID string) *PlacementVerificationResult {
	if client == nil {
		return &PlacementVerificationResult{
			Outcome:           PlacementHostCopyFallback,
			SourceApplianceID: sourceApplianceID,
		}
	}

	if targetVolumeID == "" || sourceApplianceID == "" {
		return &PlacementVerificationResult{
			Outcome: PlacementVerificationFailed,
			Error:   nil,
		}
	}

	// Query target volume to get its appliance ID
	targetVolume, err := client.GetVolume(ctx, targetVolumeID)
	if err != nil {
		log.WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  "PlacementVerification",
			"target_volume_id":  targetVolumeID,
			"placement_outcome": "unknown",
			"error_details":     err.Error(),
		}).Warnf("Placement verification failed; volume created successfully but placement outcome unknown")
		return &PlacementVerificationResult{
			Outcome:           PlacementVerificationFailed,
			SourceApplianceID: sourceApplianceID,
			Error:             err,
		}
	}

	targetApplianceID := targetVolume.ApplianceID

	// Compare appliance IDs
	if targetApplianceID == sourceApplianceID {
		log.WithFields(log.Fields{
			log.FieldComponent:    "controller",
			log.FieldOperation:    "PlacementVerification",
			"target_volume_id":    targetVolumeID,
			"target_appliance_id": targetApplianceID,
			"source_appliance_id": sourceApplianceID,
			"placement_outcome":   "xcopy",
		}).Infof("Placement verification: target on same appliance as source (XCOPY-offload eligible)")
		return &PlacementVerificationResult{
			Outcome:           PlacementXCOPYSuccess,
			TargetApplianceID: targetApplianceID,
			SourceApplianceID: sourceApplianceID,
		}
	}

	log.WithFields(log.Fields{
		log.FieldComponent:    "controller",
		log.FieldOperation:    "PlacementVerification",
		"target_volume_id":    targetVolumeID,
		"target_appliance_id": targetApplianceID,
		"source_appliance_id": sourceApplianceID,
		"placement_outcome":   "host-copy",
	}).Infof("Placement verification: target on different appliance than source (host-copy required)")
	return &PlacementVerificationResult{
		Outcome:           PlacementHostCopyFallback,
		TargetApplianceID: targetApplianceID,
		SourceApplianceID: sourceApplianceID,
	}
}
