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

package collectors

import (
	"context"
)

// VolumeMetadataProvider extends VolumeValidator and ProtocolResolver
// to provide PV name mapping and attachment state lookup
type VolumeMetadataProvider interface {
	VolumeValidator
	ProtocolResolver

	// GetAttachmentStateForVolumeID returns the attachment state for a given volume ID
	// The globalID is used to validate that the volume belongs to the correct array (multi-array safety)
	GetAttachmentStateForVolumeID(ctx context.Context, volumeID string, globalID string) (bool, error)

	// GetAttachmentStateForPVName returns the attachment state for a given PV name
	// This is used for file systems where fs.Name is the PV name
	GetAttachmentStateForPVName(ctx context.Context, pvName string) (bool, error)
}

// VolumeValidator is the interface for validating whether a volume should be included in metrics
type VolumeValidator interface {
	// IsDriverManaged checks if a volume is managed by the CSI driver
	IsDriverManaged(ctx context.Context, volumeID string) (bool, error)
	// IsDriverManagedByName checks if a volume name is managed by the CSI driver
	// This is used for file system matching where file system names match PV names
	IsDriverManagedByName(ctx context.Context, volumeName string) (bool, error)
	// RefreshCache refreshes the cache of driver-managed volumes
	RefreshCache(ctx context.Context) error
	// Available returns true if the validator is available for use
	Available() bool
	// MarkDeleteComplete marks a volume as deleted and removes it from cache
	MarkDeleteComplete(volumeID string)
	// MarkDeleteCompleteByName marks a volume as deleted by name
	MarkDeleteCompleteByName(volumeName string)
}

// NoopVolumeValidator is a no-op implementation that accepts all volumes
type NoopVolumeValidator struct{}

// IsDriverManaged always returns true for NoopVolumeValidator
func (v *NoopVolumeValidator) IsDriverManaged(_ context.Context, _ string) (bool, error) {
	return true, nil
}

// IsDriverManagedByName always returns true for NoopVolumeValidator
func (v *NoopVolumeValidator) IsDriverManagedByName(_ context.Context, _ string) (bool, error) {
	return true, nil
}

// RefreshCache is a no-op for NoopVolumeValidator
func (v *NoopVolumeValidator) RefreshCache(_ context.Context) error {
	return nil
}

// Available returns false for NoopVolumeValidator
func (v *NoopVolumeValidator) Available() bool {
	return false
}

// MarkDeleteComplete is a no-op for NoopVolumeValidator
func (v *NoopVolumeValidator) MarkDeleteComplete(_ string) {
	// No-op implementation for testing
}

// MarkDeleteCompleteByName is a no-op for NoopVolumeValidator
func (v *NoopVolumeValidator) MarkDeleteCompleteByName(_ string) {
	// No-op implementation for testing
}

// ProtocolResolver is the interface for resolving a volume ID to its actual protocol
// This uses Kubernetes PV VolumeAttributes as the single source of truth
type ProtocolResolver interface {
	// GetProtocol returns the actual protocol string for a volume (e.g., "iSCSI", "FC", "NVMeTCP", "NVMeFC", "nfs")
	// Returns "unknown" if the protocol cannot be determined
	GetProtocol(ctx context.Context, volumeID string) string
	// RefreshCache refreshes the cache of volume protocols
	RefreshCache(ctx context.Context) error
}

// NoopProtocolResolver is a no-op implementation that always returns "unknown"
type NoopProtocolResolver struct{}

// GetProtocol always returns "unknown" for NoopProtocolResolver
func (r *NoopProtocolResolver) GetProtocol(_ context.Context, _ string) string {
	return "unknown"
}

// RefreshCache is a no-op for NoopProtocolResolver
func (r *NoopProtocolResolver) RefreshCache(_ context.Context) error {
	return nil
}

// NoopVolumeMetadataProvider is a no-op implementation that accepts all volumes
// and returns detached for attachment state
type NoopVolumeMetadataProvider struct{}

func (n *NoopVolumeMetadataProvider) RefreshCache(_ context.Context) error {
	return nil
}

func (n *NoopVolumeMetadataProvider) IsDriverManaged(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func (n *NoopVolumeMetadataProvider) IsDriverManagedByName(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func (n *NoopVolumeMetadataProvider) GetProtocol(_ context.Context, _ string) string {
	return "unknown"
}

func (n *NoopVolumeMetadataProvider) Available() bool {
	return false
}

func (n *NoopVolumeMetadataProvider) MarkDeleteComplete(_ string) {
	// No-op implementation for testing
}

func (n *NoopVolumeMetadataProvider) MarkDeleteCompleteByName(_ string) {
	// No-op implementation for testing
}

func (n *NoopVolumeMetadataProvider) GetAttachmentStateForVolumeID(_ context.Context, _ string, _ string) (bool, error) {
	return false, nil
}

func (n *NoopVolumeMetadataProvider) GetAttachmentStateForPVName(_ context.Context, _ string) (bool, error) {
	return false, nil
}
