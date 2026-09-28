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

package collectors

import (
	"context"
	"fmt"
	"sync"
)

// SharedMetadataChecker forwards validation and protocol lookups to the current
// K8sMetadataChecker. It lets long-lived interceptors keep a stable resolver
// while metrics collector restarts replace the underlying Kubernetes informer.
type SharedMetadataChecker struct {
	mu      sync.RWMutex
	checker *K8sMetadataChecker
}

// Set updates the active metadata checker.
func (s *SharedMetadataChecker) Set(checker *K8sMetadataChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checker = checker
}

// Clear removes checker only if it is still the active checker.
func (s *SharedMetadataChecker) Clear(checker *K8sMetadataChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checker == checker {
		s.checker = nil
	}
}

func (s *SharedMetadataChecker) current() *K8sMetadataChecker {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.checker
}

// Available returns true when an active Kubernetes metadata checker is present.
func (s *SharedMetadataChecker) Available() bool {
	return s.current() != nil
}

// GetProtocol returns the protocol from the active checker, or unknown if none is active.
func (s *SharedMetadataChecker) GetProtocol(ctx context.Context, volumeID string) string {
	if checker := s.current(); checker != nil {
		return checker.GetProtocol(ctx, volumeID)
	}
	return "unknown"
}

// RefreshCache refreshes the active checker's cache.
func (s *SharedMetadataChecker) RefreshCache(ctx context.Context) error {
	if checker := s.current(); checker != nil {
		return checker.RefreshCache(ctx)
	}
	return fmt.Errorf("metadata checker unavailable")
}

// IsDriverManaged checks the active checker, failing closed when metadata is unavailable.
func (s *SharedMetadataChecker) IsDriverManaged(ctx context.Context, volumeID string) (bool, error) {
	if checker := s.current(); checker != nil {
		return checker.IsDriverManaged(ctx, volumeID)
	}
	return false, fmt.Errorf("metadata checker unavailable")
}

// IsDriverManagedByName checks the active checker by volume name, failing closed when metadata is unavailable.
func (s *SharedMetadataChecker) IsDriverManagedByName(ctx context.Context, volumeName string) (bool, error) {
	if checker := s.current(); checker != nil {
		return checker.IsDriverManagedByName(ctx, volumeName)
	}
	return false, fmt.Errorf("metadata checker unavailable")
}

// MarkDeleteComplete removes a deleted volume from the active checker cache.
func (s *SharedMetadataChecker) MarkDeleteComplete(volumeID string) {
	if checker := s.current(); checker != nil {
		checker.MarkDeleteComplete(volumeID)
	}
}

// MarkDeleteCompleteByName removes a deleted volume by name from the active checker cache.
func (s *SharedMetadataChecker) MarkDeleteCompleteByName(volumeName string) {
	if checker := s.current(); checker != nil {
		checker.MarkDeleteCompleteByName(volumeName)
	}
}

// GetAttachmentStateForVolumeID forwards to the active checker.
func (s *SharedMetadataChecker) GetAttachmentStateForVolumeID(ctx context.Context, volumeID string, globalID string) (bool, error) {
	if checker := s.current(); checker != nil {
		return checker.GetAttachmentStateForVolumeID(ctx, volumeID, globalID)
	}
	return false, fmt.Errorf("metadata checker unavailable")
}

// GetAttachmentStateForPVName forwards to the active checker.
func (s *SharedMetadataChecker) GetAttachmentStateForPVName(ctx context.Context, pvName string) (bool, error) {
	if checker := s.current(); checker != nil {
		return checker.GetAttachmentStateForPVName(ctx, pvName)
	}
	return false, fmt.Errorf("metadata checker unavailable")
}
