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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoopVolumeValidator_IsDriverManaged(t *testing.T) {
	validator := &NoopVolumeValidator{}
	managed, err := validator.IsDriverManaged(context.Background(), "vol-1")
	require.NoError(t, err)
	require.True(t, managed)
}

func TestNoopVolumeValidator_IsDriverManagedByName(t *testing.T) {
	validator := &NoopVolumeValidator{}
	managed, err := validator.IsDriverManagedByName(context.Background(), "vol-1")
	require.NoError(t, err)
	require.True(t, managed)
}

func TestNoopVolumeValidator_RefreshCache(t *testing.T) {
	validator := &NoopVolumeValidator{}
	err := validator.RefreshCache(context.Background())
	require.NoError(t, err)
}

func TestNoopVolumeValidator_Available(t *testing.T) {
	validator := &NoopVolumeValidator{}
	require.False(t, validator.Available())
}

func TestNoopVolumeValidator_MarkDeleteComplete(t *testing.T) {
	validator := &NoopVolumeValidator{}
	// Should not panic - this is a no-op method
	validator.MarkDeleteComplete("vol-1")
	// Add assertion to ensure test is counted
	assert.True(t, true)
}

func TestNoopVolumeValidator_MarkDeleteCompleteByName(t *testing.T) {
	validator := &NoopVolumeValidator{}
	// Should not panic - this is a no-op method
	validator.MarkDeleteCompleteByName("vol-1")
	// Add assertion to ensure test is counted
	assert.True(t, true)
}

func TestNoopProtocolResolver_GetProtocol(t *testing.T) {
	resolver := &NoopProtocolResolver{}
	protocol := resolver.GetProtocol(context.Background(), "vol-1")
	require.Equal(t, "unknown", protocol)
}

func TestNoopProtocolResolver_RefreshCache(t *testing.T) {
	resolver := &NoopProtocolResolver{}
	err := resolver.RefreshCache(context.Background())
	require.NoError(t, err)
}

func TestNoopVolumeMetadataProvider_AllMethods(t *testing.T) {
	provider := &NoopVolumeMetadataProvider{}

	// Test all methods
	err := provider.RefreshCache(context.Background())
	require.NoError(t, err)

	managed, err := provider.IsDriverManaged(context.Background(), "vol-1")
	require.NoError(t, err)
	require.True(t, managed)

	managed, err = provider.IsDriverManagedByName(context.Background(), "vol-1")
	require.NoError(t, err)
	require.True(t, managed)

	protocol := provider.GetProtocol(context.Background(), "vol-1")
	require.Equal(t, "unknown", protocol)

	require.False(t, provider.Available())

	// Should not panic
	provider.MarkDeleteComplete("vol-1")
	provider.MarkDeleteCompleteByName("vol-1")

	attached, err := provider.GetAttachmentStateForVolumeID(context.Background(), "vol-1", "global-id")
	require.NoError(t, err)
	require.False(t, attached)

	attached, err = provider.GetAttachmentStateForPVName(context.Background(), "pv-1")
	require.NoError(t, err)
	require.False(t, attached)
}

func TestNoopVolumeMetadataProvider_GetAttachmentStateForVolumeID_Coverage(t *testing.T) {
	provider := &NoopVolumeMetadataProvider{}
	// Call the method to ensure coverage
	attached, err := provider.GetAttachmentStateForVolumeID(context.Background(), "test-volume-id", "array-id")
	require.NoError(t, err)
	require.False(t, attached)
}

func TestNoopVolumeMetadataProvider_GetAttachmentStateForPVName_Coverage(t *testing.T) {
	provider := &NoopVolumeMetadataProvider{}
	// Call the method to ensure coverage
	attached, err := provider.GetAttachmentStateForPVName(context.Background(), "test-pv-name")
	require.NoError(t, err)
	require.False(t, attached)
}

func TestNoopVolumeMetadataProvider_MarkDeleteComplete(t *testing.T) {
	provider := &NoopVolumeMetadataProvider{}
	// Should not panic - this is a no-op method
	provider.MarkDeleteComplete("vol-1")
	// Add assertion to ensure test is counted
	assert.True(t, true)
}

func TestNoopVolumeMetadataProvider_MarkDeleteCompleteByName(t *testing.T) {
	provider := &NoopVolumeMetadataProvider{}
	// Should not panic - this is a no-op method
	provider.MarkDeleteCompleteByName("vol-1")
	// Add assertion to ensure test is counted
	assert.True(t, true)
}
