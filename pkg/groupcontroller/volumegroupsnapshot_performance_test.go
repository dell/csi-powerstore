/*
Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
*/

package groupcontroller

import (
	"context"
	"fmt"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// =============================================================================
// PERFORMANCE TESTS - API CALL COUNTING
// =============================================================================
// These tests verify the optimized approach uses a single GetVolumesWithFilter call

// TestValidateAndGroupVolumes_OptimizedGrouped tests the full optimized workflow for grouped volumes
func TestValidateAndGroupVolumes_OptimizedGrouped(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := &array.PowerStoreArray{
		GlobalID: "test-array-1",
		Client:   mockClient,
	}

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	// Mock GetVolumesWithFilter to return all 10 volumes in the same group (1 call)
	var volumes []gopowerstore.Volume
	for i := 1; i <= 10; i++ {
		volumes = append(volumes, gopowerstore.Volume{
			ID:          fmt.Sprintf("vol%d", i),
			VolumeGroup: []gopowerstore.VolumeGroup{{ID: "vg-123"}},
		})
	}
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return(volumes, nil).Once()

	var volumeIDs []string
	for i := 1; i <= 10; i++ {
		volumeIDs = append(volumeIDs, fmt.Sprintf("vol%d/test-array-1/scsi", i))
	}
	resultArrays, groupID, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.NoError(t, err)
	assert.NotNil(t, resultArrays)
	assert.Equal(t, "vg-123", groupID)
	mockClient.AssertExpectations(t)

	// Verify: Only 1 API call made for all 10 volumes
	mockClient.AssertNumberOfCalls(t, "GetVolumesWithFilter", 1)

	t.Logf("Optimized approach: 1 API call (GetVolumesWithFilter) for 10 volumes")
}

// TestValidateAndGroupVolumes_OptimizedUngrouped tests the full optimized workflow for ungrouped volumes
func TestValidateAndGroupVolumes_OptimizedUngrouped(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := &array.PowerStoreArray{
		GlobalID: "test-array-1",
		Client:   mockClient,
	}

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	// Mock GetVolumesWithFilter to return 5 ungrouped volumes (1 call)
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return([]gopowerstore.Volume{
		{ID: "vol1"},
		{ID: "vol2"},
		{ID: "vol3"},
		{ID: "vol4"},
		{ID: "vol5"},
	}, nil).Once()

	volumeIDs := []string{
		"vol1/test-array-1/scsi",
		"vol2/test-array-1/scsi",
		"vol3/test-array-1/scsi",
		"vol4/test-array-1/scsi",
		"vol5/test-array-1/scsi",
	}
	resultArrays, groupID, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.NoError(t, err)
	assert.NotNil(t, resultArrays)
	assert.Empty(t, groupID)
	mockClient.AssertExpectations(t)

	// Verify: Only 1 API call made for all 5 volumes
	mockClient.AssertNumberOfCalls(t, "GetVolumesWithFilter", 1)

	t.Logf("Optimized approach: 1 API call (GetVolumesWithFilter) for 5 ungrouped volumes")
}

// TestValidateAndGroupVolumes_MixedState tests detection of mixed grouped/ungrouped volumes
func TestValidateAndGroupVolumes_MixedState(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := &array.PowerStoreArray{
		GlobalID: "test-array-1",
		Client:   mockClient,
	}

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	// Mock GetVolumesWithFilter: vol1 and vol2 ungrouped, vol3 in a group
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return([]gopowerstore.Volume{
		{ID: "vol1"},
		{ID: "vol2"},
		{ID: "vol3", VolumeGroup: []gopowerstore.VolumeGroup{{ID: "vg-123"}}},
	}, nil).Once()

	volumeIDs := []string{
		"vol1/test-array-1/scsi",
		"vol2/test-array-1/scsi",
		"vol3/test-array-1/scsi",
	}
	_, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "some volumes are in volume group vg-123 while others are not in any group")
	mockClient.AssertExpectations(t)

	// Verify: Only 1 API call made even for error detection
	mockClient.AssertNumberOfCalls(t, "GetVolumesWithFilter", 1)
}
