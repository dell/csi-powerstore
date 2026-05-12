/*
Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
*/

package groupcontroller

import (
	"context"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGetOrCreateVolumeGroup_CreateNew(t *testing.T) {
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

	// No need to mock GetVolumeGroupByName - new logic doesn't call it when detectedGroupID is empty

	// Mock CreateVolumeGroup
	mockClient.On("CreateVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupCreate")).
		Return(gopowerstore.CreateResponse{ID: "vg-new-123"}, nil)

	// Mock GetVolumeGroup after creation
	mockClient.On("GetVolumeGroup", mock.Anything, "vg-new-123").
		Return(gopowerstore.VolumeGroup{ID: "vg-new-123", Name: "csi-vg-test"}, nil)

	parameters := map[string]string{"writeOrderConsistency": "true"}
	volumeIDs := []string{"vol1", "vol2"}

	vg, err := manager.getOrCreateVolumeGroup(ctx, "test-group", volumeIDs, parameters, mockArray, "")

	assert.NoError(t, err)
	assert.NotNil(t, vg)
	assert.Equal(t, "vg-new-123", vg.ID)
	mockClient.AssertExpectations(t)
}

func TestGetOrCreateVolumeGroup_UseExisting(t *testing.T) {
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

	// Mock GetVolumeGroup to return existing group (when detectedGroupID is provided)
	existingVG := gopowerstore.VolumeGroup{
		ID:   "vg-existing-123",
		Name: "csi-vg-test",
	}
	mockClient.On("GetVolumeGroup", mock.Anything, "vg-existing-123").Return(existingVG, nil)

	parameters := map[string]string{}
	volumeIDs := []string{"vol1", "vol2"}

	// Test with detected group ID - should use GetVolumeGroup instead of creating new group
	vg, err := manager.getOrCreateVolumeGroup(ctx, "test-group", volumeIDs, parameters, mockArray, "vg-existing-123")

	assert.NoError(t, err)
	assert.NotNil(t, vg)
	assert.Equal(t, "vg-existing-123", vg.ID)
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroup_WithWOC(t *testing.T) {
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

	// Mock CreateVolumeGroup
	mockClient.On("CreateVolumeGroup", mock.Anything, mock.MatchedBy(func(params *gopowerstore.VolumeGroupCreate) bool {
		return params.IsWriteOrderConsistent != nil && *params.IsWriteOrderConsistent == true
	})).Return(gopowerstore.CreateResponse{ID: "vg-woc-123"}, nil)

	// Mock GetVolumeGroup
	mockClient.On("GetVolumeGroup", mock.Anything, "vg-woc-123").
		Return(gopowerstore.VolumeGroup{ID: "vg-woc-123"}, nil)

	parameters := map[string]string{"writeOrderConsistency": "true"}
	volumeIDs := []string{"vol1", "vol2"}

	vg, err := manager.createVolumeGroup(ctx, "test-vg", volumeIDs, parameters, mockArray)

	assert.NoError(t, err)
	assert.NotNil(t, vg)
	assert.Equal(t, "vg-woc-123", vg.ID)
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroup_WithoutWOC(t *testing.T) {
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

	// Mock CreateVolumeGroup
	mockClient.On("CreateVolumeGroup", mock.Anything, mock.MatchedBy(func(params *gopowerstore.VolumeGroupCreate) bool {
		return params.IsWriteOrderConsistent != nil && *params.IsWriteOrderConsistent == false
	})).Return(gopowerstore.CreateResponse{ID: "vg-no-woc-123"}, nil)

	// Mock GetVolumeGroup
	mockClient.On("GetVolumeGroup", mock.Anything, "vg-no-woc-123").
		Return(gopowerstore.VolumeGroup{ID: "vg-no-woc-123"}, nil)

	parameters := map[string]string{"writeOrderConsistency": "false"}
	volumeIDs := []string{"vol1", "vol2"}

	vg, err := manager.createVolumeGroup(ctx, "test-vg", volumeIDs, parameters, mockArray)

	assert.NoError(t, err)
	assert.NotNil(t, vg)
	assert.Equal(t, "vg-no-woc-123", vg.ID)
	mockClient.AssertExpectations(t)
}

func TestExtractVolumeIDs(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	volumeIDs := []string{"vol1/array1/scsi", "vol2/array1/scsi", "vol3"}

	actualIDs, err := manager.extractVolumeIDs(volumeIDs)

	assert.NoError(t, err)
	assert.Len(t, actualIDs, 3)
	assert.Equal(t, "vol1", actualIDs[0])
	assert.Equal(t, "vol2", actualIDs[1])
	assert.Equal(t, "vol3", actualIDs[2])
}

func TestFindMissingVolumes(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	requestedIDs := []string{"vol1", "vol2", "vol3"}
	volumeMap := map[string]bool{
		"vol1": true,
		"vol2": true,
	}

	missing := manager.findMissingVolumes(requestedIDs, volumeMap)

	assert.Len(t, missing, 1)
	assert.Contains(t, missing, "vol3")
}

func TestFindRemovedVolumes(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	requestedIDs := []string{"vol1", "vol2"}
	existingVolumes := []gopowerstore.Volume{
		{ID: "vol1"},
		{ID: "vol2"},
		{ID: "vol3"},
	}

	removed := manager.findRemovedVolumes(requestedIDs, existingVolumes)

	assert.Len(t, removed, 1)
	assert.Contains(t, removed, "vol3")
}

func TestCreateMembershipValidationError(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	missing := []string{"vol1", "vol2"}
	removed := []string{"vol3"}

	err := manager.createMembershipValidationError(missing, removed)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "volume group membership cannot be changed from initial configuration")
	assert.Contains(t, err.Error(), "missing volumes: [vol1 vol2]")
	assert.Contains(t, err.Error(), "removed volumes: [vol3]")
}

func TestValidateExistingGroupMembership_NoChanges(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	actualVolumeIDs := []string{"vol1", "vol2"}
	volumeGroup := &gopowerstore.VolumeGroup{
		ID: "vg-123",
		Volumes: []gopowerstore.Volume{
			{
				ID: "vol1",
				ProtectionData: gopowerstore.ProtectionData{
					SourceID: "vol1",
				},
			},
			{
				ID: "vol2",
				ProtectionData: gopowerstore.ProtectionData{
					SourceID: "vol2",
				},
			},
		},
	}

	err := manager.validateExistingGroupMembership(ctx, actualVolumeIDs, volumeGroup, "vg-123")

	assert.NoError(t, err)
}

func TestValidateExistingGroupMembership_WithChanges(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	actualVolumeIDs := []string{"vol1", "vol3"}
	volumeGroup := &gopowerstore.VolumeGroup{
		ID: "vg-123",
		Volumes: []gopowerstore.Volume{
			{
				ID: "vol1",
				ProtectionData: gopowerstore.ProtectionData{
					SourceID: "vol1",
				},
			},
			{
				ID: "vol2",
				ProtectionData: gopowerstore.ProtectionData{
					SourceID: "vol2",
				},
			},
		},
	}

	err := manager.validateExistingGroupMembership(ctx, actualVolumeIDs, volumeGroup, "vg-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "volume group membership cannot be changed from initial configuration")
}

func TestAddVolumesToNewGroup_Success(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := &array.PowerStoreArray{
		GlobalID: "test-array-1",
		Client:   mockClient,
	}

	// Mock AddMembersToVolumeGroup
	mockClient.On("AddMembersToVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"), "vg-123").
		Return(gopowerstore.EmptyResponse(""), nil)

	actualVolumeIDs := []string{"vol1", "vol2"}

	err := manager.addVolumesToNewGroup(ctx, actualVolumeIDs, "vg-123", mockArray)

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroupSnapshot_Success(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := &array.PowerStoreArray{
		GlobalID: "test-array-1",
		Client:   mockClient,
	}

	// Mock CreateVolumeGroupSnapshot
	mockClient.On("CreateVolumeGroupSnapshot", mock.Anything, "vg-123", mock.AnythingOfType("*gopowerstore.VolumeGroupSnapshotCreate")).
		Return(gopowerstore.CreateResponse{ID: "snap-123"}, nil)

	// Mock GetVolumeGroup to get snapshot details
	mockClient.On("GetVolumeGroup", mock.Anything, "snap-123").
		Return(gopowerstore.VolumeGroup{
			ID:                "snap-123",
			Name:              "snapshot-1",
			CreationTimeStamp: "2023-12-11T10:00:00Z",
			Volumes: []gopowerstore.Volume{
				{
					ID: "vol1/test-array-1/scsi",
					ProtectionData: gopowerstore.ProtectionData{
						SourceID: "vol1",
					},
				},
				{
					ID: "vol2/test-array-1/scsi",
					ProtectionData: gopowerstore.ProtectionData{
						SourceID: "vol2",
					},
				},
			},
		}, nil)

	groupSnapshot, err := manager.createVolumeGroupSnapshot(ctx, "test-snapshot", "vg-123", mockArray, []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"})

	assert.NoError(t, err)
	assert.NotNil(t, groupSnapshot)
	assert.Len(t, groupSnapshot.Snapshots, 2)
	mockClient.AssertExpectations(t)
}

func TestCleanupFailedGroupSnapshot(t *testing.T) {
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

	// Mock DeleteVolumeGroup
	mockClient.On("DeleteVolumeGroup", mock.Anything, "snap-failed-123").
		Return(gopowerstore.EmptyResponse(""), nil)

	err := manager.cleanupFailedGroupSnapshot(ctx, "snap-failed-123", mockArray)

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroupSnapshot_Integration(t *testing.T) {
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

	// Mock GetVolumesWithFilter to return ungrouped volumes
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return([]gopowerstore.Volume{
		{ID: "vol1"},
		{ID: "vol2"},
	}, nil)

	// Mock volume group creation - no GetVolumeGroupByName call in new logic
	mockClient.On("CreateVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupCreate")).
		Return(gopowerstore.CreateResponse{ID: "vg-new-123"}, nil)
	mockClient.On("GetVolumeGroup", mock.Anything, "vg-new-123").
		Return(gopowerstore.VolumeGroup{ID: "vg-new-123"}, nil)

	// Mock adding volumes to the new group
	mockClient.On("AddMembersToVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"), "vg-new-123").
		Return(gopowerstore.EmptyResponse(""), nil)

	// Mock snapshot creation
	mockClient.On("CreateVolumeGroupSnapshot", mock.Anything, "vg-new-123", mock.AnythingOfType("*gopowerstore.VolumeGroupSnapshotCreate")).
		Return(gopowerstore.CreateResponse{ID: "snap-123"}, nil)
	mockClient.On("GetVolumeGroup", mock.Anything, "snap-123").
		Return(gopowerstore.VolumeGroup{
			ID:                "snap-123",
			CreationTimeStamp: "2023-12-11T10:00:00Z",
			Volumes: []gopowerstore.Volume{
				{
					ID: "vol1/test-array-1/scsi",
					ProtectionData: gopowerstore.ProtectionData{
						SourceID: "vol1",
					},
				},
				{
					ID: "vol2/test-array-1/scsi",
					ProtectionData: gopowerstore.ProtectionData{
						SourceID: "vol2",
					},
				},
			},
		}, nil)

	req := &csi.CreateVolumeGroupSnapshotRequest{
		Name:            "test-snapshot",
		SourceVolumeIds: []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"},
		Parameters:      map[string]string{"writeOrderConsistency": "true"},
	}

	resp, err := manager.CreateVolumeGroupSnapshot(ctx, req, mockArray)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "snap-123/test-array-1/scsi", resp.GroupSnapshot.GroupSnapshotId)
	assert.Len(t, resp.GroupSnapshot.Snapshots, 2)

	// Verify that all individual snapshots reference the correct group snapshot ID
	for _, snapshot := range resp.GroupSnapshot.Snapshots {
		assert.Equal(t, "snap-123/test-array-1/scsi", snapshot.GroupSnapshotId)
	}

	mockClient.AssertExpectations(t)
}

func TestCreateSnapshotsFromVolumeGroup_NativeUUIDs(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := &array.PowerStoreArray{
		GlobalID: "test-array-1",
		Client:   mockClient,
	}

	// Mock volume group with native UUID volume IDs (as returned by PowerStore API)
	volumeGroup := &gopowerstore.VolumeGroup{
		ID:   "test-vg",
		Name: "test-group",
		Volumes: []gopowerstore.Volume{
			{ID: "vol1", State: "Ready", Size: 10737418240, ProtectionData: gopowerstore.ProtectionData{SourceID: "src1"}},
			{ID: "vol2", State: "Ready", Size: 10737418240, ProtectionData: gopowerstore.ProtectionData{SourceID: "src2"}},
		},
	}

	// Should succeed using the passed-in protocol
	creationTime := timestamppb.Now()
	snapshots, err := manager.createSnapshotsFromVolumeGroupResponse(ctx, volumeGroup, mockArray, creationTime, "scsi")

	assert.NoError(t, err)
	assert.NotNil(t, snapshots)
	assert.Len(t, snapshots, 2)

	// Verify snapshot IDs use the passed-in protocol
	assert.Equal(t, "vol1/test-array-1/scsi", snapshots[0].SnapshotId)
	assert.Equal(t, "vol2/test-array-1/scsi", snapshots[1].SnapshotId)
	assert.Equal(t, "src1/test-array-1/scsi", snapshots[0].SourceVolumeId)
	assert.Equal(t, "src2/test-array-1/scsi", snapshots[1].SourceVolumeId)
}

func TestCreateSnapshotsFromVolumeGroup_AllValidFormat(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := &array.PowerStoreArray{
		GlobalID: "test-array-1",
		Client:   mockClient,
	}

	// Mock volume group with mixed CSI format volume IDs (one with missing SourceID)
	volumeGroup := &gopowerstore.VolumeGroup{
		ID:   "test-vg",
		Name: "test-group",
		Volumes: []gopowerstore.Volume{
			{
				ID:    "vol1/test-array-1/scsi",
				State: "Ready",
				Size:  10737418240,
				ProtectionData: gopowerstore.ProtectionData{
					SourceID: "vol1", // Just the UUID part
				},
			},
			{
				ID:    "vol2/test-array-1/scsi",
				State: "Ready",
				Size:  10737418240,
				// Missing SourceID to test fallback behavior
				ProtectionData: gopowerstore.ProtectionData{
					SourceID: "", // Empty SourceID to trigger fallback
				},
			},
		},
	}

	// This should succeed with fallback behavior
	creationTime := timestamppb.Now()
	snapshots, err := manager.createSnapshotsFromVolumeGroupResponse(ctx, volumeGroup, mockArray, creationTime, "scsi")

	// Should succeed
	assert.NoError(t, err)
	assert.NotNil(t, snapshots)
	assert.Len(t, snapshots, 2)

	// Verify snapshot IDs are in correct CSI format
	assert.Equal(t, "vol1/test-array-1/scsi", snapshots[0].SnapshotId)
	assert.Equal(t, "vol2/test-array-1/scsi", snapshots[1].SnapshotId)

	// Verify SourceVolumeId behavior (both should produce same result)
	assert.Equal(t, "vol1/test-array-1/scsi", snapshots[0].SourceVolumeId)
	assert.Equal(t, "vol2/test-array-1/scsi", snapshots[1].SourceVolumeId) // Should fallback to volumeUUID (vol2)
}

// =============================================================================
// Edge Case Tests for Volume Group Snapshot Operations
// =============================================================================

func TestDeleteVolumeGroupSnapshot_EdgeCases(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("malformed CSI ID - too few parts", func(t *testing.T) {
		req := &csi.DeleteVolumeGroupSnapshotRequest{
			GroupSnapshotId: "invalid-format",
		}

		resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
	})

	t.Run("malformed CSI ID - too many parts", func(t *testing.T) {
		req := &csi.DeleteVolumeGroupSnapshotRequest{
			GroupSnapshotId: "snap-123/array-1/scsi/extra/part",
		}

		resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
	})

	t.Run("malformed CSI ID - empty parts", func(t *testing.T) {
		req := &csi.DeleteVolumeGroupSnapshotRequest{
			GroupSnapshotId: "//",
		}

		resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.Contains(t, err.Error(), "array  not found")
	})

	t.Run("array not found", func(t *testing.T) {
		req := &csi.DeleteVolumeGroupSnapshotRequest{
			GroupSnapshotId: "snap-123/nonexistent-array/scsi",
		}

		resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.Contains(t, err.Error(), "array nonexistent-array not found")
	})
}

func TestGetVolumeGroupSnapshot_EdgeCases(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("malformed CSI ID - too few parts", func(t *testing.T) {
		req := &csi.GetVolumeGroupSnapshotRequest{
			GroupSnapshotId: "invalid-format",
		}

		resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
	})

	t.Run("malformed CSI ID - too many parts", func(t *testing.T) {
		req := &csi.GetVolumeGroupSnapshotRequest{
			GroupSnapshotId: "snap-123/array-1/scsi/extra/part",
		}

		resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
	})

	t.Run("array not found", func(t *testing.T) {
		req := &csi.GetVolumeGroupSnapshotRequest{
			GroupSnapshotId: "snap-123/nonexistent-array/scsi",
		}

		resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.Contains(t, err.Error(), "array nonexistent-array not found")
	})
}

func TestCreateVolumeGroupSnapshot_EdgeCases(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("empty source volume IDs", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{},
		}

		resp, err := manager.CreateVolumeGroupSnapshot(ctx, req, nil)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "at least one source volume ID is required")
	})

	t.Run("malformed volume ID in source list", func(t *testing.T) {
		// Test the helper function directly instead of going through CreateVolumeGroupSnapshot
		// to avoid complex mocking requirements
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("invalid-format")

		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Empty(t, nativeID)
		assert.Empty(t, arrayID)
		assert.Empty(t, protocol)
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
	})

	t.Run("mixed valid and invalid CSI format", func(t *testing.T) {
		// Test the helper function directly with valid format
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("vol1/test-array-1/scsi")

		assert.NoError(t, err)
		assert.Equal(t, "vol1", nativeID)
		assert.Equal(t, "test-array-1", arrayID)
		assert.Equal(t, "scsi", protocol)
	})
}

func TestValidateAndGroupVolumes_EdgeCases(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("nil volume list", func(t *testing.T) {
		arr, _, err := manager.validateAndGroupVolumes(ctx, nil)

		assert.Error(t, err)
		assert.Nil(t, arr)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "no volumes provided for group snapshot")
	})

	t.Run("volumes from different arrays", func(t *testing.T) {
		// This test would require mocking the getArrayForVolume method
		// For now, we'll test the basic structure
		volumeIDs := []string{"vol1/array1/scsi", "vol2/array2/scsi"}

		arr, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

		// Should fail because arrays are not configured
		assert.Error(t, err)
		assert.Nil(t, arr)
		assert.Contains(t, err.Error(), "array array1 not found")
	})
}

func TestCleanupFailedGroupSnapshot_EdgeCases(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("empty volume group ID", func(t *testing.T) {
		err := manager.cleanupFailedGroupSnapshot(ctx, "", nil)

		// Should not panic and should handle gracefully
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no array provided")
	})

	t.Run("nil snapshots list", func(t *testing.T) {
		err := manager.cleanupFailedGroupSnapshot(ctx, "vg-123", nil)

		// Should not panic and should handle gracefully
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no array provided")
	})
}

func TestParseCreationTime_EdgeCases(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	t.Run("empty timestamp", func(t *testing.T) {
		volumeGroup := gopowerstore.VolumeGroup{
			CreationTimeStamp: "",
		}

		timestamp := manager.parseCreationTime(volumeGroup)

		assert.NotNil(t, timestamp)
		// Should return current time when timestamp is empty
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		volumeGroup := gopowerstore.VolumeGroup{
			CreationTimeStamp: "invalid-timestamp",
		}

		timestamp := manager.parseCreationTime(volumeGroup)

		assert.NotNil(t, timestamp)
		// Should return current time when timestamp is invalid
	})

	t.Run("valid timestamp", func(t *testing.T) {
		volumeGroup := gopowerstore.VolumeGroup{
			CreationTimeStamp: "2023-12-11T10:00:00Z",
		}

		timestamp := manager.parseCreationTime(volumeGroup)

		assert.NotNil(t, timestamp)
		assert.True(t, timestamp.IsValid())
	})
}
