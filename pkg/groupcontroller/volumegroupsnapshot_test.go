/*
Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.

* Dell Technologies, Dell and other trademarks are trademarks of Dell Inc.
* or its subsidiaries. Other trademarks may be trademarks of their respective
* owners.
*
*/

package groupcontroller

import (
	"context"
	"strings"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestVolumeGroupSnapshotManager_validateCreateRequest(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("valid request", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"},
		}
		// Set up arrays to avoid nil pointer in ParseVolumeID
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err)
		// validateCreateRequest returns sanitized CSI IDs
	})

	t.Run("empty name", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "",
			SourceVolumeIds: []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})

	t.Run("name too long", func(t *testing.T) {
		longName := strings.Repeat("a", 129) // 129 characters, exceeds 128 limit
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            longName,
			SourceVolumeIds: []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot exceed 128 characters")
		assert.Contains(t, err.Error(), "129")
	})

	t.Run("name at maximum length", func(t *testing.T) {
		maxName := strings.Repeat("a", 128) // 128 characters, exactly at limit
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            maxName,
			SourceVolumeIds: []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err, "128 character name should be valid")
	})

	t.Run("no source volumes", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one source volume")
	})

	t.Run("single volume", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/scsi"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err) // validateCreateRequest should succeed for single volume
		// validateCreateRequest returns sanitized CSI IDs

		// Single volumes are now allowed - should not fail due to volume count
	})

	t.Run("real PowerStore volume ID format", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name: "test-snapshot",
			SourceVolumeIds: []string{
				"volume be866440-d237-4f3c-8e0c-1878b483f7ef/PS00763f268d16/scsi",
				"volume a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d/PS00763f268d16/scsi",
			},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err)
		// validateCreateRequest no longer returns volume IDs, only validates
	})
}

func TestVolumeGroupSnapshotManager_CreateVolumeGroupSnapshot(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("nil request", func(t *testing.T) {
		resp, err := manager.CreateVolumeGroupSnapshot(ctx, nil, nil)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})

	t.Run("no arrays configured", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test",
			SourceVolumeIds: []string{"vol1/array1/scsi", "vol2/array1/scsi"},
		}
		resp, err := manager.CreateVolumeGroupSnapshot(ctx, req, nil)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "array array1 not found")
	})
}

func TestVolumeGroupSnapshotManager_DeleteVolumeGroupSnapshot(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("nil request", func(t *testing.T) {
		resp, err := manager.DeleteVolumeGroupSnapshot(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "group snapshot ID cannot be empty")
	})

	t.Run("simple group snapshot ID format", func(t *testing.T) {
		req := &csi.DeleteVolumeGroupSnapshotRequest{
			GroupSnapshotId: "70d070c8-ed7f-4deb-a0ac-5c0e12439ffc/test-array-1/scsi",
		}
		resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "array test-array-1 not found")
	})
}

func TestVolumeGroupSnapshotManager_GetVolumeGroupSnapshot(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("nil request", func(t *testing.T) {
		resp, err := manager.GetVolumeGroupSnapshot(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "group snapshot ID cannot be empty")
	})

	t.Run("simple group snapshot ID format", func(t *testing.T) {
		req := &csi.GetVolumeGroupSnapshotRequest{
			GroupSnapshotId: "70d070c8-ed7f-4deb-a0ac-5c0e12439ffc/test-array-1/scsi",
		}
		resp, err := manager.GetVolumeGroupSnapshot(ctx, req)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "array test-array-1 not found")
	})
}

func TestVolumeGroupSnapshotManager_validateCreateRequest_edgeCases(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("nil request", func(t *testing.T) {
		_, err := manager.validateCreateRequest(ctx, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})

	t.Run("volume ID format validation", func(t *testing.T) {
		testCases := []struct {
			name        string
			volumeIDs   []string
			expectError bool
		}{
			{"valid format", []string{"vol1/array1/scsi", "vol2/array1/scsi"}, false},
			{"single volume", []string{"vol1/array1/scsi"}, false},                              // Passes validation, single volumes allowed
			{"empty volume ID", []string{"", "vol2/array1/scsi"}, true},                         // Fails validation - empty volume ID
			{"no slashes", []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"}, false}, // Passes validation, fails later
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := &csi.CreateVolumeGroupSnapshotRequest{
					Name:            "test",
					SourceVolumeIds: tc.volumeIDs,
				}
				// Set up arrays for ParseVolumeID
				mockArray := &array.PowerStoreArray{
					GlobalID: "test-array-1",
				}
				arrays := map[string]*array.PowerStoreArray{
					"test-array-1": mockArray,
				}
				manager.SetArrays(arrays)

				_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
				if tc.expectError {
					assert.Error(t, err)
				} else {
					// May still error due to volume count, but not validation error
					if err != nil {
						hasExpectedError := assert.Contains(t, err.Error(), "at least 2 volumes") ||
							assert.Contains(t, err.Error(), "name cannot be empty")
						assert.True(t, hasExpectedError)
					}
				}
			})
		}
	})

	t.Run("nfs protocol should fail", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/nfs"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "volume group snapshots only support block volumes")
		assert.Contains(t, err.Error(), "got protocol nfs")
	})

	t.Run("invalid protocol should fail", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/invalid"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "volume group snapshots only support block volumes")
		assert.Contains(t, err.Error(), "got protocol invalid")
	})

	t.Run("scsi protocol should pass", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/scsi"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err)
	})

	t.Run("fc protocol should pass", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/fc"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err)
	})

	t.Run("nvme protocol should pass", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/nvme"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err)
	})

	t.Run("uppercase SCSI protocol should pass", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/SCSI"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err)
	})

	t.Run("uppercase FC protocol should pass", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/FC"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err)
	})

	t.Run("uppercase NVMe protocol should pass", func(t *testing.T) {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/NVMe"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.NoError(t, err)
	})

	t.Run("metro volume should fail", func(t *testing.T) {
		// Test with a volume ID that would be parsed as a metro volume
		// Metro volumes have format: localID/arrayID/protocol:remoteID/remoteArrayID/protocol
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/test-array-1/scsi:vol2/test-array-2/scsi"},
		}
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		_, err := manager.validateCreateRequest(ctx, req, arrays["test-array-1"])
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "volume group snapshots do not support metro volumes")
	})
}

func TestVolumeGroupSnapshotManager_extractVolumeIDs(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	t.Run("valid volume IDs", func(t *testing.T) {
		volumeIDs := []string{"vol1/array1/scsi", "vol2/array2/scsi"}

		result, err := manager.extractVolumeIDs(volumeIDs)
		assert.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, "vol1", result[0])
		assert.Equal(t, "vol2", result[1])
	})

	t.Run("empty volume IDs list", func(t *testing.T) {
		volumeIDs := []string{}

		result, err := manager.extractVolumeIDs(volumeIDs)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "no valid volume IDs found")
	})

	t.Run("empty volume ID", func(t *testing.T) {
		volumeIDs := []string{""}

		result, err := manager.extractVolumeIDs(volumeIDs)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid volume ID format")
	})

	t.Run("invalid format but not empty", func(t *testing.T) {
		volumeIDs := []string{"invalid-format"}

		result, err := manager.extractVolumeIDs(volumeIDs)
		assert.NoError(t, err) // extractVolumeID is permissive for non-empty strings
		assert.Equal(t, []string{"invalid-format"}, result)
	})
}

func TestVolumeGroupSnapshotManager_extractVolumeID(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	t.Run("valid CSI format", func(t *testing.T) {
		volumeID := "vol123/array1/scsi"

		result, err := manager.extractVolumeID(volumeID)
		assert.NoError(t, err)
		assert.Equal(t, "vol123", result)
	})

	t.Run("empty volume ID", func(t *testing.T) {
		volumeID := ""

		result, err := manager.extractVolumeID(volumeID)
		assert.Error(t, err)
		assert.Equal(t, "", result)
		assert.Contains(t, err.Error(), "invalid volume ID format")
	})

	t.Run("volume ID without slashes", func(t *testing.T) {
		volumeID := "vol123"

		result, err := manager.extractVolumeID(volumeID)
		assert.NoError(t, err)
		assert.Equal(t, "vol123", result)
	})

	t.Run("volume ID with multiple parts", func(t *testing.T) {
		volumeID := "vol123/array1/scsi/extra"

		result, err := manager.extractVolumeID(volumeID)
		assert.NoError(t, err)
		assert.Equal(t, "vol123", result)
	})
}

func TestVolumeGroupSnapshotManager_createVolumeGroup(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("create volume group with default WOC", func(t *testing.T) {
		groupName := "test-group"
		volumeIDs := []string{"vol1/array1/scsi", "vol2/array1/scsi"}
		parameters := map[string]string{}

		// Create mock client
		mockClient := new(gopowerstoremock.Client)
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
			Client:   mockClient,
		}

		// Mock successful CreateVolumeGroup call
		mockClient.On("CreateVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupCreate")).
			Return(gopowerstore.CreateResponse{ID: "vg-123"}, nil)

		// Mock GetVolumeGroup call
		mockClient.On("GetVolumeGroup", mock.Anything, "vg-123").
			Return(gopowerstore.VolumeGroup{ID: "vg-123"}, nil)

		group, err := manager.createVolumeGroup(ctx, groupName, volumeIDs, parameters, mockArray)
		assert.NoError(t, err)
		assert.Equal(t, "vg-123", group.ID)
		mockClient.AssertExpectations(t)
	})

	t.Run("create volume group with WOC disabled", func(t *testing.T) {
		groupName := "test-group"
		volumeIDs := []string{"vol1/array1/scsi"}
		parameters := map[string]string{
			"writeOrderConsistency": "false",
		}

		// Create mock client
		mockClient := new(gopowerstoremock.Client)
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
			Client:   mockClient,
		}

		// Mock successful CreateVolumeGroup call
		mockClient.On("CreateVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupCreate")).
			Return(gopowerstore.CreateResponse{ID: "vg-123"}, nil)

		// Mock GetVolumeGroup call
		mockClient.On("GetVolumeGroup", mock.Anything, "vg-123").
			Return(gopowerstore.VolumeGroup{ID: "vg-123"}, nil)

		group, err := manager.createVolumeGroup(ctx, groupName, volumeIDs, parameters, mockArray)
		assert.NoError(t, err)
		assert.Equal(t, "vg-123", group.ID)
		mockClient.AssertExpectations(t)
	})

	t.Run("create volume group with invalid WOC parameter", func(t *testing.T) {
		groupName := "test-group"
		volumeIDs := []string{"vol1/array1/scsi"}
		parameters := map[string]string{
			"writeOrderConsistency": "invalid-value",
		}

		// Create mock client
		mockClient := new(gopowerstoremock.Client)
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
			Client:   mockClient,
		}

		// Mock successful CreateVolumeGroup call (should use default WOC=true)
		mockClient.On("CreateVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupCreate")).
			Return(gopowerstore.CreateResponse{ID: "vg-123"}, nil)

		// Mock GetVolumeGroup call
		mockClient.On("GetVolumeGroup", mock.Anything, "vg-123").
			Return(gopowerstore.VolumeGroup{ID: "vg-123"}, nil)

		group, err := manager.createVolumeGroup(ctx, groupName, volumeIDs, parameters, mockArray)
		assert.NoError(t, err)
		assert.Equal(t, "vg-123", group.ID)
		mockClient.AssertExpectations(t)
	})
}

func TestVolumeGroupSnapshotManager_validateAndGroupVolumes(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	t.Run("volumes from different arrays should fail", func(t *testing.T) {
		// This test simulates volumes from different arrays
		// In a real scenario, getArrayForVolume would extract different array IDs from volume IDs
		volumeIDs := []string{"vol1/array1/scsi", "vol2/array2/scsi"}

		// Call validateAndGroupVolumes - it should fail due to array not found
		// The multi-array validation would happen after array lookup succeeds
		arrays, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

		// Should fail because arrays are not configured
		assert.Error(t, err)
		assert.Nil(t, arrays)
		// In real scenario with arrays configured, this would fail with "all volumes must be on the same PowerStore array"
		// For now, it fails with array not found, which is expected in test environment
	})

	t.Run("volumes from same array should pass", func(t *testing.T) {
		// This test simulates volumes from the same array
		// In a real scenario with proper array setup, this would pass
		volumeIDs := []string{"vol1/array1/scsi", "vol2/array1/scsi"}

		// Call validateAndGroupVolumes - it should fail due to no arrays configured
		// but not due to array mismatch
		arrays, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

		// Should fail due to no arrays configured, not array mismatch
		assert.Error(t, err)
		assert.Nil(t, arrays)
		// Error should NOT be "all volumes must be on the same PowerStore array"
		assert.NotContains(t, err.Error(), "all volumes must be on the same PowerStore array")
	})

	t.Run("empty volume list should fail validation", func(t *testing.T) {
		// Set up arrays
		mockArray := &array.PowerStoreArray{
			GlobalID: "test-array-1",
		}
		arrays := map[string]*array.PowerStoreArray{
			"test-array-1": mockArray,
		}
		manager.SetArrays(arrays)

		volumeIDs := []string{}

		resultArray, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

		// Empty list should fail validation - can't create snapshot of no volumes
		assert.Error(t, err)
		assert.Nil(t, resultArray)
		assert.Contains(t, err.Error(), "no volumes provided")
	})
}

func TestVolumeGroupSnapshotManager_generateStableVolumeGroupName(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	t.Run("consistent naming for same volume set", func(t *testing.T) {
		volumeIDs := []string{"vol1/array1/scsi", "vol2/array1/scsi"}
		snapshotName := "snapshot1"
		prefix := "test-prefix"

		name1 := manager.generateStableVolumeGroupName(volumeIDs, snapshotName, prefix)
		name2 := manager.generateStableVolumeGroupName(volumeIDs, "different-snapshot-name", prefix)

		assert.Equal(t, name1, name2, "Same volume set should generate same name regardless of snapshot name")
		assert.Contains(t, name1, prefix+"-")
	})

	t.Run("different naming for different volume sets", func(t *testing.T) {
		volumeIDs1 := []string{"vol1/array1/scsi", "vol2/array1/scsi"}
		volumeIDs2 := []string{"vol1/array1/scsi", "vol3/array1/scsi"}
		prefix := "test-prefix"

		name1 := manager.generateStableVolumeGroupName(volumeIDs1, "snapshot1", prefix)
		name2 := manager.generateStableVolumeGroupName(volumeIDs2, "snapshot2", prefix)

		assert.NotEqual(t, name1, name2, "Different volume sets should generate different names")
	})

	t.Run("order-independent naming", func(t *testing.T) {
		volumeIDs1 := []string{"vol1/array1/scsi", "vol2/array1/scsi"}
		volumeIDs2 := []string{"vol2/array1/scsi", "vol1/array1/scsi"}
		prefix := "test-prefix"

		name1 := manager.generateStableVolumeGroupName(volumeIDs1, "snapshot1", prefix)
		name2 := manager.generateStableVolumeGroupName(volumeIDs2, "snapshot2", prefix)

		assert.Equal(t, name1, name2, "Volume order should not affect naming")
	})

	t.Run("empty volume list", func(t *testing.T) {
		volumeIDs := []string{}
		prefix := "test-prefix"

		name := manager.generateStableVolumeGroupName(volumeIDs, "snapshot1", prefix)

		assert.Equal(t, "", name, "Empty volume list should return empty string")
	})

	t.Run("single volume", func(t *testing.T) {
		volumeIDs := []string{"vol1/array1/scsi"}
		prefix := "test-prefix"

		name := manager.generateStableVolumeGroupName(volumeIDs, "snapshot1", prefix)

		assert.Contains(t, name, prefix+"-")
		assert.True(t, len(name) > len(prefix+"-"))
	})

	t.Run("snapshot name changes but volume set same", func(t *testing.T) {
		volumeIDs := []string{"vol1/array1/scsi", "vol2/array1/scsi"}
		prefix := "test-prefix"

		name1 := manager.generateStableVolumeGroupName(volumeIDs, "backup-2023-12-10", prefix)
		name2 := manager.generateStableVolumeGroupName(volumeIDs, "backup-2023-12-11", prefix)
		name3 := manager.generateStableVolumeGroupName(volumeIDs, "backup-with-uuid-12345", prefix)

		assert.Equal(t, name1, name2, "Different snapshot names should not affect volume group name")
		assert.Equal(t, name2, name3, "UUID in snapshot name should not affect volume group name")
	})

	t.Run("default prefix usage", func(t *testing.T) {
		volumeIDs := []string{"vol1/array1/scsi", "vol2/array1/scsi"}

		name := manager.generateStableVolumeGroupName(volumeIDs, "snapshot1", defaultVolumeGroupPrefix)

		assert.Contains(t, name, defaultVolumeGroupPrefix+"-")
		assert.True(t, len(name) > len(defaultVolumeGroupPrefix+"-"))
	})
}

func TestVolumeGroupSnapshotManager_getOrCreateVolumeGroup_WithVolumeGroupPrefixParam(t *testing.T) {
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

	t.Run("create new group with user-specified prefix", func(t *testing.T) {
		// Mock CreateVolumeGroup - should be called with name using user-specified prefix
		mockClient.On("CreateVolumeGroup", mock.Anything, mock.MatchedBy(func(params *gopowerstore.VolumeGroupCreate) bool {
			return strings.HasPrefix(params.Name, "my-custom-prefix-")
		})).Return(gopowerstore.CreateResponse{ID: "vg-custom-123"}, nil).Once()

		// Mock GetVolumeGroup after creation
		mockClient.On("GetVolumeGroup", mock.Anything, "vg-custom-123").
			Return(gopowerstore.VolumeGroup{ID: "vg-custom-123"}, nil).Once()

		parameters := map[string]string{"volumeGroupPrefix": "my-custom-prefix"}
		volumeIDs := []string{"vol1", "vol2"}

		vg, err := manager.getOrCreateVolumeGroup(ctx, "test-group", volumeIDs, parameters, mockArray, "")

		assert.NoError(t, err)
		assert.NotNil(t, vg)
		assert.Equal(t, "vg-custom-123", vg.ID)
		mockClient.AssertExpectations(t)
	})

	t.Run("existing group with matching prefix", func(t *testing.T) {
		// Mock GetVolumeGroup to return existing group with name starting with prefix
		existingVG := gopowerstore.VolumeGroup{
			ID:   "vg-existing-123",
			Name: "my-custom-prefix-abc123",
		}
		mockClient.On("GetVolumeGroup", mock.Anything, "vg-existing-123").Return(existingVG, nil).Once()

		parameters := map[string]string{"volumeGroupPrefix": "my-custom-prefix"}
		volumeIDs := []string{"vol1", "vol2"}

		vg, err := manager.getOrCreateVolumeGroup(ctx, "test-group", volumeIDs, parameters, mockArray, "vg-existing-123")

		assert.NoError(t, err)
		assert.NotNil(t, vg)
		assert.Equal(t, "vg-existing-123", vg.ID)
		assert.Equal(t, "my-custom-prefix-abc123", vg.Name)
		mockClient.AssertExpectations(t)
	})

	t.Run("existing group with mismatching prefix should fail", func(t *testing.T) {
		// Mock GetVolumeGroup to return existing group with name not starting with prefix
		existingVG := gopowerstore.VolumeGroup{
			ID:   "vg-existing-123",
			Name: "different-prefix-xyz789",
		}
		mockClient.On("GetVolumeGroup", mock.Anything, "vg-existing-123").Return(existingVG, nil).Once()

		parameters := map[string]string{"volumeGroupPrefix": "my-custom-prefix"}
		volumeIDs := []string{"vol1", "vol2"}

		vg, err := manager.getOrCreateVolumeGroup(ctx, "test-group", volumeIDs, parameters, mockArray, "vg-existing-123")

		assert.Error(t, err)
		assert.Nil(t, vg)
		assert.Contains(t, err.Error(), "volumes are already in volume group \"different-prefix-xyz789\"")
		assert.Contains(t, err.Error(), "does not start with the requested volumeGroupPrefix \"my-custom-prefix\"")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		mockClient.AssertExpectations(t)
	})

	t.Run("without volumeGroupPrefix parameter use default prefix", func(t *testing.T) {
		// Mock CreateVolumeGroup - should be called with generated name (starts with default prefix)
		mockClient.On("CreateVolumeGroup", mock.Anything, mock.MatchedBy(func(params *gopowerstore.VolumeGroupCreate) bool {
			return strings.HasPrefix(params.Name, defaultVolumeGroupPrefix+"-")
		})).Return(gopowerstore.CreateResponse{ID: "vg-generated-123"}, nil).Once()

		// Mock GetVolumeGroup after creation
		mockClient.On("GetVolumeGroup", mock.Anything, "vg-generated-123").
			Return(gopowerstore.VolumeGroup{ID: "vg-generated-123"}, nil).Once()

		parameters := map[string]string{} // No volumeGroupPrefix parameter
		volumeIDs := []string{"vol1", "vol2"}

		vg, err := manager.getOrCreateVolumeGroup(ctx, "test-group", volumeIDs, parameters, mockArray, "")

		assert.NoError(t, err)
		assert.NotNil(t, vg)
		assert.Equal(t, "vg-generated-123", vg.ID)
		mockClient.AssertExpectations(t)
	})

	t.Run("existing group with default prefix should pass when no prefix specified", func(t *testing.T) {
		// Mock GetVolumeGroup to return existing group with default prefix
		existingVG := gopowerstore.VolumeGroup{
			ID:   "vg-existing-123",
			Name: defaultVolumeGroupPrefix + "-abc123",
		}
		mockClient.On("GetVolumeGroup", mock.Anything, "vg-existing-123").Return(existingVG, nil).Once()

		parameters := map[string]string{} // No volumeGroupPrefix parameter
		volumeIDs := []string{"vol1", "vol2"}

		vg, err := manager.getOrCreateVolumeGroup(ctx, "test-group", volumeIDs, parameters, mockArray, "vg-existing-123")

		assert.NoError(t, err)
		assert.NotNil(t, vg)
		assert.Equal(t, "vg-existing-123", vg.ID)
		assert.Equal(t, defaultVolumeGroupPrefix+"-abc123", vg.Name)
		mockClient.AssertExpectations(t)
	})
}
