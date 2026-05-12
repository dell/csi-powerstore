/*
Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.

* Dell Technologies, Dell and other trademarks are trademarks of Dell Inc.
* or its subsidiaries. Other trademarks may be trademarks of their respective
* owners.
*/

package groupcontroller

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Helper function to create a mock array with PowerStore client
func createMockArray(_ *testing.T, mockClient *gopowerstoremock.Client) *array.PowerStoreArray {
	return &array.PowerStoreArray{
		GlobalID: "test-array-1",
		Client:   mockClient,
		IP:       "127.0.0.1",
		Username: "test",
		Password: "test",
	}
}

// Helper function to create API error
func createAPIError(statusCode int, message string) gopowerstore.APIError {
	return gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: statusCode,
			Message:    message,
		},
	}
}

func TestGetArrayForVolume_Success(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	arr, err := manager.getArrayForVolume("vol1/test-array-1/scsi")

	assert.NoError(t, err)
	assert.NotNil(t, arr)
	assert.Equal(t, "test-array-1", arr.GlobalID)
}

func TestGetArrayForVolume_ArrayNotFound(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	// Don't set any arrays - array should not be found
	arr, err := manager.getArrayForVolume("vol-notfound/test-array-1/scsi")

	assert.Error(t, err)
	assert.Nil(t, arr)
	assert.Contains(t, err.Error(), "array test-array-1 not found")
}

func TestValidateAndGroupVolumes_AllInSameGroup(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	// Mock GetVolumesWithFilter to return volumes with same volume group
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return([]gopowerstore.Volume{
		{ID: "vol1", VolumeGroup: []gopowerstore.VolumeGroup{{ID: "vg-same"}}},
		{ID: "vol2", VolumeGroup: []gopowerstore.VolumeGroup{{ID: "vg-same"}}},
	}, nil)

	volumeIDs := []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"}
	resultArray, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.NoError(t, err)
	assert.NotNil(t, resultArray)
	mockClient.AssertExpectations(t)
}

func TestValidateAndGroupVolumes_InDifferentGroups(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	// Mock GetVolumesWithFilter to return volumes in different groups
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return([]gopowerstore.Volume{
		{ID: "vol1", VolumeGroup: []gopowerstore.VolumeGroup{{ID: "vg-1"}}},
		{ID: "vol2", VolumeGroup: []gopowerstore.VolumeGroup{{ID: "vg-2"}}},
	}, nil)

	volumeIDs := []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"}
	resultArrays, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.Error(t, err)
	assert.Nil(t, resultArrays)
	assert.Contains(t, err.Error(), "volumes are in different volume groups")
	mockClient.AssertExpectations(t)
}

func TestValidateAndGroupVolumes_AllNotInAnyGroup(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	// Mock GetVolumesWithFilter to return volumes with no volume groups
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return([]gopowerstore.Volume{
		{ID: "vol1"},
		{ID: "vol2"},
	}, nil)

	volumeIDs := []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"}
	resultArray, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.NoError(t, err)
	assert.NotNil(t, resultArray)
	mockClient.AssertExpectations(t)
}

func TestParseCreationTime_ValidTimestamp(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	volumeGroup := gopowerstore.VolumeGroup{
		CreationTimeStamp: "2023-12-11T10:00:00Z",
	}

	timestamp := manager.parseCreationTime(volumeGroup)

	assert.NotNil(t, timestamp)
	assert.Greater(t, timestamp.Seconds, int64(0))
}

func TestParseCreationTime_InvalidTimestamp(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	volumeGroup := gopowerstore.VolumeGroup{
		CreationTimeStamp: "invalid-timestamp",
	}

	timestamp := manager.parseCreationTime(volumeGroup)

	assert.NotNil(t, timestamp)
	// Should return current time on parse failure
	assert.Greater(t, timestamp.Seconds, int64(0))
}

func TestParseCreationTime_EmptyTimestamp(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	volumeGroup := gopowerstore.VolumeGroup{
		CreationTimeStamp: "",
	}

	timestamp := manager.parseCreationTime(volumeGroup)

	assert.NotNil(t, timestamp)
	// Should return current time when empty
	assert.Greater(t, timestamp.Seconds, int64(0))
}

func TestExtractVolumeID_ValidCSIFormat(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	volumeID, err := manager.extractVolumeID("vol123/array1/scsi")

	assert.NoError(t, err)
	assert.Equal(t, "vol123", volumeID)
}

func TestExtractVolumeID_UUIDOnly(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	volumeID, err := manager.extractVolumeID("vol123")

	assert.NoError(t, err)
	assert.Equal(t, "vol123", volumeID)
}

func TestExtractVolumeID_EmptyString(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	volumeID, err := manager.extractVolumeID("")

	assert.Error(t, err)
	assert.Empty(t, volumeID)
	assert.Contains(t, err.Error(), "invalid volume ID format")
}

// =============================================================================
// GetVolumeGroupSnapshot Tests
// =============================================================================

func TestGetVolumeGroupSnapshot_Success(t *testing.T) {
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

	// Mock GetVolumeGroupSnapshot to return snapshot details (using native ID)
	volumeGroupSnapshot := gopowerstore.VolumeGroup{
		ID:   "vg-snapshot-123",
		Name: "test-snapshot",
		Volumes: []gopowerstore.Volume{
			{
				ID:    "vol1/test-array-1/scsi",
				State: "Ready",
				Size:  10737418240,
				ProtectionData: gopowerstore.ProtectionData{
					SourceID: "vol1",
				},
			},
			{
				ID:    "vol2/test-array-1/scsi",
				State: "Ready",
				Size:  10737418240,
				ProtectionData: gopowerstore.ProtectionData{
					SourceID: "vol2",
				},
			},
		},
		CreationTimeStamp: "2023-12-11T10:00:00Z",
	}
	mockClient.On("GetVolumeGroupSnapshot", mock.Anything, "vg-snapshot-123").Return(volumeGroupSnapshot, nil)

	req := &csi.GetVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
	}

	resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.GroupSnapshot)
	assert.Equal(t, "vg-snapshot-123/test-array-1/scsi", resp.GroupSnapshot.GroupSnapshotId)
	assert.True(t, resp.GroupSnapshot.ReadyToUse)
	assert.NotNil(t, resp.GroupSnapshot.CreationTime)
	// createSnapshotsFromVolumeGroup creates individual snapshots for each volume
	assert.Len(t, resp.GroupSnapshot.Snapshots, 2)
	assert.Equal(t, "vol1/test-array-1/scsi", resp.GroupSnapshot.Snapshots[0].SnapshotId)
	assert.Equal(t, "vol2/test-array-1/scsi", resp.GroupSnapshot.Snapshots[1].SnapshotId)
	mockClient.AssertExpectations(t)
}

func TestGetVolumeGroupSnapshot_EmptyGroupSnapshotID(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	req := &csi.GetVolumeGroupSnapshotRequest{
		GroupSnapshotId: "",
	}

	resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "group snapshot ID cannot be empty")
}

func TestGetVolumeGroupSnapshot_NoArraysConfigured(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	// Don't set any arrays
	req := &csi.GetVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
	}

	resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "array test-array-1 not found")
}

func TestGetVolumeGroupSnapshot_NotFound(t *testing.T) {
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

	// Mock GetVolumeGroup to return not found error
	notFoundError := gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusNotFound,
			Message:    "volume group not found",
		},
	}
	mockClient.On("GetVolumeGroupSnapshot", mock.Anything, "vg-nonexistent").Return(gopowerstore.VolumeGroup{}, notFoundError)

	req := &csi.GetVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-nonexistent/test-array-1/scsi",
	}

	resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "group snapshot vg-nonexistent/test-array-1/scsi not found")
	mockClient.AssertExpectations(t)
}

func TestGetVolumeGroupSnapshot_APIError(t *testing.T) {
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

	// Mock GetVolumeGroup to return internal server error (using native ID)
	serverError := gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		},
	}
	mockClient.On("GetVolumeGroupSnapshot", mock.Anything, "vg-snapshot-123").Return(gopowerstore.VolumeGroup{}, serverError)

	req := &csi.GetVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
	}

	resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to get volume group snapshot vg-snapshot-123")
	mockClient.AssertExpectations(t)
}

func TestGetVolumeGroupSnapshot_EmptyVolumeGroup(t *testing.T) {
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

	// Mock GetVolumeGroupSnapshot - returns the snapshot itself with no volumes (using native ID)
	volumeGroupSnapshot := gopowerstore.VolumeGroup{
		ID:      "vg-snapshot-empty",
		Name:    "empty-snapshot",
		Volumes: []gopowerstore.Volume{},
	}
	mockClient.On("GetVolumeGroupSnapshot", mock.Anything, "vg-snapshot-empty").Return(volumeGroupSnapshot, nil)

	req := &csi.GetVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-empty/test-array-1/scsi",
	}

	resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.GroupSnapshot)
	assert.Equal(t, "vg-snapshot-empty/test-array-1/scsi", resp.GroupSnapshot.GroupSnapshotId)
	assert.Len(t, resp.GroupSnapshot.Snapshots, 0)
	mockClient.AssertExpectations(t)
}

// =============================================================================
// DeleteVolumeGroupSnapshot Tests
// =============================================================================

func TestDeleteVolumeGroupSnapshot_Success(t *testing.T) {
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

	// Mock DeleteVolumeGroup to succeed (using native ID)
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vg-snapshot-123").Return(gopowerstore.EmptyResponse(""), nil)

	req := &csi.DeleteVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
	}

	resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockClient.AssertExpectations(t)
}

func TestDeleteVolumeGroupSnapshot_EmptyGroupSnapshotID(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	req := &csi.DeleteVolumeGroupSnapshotRequest{
		GroupSnapshotId: "",
	}

	resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "group snapshot ID cannot be empty")
}

func TestDeleteVolumeGroupSnapshot_NoArraysConfigured(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	// Don't set any arrays
	req := &csi.DeleteVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
	}

	resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "array test-array-1 not found")
}

func TestDeleteVolumeGroupSnapshot_AlreadyDeleted(t *testing.T) {
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

	// Mock DeleteVolumeGroup to return not found (idempotent)
	notFoundError := gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusNotFound,
			Message:    "volume group not found",
		},
	}
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vg-snapshot-deleted").Return(gopowerstore.EmptyResponse(""), notFoundError)

	req := &csi.DeleteVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-deleted/test-array-1/scsi",
	}

	resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockClient.AssertExpectations(t)
}

func TestDeleteVolumeGroupSnapshot_APIError(t *testing.T) {
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

	// Mock DeleteVolumeGroup to return internal server error
	serverError := gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		},
	}
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vg-snapshot-123").Return(gopowerstore.EmptyResponse(""), serverError)

	req := &csi.DeleteVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
	}

	resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to delete volume group snapshot vg-snapshot-123")
	mockClient.AssertExpectations(t)
}

func TestDeleteVolumeGroupSnapshot_WithSecrets(t *testing.T) {
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

	// Mock DeleteVolumeGroup to succeed
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vg-snapshot-123").Return(gopowerstore.EmptyResponse(""), nil)

	req := &csi.DeleteVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
		Secrets: map[string]string{
			"username": "admin",
			"password": "password",
		},
	}

	resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockClient.AssertExpectations(t)
}

func TestDeleteVolumeGroupSnapshot_CleanupSkipped(t *testing.T) {
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

	// Mock DeleteVolumeGroup to succeed
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vg-snapshot-123").Return(gopowerstore.EmptyResponse(""), nil)

	req := &csi.DeleteVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
	}

	// Should succeed - cleanup is now skipped (volume groups are persistent)
	resp, err := manager.DeleteVolumeGroupSnapshot(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockClient.AssertExpectations(t)
}

// =============================================================================
// Validation Function Tests
// =============================================================================

// =============================================================================
// Additional Error Condition Tests
// =============================================================================

func TestValidateAndGroupVolumes_InvalidVolumeID(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	// Invalid volume ID format (missing parts)
	volumeIDs := []string{"invalid-volume-id"}

	_, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid volume ID format")
}

func TestValidateAndGroupVolumes_EmptyVolumeList(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	// Empty volume list
	volumeIDs := []string{}

	_, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)
	// Should return error - can't create snapshot of no volumes
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no volumes provided")
}

func TestGetVolumeGroupSnapshot_GetSnapshotsError(t *testing.T) {
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

	// Mock GetVolumeGroupSnapshot to fail
	serverError := gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get snapshots",
		},
	}
	mockClient.On("GetVolumeGroupSnapshot", mock.Anything, "vg-snapshot-123").Return(gopowerstore.VolumeGroup{}, serverError)

	req := &csi.GetVolumeGroupSnapshotRequest{
		GroupSnapshotId: "vg-snapshot-123/test-array-1/scsi",
	}

	resp, err := manager.GetVolumeGroupSnapshot(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to get volume group snapshot vg-snapshot-123")
	mockClient.AssertExpectations(t)
}

func TestExtractVolumeID_InvalidFormat(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	// Test only truly invalid formats (empty string)
	_, err := manager.extractVolumeID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid volume ID format")
}

func TestExtractVolumeID_ValidFormat(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	volumeID := "vol-123/array-456/scsi"
	actualID, err := manager.extractVolumeID(volumeID)

	assert.NoError(t, err)
	assert.Equal(t, "vol-123", actualID)
}

func TestValidateCreateRequest_NameTooLong(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	// Create a name longer than 128 characters
	longName := string(make([]byte, 129))
	for i := range longName {
		longName = longName[:i] + "a" + longName[i+1:]
	}

	req := &csi.CreateVolumeGroupSnapshotRequest{
		Name:            longName,
		SourceVolumeIds: []string{"vol1/array1/scsi"},
	}

	_, err := manager.validateCreateRequest(ctx, req, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot exceed 128 characters")
}

func TestValidateCreateRequest_EmptyName(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	req := &csi.CreateVolumeGroupSnapshotRequest{
		Name:            "",
		SourceVolumeIds: []string{"vol1/array1/scsi"},
	}

	_, err := manager.validateCreateRequest(ctx, req, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "group snapshot name cannot be empty")
}

func TestValidateCreateRequest_NoSourceVolumes(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	req := &csi.CreateVolumeGroupSnapshotRequest{
		Name:            "test-snapshot",
		SourceVolumeIds: []string{},
	}

	_, err := manager.validateCreateRequest(ctx, req, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source volume")
}

// =============================================================================
// Additional Coverage Tests (to push above 90%)
// =============================================================================

func TestCleanupFailedGroupSnapshot_Success(t *testing.T) {
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

	// Mock DeleteVolumeGroup to succeed
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vg-failed-123").Return(gopowerstore.EmptyResponse(""), nil)

	err := manager.cleanupFailedGroupSnapshot(ctx, "vg-failed-123", mockArray)

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestCleanupFailedGroupSnapshot_AlreadyDeleted(t *testing.T) {
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

	// Mock DeleteVolumeGroup to return not found (idempotent)
	notFoundError := gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusNotFound,
			Message:    "volume group not found",
		},
	}
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vg-already-deleted").Return(gopowerstore.EmptyResponse(""), notFoundError)

	err := manager.cleanupFailedGroupSnapshot(ctx, "vg-already-deleted", mockArray)

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestCleanupFailedGroupSnapshot_NoArrays(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()

	// Don't set any arrays
	err := manager.cleanupFailedGroupSnapshot(ctx, "vg-failed-123", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no array provided")
}

func TestCleanupFailedGroupSnapshot_APIError(t *testing.T) {
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

	// Mock DeleteVolumeGroup to return API error
	serverError := gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		},
	}
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vg-failed-123").Return(gopowerstore.EmptyResponse(""), serverError)

	err := manager.cleanupFailedGroupSnapshot(ctx, "vg-failed-123", mockArray)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "internal server error")
	mockClient.AssertExpectations(t)
}

func TestEnsureVolumesInGroup_ExistingGroup(t *testing.T) {
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

	// Preload existing volume group with volumes
	volumeGroup := gopowerstore.VolumeGroup{
		ID:   "vg-existing-123",
		Name: "existing-group",
		Volumes: []gopowerstore.Volume{
			{ID: "vol-1"},
			{ID: "vol-2"},
		},
	}

	volumeIDs := []string{"vol-1/test-array-1/scsi", "vol-2/test-array-1/scsi"}

	err := manager.ensureVolumesInGroup(ctx, volumeIDs, &volumeGroup, mockArray)

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestEnsureVolumesInGroup_NewGroup(t *testing.T) {
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

	// Preload empty volume group (new group)
	volumeGroup := gopowerstore.VolumeGroup{
		ID:      "vg-new-123",
		Name:    "new-group",
		Volumes: []gopowerstore.Volume{},
	}

	// Mock AddMembersToVolumeGroup to add volumes
	mockClient.On("AddMembersToVolumeGroup", mock.Anything, mock.Anything, "vg-new-123").Return(gopowerstore.EmptyResponse(""), nil)

	volumeIDs := []string{"vol-1/test-array-1/scsi", "vol-2/test-array-1/scsi"}

	err := manager.ensureVolumesInGroup(ctx, volumeIDs, &volumeGroup, mockArray)

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestEnsureVolumesInGroup_GetGroupError(t *testing.T) {
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

	// Simulate failure while adding members to new group
	serverError := gopowerstore.APIError{
		ErrorMsg: &api.ErrorMsg{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		},
	}
	volumeGroup := gopowerstore.VolumeGroup{
		ID:      "vg-error-123",
		Name:    "error-group",
		Volumes: []gopowerstore.Volume{},
	}
	mockClient.On("AddMembersToVolumeGroup", mock.Anything, mock.Anything, "vg-error-123").Return(gopowerstore.EmptyResponse(""), serverError)

	volumeIDs := []string{"vol-1/test-array-1/scsi"}

	err := manager.ensureVolumesInGroup(ctx, volumeIDs, &volumeGroup, mockArray)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add volumes to group")
	mockClient.AssertExpectations(t)
}

// =============================================================================
// parseGroupSnapshotID Helper Function Tests
// =============================================================================

func TestVolumeGroupSnapshotManager_parseGroupSnapshotID(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()

	t.Run("valid CSI format", func(t *testing.T) {
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("snap-123/test-array-1/scsi")

		assert.NoError(t, err)
		assert.Equal(t, "snap-123", nativeID)
		assert.Equal(t, "test-array-1", arrayID)
		assert.Equal(t, "scsi", protocol)
	})

	t.Run("valid CSI format with complex IDs", func(t *testing.T) {
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("70d070c8-ed7f-4deb-a0ac-5c0e12439ffc/PSabcdef012345/nvme")

		assert.NoError(t, err)
		assert.Equal(t, "70d070c8-ed7f-4deb-a0ac-5c0e12439ffc", nativeID)
		assert.Equal(t, "PSabcdef012345", arrayID)
		assert.Equal(t, "nvme", protocol)
	})

	t.Run("empty ID", func(t *testing.T) {
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("")

		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
		assert.Empty(t, nativeID)
		assert.Empty(t, arrayID)
		assert.Empty(t, protocol)
	})

	t.Run("missing parts - only native ID", func(t *testing.T) {
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("snap-123")

		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
		assert.Empty(t, nativeID)
		assert.Empty(t, arrayID)
		assert.Empty(t, protocol)
	})

	t.Run("missing parts - native ID and array ID", func(t *testing.T) {
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("snap-123/test-array-1")

		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
		assert.Empty(t, nativeID)
		assert.Empty(t, arrayID)
		assert.Empty(t, protocol)
	})

	t.Run("too many parts", func(t *testing.T) {
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("snap-123/test-array-1/scsi/extra")

		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "invalid group snapshot ID format")
		assert.Empty(t, nativeID)
		assert.Empty(t, arrayID)
		assert.Empty(t, protocol)
	})

	t.Run("parts with empty strings", func(t *testing.T) {
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("snap-123//scsi")

		assert.NoError(t, err)
		assert.Equal(t, "snap-123", nativeID)
		assert.Equal(t, "", arrayID)
		assert.Equal(t, "scsi", protocol)
	})

	t.Run("all parts empty", func(t *testing.T) {
		nativeID, arrayID, protocol, err := manager.parseGroupSnapshotID("//")

		assert.NoError(t, err)
		assert.Equal(t, "", nativeID)
		assert.Equal(t, "", arrayID)
		assert.Equal(t, "", protocol)
	})
}

// =============================================================================
// createVolumeGroupSnapshot Tests (targeting 69.2% -> higher coverage)
// =============================================================================

func TestCreateVolumeGroupSnapshotMock_Success(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	// Mock CreateVolumeGroupSnapshot
	mockClient.On("CreateVolumeGroupSnapshot", mock.Anything, "vg-123", mock.AnythingOfType("*gopowerstore.VolumeGroupSnapshotCreate")).
		Return(gopowerstore.CreateResponse{ID: "vgs-456"}, nil)

	// Mock GetVolumeGroup for the created snapshot
	mockClient.On("GetVolumeGroup", mock.Anything, "vgs-456").
		Return(gopowerstore.VolumeGroup{
			ID:                "vgs-456",
			Name:              "test-snap",
			CreationTimeStamp: "2024-01-15T10:00:00Z",
			Volumes: []gopowerstore.Volume{
				{
					ID:    "snap-vol-1",
					State: "Ready",
					Size:  1073741824,
					ProtectionData: gopowerstore.ProtectionData{
						SourceID: "src-vol-1",
					},
				},
			},
		}, nil)

	sourceVolumeIDs := []string{"src-vol-1/test-array-1/scsi"}

	result, err := manager.createVolumeGroupSnapshot(ctx, "test-snap", "vg-123", mockArray, sourceVolumeIDs)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "vgs-456/test-array-1/scsi", result.GroupSnapshotId)
	assert.Len(t, result.Snapshots, 1)
	assert.True(t, result.ReadyToUse)
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroupSnapshot_SourceIDEmpty(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	mockClient.On("CreateVolumeGroupSnapshot", mock.Anything, "vg-123", mock.AnythingOfType("*gopowerstore.VolumeGroupSnapshotCreate")).
		Return(gopowerstore.CreateResponse{ID: "vgs-456"}, nil)

	// Return volume with empty SourceID to hit the fallback path
	mockClient.On("GetVolumeGroup", mock.Anything, "vgs-456").
		Return(gopowerstore.VolumeGroup{
			ID:                "vgs-456",
			CreationTimeStamp: "2024-01-15T10:00:00Z",
			Volumes: []gopowerstore.Volume{
				{
					ID:             "snap-vol-1",
					State:          "Ready",
					Size:           1073741824,
					ProtectionData: gopowerstore.ProtectionData{SourceID: ""},
				},
			},
		}, nil)

	sourceVolumeIDs := []string{"src-vol-1/test-array-1/scsi"}
	result, err := manager.createVolumeGroupSnapshot(ctx, "test-snap", "vg-123", mockArray, sourceVolumeIDs)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	// When SourceID is empty, it falls back to the volume UUID
	assert.Equal(t, "snap-vol-1/test-array-1/scsi", result.Snapshots[0].SourceVolumeId)
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroupSnapshot_CreateFails(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	mockClient.On("CreateVolumeGroupSnapshot", mock.Anything, "vg-123", mock.AnythingOfType("*gopowerstore.VolumeGroupSnapshotCreate")).
		Return(gopowerstore.CreateResponse{}, createAPIError(http.StatusInternalServerError, "create failed"))

	sourceVolumeIDs := []string{"src-vol-1/test-array-1/scsi"}
	result, err := manager.createVolumeGroupSnapshot(ctx, "test-snap", "vg-123", mockArray, sourceVolumeIDs)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to create volume group snapshot")
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroupSnapshot_GetAfterCreateNotFound(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	mockClient.On("CreateVolumeGroupSnapshot", mock.Anything, "vg-123", mock.AnythingOfType("*gopowerstore.VolumeGroupSnapshotCreate")).
		Return(gopowerstore.CreateResponse{ID: "vgs-456"}, nil)

	// GetVolumeGroup returns NotFound after creation
	mockClient.On("GetVolumeGroup", mock.Anything, "vgs-456").
		Return(gopowerstore.VolumeGroup{}, createAPIError(http.StatusNotFound, "not found"))

	sourceVolumeIDs := []string{"src-vol-1/test-array-1/scsi"}
	result, err := manager.createVolumeGroupSnapshot(ctx, "test-snap", "vg-123", mockArray, sourceVolumeIDs)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get created volume group snapshot")
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroupSnapshot_GetAfterCreateAPIError(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	mockClient.On("CreateVolumeGroupSnapshot", mock.Anything, "vg-123", mock.AnythingOfType("*gopowerstore.VolumeGroupSnapshotCreate")).
		Return(gopowerstore.CreateResponse{ID: "vgs-456"}, nil)

	// GetVolumeGroup returns non-NotFound API error
	mockClient.On("GetVolumeGroup", mock.Anything, "vgs-456").
		Return(gopowerstore.VolumeGroup{}, createAPIError(http.StatusInternalServerError, "server error"))

	// Cleanup attempt: DeleteVolumeGroup
	mockClient.On("DeleteVolumeGroup", mock.Anything, "vgs-456").
		Return(gopowerstore.EmptyResponse(""), nil)

	sourceVolumeIDs := []string{"src-vol-1/test-array-1/scsi"}
	result, err := manager.createVolumeGroupSnapshot(ctx, "test-snap", "vg-123", mockArray, sourceVolumeIDs)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get created volume group snapshot")
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroupSnapshot_GetAfterCreateNonAPIError(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	mockClient.On("CreateVolumeGroupSnapshot", mock.Anything, "vg-123", mock.AnythingOfType("*gopowerstore.VolumeGroupSnapshotCreate")).
		Return(gopowerstore.CreateResponse{ID: "vgs-456"}, nil)

	// GetVolumeGroup returns a non-API error (e.g. network error)
	mockClient.On("GetVolumeGroup", mock.Anything, "vgs-456").
		Return(gopowerstore.VolumeGroup{}, fmt.Errorf("network timeout"))

	sourceVolumeIDs := []string{"src-vol-1/test-array-1/scsi"}
	result, err := manager.createVolumeGroupSnapshot(ctx, "test-snap", "vg-123", mockArray, sourceVolumeIDs)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get created volume group snapshot")
	mockClient.AssertExpectations(t)
}

// =============================================================================
// validateAndGroupVolumes additional coverage tests
// =============================================================================

func TestValidateAndGroupVolumes_MultiArrayFails(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient1 := new(gopowerstoremock.Client)
	mockClient2 := new(gopowerstoremock.Client)

	arrays := map[string]*array.PowerStoreArray{
		"array-1": {GlobalID: "array-1", Client: mockClient1},
		"array-2": {GlobalID: "array-2", Client: mockClient2},
	}
	manager.SetArrays(arrays)

	volumeIDs := []string{"vol1/array-1/scsi", "vol2/array-2/scsi"}
	_, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all volumes must be on the same PowerStore array")
}

func TestValidateAndGroupVolumes_VolumesNotFound(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	// Return fewer volumes than requested
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return([]gopowerstore.Volume{
		{ID: "vol1"},
	}, nil)

	volumeIDs := []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"}
	_, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "volumes not found")
	mockClient.AssertExpectations(t)
}

func TestValidateAndGroupVolumes_MixedGroupedUngrouped(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	// Return volumes where some are grouped and some are not
	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).Return([]gopowerstore.Volume{
		{ID: "vol1", VolumeGroup: []gopowerstore.VolumeGroup{{ID: "vg-1"}}},
		{ID: "vol2"}, // ungrouped
	}, nil)

	volumeIDs := []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"}
	_, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "some volumes are in volume group")
	mockClient.AssertExpectations(t)
}

func TestValidateAndGroupVolumes_GetVolumesAPIError(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	arrays := map[string]*array.PowerStoreArray{
		"test-array-1": mockArray,
	}
	manager.SetArrays(arrays)

	mockClient.On("GetVolumesWithFilter", mock.Anything, mock.Anything).
		Return([]gopowerstore.Volume{}, createAPIError(http.StatusInternalServerError, "query failed"))

	volumeIDs := []string{"vol1/test-array-1/scsi", "vol2/test-array-1/scsi"}
	_, _, err := manager.validateAndGroupVolumes(ctx, volumeIDs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to query volumes")
	mockClient.AssertExpectations(t)
}

// =============================================================================
// createVolumeGroup error path tests
// =============================================================================

func TestCreateVolumeGroup_CreateAPIError(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	mockClient.On("CreateVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupCreate")).
		Return(gopowerstore.CreateResponse{}, createAPIError(http.StatusInternalServerError, "create failed"))

	_, err := manager.createVolumeGroup(ctx, "test-group", []string{"vol1/array1/scsi"}, map[string]string{}, mockArray)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create volume group")
	mockClient.AssertExpectations(t)
}

func TestCreateVolumeGroup_GetAfterCreateError(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	mockClient.On("CreateVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupCreate")).
		Return(gopowerstore.CreateResponse{ID: "vg-123"}, nil)

	mockClient.On("GetVolumeGroup", mock.Anything, "vg-123").
		Return(gopowerstore.VolumeGroup{}, createAPIError(http.StatusInternalServerError, "get failed"))

	_, err := manager.createVolumeGroup(ctx, "test-group", []string{"vol1/array1/scsi"}, map[string]string{}, mockArray)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get created volume group")
	mockClient.AssertExpectations(t)
}

// =============================================================================
// getOrCreateVolumeGroup error path test
// =============================================================================

func TestGetOrCreateVolumeGroup_DetectedGroupGetError(t *testing.T) {
	manager := NewVolumeGroupSnapshotManager()
	ctx := context.Background()
	mockClient := new(gopowerstoremock.Client)
	mockArray := createMockArray(t, mockClient)

	mockClient.On("GetVolumeGroup", mock.Anything, "vg-detected").
		Return(gopowerstore.VolumeGroup{}, createAPIError(http.StatusInternalServerError, "get failed"))

	_, err := manager.getOrCreateVolumeGroup(ctx, "test-snap", []string{"vol1/test-array-1/scsi"}, map[string]string{}, mockArray, "vg-detected")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get detected volume group")
	mockClient.AssertExpectations(t)
}
