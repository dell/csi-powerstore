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
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	log "github.com/dell/csmlog"
	"github.com/dell/gopowerstore"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VolumeGroupSnapshotManager manages group snapshot operations
type VolumeGroupSnapshotManager struct {
	arrays map[string]*array.PowerStoreArray
}

const (
	snapLengthMax = 128
	wocParam      = "writeOrderConsistency"

	// Protocol constants for volume validation
	protocolSCSI = "scsi"
	protocolFC   = "fc"
	protocolNVMe = "nvme"

	// Volume group naming constants
	defaultVolumeGroupPrefix = "csi-vg"
	volumeGroupPrefixParam   = "volumeGroupPrefix"
)

// NewVolumeGroupSnapshotManager creates a new group snapshot manager
func NewVolumeGroupSnapshotManager() *VolumeGroupSnapshotManager {
	return &VolumeGroupSnapshotManager{
		arrays: make(map[string]*array.PowerStoreArray),
	}
}

// =============================================================================
// MANAGER LIFECYCLE FUNCTIONS
// =============================================================================
// These functions handle the initialization and configuration of the VolumeGroupSnapshotManager.

// SetArrays sets the available arrays for the manager
func (m *VolumeGroupSnapshotManager) SetArrays(arrays map[string]*array.PowerStoreArray) {
	m.arrays = arrays
}

// =============================================================================
// CSI INTERFACE FUNCTIONS
// =============================================================================
// These functions implement the CSI VolumeGroupSnapshot RPC interface.
// They are the main entry points for CSI operations and should not be called directly
// by other internal functions.

// CreateVolumeGroupSnapshot creates a group snapshot of specified volumes.
//
// Implements CSI CreateVolumeGroupSnapshot RPC with validation, volume grouping, and snapshot creation.
// Volume groups are persistent with immutable membership and stable naming based on volume IDs.
func (m *VolumeGroupSnapshotManager) CreateVolumeGroupSnapshot(ctx context.Context, req *csi.CreateVolumeGroupSnapshotRequest, defaultArray *array.PowerStoreArray) (*csi.CreateVolumeGroupSnapshotResponse, error) {
	log.WithContext(ctx).Infof("CreateVolumeGroupSnapshot called with name: %s, source volumes: %v", req.GetName(), req.GetSourceVolumeIds())

	sourceVols, err := m.validateCreateRequest(ctx, req, defaultArray)
	if err != nil {
		return nil, err
	}

	arr, groupID, err := m.validateAndGroupVolumes(ctx, sourceVols)
	if err != nil {
		return nil, err
	}
	if arr == nil {
		return nil, status.Error(codes.Internal, "no array available")
	}

	volumeGroup, err := m.getOrCreateVolumeGroup(ctx, req.GetName(), sourceVols, req.GetParameters(), arr, groupID)
	if err != nil {
		return nil, err
	}

	if err := m.ensureVolumesInGroup(ctx, sourceVols, volumeGroup, arr); err != nil {
		log.WithContext(ctx).Warnf("Failed to add volumes to group %s: %s", volumeGroup.ID, err.Error())
		return nil, err
	}

	groupSnapshot, err := m.createVolumeGroupSnapshot(ctx, req.GetName(), volumeGroup.ID, arr, sourceVols)
	if err != nil {
		log.WithContext(ctx).Warnf("Failed to create volume group snapshot: %s", err.Error())
		return nil, err
	}

	log.WithContext(ctx).Infof("Successfully created group snapshot %s with %d member snapshots", groupSnapshot.GroupSnapshotId, len(groupSnapshot.Snapshots))

	return &csi.CreateVolumeGroupSnapshotResponse{
		GroupSnapshot: groupSnapshot,
	}, nil
}

// =============================================================================
// CSI INTERFACE FUNCTIONS
// =============================================================================
// DeleteVolumeGroupSnapshot deletes a group snapshot and its member snapshots.
//
// Implements CSI DeleteVolumeGroupSnapshot RPC with validation and PowerStore snapshot deletion.
// Volume group snapshots are deleted atomically; volume groups are cleaned up on best-effort basis.
func (m *VolumeGroupSnapshotManager) DeleteVolumeGroupSnapshot(ctx context.Context, req *csi.DeleteVolumeGroupSnapshotRequest) (*csi.DeleteVolumeGroupSnapshotResponse, error) {
	log.WithContext(ctx).Infof("DeleteVolumeGroupSnapshot called with group_snapshot_id: %s", req.GetGroupSnapshotId())

	if req.GetGroupSnapshotId() == "" {
		return nil, status.Error(codes.InvalidArgument, "group snapshot ID cannot be empty")
	}

	csiGroupSnapshotID := req.GetGroupSnapshotId()
	nativeSnapshotID, arrayID, _, parseErr := m.parseGroupSnapshotID(csiGroupSnapshotID)
	if parseErr != nil {
		// CSI spec v1.12: DeleteVolumeGroupSnapshot MUST be idempotent
		// Invalid or non-existent ID MUST return OK
		log.Infof("DeleteVolumeGroupSnapshot: invalid ID format %s, returning OK for idempotency", csiGroupSnapshotID)
		return &csi.DeleteVolumeGroupSnapshotResponse{}, nil
	}

	log.WithContext(ctx).Infof("Deleting group snapshot %s (native ID: %s) using array %s", csiGroupSnapshotID, nativeSnapshotID, arrayID)

	if _, exists := m.arrays[arrayID]; !exists {
		return nil, status.Errorf(codes.NotFound, "array %s not found for group snapshot %s", arrayID, csiGroupSnapshotID)
	}
	arr := m.arrays[arrayID]

	var err error
	_, err = arr.GetClient().DeleteVolumeGroup(ctx, nativeSnapshotID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			log.WithContext(ctx).Infof("Volume group snapshot %s not found, assuming already deleted", csiGroupSnapshotID)
			return &csi.DeleteVolumeGroupSnapshotResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to delete volume group snapshot %s: %s", csiGroupSnapshotID, err.Error())
	}

	log.WithContext(ctx).Infof("Successfully deleted volume group snapshot %s", csiGroupSnapshotID)

	return &csi.DeleteVolumeGroupSnapshotResponse{}, nil
}

// =============================================================================
// CSI INTERFACE FUNCTIONS
// =============================================================================
// GetVolumeGroupSnapshot retrieves information about a group snapshot.
//
// Implements CSI GetVolumeGroupSnapshot RPC with validation and PowerStore snapshot retrieval.
// Returns current state with individual volume snapshot details for CSI compliance.
func (m *VolumeGroupSnapshotManager) GetVolumeGroupSnapshot(ctx context.Context, req *csi.GetVolumeGroupSnapshotRequest) (*csi.GetVolumeGroupSnapshotResponse, error) {
	log.WithContext(ctx).Infof("GetVolumeGroupSnapshot called with group_snapshot_id: %s", req.GetGroupSnapshotId())

	if req.GetGroupSnapshotId() == "" {
		return nil, status.Error(codes.InvalidArgument, "group snapshot ID cannot be empty")
	}

	csiGroupSnapshotID := req.GetGroupSnapshotId()
	nativeSnapshotID, arrayID, protocol, parseErr := m.parseGroupSnapshotID(csiGroupSnapshotID)
	if parseErr != nil {
		// CSI spec v1.12: GetVolumeGroupSnapshot with non-existent ID MUST return NotFound
		return nil, status.Errorf(codes.NotFound, "group snapshot %s not found: %s", csiGroupSnapshotID, parseErr.Error())
	}

	log.WithContext(ctx).Infof("Getting group snapshot %s (native ID: %s) using array %s", csiGroupSnapshotID, nativeSnapshotID, arrayID)

	if _, exists := m.arrays[arrayID]; !exists {
		return nil, status.Errorf(codes.NotFound, "array %s not found for group snapshot %s", arrayID, csiGroupSnapshotID)
	}
	arr := m.arrays[arrayID]

	volumeGroupSnapshot, err := arr.GetClient().GetVolumeGroupSnapshot(ctx, nativeSnapshotID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return nil, status.Error(codes.NotFound, fmt.Sprintf("group snapshot %s not found", csiGroupSnapshotID))
		}
		return nil, status.Errorf(codes.Internal, "failed to get volume group snapshot %s: %s", csiGroupSnapshotID, err.Error())
	}

	// Parse creation time once to ensure consistency across all snapshots
	creationTime := m.parseCreationTime(volumeGroupSnapshot)

	snapshots, err := m.createSnapshotsFromVolumeGroupResponse(ctx, &volumeGroupSnapshot, arr, creationTime, protocol)
	if err != nil {
		return nil, err
	}

	groupSnapshot := &csi.VolumeGroupSnapshot{
		GroupSnapshotId: csiGroupSnapshotID,
		Snapshots:       snapshots,
		CreationTime:    creationTime,
		ReadyToUse:      true, // PowerStore snapshots are immediately ready
	}

	return &csi.GetVolumeGroupSnapshotResponse{
		GroupSnapshot: groupSnapshot,
	}, nil
}

// =============================================================================
// VALIDATION FUNCTIONS
// =============================================================================
// These functions validate CSI requests and ensure they meet the requirements
// for successful VolumeGroupSnapshot operations.

// validateCreateRequest validates the create volume group snapshot request and returns sanitized CSI volume IDs
func (m *VolumeGroupSnapshotManager) validateCreateRequest(ctx context.Context, req *csi.CreateVolumeGroupSnapshotRequest, defaultArray *array.PowerStoreArray) ([]string, error) {
	// Validate snapshot name
	snapshotName := req.GetName()
	if snapshotName == "" {
		return nil, status.Error(codes.InvalidArgument, "group snapshot name cannot be empty")
	}

	if len(snapshotName) > snapLengthMax {
		log.WithContext(ctx).Warnf("Group snapshot name %q exceeds %d character limit (length: %d)", snapshotName, snapLengthMax, len(snapshotName))
		return nil, status.Errorf(codes.InvalidArgument, "group snapshot name cannot exceed %d characters (got %d)", snapLengthMax, len(snapshotName))
	}

	// Validate source volumes
	sourceVolumeIDs := req.GetSourceVolumeIds()
	if len(sourceVolumeIDs) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one source volume ID is required")
	}

	// Parse and validate source volume IDs using array.ParseVolumeID for robust parsing
	var sanitizedVolumeIDs []string

	for _, volumeID := range sourceVolumeIDs {
		volumeHandle, err := array.ParseVolumeID(ctx, volumeID, defaultArray, nil)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid volume ID format %s: %v", volumeID, err)
		}

		// Validate protocol - only allow block volumes (SCSI, FC, NVMe)
		protocol := strings.ToLower(volumeHandle.Protocol)
		if protocol != protocolSCSI && protocol != protocolFC && protocol != protocolNVMe {
			return nil, status.Errorf(codes.InvalidArgument, "volume group snapshots only support block volumes, got protocol %s for volume %s", volumeHandle.Protocol, volumeID)
		}

		// Validate metro volume - reject metro volumes
		if volumeHandle.IsMetro() {
			return nil, status.Errorf(codes.InvalidArgument, "volume group snapshots do not support metro volumes, volume %s is a metro volume", volumeID)
		}

		// Reconstruct CSI ID from parsed components to ensure consistent format
		csiID := fmt.Sprintf("%s/%s/%s", volumeHandle.LocalUUID, volumeHandle.LocalArrayGlobalID, volumeHandle.Protocol)
		sanitizedVolumeIDs = append(sanitizedVolumeIDs, csiID)
	}
	return sanitizedVolumeIDs, nil
}

// validateAndGroupVolumes validates volumes can be grouped and returns array and detected group ID
//
// Validates volume existence, groups by PowerStore array, and checks for group membership conflicts.
// Uses GetVolumesWithFilter to fetch all volumes with their volume group info in a single API call.
// Returns the array and detected group ID (empty string if no group detected).
func (m *VolumeGroupSnapshotManager) validateAndGroupVolumes(ctx context.Context, volumeIDs []string) (*array.PowerStoreArray, string, error) {
	// Early validation: check for empty volume list
	if len(volumeIDs) == 0 {
		return nil, "", status.Error(codes.InvalidArgument, "no volumes provided for group snapshot")
	}

	var arr *array.PowerStoreArray
	// Step 1: Get array for each volume and ensure all volumes are on the same array
	for _, volumeID := range volumeIDs {
		currentArr, err := m.getArrayForVolume(volumeID)
		if err != nil {
			return nil, "", err
		}

		// Store the first array for comparison
		if arr == nil {
			arr = currentArr
		} else if arr.GlobalID != currentArr.GlobalID {
			// Found a volume on a different array
			return nil, "", status.Error(codes.FailedPrecondition, "all volumes must be on the same PowerStore array")
		}
	}

	// Step 2: Fetch all volumes with volume group info in a single API call
	volumeUUIDs, err := m.extractVolumeIDs(volumeIDs)
	if err != nil {
		return nil, "", err
	}

	filters := map[string]string{
		"id":     fmt.Sprintf("in.(%s)", strings.Join(volumeUUIDs, ",")),
		"select": "id,volume_groups(id)",
	}

	volumes, err := arr.GetClient().GetVolumesWithFilter(ctx, filters)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "failed to query volumes: %v", err)
	}

	// Validate all requested volumes were found
	if len(volumes) != len(volumeUUIDs) {
		foundIDs := make(map[string]bool)
		for _, v := range volumes {
			foundIDs[v.ID] = true
		}
		var missing []string
		for _, id := range volumeUUIDs {
			if !foundIDs[id] {
				missing = append(missing, id)
			}
		}
		return nil, "", status.Errorf(codes.NotFound, "volumes not found: %v", missing)
	}

	// Step 3: Analyze volume group membership from the filter results
	var detectedGroupID string
	hasUngroupedVolumes := false

	for _, vol := range volumes {
		if len(vol.VolumeGroup) == 0 {
			hasUngroupedVolumes = true
		} else {
			groupID := vol.VolumeGroup[0].ID
			if detectedGroupID == "" {
				detectedGroupID = groupID
				log.WithContext(ctx).Infof("Detected volume group %s", groupID)
			} else if detectedGroupID != groupID {
				return nil, "", status.Errorf(codes.FailedPrecondition,
					"volumes are in different volume groups: %s and %s", detectedGroupID, groupID)
			}
		}
	}

	// Ensure consistent state: all grouped or all ungrouped
	if hasUngroupedVolumes && detectedGroupID != "" {
		return nil, "", status.Errorf(codes.FailedPrecondition,
			"some volumes are in volume group %s while others are not in any group", detectedGroupID)
	}

	if detectedGroupID != "" {
		log.WithContext(ctx).Infof("All %d volumes are in volume group %s", len(volumeIDs), detectedGroupID)
	} else {
		log.WithContext(ctx).Infof("All %d volumes are ungrouped", len(volumeIDs))
	}

	return arr, detectedGroupID, nil
}

// getArrayForVolume parses volume ID and returns the corresponding array
func (m *VolumeGroupSnapshotManager) getArrayForVolume(volumeID string) (*array.PowerStoreArray, error) {
	// Parse volume ID to extract array ID and actual volume ID
	parts := strings.Split(volumeID, "/")
	if len(parts) < 3 {
		return nil, status.Error(codes.InvalidArgument, "invalid volume ID format")
	}

	arrayID := parts[1]
	actualVolumeID := parts[0]

	log.Debugf("Looking up volume: CSI ID=%s, Actual ID=%s, Array ID=%s", volumeID, actualVolumeID, arrayID)

	// Get array (volume existence will be validated later during group detection)
	if _, exists := m.arrays[arrayID]; !exists {
		return nil, status.Errorf(codes.NotFound, "array %s not found", arrayID)
	}
	arr := m.arrays[arrayID]

	log.Debugf("Successfully validated array %s for volume %s", arrayID, actualVolumeID)
	return arr, nil
}

// =============================================================================
// VOLUME GROUP MANAGEMENT FUNCTIONS
// =============================================================================
// These functions handle the creation, management, and cleanup of volume groups.
// They ensure volume groups are created with stable naming and proper membership.

// getOrCreateVolumeGroup gets or creates a volume group for snapshots
func (m *VolumeGroupSnapshotManager) getOrCreateVolumeGroup(ctx context.Context, groupName string, volumeIDs []string, parameters map[string]string, arr *array.PowerStoreArray, detectedGroupID string) (*gopowerstore.VolumeGroup, error) {
	// Determine which prefix to use: user-specified or default
	prefix := parameters[volumeGroupPrefixParam]
	if prefix == "" {
		prefix = defaultVolumeGroupPrefix
	} else {
		log.WithContext(ctx).Infof("Using user-specified volume group prefix: %s", prefix)
	}

	if detectedGroupID != "" {
		// Use the detected group ID - get actual group by ID
		log.WithContext(ctx).Infof("Using detected volume group ID: %s", detectedGroupID)
		volumeGroup, err := arr.GetClient().GetVolumeGroup(ctx, detectedGroupID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get detected volume group %s: %s", detectedGroupID, err.Error())
		}

		// If user specified a custom prefix, verify it matches the detected group name prefix
		if prefix != defaultVolumeGroupPrefix && !strings.HasPrefix(volumeGroup.Name, prefix) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"volumes are already in volume group %q (ID: %s), which does not start with the requested volumeGroupPrefix %q",
				volumeGroup.Name, detectedGroupID, prefix)
		}

		log.WithContext(ctx).Infof("Successfully retrieved detected volume group %s", detectedGroupID)
		return &volumeGroup, nil
	}

	// No existing group detected - determine name and create
	volumeGroupName := m.generateStableVolumeGroupName(volumeIDs, groupName, prefix)
	if prefix != defaultVolumeGroupPrefix {
		log.WithContext(ctx).Infof("Using user-specified volume group prefix %q for snapshot %s", prefix, groupName)
	} else {
		log.WithContext(ctx).Infof("No existing volume group detected, creating new group for snapshot %s", groupName)
	}

	// Create new volume group (will handle duplicate name errors appropriately)
	return m.createVolumeGroup(ctx, volumeGroupName, volumeIDs, parameters, arr)
}

// createVolumeGroup creates a new volume group
func (m *VolumeGroupSnapshotManager) createVolumeGroup(ctx context.Context, groupName string, volumeIDs []string, parameters map[string]string, arr *array.PowerStoreArray) (*gopowerstore.VolumeGroup, error) {
	// Extract actual volume IDs from CSI volume IDs
	var sourceVols []string
	for _, v := range volumeIDs {
		actualVolumeID, err := m.extractVolumeID(v)
		if err != nil {
			return nil, err
		}
		sourceVols = append(sourceVols, actualVolumeID)
	}

	// Handle write order consistency parameter with robust parsing
	isWOC := true
	if wocValue, exists := parameters[wocParam]; exists {
		if parsed, err := strconv.ParseBool(strings.TrimSpace(wocValue)); err == nil {
			isWOC = parsed
		} else {
			// For unrecognized values, use default (true) for backward compatibility
			log.WithContext(ctx).Warnf("Unrecognized boolean value '%s' for %s, using default %v: %s", wocValue, wocParam, isWOC, err.Error())
		}
	}
	if !isWOC {
		log.WithContext(ctx).Info("WOC is disabled")
	}

	// Create volume group
	groupCreate := &gopowerstore.VolumeGroupCreate{
		Name:                   groupName,
		VolumeIDs:              sourceVols,
		IsWriteOrderConsistent: &isWOC,
	}

	log.WithContext(ctx).Infof("Creating volume group with name=%s, volumes=%v, WOC=%v", groupName, sourceVols, isWOC)
	group, err := arr.GetClient().CreateVolumeGroup(ctx, groupCreate)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create volume group: %s", err.Error())
	}

	log.WithContext(ctx).Infof("Volume group created with ID=%s", group.ID)

	// Get the created volume group
	volumeGroup, err := arr.GetClient().GetVolumeGroup(ctx, group.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get created volume group: %s", err.Error())
	}

	log.WithContext(ctx).Infof("Retrieved volume group %s has %d volumes", volumeGroup.ID, len(volumeGroup.Volumes))
	for i, vol := range volumeGroup.Volumes {
		log.WithContext(ctx).Infof("Volume %d: ID=%s", i, vol.ID)
	}

	log.WithContext(ctx).Infof("Successfully created volume group %s with ID %s", groupName, volumeGroup.ID)
	return &volumeGroup, nil
}

// ensureVolumesInGroup ensures volumes are properly managed within a volume group
func (m *VolumeGroupSnapshotManager) ensureVolumesInGroup(ctx context.Context, volumeIDs []string, volumeGroup *gopowerstore.VolumeGroup, arr *array.PowerStoreArray) error {
	// Extract actual volume IDs from CSI volume IDs
	actualVolumeIDs, err := m.extractVolumeIDs(volumeIDs)
	if err != nil {
		return err
	}

	// Route based on whether this is an existing or new volume group
	if len(volumeGroup.Volumes) > 0 {
		return m.validateExistingGroupMembership(ctx, actualVolumeIDs, volumeGroup, volumeGroup.ID)
	}

	return m.addVolumesToNewGroup(ctx, actualVolumeIDs, volumeGroup.ID, arr)
}

// extractVolumeID extracts actual volume ID from CSI volume ID format.
//
// CSI volume IDs have format: "volumeID/arrayID/protocol"
// This function extracts just the volumeID part for PowerStore operations.
func (m *VolumeGroupSnapshotManager) extractVolumeID(volumeID string) (string, error) {
	// Simple parsing for volume ID extraction
	// CSI volume IDs have format: "volumeID/arrayID/protocol"
	if volumeID == "" {
		return "", status.Errorf(codes.InvalidArgument, "invalid volume ID format: %s", volumeID)
	}
	parts := strings.Split(volumeID, "/")
	if len(parts) >= 1 {
		return parts[0], nil
	}
	return "", status.Errorf(codes.InvalidArgument, "invalid volume ID format: %s", volumeID)
}

// parseGroupSnapshotID parses CSI format group snapshot ID to extract components
// Expected format: "snapshotID/arrayID/protocol"
// Returns nativeSnapshotID, arrayID, protocol, error
func (m *VolumeGroupSnapshotManager) parseGroupSnapshotID(csiGroupSnapshotID string) (string, string, string, error) {
	parts := strings.Split(csiGroupSnapshotID, "/")
	if len(parts) != 3 {
		return "", "", "", status.Errorf(codes.InvalidArgument, "invalid group snapshot ID format %s, expected format: snapshotID/arrayID/protocol", csiGroupSnapshotID)
	}

	nativeSnapshotID := parts[0]
	arrayID := parts[1]
	protocol := parts[2]

	return nativeSnapshotID, arrayID, protocol, nil
}

// createSnapshotsFromVolumeGroupResponse creates individual CSI snapshots from a PowerStore API volume group snapshot response.
//
// This function converts the PowerStore volume group snapshot API response to CSI snapshot format,
// creating individual snapshot objects for each volume in the group snapshot.
func (m *VolumeGroupSnapshotManager) createSnapshotsFromVolumeGroupResponse(ctx context.Context, volumeGroup *gopowerstore.VolumeGroup, arr *array.PowerStoreArray, creationTime *timestamppb.Timestamp, protocol string) ([]*csi.Snapshot, error) {
	var snapshots []*csi.Snapshot
	arrayID := arr.GetGlobalID()

	for _, vol := range volumeGroup.Volumes {
		log.WithContext(ctx).Debugf("Volume: ID=%s, State=%s", vol.ID, vol.State)

		// Parse volume ID - may be native UUID or CSI format (volumeUUID/arrayID/protocol)
		volID := strings.Split(vol.ID, "/")
		volumeUUID := volID[0]

		// Use protocol from vol.ID if in CSI format, otherwise use the passed-in protocol
		volProtocol := protocol
		if len(volID) >= 3 {
			volProtocol = volID[2]
		}

		// Handle SourceVolumeId construction with fallback for missing SourceID
		var sourceVolumeID string
		if vol.ProtectionData.SourceID == "" {
			log.WithContext(ctx).Warnf("Volume %s has invalid protection data: missing SourceID. Using volume UUID (%s) as fallback for SourceVolumeId", vol.ID, volumeUUID)
			sourceVolumeID = volumeUUID // Fallback to volume UUID
		} else {
			sourceVolumeID = vol.ProtectionData.SourceID
		}

		// Create individual CSI snapshot with proper CSI format
		csiSnapshot := &csi.Snapshot{
			SnapshotId:      volumeUUID + "/" + arrayID + "/" + volProtocol,
			ReadyToUse:      vol.State == "Ready",
			SourceVolumeId:  sourceVolumeID + "/" + arrayID + "/" + volProtocol,
			SizeBytes:       vol.Size,
			CreationTime:    creationTime,
			GroupSnapshotId: volumeGroup.ID,
		}

		snapshots = append(snapshots, csiSnapshot)
	}

	return snapshots, nil
}

// extractVolumeIDs extracts actual volume IDs from CSI volume ID format.
//
// CSI volume IDs have format: "volumeID/arrayID/protocol"
// This function extracts just the volumeID part for PowerStore operations.
func (m *VolumeGroupSnapshotManager) extractVolumeIDs(volumeIDs []string) ([]string, error) {
	var actualVolumeIDs []string
	for _, volumeID := range volumeIDs {
		extractedID, err := m.extractVolumeID(volumeID)
		if err != nil {
			return nil, err
		}
		actualVolumeIDs = append(actualVolumeIDs, extractedID)
	}

	if len(actualVolumeIDs) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no valid volume IDs found")
	}

	return actualVolumeIDs, nil
}

// validateExistingGroupMembership validates that requested volumes match existing group membership.
//
// This function enforces strict membership consistency for existing volume groups.
// Once a volume group is created, its membership cannot be changed to ensure
// data consistency and predictable snapshot behavior.
func (m *VolumeGroupSnapshotManager) validateExistingGroupMembership(ctx context.Context, actualVolumeIDs []string, volumeGroup *gopowerstore.VolumeGroup, volumeGroupID string) error {
	// Build map of existing volumes for efficient lookup
	existingVolumes := make(map[string]bool)
	for _, vol := range volumeGroup.Volumes {
		existingVolumes[vol.ID] = true
	}

	// Check for membership changes
	missingVolumes := m.findMissingVolumes(actualVolumeIDs, existingVolumes)
	removedVolumes := m.findRemovedVolumes(actualVolumeIDs, volumeGroup.Volumes)

	// Validate no membership changes
	if len(missingVolumes) > 0 || len(removedVolumes) > 0 {
		return m.createMembershipValidationError(missingVolumes, removedVolumes)
	}

	log.WithContext(ctx).Infof("Volume group membership validated - all %d volumes are already in group %s",
		len(actualVolumeIDs), volumeGroupID)
	return nil
}

// addVolumesToNewGroup adds volumes to a newly created (empty) volume group.
//
// This function handles the first-time population of a volume group with all
// requested volumes. It's called only when the volume group is empty.
func (m *VolumeGroupSnapshotManager) addVolumesToNewGroup(ctx context.Context, actualVolumeIDs []string, volumeGroupID string, arr *array.PowerStoreArray) error {
	log.WithContext(ctx).Infof("Adding %d volumes to newly created volume group %s", len(actualVolumeIDs), volumeGroupID)

	volumeMembers := &gopowerstore.VolumeGroupMembers{
		VolumeIDs: actualVolumeIDs,
	}

	if _, err := arr.GetClient().AddMembersToVolumeGroup(ctx, volumeMembers, volumeGroupID); err != nil {
		return status.Errorf(codes.Internal, "failed to add volumes to group %s: %s",
			volumeGroupID, err.Error())
	}

	log.WithContext(ctx).Infof("Successfully added %d volumes to group %s", len(actualVolumeIDs), volumeGroupID)
	return nil
}

// findMissingVolumes identifies requested volumes not present in existing group
func (m *VolumeGroupSnapshotManager) findMissingVolumes(requestedVolumes []string, existingVolumes map[string]bool) []string {
	var missingVolumes []string
	for _, volID := range requestedVolumes {
		if !existingVolumes[volID] {
			missingVolumes = append(missingVolumes, volID)
		}
	}
	return missingVolumes
}

// findRemovedVolumes identifies existing volumes not present in request
func (m *VolumeGroupSnapshotManager) findRemovedVolumes(requestedVolumes []string, existingVolumes []gopowerstore.Volume) []string {
	var removedVolumes []string
	for _, vol := range existingVolumes {
		found := false
		for _, volID := range requestedVolumes {
			if vol.ID == volID {
				found = true
				break
			}
		}
		if !found {
			removedVolumes = append(removedVolumes, vol.ID)
		}
	}
	return removedVolumes
}

// createMembershipValidationError creates detailed error message for membership validation failures.
//
// This function builds a comprehensive error message that clearly identifies
func (m *VolumeGroupSnapshotManager) createMembershipValidationError(missingVolumes []string, removedVolumes []string) error {
	errorMsg := "volume group membership cannot be changed from initial configuration"
	if len(missingVolumes) > 0 {
		errorMsg += fmt.Sprintf(" (missing volumes: %v)", missingVolumes)
	}
	if len(removedVolumes) > 0 {
		errorMsg += fmt.Sprintf(" (removed volumes: %v)", removedVolumes)
	}

	log.Errorf("Volume group membership validation failed: %s", errorMsg)
	return status.Error(codes.FailedPrecondition, errorMsg)
}

// =============================================================================
// SNAPSHOT MANAGEMENT FUNCTIONS
// =============================================================================
// These functions handle the creation, retrieval, and cleanup of volume group snapshots.
// They interact with the PowerStore API to manage snapshot lifecycle.

// createVolumeGroupSnapshot creates a volume group snapshot using PowerStore API
func (m *VolumeGroupSnapshotManager) createVolumeGroupSnapshot(ctx context.Context, snapshotName string, volumeGroupID string, arr *array.PowerStoreArray, sourceVolumeIDs []string) (*csi.VolumeGroupSnapshot, error) {
	// Create the volume group snapshot
	snapshotCreate := &gopowerstore.VolumeGroupSnapshotCreate{
		Name:        snapshotName,
		Description: fmt.Sprintf("CSI VolumeGroupSnapshot %s", snapshotName),
	}

	snapshotResp, err := arr.GetClient().CreateVolumeGroupSnapshot(ctx, volumeGroupID, snapshotCreate)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create volume group snapshot: %s", err.Error())
	}

	// Get the created volume group snapshot to retrieve creation time and individual snapshots
	createdSnapshot, err := arr.GetClient().GetVolumeGroup(ctx, snapshotResp.ID)
	if err != nil {
		// Check if this is an API error
		if apiError, ok := err.(gopowerstore.APIError); ok {
			if apiError.NotFound() {
				// NotFound error - snapshot likely wasn't created
				log.WithContext(ctx).Errorf("Created snapshot %s not found during retrieval - assuming creation failed", snapshotResp.ID)
				return nil, status.Errorf(codes.Internal, "failed to get created volume group snapshot: %s", err.Error())
			}
			// Other API error - snapshot was created but retrieval failed, attempt cleanup
			log.WithContext(ctx).Warnf("API error retrieving created snapshot %s, attempting cleanup: %s", snapshotResp.ID, err.Error())
			if cleanupErr := m.cleanupFailedGroupSnapshot(ctx, snapshotResp.ID, arr); cleanupErr != nil {
				log.WithContext(ctx).Errorf("Failed to cleanup snapshot %s: %s", snapshotResp.ID, cleanupErr.Error())
			}
		} else {
			// For non-API errors (network, communication, etc.), don't attempt cleanup
			log.WithContext(ctx).Errorf("Communication error retrieving created snapshot %s, not attempting cleanup: %s", snapshotResp.ID, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "failed to get created volume group snapshot: %s", err.Error())
	}
	log.WithContext(ctx).Infof("Created volume group snapshot %s has %d volumes", snapshotResp.ID, len(createdSnapshot.Volumes))
	// Get array ID for snapshot ID generation
	arrayID := arr.GetGlobalID()
	// Parse creation time
	creationTime := m.parseCreationTime(createdSnapshot)

	// Extract protocol from the original request since PowerStore returns volumes in UUID format
	var protocol string
	if len(sourceVolumeIDs) > 0 {
		volID := strings.Split(sourceVolumeIDs[0], "/")
		if len(volID) >= 3 {
			protocol = volID[2]
		}
	}

	// Create the CSI format group snapshot ID once and reuse it
	csiGroupSnapshotID := snapshotResp.ID + "/" + arrayID + "/" + protocol

	// Create individual volume snapshots from the volume group snapshot
	var snapsList []*csi.Snapshot
	for _, vol := range createdSnapshot.Volumes {
		log.WithContext(ctx).Debugf("Volume: ID=%s, State=%s", vol.ID, vol.State)

		// Handle SourceVolumeId construction with fallback for missing SourceID
		var sourceVolumeID string
		if vol.ProtectionData.SourceID == "" {
			log.WithContext(ctx).Warnf("Volume %s has invalid protection data: missing SourceID. Using volume ID as fallback for SourceVolumeId", vol.ID)
			sourceVolumeID = vol.ID // Fallback to volume ID
		} else {
			sourceVolumeID = vol.ProtectionData.SourceID
		}

		// Create individual CSI snapshot with proper CSI format
		csiSnapshot := &csi.Snapshot{
			SnapshotId:      vol.ID + "/" + arrayID + "/" + protocol,
			ReadyToUse:      vol.State == "Ready",
			SourceVolumeId:  sourceVolumeID + "/" + arrayID + "/" + protocol,
			SizeBytes:       vol.Size,
			CreationTime:    creationTime,
			GroupSnapshotId: csiGroupSnapshotID,
		}

		log.WithContext(ctx).Debugf("Created individual snapshot: ID=%s, SourceVolumeID=%s, Ready=%v",
			csiSnapshot.SnapshotId, csiSnapshot.SourceVolumeId, csiSnapshot.ReadyToUse)

		snapsList = append(snapsList, csiSnapshot)
	}

	// Create the volume group snapshot response with CSI format
	groupSnapshot := &csi.VolumeGroupSnapshot{
		GroupSnapshotId: csiGroupSnapshotID,
		Snapshots:       snapsList,
		ReadyToUse:      true,
		CreationTime:    creationTime,
	}

	log.WithContext(ctx).Infof("Successfully created volume group snapshot %s with CSI ID %s and %d individual snapshots", snapshotName, csiGroupSnapshotID, len(snapsList))

	return groupSnapshot, nil
}

// cleanupFailedGroupSnapshot cleans up a failed group snapshot creation
func (m *VolumeGroupSnapshotManager) cleanupFailedGroupSnapshot(ctx context.Context, volumeGroupSnapshotID string, arr *array.PowerStoreArray) error {
	if arr == nil {
		log.WithContext(ctx).Error("No array provided for cleanup")
		return status.Error(codes.Internal, "no array provided")
	}

	log.WithContext(ctx).Warnf("Cleaning up failed group snapshot creation for volume group %s using array %s", volumeGroupSnapshotID, arr.GetGlobalID())

	// Delete the volume group
	_, err := arr.GetClient().DeleteVolumeGroup(ctx, volumeGroupSnapshotID)
	if err != nil {
		// Check if this is a not found error - if so, treat as success (idempotent)
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			log.WithContext(ctx).Infof("Volume group %s not found during cleanup, assuming already deleted", volumeGroupSnapshotID)
			return nil
		}
		log.WithContext(ctx).Warnf("Failed to delete volume group %s during cleanup: %s", volumeGroupSnapshotID, err.Error())
		return err
	}

	log.WithContext(ctx).Infof("Successfully cleaned up failed group snapshot creation for volume group %s", volumeGroupSnapshotID)
	return nil
}

// parseCreationTime parses creation time from PowerStore VolumeGroup response
func (m *VolumeGroupSnapshotManager) parseCreationTime(volumeGroup gopowerstore.VolumeGroup) *timestamppb.Timestamp {
	if volumeGroup.CreationTimeStamp != "" {
		// Parse the timestamp string - PowerStore uses ISO format
		parsedTime, err := time.Parse(time.RFC3339, volumeGroup.CreationTimeStamp)
		if err == nil {
			return timestamppb.New(parsedTime)
		}
		// Fallback to current time if parsing fails
		log.Warnf("Failed to parse creation timestamp %s: %s, using current time", volumeGroup.CreationTimeStamp, err.Error())
	}
	// Fallback to current time if no timestamp available
	return timestamppb.Now()
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================
// These functions provide helper utilities for naming, hashing, and data processing.
// They are reusable components that support the main functionality.

// generateStableVolumeGroupName generates a stable, identifiable volume group name based on volume IDs.
//
// This function creates a consistent name for volume groups based on the actual volume IDs
// rather than the snapshot name, because:
// 1. Snapshot names can change between different snapshots of the same volume set
// 2. Snapshot names often contain UUIDs or timestamps that make them unstable
// 3. The same volume set should always map to the same volume group for consistency
//
// The naming convention is: "{prefix}-{volume-set-hash}"
// where the hash is derived from the sorted volume IDs to ensure:
// - Consistent naming regardless of snapshot name changes
// - Order independence (same volumes in different order = same name)
// - Easy identification of CSI-created volume groups
// - Stable mapping between volume sets and volume groups
func (m *VolumeGroupSnapshotManager) generateStableVolumeGroupName(volumeIDs []string, snapshotName string, prefix string) string {
	log.Debugf("Generating volume group name for snapshot %q with volumes %v using prefix %q", snapshotName, volumeIDs, prefix)

	// Extract actual volume IDs (remove array and protocol info)
	actualVolumeIDs, err := m.extractVolumeIDs(volumeIDs)
	if err != nil {
		log.Errorf("Failed to extract volume IDs: %v", err)
		return ""
	}

	// Sort volume IDs to ensure consistent naming regardless of order
	sort.Strings(actualVolumeIDs)

	// Create a unique identifier from the volume set
	volumeSetHash := m.generateVolumeSetHash(actualVolumeIDs)

	// Generate identifiable name with prefix and volume set hash
	groupName := fmt.Sprintf("%s-%s", prefix, volumeSetHash)

	log.Debugf("Generated volume group name %q for volume set hash %s using prefix %q", groupName, volumeSetHash, prefix)
	return groupName
}

// generateVolumeSetHash generates a stable hash from a set of volume IDs
func (m *VolumeGroupSnapshotManager) generateVolumeSetHash(volumeIDs []string) string {
	// Join sorted volume IDs and create a short hash
	joined := strings.Join(volumeIDs, "-")

	// Use first 8 characters of SHA256 hash for uniqueness
	hash := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("%x", hash)[:8]
}
