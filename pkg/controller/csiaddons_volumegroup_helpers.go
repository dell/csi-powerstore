/*
 *
 * Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
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
	"fmt"
	"strings"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	log "github.com/dell/csmlog"
	"github.com/dell/gopowerstore"
	"github.com/container-storage-interface/spec/lib/go/csi"
	repgrpc "github.com/csi-addons/spec/lib/go/replication"
)

const (
	// defaultVGPrefix is the default prefix used for volume group names in replication
	defaultVGPrefix = "vg"

	// PromotedPrimary indicates the volume is promoted as primary
	PromotedPrimary = "primary"
	// PromotedSecondary indicates the volume is promoted as secondary
	PromotedSecondary = "secondary"
)

// checkExistingReplicationVolumeGroup checks if any of the provided volume IDs are already in replication volume groups
// on the specified array. Returns the existing volume group if found, or nil if not found.
func checkExistingReplicationVolumeGroup(ctx context.Context, arr *array.PowerStoreArray, volumeIDs []string, prefix string) (*gopowerstore.VolumeGroup, error) {
	log.Infof("Checking if %d volumes are already in replication on array %s", len(volumeIDs), arr.GetGlobalID())

	for _, volumeID := range volumeIDs {
		log.Infof("Checking if volume %s is already in replication", volumeID)

		vol, err := arr.Client.GetVolume(ctx, volumeID)
		if err != nil {
			log.Errorf("Failed to get volume %s: %v", volumeID, err)
			continue
		}

		if len(vol.VolumeGroup) == 0 {
			continue
		}

		volVG := vol.VolumeGroup[0]

		vg, err := arr.Client.GetVolumeGroup(ctx, volVG.ID)
		if err != nil {
			log.Errorf("Failed to get volume group %s for volume %s: %v", volVG.ID, volumeID, err)
			continue
		}

		// Skip if not a replication volume group
		if !strings.HasPrefix(vg.Name, prefix) {
			continue
		}

		// Check if this volume group has replication
		_, err = arr.Client.GetReplicationSessionByLocalResourceID(ctx, vg.ID)
		if err == nil {
			log.Infof("Volume %s is already in replication volume group %s", volumeID, vg.Name)
			return &vg, nil
		}
	}

	log.Infof("No volumes found in existing replication volume groups on array %s", arr.GetGlobalID())
	return nil, nil
}

// getVolumeGroupPrefix extracts the prefix parameter with default fallback
func getVolumeGroupPrefix(params map[string]string) string {
	prefix := params[CSIAddonsParamVolumeGroupPrefix]
	if prefix == "" {
		prefix = defaultVGPrefix // default for backward compatibility
	}
	return prefix
}

// vgGetParameters extracts and validates all required parameters for volume group operations
func vgGetParameters(params map[string]string) (map[string]string, error) {
	if params == nil {
		log.Errorf("vgGetParameters: request parameters are required")
		return nil, fmt.Errorf("request parameters are required")
	}

	sourceArrayID := params[sourceArrayParameter]
	if sourceArrayID == "" {
		log.Errorf("vgGetParameters: sourceArray parameter is required")
		return nil, fmt.Errorf("sourceArray parameter is required")
	}

	targetArrayID := params[targetArrayParameter]
	if targetArrayID == "" {
		log.Errorf("vgGetParameters: targetArray parameter is required")
		return nil, fmt.Errorf("targetArray parameter is required")
	}

	return params, nil
}

// getVolumeGroupName takes the indicated parameters and returns a name like
// tw-5085aa54-bafb-4f3f-a001-9c34de382f3d-APM8936-Five_Minutes
// where the requestName argument is addonsVolumeGroupUID
func getVolumeGroupName(prefix string, requestName string, rpo string, remoteClusterName string) string {
	// Remove the prefix from the request name
	requestName = strings.TrimPrefix(requestName, "vgrcontent-")

	vgName := prefix + "-" + requestName + "-" + remoteClusterName + "-" + rpo
	if len(vgName) > 128 {
		vgName = vgName[:128]
	}
	log.Infof("getVolumeGroupName %s from %s %s %s", vgName, requestName, rpo, remoteClusterName)
	return vgName
}

// findArrayWithVolumeGroup finds a VolumeGroup and the array that contains it (either source or target).
// The arguments required are:
// volumeGroupName -- the name of the volume group
// sourceArrayID -- the ID of the source array (primary)
// targetArrayID -- the ID of the target array (secondary)
// isReplicationDestination -- true if we want to find the VG that is the replication destination
func findArrayWithVolumeGroup(ctx context.Context, arrayMap map[string]*array.PowerStoreArray, volumeGroupName,
	sourceArrayID, targetArrayID string, isReplicationDestination bool,
) (*array.PowerStoreArray, *gopowerstore.VolumeGroup, error) {
	log.Infof("findArrayWithVolumeGroup volumeGroupName %s sourceArrayID %s targetArrayID %s isReplicationDestination %t", volumeGroupName, sourceArrayID, targetArrayID, isReplicationDestination)

	// Extract vgName from volumeGroupContext
	if volumeGroupName == "" {
		return nil, nil, fmt.Errorf("volumeGroupName not found in volume group context")
	}
	if sourceArrayID == "" || arrayMap[sourceArrayID] == nil {
		return nil, nil, fmt.Errorf("sourceArray not found in volume group context")
	}
	if targetArrayID == "" || arrayMap[targetArrayID] == nil {
		return nil, nil, fmt.Errorf("targetArray not found in volume group context")
	}

	log.Infof("findArrayWithVolumeGroup volumeGroupName %s sourceArrayID %s targetArrayID %s isReplicationDestination %t",
		volumeGroupName, sourceArrayID, targetArrayID, isReplicationDestination)

	// Try the source array first
	client := arrayMap[sourceArrayID].Client
	vg, err := client.GetVolumeGroupByName(ctx, volumeGroupName)
	if err != nil {
		log.Infof("findArrayWithVolumeGroup: could not find array %s", sourceArrayID)
	} else if vg.IsReplicationDestination == isReplicationDestination {
		return arrayMap[sourceArrayID], &vg, nil
	}

	// Try the target array first
	client = arrayMap[targetArrayID].Client
	vg, err = client.GetVolumeGroupByName(ctx, volumeGroupName)
	if err != nil {
		log.Infof("findArrayWithVolumeGroup: could not find array %s", targetArrayID)
	} else if vg.IsReplicationDestination == isReplicationDestination {
		return arrayMap[targetArrayID], &vg, nil
	}

	return nil, nil, fmt.Errorf("volume group %s not found on any array", volumeGroupName)
}

// findArrayWithVolumeGroupID finds array and volume group by ID only
func findArrayWithVolumeGroupID(ctx context.Context, arrayMap map[string]*array.PowerStoreArray,
	volumeGroupID string,
) (*array.PowerStoreArray, *gopowerstore.VolumeGroup, error) {
	log.Infof("findArrayWithVolumeGroupID volumeGroupID %s", volumeGroupID)

	// Extract vgName from volumeGroupContext
	if volumeGroupID == "" {
		return nil, nil, fmt.Errorf("volumeGroupID not found in volume group context")
	}

	// Iterate through all arrays to find the volume group
	for _, arr := range arrayMap {
		vg, err := findVolumeGroupOnArray(ctx, arr, volumeGroupID)
		if err == nil && vg != nil {
			return arr, vg, nil
		}
	}

	log.Infof("Did not find volume group %s on any array", volumeGroupID)
	return nil, nil, nil
}

// findVolumeGroupOnArray finds a volume group on a specific array by ID or name
// This is used when we know which array to search (avoids non-deterministic behavior)
func findVolumeGroupOnArray(ctx context.Context, arr *array.PowerStoreArray, volumeGroupID string) (*gopowerstore.VolumeGroup, error) {
	log.Infof("findVolumeGroupOnArray: searching for VG %s on array %s", volumeGroupID, arr.GetGlobalID())

	if volumeGroupID == "" {
		return nil, fmt.Errorf("volumeGroupID is empty")
	}

	// Try to find by exact ID first
	vg, err := arr.Client.GetVolumeGroup(ctx, volumeGroupID)
	if err == nil {
		log.Infof("Found VG %s by exact ID on array %s", volumeGroupID, arr.GetGlobalID())
		return &vg, nil
	}

	// Fall back to searching by name (volumeGroupID is likely the VolumeGroupContent UID)
	vgs, err := arr.Client.GetVolumeGroups(ctx)
	if err != nil {
		log.Errorf("Failed to get volume groups for array %s: %v", arr.GlobalID, err)
		return nil, err
	}

	for _, vg := range vgs {
		if vg.Name == volumeGroupID {
			log.Infof("Found VG %s by name match on array %s (VG name: %s, VG ID: %s)", volumeGroupID, arr.GetGlobalID(), vg.Name, vg.ID)
			return &vg, nil
		}
	}

	return nil, fmt.Errorf("volume group with ID %s not found on array %s", volumeGroupID, arr.GetGlobalID())
}

// mapReplicationSessionStateToStatus maps PowerStore ReplicationSession state to CSI-Addons Status enum
func mapReplicationSessionStateToStatus(sessionState gopowerstore.RSStateEnum) (repgrpc.GetVolumeReplicationInfoResponse_Status, string) {
	switch sessionState {
	case gopowerstore.RsStateOk:
		// Replication is synchronized and healthy
		return repgrpc.GetVolumeReplicationInfoResponse_HEALTHY, "replication is synchronized and healthy"

	case gopowerstore.RsStateSynchronizing:
		// Sync in progress - degraded until complete
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication is synchronizing"

	case gopowerstore.RsStateInitializing:
		// Initial sync in progress - degraded until complete
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication is initializing"

	case gopowerstore.RsStateResuming:
		// Resuming from pause - degraded until complete
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication is resuming from pause"

	case gopowerstore.RsStateReprotecting:
		// Reprotecting after failover - degraded until complete
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication is reprotecting after failover"

	case gopowerstore.RsStateFailedOver:
		// Failed over - degraded on old primary, needs reprotect
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication has failed over, reprotect required"

	case gopowerstore.RsStatePaused:
		// Paused - requires intervention
		return repgrpc.GetVolumeReplicationInfoResponse_ERROR, "replication is paused, requires intervention"

	case gopowerstore.RsStatePausedForMigration:
		// Paused for migration - requires intervention
		return repgrpc.GetVolumeReplicationInfoResponse_ERROR, "replication is paused for migration"

	case gopowerstore.RsStatePausedForNdu:
		// Paused for NDU - requires intervention
		return repgrpc.GetVolumeReplicationInfoResponse_ERROR, "replication is paused for NDU"

	case gopowerstore.RsStateSystemPaused:
		// System paused - requires intervention
		return repgrpc.GetVolumeReplicationInfoResponse_ERROR, "replication is system paused"

	case gopowerstore.RsStateError:
		// Replication error
		return repgrpc.GetVolumeReplicationInfoResponse_ERROR, "replication is in error state"

	case gopowerstore.RsStateFractured:
		// Replication fractured - error state
		return repgrpc.GetVolumeReplicationInfoResponse_ERROR, "replication is fractured"

	case gopowerstore.RsStateFailingOver:
		// Failover in progress - degraded during transition
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication is failing over"

	case gopowerstore.RsStateFailingOverForDR:
		// DR failover in progress - degraded during transition
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication is failing over for DR"

	case gopowerstore.RsStatePartialCutoverForMigration:
		// Partial cutover - degraded during migration
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication is in partial cutover for migration"

	case gopowerstore.RsStateSwitchingToMetroSync:
		// Switching to metro sync - degraded during transition
		return repgrpc.GetVolumeReplicationInfoResponse_DEGRADED, "replication is switching to metro sync"

	default:
		// Unknown state
		return repgrpc.GetVolumeReplicationInfoResponse_UNKNOWN, fmt.Sprintf("replication state is unknown: %s", sessionState)
	}
}

// ExecuteActionOnReplicationSession executes an action on a replication session
func ExecuteActionOnReplicationSession(ctx context.Context, array *array.PowerStoreArray, vgID string, action gopowerstore.ActionType) error {
	log.Infof("attempting to ExecuteActionOnReplicationSession called vgID %s action %s", vgID, action)
	rs, err := array.GetClient().GetReplicationSessionByLocalResourceID(ctx, vgID)
	if err != nil {
		log.Errorf("ExecuteActionOnReplicationSession failed: Failed to get replication session for volume group %s: %v", vgID, err)
		return err
	}
	log.Infof("Found replication session %s for volume group %s", rs.ID, vgID)
	err = ExecuteAction(&rs, array.GetClient(), action, nil)
	if err != nil {
		log.Errorf("DeleteVolumeGroup failed: Failed to ExecuteAction %v on replication session %s for volume group %s: %v", action, rs.ID, vgID, err)
		return err
	}
	log.Infof("Executed action %s on replication session %s for volume group %s", action, rs.ID, vgID)
	return nil
}

// getDefaultCapability returns default capability for addons replication
func getDefaultCapability() *csi.VolumeCapability {
	return &csi.VolumeCapability{
		AccessType: &csi.VolumeCapability_Mount{
			Mount: &csi.VolumeCapability_MountVolume{
				FsType: "ext4",
			},
		},
		AccessMode: &csi.VolumeCapability_AccessMode{
			Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		},
	}
}

// removeMembersFromVolumeGroup removes volumes from a volume group
func removeMembersFromVolumeGroup(ctx context.Context, arr *array.PowerStoreArray, vgID string, volumeIDs []string) error {
	log := log.WithContext(ctx)

	for _, volID := range volumeIDs {
		removeMembers := &gopowerstore.VolumeGroupMembers{VolumeIDs: []string{volID}}
		_, err := arr.Client.RemoveMembersFromVolumeGroup(ctx, removeMembers, vgID)
		if err != nil {
			log.Errorf("Failed to remove volume %s from volume group: %v", volID, err)
			return fmt.Errorf("failed to remove volume %s from volume group: %v", volID, err)
		}
	}
	return nil
}

// unassignProtectionPolicyFromVolumeGroup modifies the VG to remove the protection policy.
func unassignProtectionPolicyFromVolumeGroup(ctx context.Context, arr *array.PowerStoreArray, vg *gopowerstore.VolumeGroup) error {
	// Attempt to remove the protection policy.
	if vg.ProtectionPolicyID != "" {
		log.Infof("attempting to remove protection policy %s from volume group %s", vg.ProtectionPolicyID, vg.ID)
		_, err := arr.GetClient().UpdateVolumeGroupProtectionPolicy(ctx, vg.ID, &gopowerstore.VolumeGroupChangePolicy{
			ProtectionPolicyID: "",
		})
		if err != nil {
			if apiErr, ok := err.(gopowerstore.APIError); ok && apiErr.NotFound() {
				return nil
			}
			log.Errorf("Unable to un-assign PP from Volume Group: %v", err)
			return fmt.Errorf("unable to un-assign PP from Volume Group: %v", err)
		}
		return nil
	}
	return nil
}
