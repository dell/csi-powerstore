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
	"slices"
	"strings"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	log "github.com/dell/csmlog"
	"github.com/dell/gopowerstore"
	"github.com/container-storage-interface/spec/lib/go/csi"
	csiaddonsreplication "github.com/csi-addons/spec/lib/go/replication"
	volumegrouprpc "github.com/csi-addons/spec/lib/go/volumegroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CSI-Addons replication parameter keys
const (
	// CSIAddonsParamRemoteSystem is the parameter key for remote PowerStore system name
	CSIAddonsParamRemoteSystem = "replication.storage.dell.com/remoteSystem"
	// CSIAddonsParamRPO is the parameter key for RPO (e.g., "Five_Minutes", "Zero")
	CSIAddonsParamRPO = "replication.storage.dell.com/rpo"
	// CSIAddonsParamReplicationMode is the parameter key for replication mode (async/sync/metro)
	CSIAddonsParamReplicationMode = "replication.storage.dell.com/replicationMode"
	// CSIAddonsParamVolumeGroupPrefix is the parameter key for volume group prefix
	CSIAddonsParamVolumeGroupPrefix = "replication.storage.dell.com/volumeGroupPrefix"
	// CSIAddonsManagedByLabel is the label to mark PVs managed by CSI-Addons
	CSIAddonsManagedByLabel = "replication.storage.dell.com/managed-by"
	// CSIAddonsManagedByValue is the value for the managed-by label
	CSIAddonsManagedByValue = "csi-addons"

	// VolumeGroup replication parameter keys
	sourceArrayParameter     = "replication.storage.dell.com/sourceArray"
	targetArrayParameter     = "replication.storage.dell.com/targetArray"
	targetArrayNameParameter = CSIAddonsParamRemoteSystem
	volumeGroupNameParameter = "volumeGroupName"
	volumeGroupIDParameter   = "volumeGroupID"
	rpoParameter             = CSIAddonsParamRPO
	replicationModeParameter = CSIAddonsParamReplicationMode
)

// CSIAddonsReplicationServer implements the CSI-Addons Replication Controller service
// This provides replication capabilities for integration with OpenShift DR (Ramen)
// and other CSI-Addons compliant DR orchestrators.
type CSIAddonsReplicationServer struct {
	csiaddonsreplication.UnimplementedControllerServer
	service *Service // Reference to existing CSI controller service
}

// CSIAddonsVolumeGroupServer implements the CSI-Addons VolumeGroup Controller service
type CSIAddonsVolumeGroupServer struct {
	volumegrouprpc.UnimplementedControllerServer
	service *Service // Reference to existing CSI controller service
}

// NewCSIAddonsReplicationServer creates a new CSI-Addons replication server
func NewCSIAddonsReplicationServer(service *Service) *CSIAddonsReplicationServer {
	return &CSIAddonsReplicationServer{
		service: service,
	}
}

// NewCSIAddonsVolumeGroupServer creates a new CSI-Addons volumegroup server
func NewCSIAddonsVolumeGroupServer(service *Service) *CSIAddonsVolumeGroupServer {
	return &CSIAddonsVolumeGroupServer{
		service: service,
	}
}

// RegisterCSIAddonsReplicationServer registers the CSI-Addons replication server with gRPC
func RegisterCSIAddonsReplicationServer(server *grpc.Server, srv *CSIAddonsReplicationServer) {
	csiaddonsreplication.RegisterControllerServer(server, srv)
}

// EnableVolumeReplication enables replication for a volume or volume group.
// This sets up the replication session on PowerStore by assigning a Protection Policy
// to a volume group (for block volumes) or NAS server (for NFS volumes).
//
// Supported replication modes:
// - ASYNC: Asynchronous replication with configurable RPO (e.g., "Five_Minutes")
// - SYNC: Synchronous replication with Zero RPO
//
// NOTE: Metro mode is NOT supported by CSI-Addons because CSI-Addons doesn't have
// replication actions (failover, reprotect, etc.) that Metro requires.
// For Metro replication, use CSM-DR instead.
//
// Parameters from VolumeReplicationClass:
// - replication.storage.dell.com/remoteSystem: Remote PowerStore system name (required)
// - replication.storage.dell.com/rpo: RPO for async replication (e.g., "Five_Minutes")
// - replication.storage.dell.com/replicationMode: async/sync (default: async)
// - replication.storage.dell.com/volumeGroupPrefix: Prefix for volume group name (default: csi-addons-vg)
func (s *CSIAddonsReplicationServer) EnableVolumeReplication(
	ctx context.Context,
	req *csiaddonsreplication.EnableVolumeReplicationRequest,
) (*csiaddonsreplication.EnableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("CSI-Addons EnableVolumeReplication called with request: %+v", req)

	// Validate request
	if err := s.validateEnableReplicationRequest(req); err != nil {
		log.Errorf("EnableVolumeReplication validation failed: %v", err)
		return nil, err
	}

	// Extract volume ID from replication source
	volumeID, volumeGroupID, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		log.Errorf("EnableVolumeReplication failed to extract replication source: %v", err)
		return nil, err
	}

	// Get parameters from request
	params := req.GetParameters()
	if params == nil {
		params = make(map[string]string)
	}

	// Extract replication parameters
	remoteSystemName, ok := params[CSIAddonsParamRemoteSystem]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing required parameter: "+CSIAddonsParamRemoteSystem)
	}

	repMode := strings.ToUpper(params[CSIAddonsParamReplicationMode])
	if repMode == "" {
		repMode = identifiers.AsyncMode // Default to ASYNC
	}

	rpo := params[CSIAddonsParamRPO]
	vgPrefix := params[CSIAddonsParamVolumeGroupPrefix]
	if vgPrefix == "" {
		vgPrefix = defaultVGPrefix // Default volume group prefix
	}

	// Handle volume replication
	if volumeID != "" {
		log.Infof("EnableVolumeReplication: Enabling replication for volume %s with mode %s", volumeID, repMode)
		return s.enableVolumeReplicationForVolume(ctx, volumeID, remoteSystemName, repMode, rpo, vgPrefix, params)
	}

	// Handle volume group replication
	if volumeGroupID != "" {
		log.Infof("EnableVolumeReplication: Enabling replication for volume group %s with mode %s", volumeGroupID, repMode)
		return s.enableVolumeReplicationForVolumeGroup(ctx, volumeGroupID, remoteSystemName, repMode, rpo, params)
	}

	// This should never be reached due to earlier validation
	log.Errorf("EnableVolumeReplication: unreachable code reached - neither volumeID nor volumeGroupID was set")
	return nil, status.Error(codes.Internal, "internal error: invalid state")
}

// enableVolumeReplicationForVolume enables replication for a single volume
func (s *CSIAddonsReplicationServer) enableVolumeReplicationForVolume(
	ctx context.Context,
	volumeID string,
	remoteSystemName string,
	repMode string,
	rpo string,
	vgPrefix string,
	_ map[string]string,
) (*csiaddonsreplication.EnableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)

	// Parse volume handle to get array info
	volumeHandle, err := array.ParseVolumeID(ctx, volumeID, s.service.DefaultArray(), nil)
	if err != nil {
		log.Errorf("EnableVolumeReplication: Failed to parse volume ID %s: %v", volumeID, err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume ID: %v", err)
	}

	localVolumeUUID := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := strings.ToLower(volumeHandle.Protocol)

	log.Infof("EnableVolumeReplication: Parsed volume - UUID: %s, ArrayID: %s, Protocol: %s",
		localVolumeUUID, arrayID, protocol)

	// Get the array
	arr, ok := s.service.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "array with ID %s not found", arrayID)
	}

	client := arr.GetClient()

	// Check if volume already has replication configured (idempotency check)
	existingSession, err := client.GetReplicationSessionByLocalResourceID(ctx, localVolumeUUID)
	if err == nil && existingSession.ID != "" {
		log.Infof("EnableVolumeReplication: Replication already enabled for volume %s (session: %s)",
			localVolumeUUID, existingSession.ID)
		return &csiaddonsreplication.EnableVolumeReplicationResponse{}, nil
	}

	// Get remote system
	remoteSystem, err := client.GetRemoteSystemByName(ctx, remoteSystemName)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "remote system %s not found: %v", remoteSystemName, err)
	}

	switch repMode {
	case identifiers.MetroMode:
		// Metro mode is NOT supported by CSI-Addons because CSI-Addons doesn't have
		// replication actions (failover, reprotect, etc.) that Metro requires.
		// Metro replication requires CSM-DR controller for failover orchestration.
		return nil, status.Error(codes.InvalidArgument,
			"Metro replication mode is not supported by CSI-Addons. Use CSM-DR for Metro replication.")

	case identifiers.SyncMode, identifiers.AsyncMode:
		// Configure async/sync replication via protection policy
		return s.configureAsyncSyncReplication(ctx, arr, client, localVolumeUUID, remoteSystem, repMode, rpo, vgPrefix, protocol)

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported replication mode: %s. Supported modes: ASYNC, SYNC", repMode)
	}
}

// configureAsyncSyncReplication configures async or sync replication via protection policy
func (s *CSIAddonsReplicationServer) configureAsyncSyncReplication(
	ctx context.Context,
	arr *array.PowerStoreArray,
	client gopowerstore.Client,
	volumeUUID string,
	remoteSystem gopowerstore.RemoteSystem,
	repMode string,
	rpo string,
	vgPrefix string,
	protocol string,
) (*csiaddonsreplication.EnableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)

	// Validate RPO
	if repMode == identifiers.AsyncMode && rpo == "" {
		return nil, status.Error(codes.InvalidArgument, "RPO is required for ASYNC replication mode")
	}
	if repMode == identifiers.SyncMode {
		rpo = identifiers.Zero // Sync mode requires Zero RPO
	}
	if rpo == "" {
		rpo = identifiers.Zero
	}

	rpoEnum := gopowerstore.RPOEnum(rpo)
	if err := rpoEnum.IsValid(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid RPO value: %s", rpo)
	}

	// Validate RPO for mode
	if repMode == identifiers.AsyncMode && rpo == identifiers.Zero {
		return nil, status.Error(codes.InvalidArgument, "ASYNC replication mode requires non-Zero RPO")
	}
	if repMode == identifiers.SyncMode && rpo != identifiers.Zero {
		return nil, status.Error(codes.InvalidArgument, "SYNC replication mode requires Zero RPO")
	}

	// Build volume group name
	vgName := fmt.Sprintf("%s-%s-%s", vgPrefix, remoteSystem.Name, rpo)
	if len(vgName) > 128 {
		vgName = vgName[:128]
	}

	log.Infof("EnableVolumeReplication: Using volume group %s for %s replication", vgName, repMode)

	if protocol == "nfs" {
		return nil, status.Error(codes.Unimplemented, "NFS replication is not supported")
	}

	// For block volumes, apply protection policy directly to the volume
	return s.configureBlockReplication(ctx, arr, client, volumeUUID, vgName, remoteSystem.Name, rpoEnum, repMode)
}

// configureBlockReplication configures replication for block volumes via volume-level protection policy
func (s *CSIAddonsReplicationServer) configureBlockReplication(
	ctx context.Context,
	arr *array.PowerStoreArray,
	client gopowerstore.Client,
	volumeUUID string,
	vgName string,
	remoteSystemName string,
	rpoEnum gopowerstore.RPOEnum,
	repMode string,
) (*csiaddonsreplication.EnableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)

	// Ensure protection policy exists
	ppID, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to ensure protection policy: %v", err)
	}

	log.Infof("EnableVolumeReplication: Applying protection policy %s to volume %s", ppID, volumeUUID)
	_, err = client.ModifyVolume(ctx, &gopowerstore.VolumeModify{ProtectionPolicyID: &ppID}, volumeUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to apply protection policy to volume %s: %v", volumeUUID, err)
	}

	log.Infof("EnableVolumeReplication: Successfully enabled %s replication for volume %s via volume protection policy %s",
		repMode, volumeUUID, ppID)
	return &csiaddonsreplication.EnableVolumeReplicationResponse{}, nil
}

// enableVolumeReplicationForVolumeGroup enables replication for a volume group.
// This creates/ensures the Protection Policy (PP) and Replication Rule (RR) exist,
// assigns the PP to the volume group, and verifies the replication session is established.
// PP/RR assignment was moved here from CreateVolumeGroup to decouple VG creation from replication.
func (s *CSIAddonsReplicationServer) enableVolumeReplicationForVolumeGroup(
	ctx context.Context,
	volumeGroupID string,
	remoteSystemName string,
	repMode string,
	rpo string,
	params map[string]string,
) (*csiaddonsreplication.EnableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)

	log.Infof("EnableVolumeReplication: Enabling replication for volume group %s with mode %s", volumeGroupID, repMode)

	// Extract required parameters
	sourceArrayID := params[sourceArrayParameter]
	targetArrayID := params[targetArrayParameter]

	log.Infof("EnableVolumeReplication called with vgid=%s, sourceArrayID=%s, targetArrayID=%s, remoteSystem=%s, rpo=%s",
		volumeGroupID, sourceArrayID, targetArrayID, remoteSystemName, rpo)

	// Validate replication mode
	if repMode != identifiers.AsyncMode && repMode != identifiers.SyncMode {
		return nil, status.Errorf(codes.InvalidArgument, "invalid replication mode %s. Supported modes: ASYNC, SYNC", repMode)
	}

	// Validate and normalize RPO
	if repMode == identifiers.AsyncMode && rpo == "" {
		return nil, status.Error(codes.InvalidArgument, "RPO is required for ASYNC replication mode")
	}
	if repMode == identifiers.SyncMode {
		rpo = identifiers.Zero
	}
	if rpo == "" {
		rpo = identifiers.Zero
	}
	rpoEnum := gopowerstore.RPOEnum(rpo)
	if err := rpoEnum.IsValid(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid RPO value: %s", rpo)
	}
	if repMode == identifiers.AsyncMode && rpo == identifiers.Zero {
		return nil, status.Error(codes.InvalidArgument, "ASYNC replication mode requires non-Zero RPO")
	}
	if repMode == identifiers.SyncMode && rpo != identifiers.Zero {
		return nil, status.Error(codes.InvalidArgument, "SYNC replication mode requires Zero RPO")
	}

	// Try to find VG on specific arrays (source first, then target)
	arrays := s.service.Arrays()
	var arr *array.PowerStoreArray
	var vg *gopowerstore.VolumeGroup

	// Try source array first
	if sourceArr, ok := arrays[sourceArrayID]; ok {
		vgTemp, err := findVolumeGroupOnArray(ctx, sourceArr, volumeGroupID)
		if err == nil {
			arr = sourceArr
			vg = vgTemp
		}
	}

	// If not found on source, try target array
	if vg == nil {
		if targetArr, ok := arrays[targetArrayID]; ok {
			vgTemp, err := findVolumeGroupOnArray(ctx, targetArr, volumeGroupID)
			if err == nil {
				arr = targetArr
				vg = vgTemp
			}
		}
	}

	if arr == nil || vg == nil {
		log.Errorf("EnableVolumeReplication failed: Failed to find volume group %s on source or target array", volumeGroupID)
		return nil, status.Errorf(codes.NotFound, "volume group %s not found", volumeGroupID)
	}
	log.Infof("Found volume group %s (name: %s) on array %s", volumeGroupID, vg.Name, arr.GetGlobalID())

	// Check if replication is already enabled (idempotency)
	if vg.ProtectionPolicyID != "" {
		log.Infof("EnableVolumeReplication: Volume group %s already has protection policy %s", volumeGroupID, vg.ProtectionPolicyID)
		// Verify the PP has replication rules
		pp, err := arr.Client.GetProtectionPolicy(ctx, vg.ProtectionPolicyID)
		if err != nil {
			log.Errorf("EnableVolumeReplication: Failed to get protection policy %s: %v", vg.ProtectionPolicyID, err)
			return nil, status.Errorf(codes.Internal, "failed to get protection policy: %v", err)
		}
		if len(pp.ReplicationRules) > 0 {
			log.Infof("EnableVolumeReplication: Replication already enabled for volume group %s, checking session", volumeGroupID)
			existingSession, sessErr := arr.Client.GetReplicationSessionByLocalResourceID(ctx, vg.ID)
			if sessErr == nil && existingSession.ID != "" {
				log.Infof("EnableVolumeReplication: Replication session %s found for volume group %s", existingSession.ID, volumeGroupID)
				return &csiaddonsreplication.EnableVolumeReplicationResponse{}, nil
			}
			log.Infof("EnableVolumeReplication: PP+rules exist but session not yet ready for volume group %s; retrying", volumeGroupID)
			return nil, status.Errorf(codes.Unavailable, "replication session not yet available for volume group %s; retrying: %v", vg.ID, sessErr)
		}
		log.Warnf("EnableVolumeReplication: Volume group %s has PP %s but no replication rules, re-creating", volumeGroupID, vg.ProtectionPolicyID)
	}

	// Create/ensure PP and RR exist, then assign to the VG
	log.Infof("EnableVolumeReplication: Creating protection policy for volume group %s", volumeGroupID)
	ppID, err := EnsureProtectionPolicyExists(ctx, arr, vg.Name, remoteSystemName, rpoEnum)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to ensure protection policy: %v", err)
	}

	// Assign the protection policy to the volume group
	log.Infof("EnableVolumeReplication: Assigning protection policy %s to volume group %s", ppID, vg.ID)
	policyUpdate := gopowerstore.VolumeGroupChangePolicy{ProtectionPolicyID: ppID}
	_, err = arr.Client.UpdateVolumeGroupProtectionPolicy(ctx, vg.ID, &policyUpdate)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to assign protection policy to volume group: %v", err)
	}

	// Check for replication session — if not found yet, return Unavailable so the controller retries
	session, err := arr.Client.GetReplicationSessionByLocalResourceID(ctx, vg.ID)
	if err == nil && session.ID != "" {
		log.Infof("EnableVolumeReplication: Replication session %s found for volume group %s (state: %s)",
			session.ID, vg.ID, session.State)
	} else {
		log.Infof("EnableVolumeReplication: Replication session not yet available for volume group %s; PP assigned, waiting for PowerStore to create session", vg.ID)
		return nil, status.Errorf(codes.Unavailable, "replication session not yet available for volume group %s; retrying: %v", vg.ID, err)
	}

	log.Infof("EnableVolumeReplication succeeded for volume group %s with protection policy %s", volumeGroupID, ppID)
	return &csiaddonsreplication.EnableVolumeReplicationResponse{}, nil
}

// DisableVolumeReplication disables replication for a volume or volume group.
// This removes the volume from its protected volume group on PowerStore.
//
// For block volumes:
// - Removes the volume from its volume group
// - Does NOT delete the volume group or protection policy (other volumes may use them)
//
// For NFS volumes:
// - Cannot unassign protection policy from NAS server (PowerStore limitation)
// - Returns success but logs a warning
//
// NOTE: This does not delete the replication session directly. The replication session
// is managed at the volume group level, not individual volume level.
func (s *CSIAddonsReplicationServer) DisableVolumeReplication(
	ctx context.Context,
	req *csiaddonsreplication.DisableVolumeReplicationRequest,
) (*csiaddonsreplication.DisableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("CSI-Addons DisableVolumeReplication called with request: %+v", req)

	// Validate request
	if err := s.validateDisableReplicationRequest(req); err != nil {
		log.Errorf("DisableVolumeReplication validation failed: %v", err)
		return nil, err
	}

	// Extract volume ID from replication source
	volumeID, volumeGroupID, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		log.Errorf("DisableVolumeReplication failed to extract replication source: %v", err)
		return nil, err
	}

	// Handle volume replication disable
	if volumeID != "" {
		log.Infof("DisableVolumeReplication: Disabling replication for volume %s", volumeID)
		return s.disableVolumeReplicationForVolume(ctx, volumeID)
	}

	// Handle volume group replication disable
	if volumeGroupID != "" {
		log.Infof("DisableVolumeReplication: Disabling replication for volume group %s", volumeGroupID)
		return s.disableVolumeReplicationForVolumeGroup(ctx, volumeGroupID)
	}

	return &csiaddonsreplication.DisableVolumeReplicationResponse{}, nil
}

func (s *CSIAddonsReplicationServer) disableVolumeReplicationForVolume(
	ctx context.Context,
	volumeID string,
) (*csiaddonsreplication.DisableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)

	// Parse volume handle to get array info
	volumeHandle, err := array.ParseVolumeID(ctx, volumeID, s.service.DefaultArray(), nil)
	if err != nil {
		log.Errorf("DisableVolumeReplication: Failed to parse volume ID %s: %v", volumeID, err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume ID: %v", err)
	}

	localVolumeUUID := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := strings.ToLower(volumeHandle.Protocol)

	log.Infof("DisableVolumeReplication: Parsed volume - UUID: %s, ArrayID: %s, Protocol: %s",
		localVolumeUUID, arrayID, protocol)

	// Get the array
	arr, ok := s.service.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "array with ID %s not found", arrayID)
	}

	client := arr.GetClient()

	// Handle NFS volumes
	if protocol == "nfs" {
		return nil, status.Error(codes.Unimplemented, "NFS replication is not supported")
	}

	// Handle block volumes
	return s.disableBlockReplication(ctx, client, localVolumeUUID)
}

// disableBlockReplication disables replication for a block volume by unassigning its protection policy
func (s *CSIAddonsReplicationServer) disableBlockReplication(
	ctx context.Context,
	client gopowerstore.Client,
	volumeUUID string,
) (*csiaddonsreplication.DisableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)

	// If replication session is Failed_Over, allow disable only when local role is Source/primary
	rs, err := client.GetReplicationSessionByLocalResourceID(ctx, volumeUUID)
	if err != nil {
		if apiErr, ok := err.(gopowerstore.APIError); ok && apiErr.NotFound() {
			log.Infof("DisableVolumeReplication: no replication session found for volume %s", volumeUUID)
			return &csiaddonsreplication.DisableVolumeReplicationResponse{}, nil
		}
		log.Errorf("DisableVolumeReplication: failed to get replication session for volume %s: %v", volumeUUID, err)
		return nil, status.Errorf(codes.Internal, "failed to get replication session: %v", err)
	}

	if rs.ID != "" && rs.State == gopowerstore.RsStateFailedOver {
		localIsPrimary := false
		switch gopowerstore.ReplicationRoleEnum(rs.Role) {
		case gopowerstore.ReplicationRoleSource:
			localIsPrimary = true
		}

		if !localIsPrimary {
			msg := fmt.Sprintf("replication session %s is Failed_Over (local secondary); promote/failover here or disable on the primary side", rs.ID)
			log.Warnf("DisableVolumeReplication: %s", msg)
			return nil, status.Errorf(codes.FailedPrecondition, "%s", msg)
		}

		log.Infof("DisableVolumeReplication: replication session %s is Failed_Over but local role is Source; attempting disable from this side", rs.ID)
	}

	if rs.Role == string(gopowerstore.ReplicationRoleDestination) {
		// Session still active — source-side cleanup has not yet completed.
		// Return Aborted so the controller retries after the source VGR's
		// DisableVolumeReplication removes the replication session.
		log.Infof("DisableVolumeReplication: volume %s is Destination with active session %s; returning Aborted (source cleanup pending)", volumeUUID, rs.ID)
		return nil, status.Errorf(codes.OutOfRange, "destination volume %s still has active replication session %s; retry after source-side cleanup", volumeUUID, rs.ID)
	}

	// Get the volume to capture its protection policy ID before unassigning
	vol, err := client.GetVolume(ctx, volumeUUID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return &csiaddonsreplication.DisableVolumeReplicationResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to get volume %s: %v", volumeUUID, err)
	}
	protectionPolicyID := vol.ProtectionPolicyID

	log.Infof("DisableVolumeReplication: Unassigning protection policy from volume %s", volumeUUID)
	emptyPolicy := ""
	_, err = client.ModifyVolume(ctx, &gopowerstore.VolumeModify{ProtectionPolicyID: &emptyPolicy}, volumeUUID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return &csiaddonsreplication.DisableVolumeReplicationResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to unassign protection policy from volume %s: %v", volumeUUID, err)
	}

	// Delete protection policy if no other volumes or volume groups use it
	if protectionPolicyID != "" {
		pp, ppErr := client.GetProtectionPolicy(ctx, protectionPolicyID)
		if ppErr != nil {
			log.Warnf("DisableVolumeReplication: failed to get protection policy %s for cleanup: %v", protectionPolicyID, ppErr)
		} else if len(pp.Volumes) == 0 && len(pp.VolumeGroups) == 0 {
			log.Infof("DisableVolumeReplication: deleting unused protection policy %s", protectionPolicyID)
			_, delErr := client.DeleteProtectionPolicy(ctx, protectionPolicyID)
			if delErr != nil {
				log.Warnf("DisableVolumeReplication: failed to delete protection policy %s: %v", protectionPolicyID, delErr)
			} else {
				log.Infof("DisableVolumeReplication: deleted protection policy %s", protectionPolicyID)
				// Delete replication rules if no other policies use them
				for _, rule := range pp.ReplicationRules {
					rr, rrErr := client.GetReplicationRule(ctx, rule.ID)
					if rrErr != nil {
						log.Warnf("DisableVolumeReplication: failed to get replication rule %s: %v", rule.ID, rrErr)
						continue
					}
					if len(rr.ProtectionPolicies) == 0 {
						_, rrDelErr := client.DeleteReplicationRule(ctx, rule.ID)
						if rrDelErr != nil {
							if apiErr, ok := rrDelErr.(gopowerstore.APIError); ok && apiErr.NotFound() {
								log.Infof("DisableVolumeReplication: RR %s already deleted", rule.ID)
							} else {
								log.Infof("DisableVolumeReplication: RR %s deletion blocked (session teardown in progress): %v; returning Unavailable for retry", rule.ID, rrDelErr)
								return nil, status.Errorf(codes.Unavailable, "replication rule %s deletion blocked (session teardown in progress): %v", rule.ID, rrDelErr)
							}
						} else {
							log.Infof("DisableVolumeReplication: deleted replication rule %s", rule.ID)
						}
					}
				}
			}
		} else {
			log.Infof("DisableVolumeReplication: protection policy %s still used by %d volumes and %d volume groups, not deleting",
				protectionPolicyID, len(pp.Volumes), len(pp.VolumeGroups))
		}
	}

	log.Infof("DisableVolumeReplication: Successfully disabled replication for volume %s", volumeUUID)
	return &csiaddonsreplication.DisableVolumeReplicationResponse{}, nil
}

// disableVolumeReplicationForVolumeGroup disables replication for a volume group
// disableVolumeReplicationForVolume disables replication for a single volume
// 1. Parse volume group ID to get array info
// 2. Get the volume group
// 3. Unassign protection policy from the volume group
func (s *CSIAddonsReplicationServer) disableVolumeReplicationForVolumeGroup(
	ctx context.Context,
	volumeGroupID string,
) (*csiaddonsreplication.DisableVolumeReplicationResponse, error) {
	log := log.WithContext(ctx)
	resp := csiaddonsreplication.DisableVolumeReplicationResponse{}

	array, vg, err := findArrayWithVolumeGroupID(ctx, s.service.Arrays(), volumeGroupID)
	if err != nil {
		// findArrayWithVolumeGroupID only errors when the volume group ID is empty
		return nil, status.Errorf(codes.InvalidArgument, "failed to find array with volume group %s: %v", volumeGroupID, err)
	}
	if vg == nil {
		log.Infof("DisableVolumeReplication: volume group %s not found on any array (already deleted)", volumeGroupID)
		return &resp, nil
	}

	// Determine if this is source or destination based on replication session role
	// The session role is the authoritative source; the VG flag may be stale after unplanned failover
	var destination bool
	sess, sessErr := array.Client.GetReplicationSessionByLocalResourceID(ctx, vg.ID)

	if sessErr == nil && sess.ID != "" {
		// Session exists - determine role from session (authoritative)
		// PowerStore may not update is_replication_destination flag after unplanned failover,
		// so we trust the session role as the source of truth
		sessionRole := gopowerstore.ReplicationRoleEnum(sess.Role)
		destination = (sessionRole == gopowerstore.ReplicationRoleDestination)

		log.Infof("DisableVolumeReplication: VG %s session %s state=%s role=%s -> destination=%t (vg.IsReplicationDestination=%t)",
			vg.ID, sess.ID, sess.State, sess.Role, destination, vg.IsReplicationDestination)

		if destination != vg.IsReplicationDestination {
			log.Warnf("DisableVolumeReplication: VG %s flag mismatch - vg.IsReplicationDestination=%t but session role indicates destination=%t; using session role",
				vg.ID, vg.IsReplicationDestination, destination)
		}
	} else {
		// No session - fall back to VG flag
		destination = vg.IsReplicationDestination
		log.Infof("DisableVolumeReplication: No replication session found for VG %s (error: %v); using vg.IsReplicationDestination=%t",
			vg.ID, sessErr, destination)
	}

	log.Infof("DisableVolumeReplication: Disabling replication for volume group %s %s %s destination=%t", volumeGroupID, vg.Name,
		array.GlobalID, destination)

	if destination {
		// Check whether the replication session is still active.  If it is, source-side
		// cleanup has not yet completed; returning Aborted causes the controller to retry
		// after the source VGR's DisableVolumeReplication runs and removes the session.
		if sess.ID != "" {
			log.Infof("DisableVolumeReplication: destination VG %s still has active session %s; returning Aborted (source cleanup pending)", vg.ID, sess.ID)
			return nil, status.Errorf(codes.OutOfRange, "destination VG %s still has active replication session %s; retry after source-side cleanup", vg.ID, sess.ID)
		}
		// Capture the PP ID before clearing so we can delete it after cleanup
		originalPPID := vg.ProtectionPolicyID
		// Session gone — safe to remove protection policy from VG and member volumes.
		if vg.ProtectionPolicyID != "" {
			log.Infof("DisableVolumeReplication: clearing protection policy %s from destination VG %s/%s on array %s",
				vg.ProtectionPolicyID, vg.ID, vg.Name, array.GlobalID)
			policyUpdate := gopowerstore.VolumeGroupChangePolicy{ProtectionPolicyID: ""}
			_, err = array.Client.UpdateVolumeGroupProtectionPolicy(ctx, vg.ID, &policyUpdate)
			if err != nil {
				log.Errorf("DisableVolumeReplication: failed to clear protection policy from destination VG %s: %v", vg.ID, err)
				return nil, status.Errorf(codes.Internal, "failed to clear protection policy from destination VG %s: %v", vg.ID, err)
			}
			log.Infof("DisableVolumeReplication: cleared protection policy from destination VG %s", vg.ID)
		} else {
			log.Infof("DisableVolumeReplication: destination VG %s/%s already has no protection policy", vg.ID, vg.Name)
		}
		// PowerStore forbids RemoveMembersFromVolumeGroup on destination VGs
		// (IsReplicationDestination=true) even after the session and protection policy
		// are gone.  Delete the VG directly instead — this mirrors deleteTargetArrayVolumeGroup
		// and frees all member volumes from the VG so DeleteVolume can proceed.
		_, delErr := array.Client.DeleteVolumeGroup(ctx, vg.ID)
		if delErr != nil {
			if apiError, ok := delErr.(gopowerstore.APIError); ok && apiError.NotFound() {
				log.Infof("DisableVolumeReplication: destination VG %s already deleted", vg.ID)
			} else {
				log.Errorf("DisableVolumeReplication: failed to delete destination VG %s: %v", vg.ID, delErr)
				return nil, status.Errorf(codes.Internal, "failed to delete destination VG %s: %v", vg.ID, delErr)
			}
		} else {
			log.Infof("DisableVolumeReplication: deleted destination VG %s/%s", vg.ID, vg.Name)
		}
		// Clear protection-policy references from individual volumes so DeleteVolume succeeds.
		emptyPolicy := ""
		for _, vol := range vg.Volumes {
			_, modErr := array.Client.ModifyVolume(ctx, &gopowerstore.VolumeModify{ProtectionPolicyID: &emptyPolicy}, vol.ID)
			if modErr != nil {
				log.Warnf("DisableVolumeReplication: could not clear protection policy from destination volume %s: %v", vol.ID, modErr)
			} else {
				log.Infof("DisableVolumeReplication: cleared protection policy from destination volume %s", vol.ID)
			}
		}
		// Delete the protection policy — destination VGs have unique PPs that cannot be reused
		if originalPPID != "" {
			log.Infof("DisableVolumeReplication: deleting protection policy %s for destination VG %s", originalPPID, vg.ID)
			_, ppDelErr := array.Client.DeleteProtectionPolicy(ctx, originalPPID)
			if ppDelErr != nil {
				log.Warnf("DisableVolumeReplication: failed to delete protection policy %s: %v", originalPPID, ppDelErr)
			} else {
				log.Infof("DisableVolumeReplication: deleted protection policy %s", originalPPID)
			}
		}
		return &resp, nil
	}

	// If there is no protection policy ID, the PP was already deleted on a prior call.
	// Check for an orphaned RR by name and delete it if no other PPs reference it.
	if vg.ProtectionPolicyID == "" {
		rrName := "rr-" + vg.Name
		rr, rrErr := array.Client.GetReplicationRuleByName(ctx, rrName)
		if rrErr == nil && rr.ID != "" && len(rr.ProtectionPolicies) == 0 {
			log.Infof("DisableVolumeReplication: found orphaned replication rule %s (%s), attempting deletion", rrName, rr.ID)
			_, rrDelErr := array.Client.DeleteReplicationRule(ctx, rr.ID)
			if rrDelErr != nil {
				if apiErr, ok := rrDelErr.(gopowerstore.APIError); ok && apiErr.NotFound() {
					log.Infof("DisableVolumeReplication: orphaned RR %s already deleted", rr.ID)
				} else {
					log.Infof("DisableVolumeReplication: orphaned RR %s deletion blocked (session teardown in progress): %v; returning Unavailable for retry", rr.ID, rrDelErr)
					return nil, status.Errorf(codes.Unavailable, "replication rule %s deletion blocked (session teardown in progress): %v", rr.ID, rrDelErr)
				}
			} else {
				log.Infof("DisableVolumeReplication: deleted orphaned replication rule %s (%s)", rrName, rr.ID)
			}
		}
		return &resp, nil
	}

	// Get the protection policy
	pp, err := array.Client.GetProtectionPolicy(ctx, vg.ProtectionPolicyID)
	if err != nil {
		log.Errorf("DisableVolumeReplication failed: Failed to get protection policy %s for volume group %s: %v", vg.ProtectionPolicyID, volumeGroupID, err)
		if apiErr, ok := err.(gopowerstore.APIError); ok && apiErr.NotFound() {
			return nil, status.Errorf(codes.NotFound, "protection policy %s for volume group %s not found: %v", vg.ProtectionPolicyID, volumeGroupID, err)
		}
		return nil, status.Errorf(codes.Internal, "failed to get protection policy %s for volume group %s: %v", vg.ProtectionPolicyID, volumeGroupID, err)
	}

	// Pause replication session before deleting replication rules
	log.Infof("Pausing replication session for volume group %s", vg.ID)
	err = ExecuteActionOnReplicationSession(ctx, array, vg.ID, gopowerstore.RsActionPause)
	if err != nil {
		log.Warnf("DisableVolumeReplication: Failed to pause replication session for volume group %s: %v", vg.ID, err)
		// Continue with deletion attempt even if pause fails
	}

	log.Infof("DisableVolumeReplication: Pause completed, proceeding with protection policy deletion for volume group %s", volumeGroupID)

	// Unassign protection policy from volume group before deletion
	if vg.ProtectionPolicyID != "" {
		log.Infof("Unassigning protection policy %s from volume group %s", vg.ProtectionPolicyID, vg.ID)
		err := unassignProtectionPolicyFromVolumeGroup(ctx, array, vg)
		if err != nil {
			log.Warnf("Failed to unassign protection policy from volume group: %v", err)
			// Continue with deletion attempt even if unassignment fails
		} else {
			log.Infof("Successfully unassigned protection policy from volume group %s", vg.ID)
		}
	}

	// Clear the PP from individual volumes before deleting it — PowerStore blocks PP deletion
	// while any volume still references it.
	emptyPolicy := ""
	for _, vol := range pp.Volumes {
		_, modErr := array.Client.ModifyVolume(ctx, &gopowerstore.VolumeModify{ProtectionPolicyID: &emptyPolicy}, vol.ID)
		if modErr != nil {
			if apiErr, ok := modErr.(gopowerstore.APIError); ok && apiErr.NotFound() {
				continue
			}
			log.Warnf("DisableVolumeReplication: could not clear protection policy from volume %s: %v", vol.ID, modErr)
		}
	}

	// Delete the protection policy first (following pattern from DeleteStorageProtectionGroup)
	log.Infof("Deleting protection policy %s for volume group %s", vg.ProtectionPolicyID, volumeGroupID)
	_, err = array.Client.DeleteProtectionPolicy(ctx, vg.ProtectionPolicyID)
	if err != nil {
		log.Errorf("Failed to delete protection policy %s for volume group %s: %v", vg.ProtectionPolicyID, volumeGroupID, err)
		return nil, status.Errorf(codes.Internal, "failed to delete protection policy %s for volume group %s: %v", vg.ProtectionPolicyID, volumeGroupID, err)
	}

	log.Infof("DisableVolumeReplication: Protection policy deletion completed, proceeding with replication rule cleanup for volume group %s", volumeGroupID)

	// Now delete the replication rules (only if they have no protection policies associated)
	for _, rule := range pp.ReplicationRules {
		log.Infof("Deleting target replication rule %s for volume group %s", rule.ID, volumeGroupID)

		// Check if the rule has any protection policies associated
		rr, err := array.Client.GetReplicationRule(ctx, rule.ID)
		if err != nil {
			log.Warnf("Failed to get replication rule %s for checking: %v", rule.ID, err)
			continue
		}

		if len(rr.ProtectionPolicies) == 0 {
			_, rrDelErr := array.Client.DeleteReplicationRule(ctx, rule.ID)
			if rrDelErr != nil {
				if apiErr, ok := rrDelErr.(gopowerstore.APIError); ok && apiErr.NotFound() {
					log.Infof("DisableVolumeReplication: RR %s already deleted", rule.ID)
				} else {
					log.Infof("DisableVolumeReplication: RR %s deletion blocked (session teardown in progress): %v; returning Unavailable for retry", rule.ID, rrDelErr)
					return nil, status.Errorf(codes.Unavailable, "replication rule %s deletion blocked (session teardown in progress): %v", rule.ID, rrDelErr)
				}
			} else {
				log.Infof("Successfully deleted replication rule %s", rule.ID)
			}
		} else {
			log.Warnf("Skipping replication rule %s as it still has %d protection policies associated", rule.ID, len(rr.ProtectionPolicies))
		}
	}

	return &resp, nil
}

// PromoteVolume promotes a volume to primary.
// This is called during failover to make the local volume the active/primary copy.
//
// PowerStore mapping:
// - Planned failover (force=false): ExecuteActionOnReplicationSession(Failover, IsPlanned=true)
// - Unplanned failover (force=true): ExecuteActionOnReplicationSession(Failover, IsPlanned=false)
//
// The failover is executed on the replication session associated with the volume's
// volume group (for block volumes) or file system (for NFS volumes).
func (s *CSIAddonsReplicationServer) PromoteVolume(
	ctx context.Context,
	req *csiaddonsreplication.PromoteVolumeRequest,
) (*csiaddonsreplication.PromoteVolumeResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("CSI-Addons PromoteVolume called with request: %+v", req)

	// Validate request
	if err := s.validatePromoteVolumeRequest(req); err != nil {
		log.Errorf("PromoteVolume validation failed: %v", err)
		return nil, err
	}

	// Extract volume ID from replication source
	volumeID, volumeGroupID, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		log.Errorf("PromoteVolume failed to extract replication source: %v", err)
		return nil, err
	}

	force := req.GetForce()

	// Handle volume promotion
	if volumeID != "" {
		log.Infof("PromoteVolume: Promoting volume %s (force=%v)", volumeID, force)
		return s.promoteVolumeForVolume(ctx, volumeID, force)
	}

	// Handle volume group promotion
	if volumeGroupID != "" {
		log.Infof("PromoteVolume: Promoting volume group %s (force=%v)", volumeGroupID, force)
		return s.promoteVolumeForVolumeGroup(ctx, req)
	}

	log.Errorf("PromoteVolume: unreachable code reached - neither volumeID nor volumeGroupID was set")
	return nil, status.Error(codes.Internal, "internal error: neither volumeID nor volumeGroupID resolved")
}

// promoteVolumeForVolume executes failover for a single volume
func (s *CSIAddonsReplicationServer) promoteVolumeForVolume(
	ctx context.Context,
	volumeID string,
	force bool,
) (*csiaddonsreplication.PromoteVolumeResponse, error) {
	log := log.WithContext(ctx)

	// Parse volume handle to get array info
	volumeHandle, err := array.ParseVolumeID(ctx, volumeID, s.service.DefaultArray(), nil)
	if err != nil {
		log.Errorf("PromoteVolume: Failed to parse volume ID %s: %v", volumeID, err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume ID: %v", err)
	}

	localVolumeUUID := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := strings.ToLower(volumeHandle.Protocol)

	log.Infof("PromoteVolume: Parsed volume - UUID: %s, ArrayID: %s, Protocol: %s",
		localVolumeUUID, arrayID, protocol)
	if protocol == "nfs" {
		return nil, status.Error(codes.Unimplemented, "NFS replication is not supported")
	}

	// Get the array
	arr, ok := s.service.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "array with ID %s not found", arrayID)
	}

	client := arr.GetClient()

	// For block volumes, get replication session for the volume
	var replicationSession gopowerstore.ReplicationSession
	rs, err := client.GetReplicationSessionByLocalResourceID(ctx, localVolumeUUID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no replication session found for volume %s: %v", localVolumeUUID, err)
	}
	replicationSession = rs

	log.Infof("PromoteVolume: Found replication session %s in state %s", replicationSession.ID, replicationSession.State)
	log.Infof("PromoteVolume: Replication session %s role is %s", replicationSession.ID, replicationSession.Role)

	if replicationSession.State == gopowerstore.RsStateFailingOver || replicationSession.State == gopowerstore.RsStateFailingOverForDR {
		log.Infof("PromoteVolume: Failover already in progress for session %s", replicationSession.ID)
		return nil, status.Errorf(codes.Aborted, "failover already in progress for replication session %s", replicationSession.ID)
	}

	localIsPrimary := false
	localIsSecondary := false
	if replicationSession.Role != "" {
		switch gopowerstore.ReplicationRoleEnum(replicationSession.Role) {
		case gopowerstore.ReplicationRoleSource:
			localIsPrimary = true
		case gopowerstore.ReplicationRoleDestination:
			localIsSecondary = true
		}
	}

	if !localIsPrimary && !localIsSecondary {
		localIsPrimary = replicationSession.State == gopowerstore.RsStateOk
		localIsSecondary = replicationSession.State == gopowerstore.RsStateFailedOver
	}

	if localIsPrimary {
		log.Infof("PromoteVolume: Replication session %s is already primary (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
		return &csiaddonsreplication.PromoteVolumeResponse{}, nil
	}

	if localIsSecondary {
		if !force {
			remoteSystem, remoteErr := client.GetRemoteSystem(ctx, replicationSession.RemoteSystemID)
			if remoteErr != nil {
				log.Warnf("PromoteVolume: Failed to query remote system %s for session %s: %v", replicationSession.RemoteSystemID, replicationSession.ID, remoteErr)
				return nil, status.Errorf(codes.FailedPrecondition,
					"replication session %s is secondary; refusing to promote without force=true (role=%s, state=%s)",
					replicationSession.ID, replicationSession.Role, replicationSession.State)
			}

			switch gopowerstore.DataConnectStateEnum(remoteSystem.DataConnectionState) {
			case gopowerstore.ConnStateCompleteDataConnLoss, gopowerstore.ConnStateNotAvailable, gopowerstore.ConnStateNoTargetsDiscovered:
				log.Infof("PromoteVolume: Remote system %s appears down/unreachable (data_connection_state=%s); returning FailedPrecondition to allow force promotion", remoteSystem.ID, remoteSystem.DataConnectionState)
				return nil, status.Errorf(codes.FailedPrecondition,
					"replication session %s is secondary and remote system appears down (data_connection_state=%s); retry with force=true for unplanned failover",
					replicationSession.ID, remoteSystem.DataConnectionState)
			default:
				log.Infof("PromoteVolume: Remote system %s appears healthy (data_connection_state=%s); planned failover must be initiated from the primary side via DemoteVolume", remoteSystem.ID, remoteSystem.DataConnectionState)
				return nil, status.Errorf(codes.FailedPrecondition,
					"replication session %s is secondary; planned failover must be initiated from the primary side via DemoteVolume (role=%s, state=%s)",
					replicationSession.ID, replicationSession.Role, replicationSession.State)
			}
		}

		failoverParams := &gopowerstore.FailoverParams{
			IsPlanned: false,
			Reverse:   false,
		}

		log.Infof("PromoteVolume: Executing unplanned failover on session %s", replicationSession.ID)
		err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionFailover, failoverParams)
		if err != nil {
			log.Errorf("PromoteVolume: Failed to execute unplanned failover: %v", err)
			// ExecuteAction already returns a gRPC status error (Aborted when an action
			// is still in flight); return it unchanged so the code is not overwritten.
			return nil, err
		}
		log.Infof("PromoteVolume: Successfully initiated unplanned failover for replication session %s", replicationSession.ID)
		return &csiaddonsreplication.PromoteVolumeResponse{}, nil
	}

	log.Warnf("PromoteVolume: Replication session %s is in unexpected role/state combination (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
	return nil, status.Errorf(codes.FailedPrecondition, "replication session %s is in unexpected role/state combination (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
}

// promoteVolumeForVolumeGroup executes failover for a volume group
// 1. Parse volume group ID to get array info
// 2. Get the replication session for the volume group
// 3. Execute failover action

func (s *CSIAddonsReplicationServer) promoteVolumeForVolumeGroup(
	ctx context.Context,
	req *csiaddonsreplication.PromoteVolumeRequest,
) (*csiaddonsreplication.PromoteVolumeResponse, error) {
	log := log.WithContext(ctx)

	// Get volume group ID from request
	vgID := req.GetReplicationSource().GetVolumegroup().GetVolumeGroupId()
	if vgID == "" {
		log.Errorf("promoteVolumeForVolumeGroup: volume group id is required")
		return nil, status.Error(codes.InvalidArgument, "volume group id is required")
	}

	log.Infof("promoteVolumeForVolumeGroup called for volume group %s", vgID)

	// Extract parameters to get array IDs
	params, err := vgGetParameters(req.GetParameters())
	if err != nil {
		log.Errorf("promoteVolumeForVolumeGroup: Failed to validate parameters: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	sourceArrayID := params[sourceArrayParameter]
	targetArrayID := params[targetArrayParameter]

	// Try to find VG on specific arrays (source first, then target)
	arrays := s.service.Arrays()
	var arr *array.PowerStoreArray
	var vg *gopowerstore.VolumeGroup

	// Try source array first
	if sourceArr, ok := arrays[sourceArrayID]; ok {
		vgTemp, err := findVolumeGroupOnArray(ctx, sourceArr, vgID)
		if err == nil {
			arr = sourceArr
			vg = vgTemp
		}
	}

	// If not found on source, try target array
	if vg == nil {
		if targetArr, ok := arrays[targetArrayID]; ok {
			vgTemp, err := findVolumeGroupOnArray(ctx, targetArr, vgID)
			if err == nil {
				arr = targetArr
				vg = vgTemp
			}
		}
	}

	if arr == nil || vg == nil {
		log.Errorf("promoteVolumeForVolumeGroup: Failed to find volume group %s on source or target array", vgID)
		return nil, status.Errorf(codes.NotFound, "volume group %s not found", vgID)
	}

	log.Infof("promoteVolumeForVolumeGroup: Found volume group %s (name: %s) on array %s", vgID, vg.Name, arr.GetGlobalID())

	replicationSession, err := arr.Client.GetReplicationSessionByLocalResourceID(ctx, vg.ID)
	if err != nil {
		log.Errorf("promoteVolumeForVolumeGroup: Failed to get replication session for volume group %s: %v", vgID, err)
		return nil, status.Errorf(codes.FailedPrecondition, "no replication session found for volume group %s: %v", vgID, err)
	}
	log.Infof("promoteVolumeForVolumeGroup: vg ID %s replicationSession ID %s role %s state %s", vg.ID, replicationSession.ID, replicationSession.Role, replicationSession.State)

	force := req.Force
	client := arr.Client

	if replicationSession.State == gopowerstore.RsStateFailingOver || replicationSession.State == gopowerstore.RsStateFailingOverForDR {
		log.Infof("PromoteVolume: Failover already in progress for session %s", replicationSession.ID)
		return nil, status.Errorf(codes.Aborted, "failover already in progress for replication session %s", replicationSession.ID)
	}

	localIsPrimary := false
	localIsSecondary := false
	if replicationSession.Role != "" {
		switch gopowerstore.ReplicationRoleEnum(replicationSession.Role) {
		case gopowerstore.ReplicationRoleSource:
			localIsPrimary = true
		case gopowerstore.ReplicationRoleDestination:
			localIsSecondary = true
		}
	}

	if !localIsPrimary && !localIsSecondary {
		localIsPrimary = replicationSession.State == gopowerstore.RsStateOk
		localIsSecondary = replicationSession.State == gopowerstore.RsStateFailedOver
	}

	if localIsPrimary {
		log.Infof("PromoteVolume: Replication session %s is already primary (NOP) (role=%s, state=%s)",
			replicationSession.ID, replicationSession.Role, replicationSession.State)
		return &csiaddonsreplication.PromoteVolumeResponse{}, nil
	}

	if localIsSecondary {
		if !force {
			remoteSystem, remoteErr := client.GetRemoteSystem(ctx, replicationSession.RemoteSystemID)
			if remoteErr != nil {
				log.Warnf("PromoteVolume: Failed to query remote system %s for session %s: %v", replicationSession.RemoteSystemID, replicationSession.ID, remoteErr)
				return nil, status.Errorf(codes.Aborted,
					"replication session %s is secondary; refusing to promote without force=true (role=%s, state=%s)",
					replicationSession.ID, replicationSession.Role, replicationSession.State)
			}

			switch gopowerstore.DataConnectStateEnum(remoteSystem.DataConnectionState) {
			case gopowerstore.ConnStateCompleteDataConnLoss, gopowerstore.ConnStateNotAvailable, gopowerstore.ConnStateNoTargetsDiscovered:
				log.Infof("PromoteVolume: Remote system %s appears down/unreachable (data_connection_state=%s); returning FailedPrecondition to allow force promotion", remoteSystem.ID, remoteSystem.DataConnectionState)
				return nil, status.Errorf(codes.FailedPrecondition,
					"replication session %s is secondary and remote system appears down (data_connection_state=%s); retry with force=true for unplanned failover",
					replicationSession.ID, remoteSystem.DataConnectionState)
			default:
				log.Infof("PromoteVolume: Remote system %s appears healthy (data_connection_state=%s); planned failover must be initiated from the primary side via DemoteVolume", remoteSystem.ID, remoteSystem.DataConnectionState)
				return nil, status.Errorf(codes.FailedPrecondition,
					"replication session %s is secondary; planned failover must be initiated from the primary side via DemoteVolume (role=%s, state=%s)",
					replicationSession.ID, replicationSession.Role, replicationSession.State)
			}
		}

		failoverParams := &gopowerstore.FailoverParams{
			IsPlanned: false,
			Reverse:   false,
		}

		log.Infof("PromoteVolume: Executing unplanned failover on session %s", replicationSession.ID)
		err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionFailover, failoverParams)
		if err != nil {
			log.Errorf("PromoteVolume: Failed to execute unplanned failover: %v", err)
			// ExecuteAction already returns a gRPC status error (Aborted when an action
			// is still in flight); return it unchanged so the code is not overwritten.
			return nil, err
		}
		log.Infof("PromoteVolume: Successfully initiated unplanned failover for replication session %s", replicationSession.ID)
		return &csiaddonsreplication.PromoteVolumeResponse{}, nil
	}

	log.Errorf("PromoteVolume: Replication session %s is in unexpected role/state combination (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
	return nil, status.Errorf(codes.FailedPrecondition,
		"Replication session %s is in unexpected role/state combination (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
}

// DemoteVolume demotes a volume to secondary.
// This is called to prepare a volume to become secondary and receive data from the new primary.
//
// PowerStore mapping:
// - If replication session is in Failed_Over state: Execute Reprotect action to reverse replication
// - If replication session is already in OK state: No-op (already secondary/synchronized)
// - If replication session is in other states: Return appropriate error
//
// The Reprotect action reverses the replication direction, making the local volume secondary
// and the remote volume primary.
func (s *CSIAddonsReplicationServer) DemoteVolume(
	ctx context.Context,
	req *csiaddonsreplication.DemoteVolumeRequest,
) (*csiaddonsreplication.DemoteVolumeResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("CSI-Addons DemoteVolume called with request: %+v", req)

	// Validate request
	if err := s.validateDemoteVolumeRequest(req); err != nil {
		log.Errorf("DemoteVolume validation failed: %v", err)
		return nil, err
	}

	// Extract volume ID from replication source
	volumeID, volumeGroupID, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		log.Errorf("DemoteVolume failed to extract replication source: %v", err)
		return nil, err
	}

	force := req.GetForce()

	// Handle volume demotion
	if volumeID != "" {
		log.Infof("DemoteVolume: Demoting volume %s (force=%v)", volumeID, force)
		return s.demoteVolumeForVolume(ctx, volumeID, force)
	}

	// Handle volume group demotion
	if volumeGroupID != "" {
		log.Infof("DemoteVolume: Demoting volume group %s (force=%v)", volumeGroupID, force)
		return s.demoteVolumeForVolumeGroup(ctx, req)
	}

	log.Errorf("DemoteVolume: unreachable code reached - neither volumeID nor volumeGroupID was set")
	return nil, status.Error(codes.Internal, "internal error: neither volumeID nor volumeGroupID resolved")
}

// demoteVolumeForVolume executes reprotect for a single volume
func (s *CSIAddonsReplicationServer) demoteVolumeForVolume(
	ctx context.Context,
	volumeID string,
	force bool,
) (*csiaddonsreplication.DemoteVolumeResponse, error) {
	log := log.WithContext(ctx)

	// Parse volume handle to get array info
	volumeHandle, err := array.ParseVolumeID(ctx, volumeID, s.service.DefaultArray(), nil)
	if err != nil {
		log.Errorf("DemoteVolume: Failed to parse volume ID %s: %v", volumeID, err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume ID: %v", err)
	}

	localVolumeUUID := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := strings.ToLower(volumeHandle.Protocol)

	log.Infof("DemoteVolume: Parsed volume - UUID: %s, ArrayID: %s, Protocol: %s",
		localVolumeUUID, arrayID, protocol)
	if protocol == "nfs" {
		return nil, status.Error(codes.Unimplemented, "NFS replication is not supported")
	}

	// Get the array
	arr, ok := s.service.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "array with ID %s not found", arrayID)
	}

	client := arr.GetClient()

	// Get the replication session
	var replicationSession gopowerstore.ReplicationSession
	rs, err := client.GetReplicationSessionByLocalResourceID(ctx, localVolumeUUID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no replication session found for volume %s: %v", localVolumeUUID, err)
	}
	replicationSession = rs

	log.Infof("DemoteVolume: Found replication session %s in state %s", replicationSession.ID, replicationSession.State)
	log.Infof("DemoteVolume: Replication session %s role is %s", replicationSession.ID, replicationSession.Role)

	if replicationSession.State == gopowerstore.RsStateFailingOver || replicationSession.State == gopowerstore.RsStateFailingOverForDR {
		log.Infof("DemoteVolume: Failover already in progress for session %s", replicationSession.ID)
		return nil, status.Errorf(codes.Aborted, "failover already in progress for replication session %s", replicationSession.ID)
	}

	if replicationSession.State == gopowerstore.RsStateReprotecting {
		// Reprotect is already in progress
		log.Infof("DemoteVolume: Reprotect already in progress for session %s", replicationSession.ID)
		return nil, status.Errorf(codes.Aborted, "reprotect already in progress for replication session %s", replicationSession.ID)
	}

	switch replicationSession.State {
	case gopowerstore.RsStatePaused, gopowerstore.RsStatePausedForMigration, gopowerstore.RsStatePausedForNdu, gopowerstore.RsStateSystemPaused:
		// Handle paused early to avoid treating paused primaries as planned failover
		log.Warnf("DemoteVolume: Replication session %s is paused (state: %s)", replicationSession.ID, replicationSession.State)
		if force {
			log.Infof("DemoteVolume: Force flag set, attempting to resume paused session %s", replicationSession.ID)
			err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionResume, nil)
			if err != nil {
				log.Errorf("DemoteVolume: Failed to resume paused session: %v", err)
				return nil, err
			}
			log.Infof("DemoteVolume: Successfully resumed session %s", replicationSession.ID)
			return &csiaddonsreplication.DemoteVolumeResponse{}, nil
		}
		return nil, status.Errorf(codes.FailedPrecondition, "replication session %s is paused, use force=true to resume", replicationSession.ID)
	}

	localIsPrimary := false
	localIsSecondary := false
	if replicationSession.Role != "" {
		switch gopowerstore.ReplicationRoleEnum(replicationSession.Role) {
		case gopowerstore.ReplicationRoleSource:
			localIsPrimary = true
		case gopowerstore.ReplicationRoleDestination:
			localIsSecondary = true
		}
	}

	if !localIsPrimary && !localIsSecondary {
		localIsPrimary = replicationSession.State == gopowerstore.RsStateOk
		localIsSecondary = replicationSession.State == gopowerstore.RsStateFailedOver
	}

	if localIsSecondary {
		log.Infof("DemoteVolume: Replication session %s is already secondary (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
		return &csiaddonsreplication.DemoteVolumeResponse{}, nil
	}

	if localIsPrimary {
		// If the session is in Failed_Over state (promoted via unplanned failover), do not attempt a
		// planned reverse failover — PowerStore rejects Failover(Planned,Reverse=true) on a Failed_Over
		// session. Accept the demotion as a no-op; the actual direction reversal is handled by
		// ResyncVolume (Reprotect) which the controller will call next.
		if replicationSession.State == gopowerstore.RsStateFailedOver {
			log.Infof("DemoteVolume: Session %s is Failed_Over/Source (promoted via unplanned failover); accepting demotion as no-op — Reprotect will be triggered by ResyncVolume", replicationSession.ID)
			return &csiaddonsreplication.DemoteVolumeResponse{}, nil
		}
		failoverParams := &gopowerstore.FailoverParams{IsPlanned: true, Reverse: true}
		log.Infof("DemoteVolume: Executing planned failover on session %s with Reverse=true", replicationSession.ID)
		err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionFailover, failoverParams)
		if err != nil {
			log.Errorf("DemoteVolume: Failed to execute planned failover: %v", err)
			return nil, err
		}
		log.Infof("DemoteVolume: Successfully initiated planned failover for replication session %s", replicationSession.ID)
		return &csiaddonsreplication.DemoteVolumeResponse{}, nil
	}

	log.Warnf("DemoteVolume: Replication session %s is in unexpected role/state combination (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
	return nil, status.Errorf(codes.FailedPrecondition, "replication session %s is in unexpected role/state combination (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
}

// demoteVolumeForVolumeGroup executes reprotect for a volume group
func (s *CSIAddonsReplicationServer) demoteVolumeForVolumeGroup(
	ctx context.Context,
	req *csiaddonsreplication.DemoteVolumeRequest,
) (*csiaddonsreplication.DemoteVolumeResponse, error) {
	log := log.WithContext(ctx)

	// Get volume group ID from request
	vgID := req.GetReplicationSource().GetVolumegroup().GetVolumeGroupId()
	if vgID == "" {
		log.Errorf("demoteVolumeForVolumeGroup: volume group id is required")
		return nil, status.Error(codes.InvalidArgument, "volume group id is required")
	}

	log.Infof("demoteVolumeForVolumeGroup called for volume group %s", vgID)

	// Extract parameters to get array IDs
	params, err := vgGetParameters(req.GetParameters())
	if err != nil {
		log.Errorf("demoteVolumeForVolumeGroup: Failed to validate parameters: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	sourceArrayID := params[sourceArrayParameter]
	targetArrayID := params[targetArrayParameter]

	// Try to find VG on specific arrays (source first, then target)
	arrays := s.service.Arrays()
	var arr *array.PowerStoreArray
	var vg *gopowerstore.VolumeGroup

	// Try source array first
	if sourceArr, ok := arrays[sourceArrayID]; ok {
		vgTemp, err := findVolumeGroupOnArray(ctx, sourceArr, vgID)
		if err == nil {
			arr = sourceArr
			vg = vgTemp
		}
	}

	// If not found on source, try target array
	if vg == nil {
		if targetArr, ok := arrays[targetArrayID]; ok {
			vgTemp, err := findVolumeGroupOnArray(ctx, targetArr, vgID)
			if err == nil {
				arr = targetArr
				vg = vgTemp
			}
		}
	}

	if arr == nil || vg == nil {
		log.Errorf("demoteVolumeForVolumeGroup: Failed to find volume group %s on source or target array", vgID)
		return nil, status.Errorf(codes.NotFound, "volume group %s not found", vgID)
	}

	log.Infof("demoteVolumeForVolumeGroup: Found volume group %s (name: %s) on array %s", vgID, vg.Name, arr.GetGlobalID())

	replicationSession, err := arr.GetClient().GetReplicationSessionByLocalResourceID(ctx, vg.ID)
	if err != nil {
		err = status.Errorf(codes.FailedPrecondition, "no replication session found for volume group %s (name %s): %v", vg.ID, vg.Name, err)
		log.Errorf("%s", err.Error())
		return nil, err
	}

	if replicationSession.State == gopowerstore.RsStateFailingOver || replicationSession.State == gopowerstore.RsStateFailingOverForDR {
		err := status.Errorf(codes.FailedPrecondition, "DemoteVolume: Failover already in progress for vg %s rs %s", vg.Name, replicationSession.ID)
		log.Errorf("%s", err.Error())
		return nil, err
	}

	if replicationSession.State == gopowerstore.RsStateReprotecting {
		// Reprotect is already in progress
		log.Infof("DemoteVolume: Reprotect already in progress for session %s", replicationSession.ID)
		return nil, status.Errorf(codes.Aborted, "reprotect already in progress for replication session %s", replicationSession.ID)
	}

	switch replicationSession.State {
	case gopowerstore.RsStatePaused, gopowerstore.RsStatePausedForMigration,
		gopowerstore.RsStatePausedForNdu, gopowerstore.RsStateSystemPaused:
		log.Warnf("DemoteVolume: Replication session %s is paused (state: %s)", replicationSession.ID, replicationSession.State)
		if req.Force {
			log.Infof("DemoteVolume: Force flag set, attempting to resume paused session %s", replicationSession.ID)
			err = ExecuteAction(&replicationSession, arr.GetClient(), gopowerstore.RsActionResume, nil)
			if err != nil {
				log.Errorf("DemoteVolume: Failed to resume paused session: %v", err)
				return nil, err
			}
			log.Infof("DemoteVolume: Successfully force resumed session %s", replicationSession.ID)
			return &csiaddonsreplication.DemoteVolumeResponse{}, nil
		}
		return nil, status.Errorf(codes.FailedPrecondition, "replication session %s is paused, use force = true to resume", replicationSession.ID)
	}

	localIsPrimary := false
	localIsSecondary := false
	if replicationSession.Role != "" {
		switch gopowerstore.ReplicationRoleEnum(replicationSession.Role) {
		case gopowerstore.ReplicationRoleSource:
			localIsPrimary = true
		case gopowerstore.ReplicationRoleDestination:
			localIsSecondary = true
		}
	}

	if !localIsPrimary && !localIsSecondary {
		localIsPrimary = replicationSession.State == gopowerstore.RsStateOk
		localIsSecondary = replicationSession.State == gopowerstore.RsStateFailedOver
	}

	if localIsSecondary {
		log.Infof("DemoteVolume: Replication session %s is already secondary (role=%s, state=%s)", replicationSession.ID,
			replicationSession.Role, replicationSession.State)
		return &csiaddonsreplication.DemoteVolumeResponse{}, nil
	}

	if localIsPrimary {
		// If the session is in Failed_Over state (promoted via unplanned failover), do not attempt a
		// planned reverse failover — PowerStore rejects Failover(Planned,Reverse=true) on a Failed_Over
		// session. Accept the demotion as a no-op; the actual direction reversal is handled by
		// ResyncVolume (Reprotect) which the VGR controller will call next.
		if replicationSession.State == gopowerstore.RsStateFailedOver {
			log.Infof("DemoteVolume: Session %s is Failed_Over/Source (promoted via unplanned failover); accepting demotion as no-op — Reprotect will be triggered by ResyncVolume", replicationSession.ID)
			return &csiaddonsreplication.DemoteVolumeResponse{}, nil
		}
		failoverParams := &gopowerstore.FailoverParams{IsPlanned: true, Reverse: true}
		log.Infof("DemoteVolume: Executing planned failover on session %s with Reverse=true", replicationSession.ID)
		err = ExecuteAction(&replicationSession, arr.GetClient(), gopowerstore.RsActionFailover, failoverParams)
		if err != nil {
			log.Errorf("DemoteVolume: Failed to execute planned failover: %v", err)
			return nil, err
		}
		log.Infof("DemoteVolume: Successfully initiated planned failover for replication session %s", replicationSession.ID)
		return &csiaddonsreplication.DemoteVolumeResponse{}, nil
	}

	log.Warnf("DemoteVolume: Replication session %s is in unexpected role/state combination (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
	return nil, status.Errorf(codes.FailedPrecondition, "replication session %s is in unexpected role/state combination (role=%s, state=%s)", replicationSession.ID, replicationSession.Role, replicationSession.State)
}

// ResyncVolume resyncs a volume.
// This is called to resume replication after a failover, syncing data from the new primary.
//
// PowerStore mapping:
// - If session is paused: Execute Resume action
// - If force=true: Execute Sync action to force immediate synchronization
// - Check session state to determine if resync is complete
//
// Returns:
// - ready=true: Resync is complete, volume is in sync (state=OK)
// - ready=false: Resync is in progress (state=Synchronizing, Initializing, Resuming, etc.)
func (s *CSIAddonsReplicationServer) ResyncVolume(
	ctx context.Context,
	req *csiaddonsreplication.ResyncVolumeRequest,
) (*csiaddonsreplication.ResyncVolumeResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("CSI-Addons ResyncVolume called with request: %+v", req)

	// Validate request
	if err := s.validateResyncVolumeRequest(req); err != nil {
		log.Errorf("ResyncVolume validation failed: %v", err)
		return nil, err
	}

	// Extract volume ID from replication source
	volumeID, volumeGroupID, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		log.Errorf("ResyncVolume failed to extract replication source: %v", err)
		return nil, err
	}

	force := req.GetForce()

	// Handle volume resync
	if volumeID != "" {
		log.Infof("ResyncVolume: Resyncing volume %s (force=%v)", volumeID, force)
		return s.resyncVolumeForVolume(ctx, volumeID, force)
	}

	// Handle volume group resync
	if volumeGroupID != "" {
		log.Infof("ResyncVolume: Resyncing volume group %s (force=%v)", volumeGroupID, force)
		return s.resyncVolumeForVolumeGroup(ctx, req)
	}

	log.Errorf("ResyncVolume: unreachable code reached - neither volumeID nor volumeGroupID was set")
	return nil, status.Error(codes.Internal, "internal error: neither volumeID nor volumeGroupID resolved")
}

// resyncVolumeForVolume executes resync for a single volume
func (s *CSIAddonsReplicationServer) resyncVolumeForVolume(
	ctx context.Context,
	volumeID string,
	force bool,
) (*csiaddonsreplication.ResyncVolumeResponse, error) {
	log := log.WithContext(ctx)

	// Parse volume handle to get array info
	volumeHandle, err := array.ParseVolumeID(ctx, volumeID, s.service.DefaultArray(), nil)
	if err != nil {
		log.Errorf("ResyncVolume: Failed to parse volume ID %s: %v", volumeID, err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume ID: %v", err)
	}

	localVolumeUUID := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := strings.ToLower(volumeHandle.Protocol)

	log.Infof("ResyncVolume: Parsed volume - UUID: %s, ArrayID: %s, Protocol: %s",
		localVolumeUUID, arrayID, protocol)
	if protocol == "nfs" {
		return nil, status.Error(codes.Unimplemented, "NFS replication is not supported")
	}

	// Get the array
	arr, ok := s.service.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "array with ID %s not found", arrayID)
	}

	client := arr.GetClient()

	// Get the replication session
	var replicationSession gopowerstore.ReplicationSession
	rs, err := client.GetReplicationSessionByLocalResourceID(ctx, localVolumeUUID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no replication session found for volume %s: %v", localVolumeUUID, err)
	}
	replicationSession = rs

	log.Infof("ResyncVolume: Found replication session %s in state %s", replicationSession.ID, replicationSession.State)
	log.Infof("ResyncVolume: Replication session %s role is %s", replicationSession.ID, replicationSession.Role)

	localIsPrimary := false
	localIsSecondary := false
	if replicationSession.Role != "" {
		switch gopowerstore.ReplicationRoleEnum(replicationSession.Role) {
		case gopowerstore.ReplicationRoleSource:
			localIsPrimary = true
		case gopowerstore.ReplicationRoleDestination:
			localIsSecondary = true
		}
	}

	// Check the current state and determine action
	switch replicationSession.State {
	case gopowerstore.RsStateOk:
		// Already synchronized - resync is complete
		log.Infof("ResyncVolume: Replication session %s is already in OK state (synchronized)", replicationSession.ID)
		return &csiaddonsreplication.ResyncVolumeResponse{Ready: true}, nil

	case gopowerstore.RsStateSynchronizing, gopowerstore.RsStateInitializing, gopowerstore.RsStateResuming, gopowerstore.RsStateReprotecting:
		// Sync is in progress - return ready=false
		log.Infof("ResyncVolume: Replication session %s is syncing (state: %s)", replicationSession.ID, replicationSession.State)
		return &csiaddonsreplication.ResyncVolumeResponse{Ready: false}, nil

	case gopowerstore.RsStatePaused, gopowerstore.RsStatePausedForMigration, gopowerstore.RsStatePausedForNdu, gopowerstore.RsStateSystemPaused:
		// Session is paused - need to resume
		log.Infof("ResyncVolume: Replication session %s is paused, executing Resume", replicationSession.ID)

		err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionResume, nil)
		if err != nil {
			log.Errorf("ResyncVolume: Failed to execute Resume: %v", err)
			return nil, err
		}

		log.Infof("ResyncVolume: Successfully initiated Resume for replication session %s", replicationSession.ID)
		// Resume initiated, sync is in progress
		return &csiaddonsreplication.ResyncVolumeResponse{Ready: false}, nil

	case gopowerstore.RsStateFailedOver:
		// After an unplanned failover (PromoteVolume called on Destination), the new Source needs to
		// issue Reprotect to re-establish replication.
		if localIsPrimary {
			log.Infof("ResyncVolume: Session %s is Failed_Over and local is Source; executing Reprotect", replicationSession.ID)
			err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionReprotect, nil)
			if err != nil {
				log.Errorf("ResyncVolume: Failed to execute Reprotect: %v", err)
				return nil, err
			}
			return &csiaddonsreplication.ResyncVolumeResponse{Ready: false}, nil
		}
		if localIsSecondary {
			// Without force, error out with OutOfRange as suggested by Nick. This adds volume is degraded msg to VR
			log.Infof("ResyncVolumeForVolume: Session %s is Failed_Over with role Destination; returning error and waiting for Source-side Resync", replicationSession.ID)
			return nil, status.Errorf(codes.OutOfRange, "replication session %s is in Failed_Over state and local is Destination; waiting for Source-side Resync", replicationSession.ID)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "replication session %s is in Failed_Over state, use force=true to attempt sync", replicationSession.ID)

	case gopowerstore.RsStateFailingOver, gopowerstore.RsStateFailingOverForDR:
		// Failover is in progress - cannot resync yet
		return nil, status.Errorf(codes.Aborted, "failover in progress for replication session %s, cannot resync", replicationSession.ID)

	default:
		// For other states, try to force sync if requested
		if force {
			log.Infof("ResyncVolume: Force flag set, executing Sync on session %s (state: %s)", replicationSession.ID, replicationSession.State)
			err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionSync, nil)
			if err != nil {
				log.Errorf("ResyncVolume: Failed to execute Sync: %v", err)
				return nil, err
			}
			return &csiaddonsreplication.ResyncVolumeResponse{Ready: false}, nil
		}
		log.Warnf("ResyncVolume: Replication session %s is in unexpected state: %s", replicationSession.ID, replicationSession.State)
		return nil, status.Errorf(codes.FailedPrecondition, "replication session %s is in unexpected state: %s, use force=true to attempt sync", replicationSession.ID, replicationSession.State)
	}
}

// resyncVolumeForVolumeGroup executes resync for a volume group
func (s *CSIAddonsReplicationServer) resyncVolumeForVolumeGroup(ctx context.Context,
	req *csiaddonsreplication.ResyncVolumeRequest,
) (*csiaddonsreplication.ResyncVolumeResponse, error) {
	log := log.WithContext(ctx)

	// Extract parameters to validate them (array IDs not used since findArrayWithVolumeGroupID searches all arrays)
	_, err := vgGetParameters(req.GetParameters())
	if err != nil {
		log.Errorf("resyncVolumeForVolumeGroup: Failed to validate parameters: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	vgID := req.GetReplicationSource().GetVolumegroup().VolumeGroupId
	log.Infof("resyncVolumeForVolumeGroup called for volume group %s: %v", vgID, req)

	// Find a StorageGroup with the ID
	arr, vg, err := findArrayWithVolumeGroupID(ctx, s.service.Arrays(), vgID)
	if err != nil {
		log.Errorf("resyncVolumeForVolumeGroup: Failed to find volume group: %v", err)
		// findArrayWithVolumeGroupID only errors when the volume group ID is empty
		return nil, status.Errorf(codes.InvalidArgument, "failed to find volume group %s: %v", vgID, err)
	}
	if vg == nil {
		log.Errorf("resyncVolumeForVolumeGroup: volume group %s not found on any array", vgID)
		return nil, status.Errorf(codes.NotFound, "volume group %s not found", vgID)
	}

	log.Infof("resyncVolumeForVolumeGroup processing volume group on VG %s %s array %s isReplicationDestination %t",
		arr.GlobalID, vg.ID, vg.Name, vg.IsReplicationDestination)

	// Get the replication session
	replicationSession, err := arr.Client.GetReplicationSessionByLocalResourceID(ctx, vg.ID)
	if err != nil {
		err := status.Errorf(codes.FailedPrecondition, "no replication session found for volume group %s: %v", vg.ID, err)
		log.Errorf("%s", err.Error())
		return nil, err
	}

	log.Infof("resyncVolumeForVolumeGroup: Found replication session %s state %s role %s", replicationSession.ID, replicationSession.State, replicationSession.Role)
	client := arr.Client
	force := req.Force

	// Determine the actual session role from the replication session
	sessionIsSecondary := false
	if replicationSession.Role != "" {
		switch gopowerstore.ReplicationRoleEnum(replicationSession.Role) {
		case gopowerstore.ReplicationRoleDestination:
			sessionIsSecondary = true
		}
	}

	// Check the current state and determine action
	switch replicationSession.State {
	case gopowerstore.RsStateOk:
		// Already synchronized - resync is complete
		log.Infof("resyncVolumeForVolumeGroup: Replication session %s is already in OK state (synchronized)", replicationSession.ID)
		return &csiaddonsreplication.ResyncVolumeResponse{Ready: true}, nil

	case gopowerstore.RsStateSynchronizing, gopowerstore.RsStateInitializing, gopowerstore.RsStateResuming, gopowerstore.RsStateReprotecting:
		// Sync is in progress - return ready=false
		log.Infof("resyncVolumeForVolumeGroup: Replication session %s is syncing (state: %s)", replicationSession.ID, replicationSession.State)
		return &csiaddonsreplication.ResyncVolumeResponse{Ready: false}, nil

	case gopowerstore.RsStatePaused, gopowerstore.RsStatePausedForMigration, gopowerstore.RsStatePausedForNdu, gopowerstore.RsStateSystemPaused:
		// Session is paused - need to resume
		log.Infof("resyncVolumeForVolumeGroup: Replication session %s is paused, executing Resume", replicationSession.ID)

		err = ExecuteAction(&replicationSession, arr.Client, gopowerstore.RsActionResume, nil)
		if err != nil {
			log.Errorf("resyncVolumeForVolumeGroup: Failed to execute Resume: %v", err)
			return nil, err
		}

		log.Infof("resyncVolumeForVolumeGroup: Successfully initiated Resume for replication session %s", replicationSession.ID)
		// Resume initiated, sync is in progress
		return &csiaddonsreplication.ResyncVolumeResponse{Ready: false}, nil

	case gopowerstore.RsStateFailedOver:
		if !sessionIsSecondary {
			// Session role is Source - this is the promoted side that can call Reprotect
			log.Infof("resyncVolumeForVolumeGroup: Session %s is Failed_Over and local session role is Source (promoted side); executing Reprotect", replicationSession.ID)
			err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionReprotect, nil)
			if err != nil {
				log.Errorf("ResyncVolume: Failed to execute Reprotect: %v", err)
				return nil, err
			}
			return &csiaddonsreplication.ResyncVolumeResponse{Ready: false}, nil
		}
		// Session role is Destination (old primary)
		// Error out with OutOfRange as suggested by Nick. This adds volume is degraded msg to VR
		log.Infof("resyncVolumeForVolumeGroup: Session %s is Failed_Over with role Destination; returning error and waiting for Source-side Reprotect", replicationSession.ID)
		return nil, status.Errorf(codes.OutOfRange, "replication session %s is in Failed_Over state and local is Destination; waiting for Source-side Resync", replicationSession.ID)

	case gopowerstore.RsStateFailingOver, gopowerstore.RsStateFailingOverForDR:
		// Failover is in progress - cannot resync yet
		return nil, status.Errorf(codes.Aborted, "failover in progress for replication session %s, cannot resync", replicationSession.ID)

	default:
		// For other states, try to force sync if requested
		if force {
			log.Infof("ResyncVolume: Force flag set, executing Sync on session %s (state: %s)", replicationSession.ID, replicationSession.State)
			err = ExecuteAction(&replicationSession, client, gopowerstore.RsActionSync, nil)
			if err != nil {
				log.Errorf("ResyncVolume: Failed to execute Sync: %v", err)
				return nil, err
			}
			return &csiaddonsreplication.ResyncVolumeResponse{Ready: false}, nil
		}
		log.Warnf("ResyncVolume: Replication session %s is in unexpected state: %s", replicationSession.ID, replicationSession.State)
		return nil, status.Errorf(codes.FailedPrecondition, "replication session %s is in unexpected state: %s, use force=true to attempt sync", replicationSession.ID, replicationSession.State)
	}
}

// GetVolumeReplicationInfo returns replication information for a volume.
// This provides status information about the replication session.
//
// PowerStore mapping:
// - GetReplicationSession to get session details
// - Map PowerStore session state to response:
//   - OK: Synchronized, LastSyncTime from session
//   - Synchronizing, Initializing: Sync in progress
//   - Failed_Over: Volume is primary (failed over)
//   - Paused states: Replication paused
//   - Error states: Replication error
func (s *CSIAddonsReplicationServer) GetVolumeReplicationInfo(
	ctx context.Context,
	req *csiaddonsreplication.GetVolumeReplicationInfoRequest,
) (*csiaddonsreplication.GetVolumeReplicationInfoResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("CSI-Addons GetVolumeReplicationInfo called with request: %+v", req)

	// Validate request
	if err := s.validateGetVolumeReplicationInfoRequest(req); err != nil {
		log.Errorf("GetVolumeReplicationInfo validation failed: %v", err)
		return nil, err
	}

	// Extract volume ID from replication source
	volumeID, volumeGroupID, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		log.Errorf("GetVolumeReplicationInfo failed to extract replication source: %v", err)
		return nil, err
	}

	// Handle volume replication info
	if volumeID != "" {
		log.Infof("GetVolumeReplicationInfo: Getting info for volume %s", volumeID)
		return s.getVolumeReplicationInfoForVolume(ctx, volumeID)
	}

	// Handle volume group replication info
	if volumeGroupID != "" {
		log.Infof("GetVolumeReplicationInfo: Getting info for volume group %s", volumeGroupID)
		return s.getVolumeReplicationInfoForVolumeGroup(ctx, volumeGroupID)
	}

	log.Errorf("GetVolumeReplicationInfo: unreachable code reached - neither volumeID nor volumeGroupID was set")
	return nil, status.Error(codes.Internal, "internal error: neither volumeID nor volumeGroupID resolved")
}

// getVolumeReplicationInfoForVolume retrieves replication info for a single volume
func (s *CSIAddonsReplicationServer) getVolumeReplicationInfoForVolume(
	ctx context.Context,
	volumeID string,
) (*csiaddonsreplication.GetVolumeReplicationInfoResponse, error) {
	log := log.WithContext(ctx)

	// Parse volume handle to get array info
	volumeHandle, err := array.ParseVolumeID(ctx, volumeID, s.service.DefaultArray(), nil)
	if err != nil {
		log.Errorf("GetVolumeReplicationInfo: Failed to parse volume ID %s: %v", volumeID, err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume ID: %v", err)
	}

	localVolumeUUID := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := strings.ToLower(volumeHandle.Protocol)

	log.Infof("GetVolumeReplicationInfo: Parsed volume - UUID: %s, ArrayID: %s, Protocol: %s",
		localVolumeUUID, arrayID, protocol)
	if protocol == "nfs" {
		return nil, status.Error(codes.Unimplemented, "NFS replication is not supported")
	}

	// Get the array
	arr, ok := s.service.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "array with ID %s not found", arrayID)
	}

	client := arr.GetClient()

	// Get the replication session
	var replicationSession gopowerstore.ReplicationSession
	rs, err := client.GetReplicationSessionByLocalResourceID(ctx, localVolumeUUID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no replication session found for volume %s: %v", localVolumeUUID, err)
	}
	replicationSession = rs

	log.Infof("GetVolumeReplicationInfo: session %s role %s state %s type %s",
		replicationSession.ID, replicationSession.Role, replicationSession.State, replicationSession.Type)

	// Map replication session state to CSI-Addons status
	statusVal, statusMessage := mapReplicationSessionStateToStatus(replicationSession.State)

	// Build response
	response := &csiaddonsreplication.GetVolumeReplicationInfoResponse{
		Status:        statusVal,
		StatusMessage: statusMessage,
	}

	// Set LastSyncTime based on state
	switch replicationSession.State {
	case gopowerstore.RsStateOk:
		// Synchronized - report current time as last sync
		response.LastSyncTime = timestamppb.Now()
		log.Infof("GetVolumeReplicationInfo: Session %s is healthy and synchronized", replicationSession.ID)

	case gopowerstore.RsStateFailedOver:
		// Failed over - volume is now primary on this side, but replication is degraded
		// Report current time since this side is active
		response.LastSyncTime = timestamppb.Now()
		log.Infof("GetVolumeReplicationInfo: Session %s has failed over, now primary on this array", replicationSession.ID)

	case gopowerstore.RsStateSynchronizing, gopowerstore.RsStateInitializing, gopowerstore.RsStateResuming, gopowerstore.RsStateReprotecting:
		// Sync in progress - don't set LastSyncTime until complete
		log.Infof("GetVolumeReplicationInfo: Session %s is syncing (state: %s)", replicationSession.ID, replicationSession.State)

	case gopowerstore.RsStateFailingOver, gopowerstore.RsStateFailingOverForDR:
		// Failover in progress - don't set LastSyncTime during transition
		log.Infof("GetVolumeReplicationInfo: Session %s is failing over (state: %s)", replicationSession.ID, replicationSession.State)

	default:
		// Paused, error, or other states - don't set LastSyncTime
		log.Warnf("GetVolumeReplicationInfo: Session %s is in non-healthy state: %s", replicationSession.ID, replicationSession.State)
	}

	log.Infof("GetVolumeReplicationInfo: Session %s - State: %s, Status: %s, StatusMessage: %s, LastSyncTime: %v",
		replicationSession.ID, replicationSession.State, response.Status, response.StatusMessage, response.LastSyncTime)

	return response, nil
}

// getVolumeReplicationInfoForVolumeGroup retrieves replication info for a volume group
func (s *CSIAddonsReplicationServer) getVolumeReplicationInfoForVolumeGroup(
	ctx context.Context,
	volumeGroupID string,
) (*csiaddonsreplication.GetVolumeReplicationInfoResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("getVolumeReplicationInfoForVolumeGroup called for volume group %s", volumeGroupID)

	// Find the array with the volume group
	arrays := s.service.Arrays()
	arr, vg, err := findArrayWithVolumeGroupID(ctx, arrays, volumeGroupID)
	if vg == nil || err != nil {
		log.Errorf("getVolumeReplicationInfoForVolumeGroup: Failed to find array with volume group ID %s: %v", volumeGroupID, err)
		return nil, status.Errorf(codes.NotFound, "volume group %s not found: %v", volumeGroupID, err)
	}
	log.Infof("getVolumeReplicationInfoForVolumeGroup: processing VG %s on array %s", volumeGroupID, arr.GetGlobalID())

	// Retrieve the replication session
	replicationSession, err := arr.GetClient().GetReplicationSessionByLocalResourceID(ctx, vg.ID)
	if err != nil {
		log.Errorf("getVolumeReplicationInfoForVolumeGroup: Failed to get replication session for VolumeGroup %s: %v", vg.ID, err)
		return nil, status.Errorf(codes.FailedPrecondition, "no replication session found for volume group %s: %v", vg.ID, err)
	}
	log.Infof("getVolumeReplicationInfoForVolumeGroup: session %s role %s state %s type %s",
		replicationSession.ID, replicationSession.Role, replicationSession.State, replicationSession.Type)

	// Map replication session state to CSI-Addons status
	statusVal, statusMessage := mapReplicationSessionStateToStatus(replicationSession.State)

	// Build response
	response := &csiaddonsreplication.GetVolumeReplicationInfoResponse{
		Status:        statusVal,
		StatusMessage: statusMessage,
	}

	// Set LastSyncTime based on state
	switch replicationSession.State {
	case gopowerstore.RsStateOk:
		// Synchronized - report current time as last sync
		response.LastSyncTime = timestamppb.Now()
		log.Infof("getVolumeReplicationInfoForVolumeGroup: Session %s is healthy and synchronized", replicationSession.ID)

	case gopowerstore.RsStateFailedOver:
		// Failed over - volume is now primary on this side, but replication is degraded
		// Report current time since this side is active
		response.LastSyncTime = timestamppb.Now()
		log.Infof("getVolumeReplicationInfoForVolumeGroup: Session %s has failed over, now primary on this array", replicationSession.ID)

	case gopowerstore.RsStateSynchronizing, gopowerstore.RsStateInitializing, gopowerstore.RsStateResuming, gopowerstore.RsStateReprotecting:
		// Sync in progress - don't set LastSyncTime until complete
		log.Infof("getVolumeReplicationInfoForVolumeGroup: Session %s is syncing (state: %s)", replicationSession.ID, replicationSession.State)

	case gopowerstore.RsStateFailingOver, gopowerstore.RsStateFailingOverForDR:
		// Failover in progress - don't set LastSyncTime during transition
		log.Infof("getVolumeReplicationInfoForVolumeGroup: Session %s is failing over (state: %s)", replicationSession.ID, replicationSession.State)

	default:
		// Paused, error, or other states - don't set LastSyncTime
		log.Warnf("getVolumeReplicationInfoForVolumeGroup: Session %s is in non-healthy state: %s", replicationSession.ID, replicationSession.State)
	}

	log.Infof("getVolumeReplicationInfoForVolumeGroup: Session %s - State: %s, Status: %s, StatusMessage: %s, LastSyncTime: %v",
		replicationSession.ID, replicationSession.State, response.Status, response.StatusMessage, response.LastSyncTime)

	return response, nil
}

// GetReplicationDestinationInfo returns the destination volume details for an existing replication.
// This identifies which volume on the remote cluster corresponds to the replicated source volume.
//
// PowerStore mapping:
// - GetReplicationSessionByLocalResourceID to find the session for the local volume
// - Use RemoteResourceID as the destination volume UUID
// - Use GetRemoteSystem to find the remote array GlobalID (SerialNumber)
// - Construct destination volume ID as <remoteUUID>/<remoteArrayGlobalID>/<protocol>
func (s *CSIAddonsReplicationServer) GetReplicationDestinationInfo(
	ctx context.Context,
	req *csiaddonsreplication.GetReplicationDestinationInfoRequest,
) (*csiaddonsreplication.GetReplicationDestinationInfoResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("CSI-Addons GetReplicationDestinationInfo called with request: %+v", req)

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if req.GetReplicationSource() == nil {
		return nil, status.Error(codes.InvalidArgument, "replication_source is required")
	}

	volumeID, volumeGroupID, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		log.Errorf("GetReplicationDestinationInfo failed to extract replication source: %v", err)
		return nil, err
	}

	if volumeID != "" {
		log.Infof("GetReplicationDestinationInfo: Getting destination info for volume %s", volumeID)
		return s.getReplicationDestinationInfoForVolume(ctx, volumeID)
	}

	if volumeGroupID != "" {
		log.Infof("GetReplicationDestinationInfo: Getting destination info for volume group %s", volumeGroupID)
		return s.getReplicationDestinationInfoForVolumeGroup(ctx, volumeGroupID)
	}

	return nil, status.Error(codes.InvalidArgument, "volume or volume_group is required in replication_source")
}

// getReplicationDestinationInfoForVolume retrieves the replication destination for a single volume.
// It looks up the replication session for the local volume and constructs the remote volume handle.
func (s *CSIAddonsReplicationServer) getReplicationDestinationInfoForVolume(
	ctx context.Context,
	volumeID string,
) (*csiaddonsreplication.GetReplicationDestinationInfoResponse, error) {
	log := log.WithContext(ctx)

	// Parse volume handle to get local UUID, array ID, and protocol
	volumeHandle, err := array.ParseVolumeID(ctx, volumeID, s.service.DefaultArray(), nil)
	if err != nil {
		log.Errorf("GetReplicationDestinationInfo: Failed to parse volume ID %s: %v", volumeID, err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume ID: %v", err)
	}

	localVolumeUUID := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := strings.ToLower(volumeHandle.Protocol)

	log.Infof("GetReplicationDestinationInfo: Parsed volume - UUID: %s, ArrayID: %s, Protocol: %s",
		localVolumeUUID, arrayID, protocol)

	// Get the array client
	arr, ok := s.service.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "array with ID %s not found", arrayID)
	}

	client := arr.GetClient()

	// Get the replication session for this volume
	rs, err := client.GetReplicationSessionByLocalResourceID(ctx, localVolumeUUID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no replication session found for volume %s: %v", localVolumeUUID, err)
	}

	// RemoteResourceID is the UUID of the replicated volume on the remote array
	remoteVolumeUUID := rs.RemoteResourceID
	if remoteVolumeUUID == "" {
		// Destination details are not populated yet; transient until replication is established
		return nil, status.Errorf(codes.Unavailable, "remote resource ID not yet available in replication session for volume %s", localVolumeUUID)
	}

	// Get the remote system to find the remote array GlobalID (SerialNumber == GlobalID in PowerStore)
	remoteSystem, err := client.GetRemoteSystem(ctx, rs.RemoteSystemID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get remote system %s: %v", rs.RemoteSystemID, err)
	}

	// Construct the destination volume ID: <remoteUUID>/<remoteArrayGlobalID>/<protocol>
	destinationVolumeID := fmt.Sprintf("%s/%s/%s", remoteVolumeUUID, remoteSystem.SerialNumber, protocol)

	log.Infof("GetReplicationDestinationInfo: Destination volume ID for %s is %s", localVolumeUUID, destinationVolumeID)

	return &csiaddonsreplication.GetReplicationDestinationInfoResponse{
		ReplicationDestination: &csiaddonsreplication.ReplicationDestination{
			Type: &csiaddonsreplication.ReplicationDestination_Volume{
				Volume: &csiaddonsreplication.ReplicationDestination_VolumeDestination{
					VolumeId: destinationVolumeID,
				},
			},
		},
	}, nil
}

// getReplicationDestinationInfoForVolumeGroup retrieves the replication destination for a volume group.
// Returns all source-to-destination volume ID mappings for volumes in the group.
func (s *CSIAddonsReplicationServer) getReplicationDestinationInfoForVolumeGroup(
	ctx context.Context,
	volumeGroupID string,
) (*csiaddonsreplication.GetReplicationDestinationInfoResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("GetReplicationDestinationInfo: Getting destination info for volume group %s", volumeGroupID)

	// Find the volume group on one of the configured arrays
	arrays := s.service.Arrays()
	var arr *array.PowerStoreArray
	var vg *gopowerstore.VolumeGroup

	arr, vg, err := findArrayWithVolumeGroupID(ctx, arrays, volumeGroupID)
	if vg == nil || err != nil || arr == nil {
		log.Errorf("GetReplicationDestinationInfo: Volume group %s not found on any configured array: %v", volumeGroupID, err)
		return nil, status.Errorf(codes.NotFound, "volume group %s not found", volumeGroupID)
	}

	client := arr.GetClient()

	// Get the replication session for this volume group
	rs, err := client.GetReplicationSessionByLocalResourceID(ctx, vg.ID)
	if err != nil {
		log.Errorf("GetReplicationDestinationInfo: No replication session found for volume group %s: %v", vg.ID, err)
		return nil, status.Errorf(codes.FailedPrecondition, "no replication session found for volume group %s: %v", volumeGroupID, err)
	}

	// RemoteResourceID is the UUID of the replicated volume group on the remote array
	remoteVolumeGroupUUID := rs.RemoteResourceID
	if remoteVolumeGroupUUID == "" {
		// Destination details are not populated yet; transient until replication is established
		return nil, status.Errorf(codes.Unavailable, "remote resource ID not yet available in replication session for volume group %s", volumeGroupID)
	}

	// Get the remote system to find the remote array GlobalID (SerialNumber == GlobalID in PowerStore)
	remoteSystem, err := client.GetRemoteSystem(ctx, rs.RemoteSystemID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get remote system %s: %v", rs.RemoteSystemID, err)
	}

	// Construct the destination volume group ID: <remoteUUID>
	destinationVolumeGroupID := fmt.Sprintf("%s", remoteVolumeGroupUUID)

	log.Infof("GetReplicationDestinationInfo: Destination volume group ID for %s is %s", volumeGroupID, destinationVolumeGroupID)

	// Build volume ID mappings from StorageElementPairs
	// Protocol is "scsi" for block volumes (volume group replication is block-only)
	protocol := "scsi"
	volumeMappings := make(map[string]string)

	for _, pair := range rs.StorageElementPairs {
		// Construct source volume ID: <localUUID>/<localArrayGlobalID>/<protocol>
		sourceVolumeID := fmt.Sprintf("%s/%s/%s", pair.LocalStorageElementID, arr.GetGlobalID(), protocol)

		// Construct destination volume ID: <remoteUUID>/<remoteArrayGlobalID>/<protocol>
		destinationVolumeID := fmt.Sprintf("%s/%s/%s", pair.RemoteStorageElementID, remoteSystem.SerialNumber, protocol)

		volumeMappings[sourceVolumeID] = destinationVolumeID
	}

	log.Infof("GetReplicationDestinationInfo: volume group %s mappings:  %v", volumeGroupID, volumeMappings)

	return &csiaddonsreplication.GetReplicationDestinationInfoResponse{
		ReplicationDestination: &csiaddonsreplication.ReplicationDestination{
			Type: &csiaddonsreplication.ReplicationDestination_Volumegroup{
				Volumegroup: &csiaddonsreplication.ReplicationDestination_VolumeGroupDestination{
					VolumeGroupId: destinationVolumeGroupID,
					VolumeIds:     volumeMappings,
				},
			},
		},
	}, nil
}

// =============================================================================
// Validation helpers
// =============================================================================

func (s *CSIAddonsReplicationServer) validateEnableReplicationRequest(req *csiaddonsreplication.EnableVolumeReplicationRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	// replication_source must be provided
	if req.GetReplicationSource() == nil {
		return status.Error(codes.InvalidArgument, "replication_source is required")
	}

	_, _, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		return err
	}

	return nil
}

func (s *CSIAddonsReplicationServer) validateDisableReplicationRequest(req *csiaddonsreplication.DisableVolumeReplicationRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if req.GetReplicationSource() == nil {
		return status.Error(codes.InvalidArgument, "replication_source is required")
	}

	_, _, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		return err
	}

	return nil
}

func (s *CSIAddonsReplicationServer) validatePromoteVolumeRequest(req *csiaddonsreplication.PromoteVolumeRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if req.GetReplicationSource() == nil {
		return status.Error(codes.InvalidArgument, "replication_source is required")
	}

	_, _, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		return err
	}

	return nil
}

func (s *CSIAddonsReplicationServer) validateDemoteVolumeRequest(req *csiaddonsreplication.DemoteVolumeRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if req.GetReplicationSource() == nil {
		return status.Error(codes.InvalidArgument, "replication_source is required")
	}

	_, _, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		return err
	}

	return nil
}

func (s *CSIAddonsReplicationServer) validateResyncVolumeRequest(req *csiaddonsreplication.ResyncVolumeRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if req.GetReplicationSource() == nil {
		return status.Error(codes.InvalidArgument, "replication_source is required")
	}

	_, _, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		return err
	}

	return nil
}

func (s *CSIAddonsReplicationServer) validateGetVolumeReplicationInfoRequest(req *csiaddonsreplication.GetVolumeReplicationInfoRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if req.GetReplicationSource() == nil {
		return status.Error(codes.InvalidArgument, "replication_source is required")
	}

	_, _, err := s.extractReplicationSource(req.GetReplicationSource())
	if err != nil {
		return err
	}

	return nil
}

// =============================================================================
// Helper functions
// =============================================================================

// extractReplicationSource extracts volume ID or volume group ID from ReplicationSource
func (s *CSIAddonsReplicationServer) extractReplicationSource(source *csiaddonsreplication.ReplicationSource) (volumeID, volumeGroupID string, err error) {
	if source == nil {
		return "", "", nil
	}

	switch t := source.GetType().(type) {
	case *csiaddonsreplication.ReplicationSource_Volume:
		if t.Volume != nil {
			volumeID = t.Volume.GetVolumeId()
		}
	case *csiaddonsreplication.ReplicationSource_Volumegroup:
		if t.Volumegroup != nil {
			volumeGroupID = t.Volumegroup.GetVolumeGroupId()
		}
	default:
		return "", "", status.Errorf(codes.InvalidArgument, "unknown replication source type")
	}

	if volumeID == "" && volumeGroupID == "" {
		return "", "", status.Error(codes.InvalidArgument, "volume or volume_group is required in replication_source")
	}

	return volumeID, volumeGroupID, nil
}

// =============================================================================
// VolumeGroup Management Operations
// =============================================================================
// These functions implement CSI-Addons VolumeGroup controller operations for
// creating, modifying, and deleting volume groups with replication.

// CreateVolumeGroup creates a volume group.
// This is called by CSI-Addons VolumeGroup controller to create a volume group.
// It only creates the VG and adds member volumes — it does NOT assign a protection policy
// or replication rule. PP/RR assignment is handled by enableVolumeReplicationForVolumeGroup.
func (s *CSIAddonsVolumeGroupServer) CreateVolumeGroup(ctx context.Context,
	req *volumegrouprpc.CreateVolumeGroupRequest,
) (*volumegrouprpc.CreateVolumeGroupResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("CreateVolumeGroup called  %v", req)

	volumeGroup := volumegrouprpc.VolumeGroup{}
	resp := &volumegrouprpc.CreateVolumeGroupResponse{}
	resp.VolumeGroup = &volumeGroup

	// Validate incoming parameters
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "CreateVolumeGroup failed: volume group name is required")
	}
	volumeGroupContentID := strings.TrimPrefix(req.Name, "vgrcontent-")
	if len(req.VolumeIds) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "CreateVolumeGroup failed: at least one volume id is required to create a volume group")
	}

	// Validate parameters using vgGetParameters
	params, err := vgGetParameters(req.Parameters)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// Extract required parameters
	sourceArrayID := params[sourceArrayParameter]
	targetArrayID := params[targetArrayParameter]
	targetArrayName := params[targetArrayNameParameter]
	mode := params[replicationModeParameter]
	log.Infof("CreateVolumeGroup  %s remoteSystem %s mode %s", sourceArrayID, targetArrayID, mode)

	// Determine which array the volumes belong to by parsing the first volume ID
	// This determines if this is a source side or target side CreateVolumeGroup call
	var volumeArrayID string
	if len(req.VolumeIds) > 0 {
		firstVolumeHandle, err := array.ParseVolumeID(ctx, req.VolumeIds[0], nil, getDefaultCapability())
		if err != nil {
			log.Errorf("CreateVolumeGroup failed: Failed to parse volume id %s: %v", req.VolumeIds[0], err)
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume id %s: %v", req.VolumeIds[0], err)
		}
		volumeArrayID = firstVolumeHandle.LocalArrayGlobalID
	}

	// If volumes belong to target array, this is a target side CreateVolumeGroup call
	if volumeArrayID == targetArrayID {
		log.Infof("CreateVolumeGroup: Volumes belong to target array %s, calling createReplicaVolumeGroup", targetArrayID)
		return s.createReplicaVolumeGroup(ctx, req, params, resp)
	}

	// Validate array existence
	arrays := s.service.Arrays()
	sourceArray, ok := arrays[sourceArrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "CreateVolumeGroup failed: sourceArray %s not found", sourceArrayID)
	}
	_, ok = arrays[targetArrayID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "CreateVolumeGroup failed: targetArray %s not found", targetArrayID)
	}

	// Check if the first volume is a replication destination (unplanned failover scenario).
	// In an unplanned failover, the VGRC's "source" array may already hold destination volumes
	// from a prior replication relationship. These volumes are already in an existing destination
	// VG, so we must route to createReplicaVolumeGroup instead of creating a new VG.
	if len(req.VolumeIds) > 0 {
		firstVolumeHandle, err := array.ParseVolumeID(ctx, req.VolumeIds[0], nil, getDefaultCapability())
		if err == nil {
			if arr, ok := arrays[firstVolumeHandle.LocalArrayGlobalID]; ok {
				vol, volErr := arr.Client.GetVolume(ctx, firstVolumeHandle.LocalUUID)
				if volErr == nil && vol.IsReplicationDestination {
					log.Infof("CreateVolumeGroup: First volume %s is a replication destination on array %s, routing to createReplicaVolumeGroup",
						firstVolumeHandle.LocalUUID, firstVolumeHandle.LocalArrayGlobalID)
					return s.createReplicaVolumeGroup(ctx, req, params, resp)
				}
			}
		}
	}

	log.Infof("Creating volume group for %s", volumeGroupContentID)

	csiVolumes := make([]*csi.Volume, 0)
	sourceArrayVolumeIDs := make([]string, 0)

	// Validate that all volumes are from the same storage array
	referenceArrayID := ""
	for _, id := range req.VolumeIds {
		if id == "" {
			continue
		}
		volumeHandle, err := array.ParseVolumeID(ctx, id, s.service.DefaultArray(), getDefaultCapability())
		if err != nil {
			log.Errorf("CreateVolumeGroup failed: Failed to parse volume id %s: %v", id, err)
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume id %s: %v", id, err)
		}
		if referenceArrayID == "" {
			referenceArrayID = volumeHandle.LocalArrayGlobalID
		} else if volumeHandle.LocalArrayGlobalID != referenceArrayID {
			log.Errorf("CreateVolumeGroup failed: Volume %s belongs to array %s, but expected array %s", id, volumeHandle.LocalArrayGlobalID, referenceArrayID)
			return nil, status.Errorf(codes.InvalidArgument, "CreateVolumeGroup failed: all volumes must belong to the same storage array")
		}
	}

	// Determine which array the volumes belong to
	var workingArray *array.PowerStoreArray
	switch referenceArrayID {
	case sourceArrayID:
		workingArray = sourceArray
		log.Infof("Volumes belong to source array %s", sourceArrayID)
	case targetArrayID:
		workingArray = arrays[targetArrayID]
		log.Infof("Volumes belong to target array %s (failover scenario)", targetArrayID)
	default:
		if arr, exists := arrays[referenceArrayID]; exists {
			workingArray = arr
			log.Infof("Found working array %s by volume analysis", referenceArrayID)
		} else {
			return nil, status.Errorf(codes.NotFound, "CreateVolumeGroup failed: volumes belong to array %s but it's not configured", referenceArrayID)
		}
	}

	// Populate the volumes
	for _, id := range req.VolumeIds {
		if id == "" {
			continue
		}
		volumeHandle, err := array.ParseVolumeID(ctx, id, s.service.DefaultArray(), getDefaultCapability())
		if err != nil {
			log.Errorf("CreateVolumeGroup failed: Failed to parse volume id %s: %v", id, err)
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume id %s: %v", id, err)
		}
		localID := strings.Split(volumeHandle.LocalUUID, "/")[0]
		sourceArrayVolumeIDs = append(sourceArrayVolumeIDs, localID)

		volume, err := workingArray.GetClient().GetVolume(ctx, volumeHandle.LocalUUID)
		if err == nil {
			csiVolume := getCSIVolume(volume.ID, volume.Size)
			csiVolumes = append(csiVolumes, csiVolume)
		} else {
			log.Errorf("CreateVolumeGroup failed: Failed to get volume %s: %v", id, err)
			if apiErr, ok := err.(gopowerstore.APIError); ok && apiErr.NotFound() {
				return nil, status.Errorf(codes.NotFound, "volume %s not found: %v", id, err)
			}
			return nil, status.Errorf(codes.Internal, "failed to get volume %s: %v", id, err)
		}
	}

	// Check if volumes are already in a volume group
	prefix := getVolumeGroupPrefix(params)
	existingVG, err := checkExistingReplicationVolumeGroup(ctx, workingArray, sourceArrayVolumeIDs, prefix)
	if err != nil {
		log.Errorf("CreateVolumeGroup failed: Failed to check existing volume groups: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to check existing volume groups: %v", err)
	}
	if existingVG != nil {
		log.Infof("Volumes are already in volume group %s", existingVG.Name)
		respVG := &volumegrouprpc.VolumeGroup{
			VolumeGroupId:      existingVG.ID,
			VolumeGroupContext: make(map[string]string),
			Volumes:            csiVolumes,
		}
		respVG.VolumeGroupContext[volumeGroupIDParameter] = existingVG.ID
		respVG.VolumeGroupContext[volumeGroupNameParameter] = existingVG.Name
		respVG.VolumeGroupContext[sourceArrayParameter] = sourceArrayID
		respVG.VolumeGroupContext[targetArrayParameter] = targetArrayID
		respVG.VolumeGroupContext[targetArrayNameParameter] = targetArrayName
		resp.VolumeGroup = respVG
		return resp, nil
	}

	rpo := params[rpoParameter]
	if rpo == "" && mode == identifiers.SyncMode {
		rpo = identifiers.Zero
	}

	// Generate the volume group name
	vgName := getVolumeGroupName(prefix, volumeGroupContentID, rpo, targetArrayName)

	// Create the volume group (without protection policy)
	vg, err := s.createVolumeGroup(ctx, workingArray, volumeGroupContentID, sourceArrayVolumeIDs, vgName, mode)
	if err != nil {
		log.Errorf("CreateVolumeGroup failed: %v", err)
		// createVolumeGroup already returns a gRPC status error
		return nil, err
	}

	vg.VolumeGroupContext[sourceArrayParameter] = sourceArrayID
	vg.VolumeGroupContext[targetArrayParameter] = targetArrayID
	vg.VolumeGroupContext[targetArrayNameParameter] = targetArrayName
	resp.VolumeGroup = vg
	resp.VolumeGroup.Volumes = csiVolumes
	log.Infof("CreateVolumeGroup returning VolumeGroup %v", resp.VolumeGroup)

	return resp, nil
}

// createReplicaVolumeGroup handles creation of replica volume group on secondary array
func (s *CSIAddonsVolumeGroupServer) createReplicaVolumeGroup(ctx context.Context,
	req *volumegrouprpc.CreateVolumeGroupRequest, params map[string]string,
	resp *volumegrouprpc.CreateVolumeGroupResponse,
) (*volumegrouprpc.CreateVolumeGroupResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("createReplicaVolumeGroup called req %v params %v", req, params)

	// Validate that all volumes are from the same storage array
	referenceArrayID := ""
	for _, id := range req.VolumeIds {
		if id == "" {
			continue
		}
		volumeHandle, err := array.ParseVolumeID(ctx, id, s.service.DefaultArray(), getDefaultCapability())
		if err != nil {
			log.Errorf("CreateVolumeGroup failed: Failed to parse volume id %s: %v", id, err)
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume id %s: %v", id, err)
		}
		if referenceArrayID == "" {
			referenceArrayID = volumeHandle.LocalArrayGlobalID
		} else if volumeHandle.LocalArrayGlobalID != referenceArrayID {
			log.Errorf("CreateVolumeGroup failed: Volume %s belongs to array %s, but expected array %s", id, volumeHandle.LocalArrayGlobalID, referenceArrayID)
			return nil, status.Errorf(codes.InvalidArgument, "CreateVolumeGroup failed: volumes from multiple arrays in groups")
		}
	}

	// Validate that all volumes are members of the same volume group
	var volumeGroupID string
	var volumeGroupName string
	workingArray := s.service.Arrays()[referenceArrayID]
	if workingArray == nil {
		return nil, status.Errorf(codes.NotFound, "CreateVolumeGroup failed: array %s not found", referenceArrayID)
	}

	firstSeen := false
	for _, id := range req.VolumeIds {
		if id == "" {
			continue
		}
		volumeHandle, err := array.ParseVolumeID(ctx, id, s.service.DefaultArray(), getDefaultCapability())
		if err != nil {
			log.Errorf("CreateVolumeGroup failed: Failed to parse volume id %s: %v", id, err)
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume id %s: %v", id, err)
		}

		localID := strings.Split(volumeHandle.LocalUUID, "/")[0]
		vgs, err := workingArray.GetClient().GetVolumeGroupsByVolumeID(ctx, localID)
		if err != nil {
			log.Errorf("CreateVolumeGroup failed: Failed to get volume groups for volume %s: %v", id, err)
			return nil, status.Errorf(codes.Internal, "failed to get volume groups for volume %s: %v", id, err)
		}

		if len(vgs.VolumeGroup) == 0 {
			log.Errorf("CreateVolumeGroup failed: Volume %s is not a member of any volume group", id)
			return nil, status.Errorf(codes.InvalidArgument, "CreateVolumeGroup failed: volume %s is not a member of any volume group", id)
		}

		currentVGID := vgs.VolumeGroup[0].ID
		currentVGName := vgs.VolumeGroup[0].Name

		if !firstSeen {
			volumeGroupID = currentVGID
			volumeGroupName = currentVGName
			firstSeen = true
		} else if currentVGID != volumeGroupID {
			log.Errorf("CreateVolumeGroup failed: Volume %s belongs to volume group %s, but expected volume group %s", id, currentVGID, volumeGroupID)
			return nil, status.Errorf(codes.InvalidArgument, "CreateVolumeGroup failed: disparate volume groups")
		}
	}

	// Read the volume group to get its details
	vg, err := workingArray.GetClient().GetVolumeGroup(ctx, volumeGroupID)
	if err != nil {
		log.Errorf("CreateVolumeGroup failed: Failed to get volume group %s: %v", volumeGroupID, err)
		if apiErr, ok := err.(gopowerstore.APIError); ok && apiErr.NotFound() {
			return nil, status.Errorf(codes.NotFound, "volume group %s not found: %v", volumeGroupID, err)
		}
		return nil, status.Errorf(codes.Internal, "failed to get volume group %s: %v", volumeGroupID, err)
	}

	// Use the actual volume group ID from the target array (not extracted from name)
	// PP/RR assignment is handled by enableVolumeReplicationForVolumeGroup
	resp.VolumeGroup.VolumeGroupId = vg.ID
	resp.VolumeGroup.VolumeGroupContext = make(map[string]string)
	resp.VolumeGroup.VolumeGroupContext[sourceArrayParameter] = params[sourceArrayParameter]
	resp.VolumeGroup.VolumeGroupContext[targetArrayParameter] = params[targetArrayParameter]
	resp.VolumeGroup.VolumeGroupContext[targetArrayNameParameter] = params[targetArrayNameParameter]
	resp.VolumeGroup.VolumeGroupContext[volumeGroupNameParameter] = volumeGroupName

	log.Infof("CreateVolumeGroup returning VolumeGroup %v for existing volume group %s, resp: %v", resp.VolumeGroup, volumeGroupName, resp)
	return resp, nil
}

// createVolumeGroup creates a volume group on the specified array.
// This only creates the VG and adds member volumes — it does NOT assign a protection policy
// or replication rule. PP/RR assignment is handled by enableVolumeReplicationForVolumeGroup.
func (s *CSIAddonsVolumeGroupServer) createVolumeGroup(ctx context.Context, arr *array.PowerStoreArray, _ string,
	memberVolumeIDs []string, vgName string, mode string,
) (*volumegrouprpc.VolumeGroup, error) {
	log := log.WithContext(ctx)

	resp := &volumegrouprpc.VolumeGroup{}
	resp.VolumeGroupContext = make(map[string]string)
	resp.VolumeGroupContext[volumeGroupNameParameter] = vgName

	log.Infof("Checking if volume group %s exists", vgName)
	vg, err := arr.Client.GetVolumeGroupByName(ctx, vgName)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			log.Infof("Volume group %s not found, creating it", vgName)

			isWriteOrderConsistent := false
			if mode == identifiers.SyncMode {
				isWriteOrderConsistent = true
			}
			group, err := arr.Client.CreateVolumeGroup(ctx, &gopowerstore.VolumeGroupCreate{
				Name:                   vgName,
				IsWriteOrderConsistent: &isWriteOrderConsistent,
				VolumeIDs:              memberVolumeIDs,
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "can't create volume group: %s", err.Error())
			}

			vg, err = arr.Client.GetVolumeGroup(ctx, group.ID)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "can't get volume group by id: %s", err.Error())
			}
		} else {
			return nil, status.Errorf(codes.Internal, "can't query volume group by name: %s", err.Error())
		}
	} else {
		log.Infof("Volume group %s found, updating if needed", vgName)
		// Add new members if needed
		existingMembers := make(map[string]bool)
		for _, v := range vg.Volumes {
			existingMembers[v.ID] = true
		}

		newMembers := &gopowerstore.VolumeGroupMembers{}
		for _, vid := range memberVolumeIDs {
			if !existingMembers[vid] {
				newMembers.VolumeIDs = append(newMembers.VolumeIDs, vid)
			}
		}
		if len(newMembers.VolumeIDs) > 0 {
			_, err = arr.Client.AddMembersToVolumeGroup(ctx, newMembers, vg.ID)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "can't add members to volume group: %s", err.Error())
			}
		}
	}

	resp.VolumeGroupId = vg.ID
	return resp, nil
}

// ModifyVolumeGroupMembership modifies the membership of a volume group
func (s *CSIAddonsVolumeGroupServer) ModifyVolumeGroupMembership(ctx context.Context,
	req *volumegrouprpc.ModifyVolumeGroupMembershipRequest,
) (*volumegrouprpc.ModifyVolumeGroupMembershipResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("ModifyVolumeGroupMembership called  %v", req)

	vgid := req.GetVolumeGroupId()
	if vgid == "" {
		log.Errorf("ModifyVolumeGroupMembership failed: VolumeGroup id must be specified")
		return nil, status.Errorf(codes.InvalidArgument, "ModifyVolumeGroupMembership failed: VolumeGroup id must be specified")
	}

	// Extract parameters to get array IDs
	params, err := vgGetParameters(req.Parameters)
	if err != nil {
		log.Errorf("ModifyVolumeGroupMembership: Failed to validate parameters: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	sourceArrayID := params[sourceArrayParameter]
	targetArrayID := params[targetArrayParameter]

	// Try to find VG on specific arrays (source first, then target)
	arrays := s.service.Arrays()
	var myarray *array.PowerStoreArray
	var vg *gopowerstore.VolumeGroup

	// Try source array first
	if sourceArr, ok := arrays[sourceArrayID]; ok {
		vgTemp, err := findVolumeGroupOnArray(ctx, sourceArr, req.VolumeGroupId)
		if err == nil {
			myarray = sourceArr
			vg = vgTemp
		}
	}

	// If not found on source, try target array
	if vg == nil {
		if targetArr, ok := arrays[targetArrayID]; ok {
			vgTemp, err := findVolumeGroupOnArray(ctx, targetArr, req.VolumeGroupId)
			if err == nil {
				myarray = targetArr
				vg = vgTemp
			}
		}
	}

	if vg == nil {
		if len(req.VolumeIds) == 0 {
			return &volumegrouprpc.ModifyVolumeGroupMembershipResponse{}, nil
		}
		log.Errorf("ModifyVolumeGroupMembership: volume group %s not found on source or target array", req.VolumeGroupId)
		return nil, status.Errorf(codes.NotFound, "volume group %s not found", req.VolumeGroupId)
	}

	// We can't modify the group membership if the volume group isn't the current source.
	if vg.IsReplicationDestination {
		log.Infof("ModifyVolumeGroupMembership: volume group %s is replication destination- cannot update membership, returning success", req.VolumeGroupId)
	} else {
		log.Infof("ModifyVolumeGroupMembership: Found volume group %s (name: %s) on array %s", req.VolumeGroupId, vg.Name, myarray.GetGlobalID())

		// Translate external IDs to local UUIDs
		members := make([]string, 0)
		for _, vh := range req.VolumeIds {
			volumeHandle, err := array.ParseVolumeID(ctx, vh, nil, getDefaultCapability())
			if err != nil {
				log.Errorf("ModifyVolumeGroupMembership failed: Failed to parse volume id %s: %v", vh, err)
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse volume id %s: %v", vh, err)
			}
			members = append(members, volumeHandle.LocalUUID)
		}

		// Get current members
		arrayVolumeIDs := make(map[string]bool)
		for _, v := range vg.Volumes {
			arrayVolumeIDs[v.ID] = true
		}

		// Determine volumes to add and remove
		toBeAdded := make([]string, 0)
		for _, id := range members {
			if !arrayVolumeIDs[id] {
				toBeAdded = append(toBeAdded, id)
			}
		}

		toBeRemoved := make([]string, 0)
		for id := range arrayVolumeIDs {
			if !slices.Contains(members, id) {
				toBeRemoved = append(toBeRemoved, id)
			}
		}

		log.Infof("ModifyVolumeGroupMembership: toBeAdded %v, toBeRemoved %v", toBeAdded, toBeRemoved)

		if len(toBeAdded) > 0 {
			addMembers := &gopowerstore.VolumeGroupMembers{VolumeIDs: toBeAdded}
			_, err = myarray.Client.AddMembersToVolumeGroup(ctx, addMembers, vg.ID)
			if err != nil {
				log.Errorf("Failed to add members: %v", err)
				return nil, status.Errorf(codes.Internal, "failed to add members to volume group %s: %v", vg.ID, err)
			}
		}

		if len(toBeRemoved) > 0 {
			err = removeMembersFromVolumeGroup(ctx, myarray, vg.ID, toBeRemoved)
			if err != nil {
				log.Errorf("Failed to remove members: %v", err)
				return nil, status.Errorf(codes.Internal, "failed to remove members from volume group %s: %v", vg.ID, err)
			}
		}
	}

	// Get updated volume group
	volumes, err := myarray.Client.GetVolumeGroup(ctx, vg.ID)
	if err != nil {
		if apiErr, ok := err.(gopowerstore.APIError); ok && apiErr.NotFound() {
			return nil, status.Errorf(codes.NotFound, "volume group %s not found: %v", vg.ID, err)
		}
		return nil, status.Errorf(codes.Internal, "failed to get volume group %s: %v", vg.ID, err)
	}

	csiVolumes := make([]*csi.Volume, 0)
	for _, v := range volumes.Volumes {
		csiVolumes = append(csiVolumes, getCSIVolume(v.ID, v.Size))
	}

	volumeGroup := &volumegrouprpc.VolumeGroup{
		VolumeGroupId:      vg.ID,
		VolumeGroupContext: make(map[string]string),
		Volumes:            csiVolumes,
	}
	volumeGroup.VolumeGroupContext[volumeGroupNameParameter] = vg.Name

	resp := &volumegrouprpc.ModifyVolumeGroupMembershipResponse{VolumeGroup: volumeGroup}
	log.Infof("ModifyVolumeGroupMembership succeeded")
	return resp, nil
}

// DeleteVolumeGroup deletes a volume group
// Must delete the source volume group in order to delete the target volume group.
func (s *CSIAddonsVolumeGroupServer) DeleteVolumeGroup(ctx context.Context,
	req *volumegrouprpc.DeleteVolumeGroupRequest,
) (*volumegrouprpc.DeleteVolumeGroupResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("DeleteVolumeGroup called  %v", req)

	array, vg, err := findArrayWithVolumeGroupID(ctx, s.service.Arrays(), req.VolumeGroupId)
	if err != nil {
		log.Errorf("DeleteVolumeGroup: Failed to find array with volume group ID %s: %v", req.VolumeGroupId, err)
		// findArrayWithVolumeGroupID only errors when the volume group ID is empty
		return nil, status.Errorf(codes.InvalidArgument, "failed to find array with volume group %s: %v", req.VolumeGroupId, err)
	}
	if array == nil || vg == nil {
		log.Infof("DeleteVolumeGroup: VolumeGroup %s not found. Assuming already deleted.", req.VolumeGroupId)
		return &volumegrouprpc.DeleteVolumeGroupResponse{}, nil
	}
	if vg.IsReplicationDestination {
		log.Infof("DeleteVolumeGroup processing ReplicationDestination %s %s on array %s as nop", vg.Name, vg.ID, array.GlobalID)
		return &volumegrouprpc.DeleteVolumeGroupResponse{}, nil
	}

	log.Infof("DeleteVolumeGroup processing ReplicationSource %s %s on array %s", vg.Name, vg.ID, array.GlobalID)

	err = s.deleteArrayVolumeGroup(ctx, array, vg)
	if err != nil {
		log.Errorf("Failed to delete array source volume group %s %s: %v", vg.Name, vg.ID, err)
		if _, ok := status.FromError(err); ok {
			// deleteArrayVolumeGroup already returned a gRPC status error (e.g. DeadlineExceeded)
			return nil, err
		}
		return nil, status.Errorf(codes.Internal, "failed to delete volume group %s: %v", vg.ID, err)
	}

	return &volumegrouprpc.DeleteVolumeGroupResponse{}, nil
}

// ListVolumeGroups lists volume groups
func (s *CSIAddonsVolumeGroupServer) ListVolumeGroups(ctx context.Context,
	req *volumegrouprpc.ListVolumeGroupsRequest,
) (*volumegrouprpc.ListVolumeGroupsResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("ListVolumeGroups called %v", req)

	arrays := s.service.Arrays()
	entries := make([]*volumegrouprpc.ListVolumeGroupsResponse_Entry, 0)

	for _, arr := range arrays {
		arrayVGs, err := arr.Client.GetVolumeGroups(ctx)
		if err != nil {
			log.Infof("Could not get VolumeGroups from array %s: %v", arr.GetGlobalID(), err)
			continue
		}

		for _, arrayVG := range arrayVGs {
			// Only return replication volume groups (those with the default prefix)
			if !strings.HasPrefix(arrayVG.Name, defaultVGPrefix) {
				continue
			}

			vg := &volumegrouprpc.VolumeGroup{
				VolumeGroupId:      arrayVG.ID,
				VolumeGroupContext: make(map[string]string),
			}
			vg.VolumeGroupContext[volumeGroupNameParameter] = arrayVG.Name
			entry := &volumegrouprpc.ListVolumeGroupsResponse_Entry{
				VolumeGroup: vg,
			}
			entries = append(entries, entry)
		}
	}

	return &volumegrouprpc.ListVolumeGroupsResponse{
		Entries: entries,
	}, nil
}

// ControllerGetVolumeGroup gets a volume group
func (s *CSIAddonsVolumeGroupServer) ControllerGetVolumeGroup(ctx context.Context,
	req *volumegrouprpc.ControllerGetVolumeGroupRequest,
) (*volumegrouprpc.ControllerGetVolumeGroupResponse, error) {
	log := log.WithContext(ctx)
	log.Infof("ControllerGetVolumeGroup called %v", req)

	arrays := s.service.Arrays()

	// Try to find the volume group by ID
	for _, arr := range arrays {
		vg, err := arr.Client.GetVolumeGroup(ctx, req.VolumeGroupId)
		if err == nil {
			// Convert volumes to CSI volumes
			csiVolumes := make([]*csi.Volume, 0)
			for _, vol := range vg.Volumes {
				csiVolume := getCSIVolume(vol.ID, vol.Size)
				csiVolumes = append(csiVolumes, csiVolume)
			}

			responseVG := &volumegrouprpc.VolumeGroup{
				VolumeGroupId:      vg.ID,
				VolumeGroupContext: make(map[string]string),
				Volumes:            csiVolumes,
			}
			responseVG.VolumeGroupContext[volumeGroupNameParameter] = vg.Name

			return &volumegrouprpc.ControllerGetVolumeGroupResponse{
				VolumeGroup: responseVG,
			}, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "volume group %s not found", req.VolumeGroupId)
}

// deleteArrayVolumeGroup deletes a source volume group
func (s *CSIAddonsVolumeGroupServer) deleteArrayVolumeGroup(ctx context.Context, arr *array.PowerStoreArray,
	arrayVG *gopowerstore.VolumeGroup,
) error {
	log := log.WithContext(ctx)
	log.Infof("deleteArrayVolumeGroup called for %s", arrayVG.Name)

	// Pause replication session
	err := ExecuteActionOnReplicationSession(ctx, arr, arrayVG.ID, gopowerstore.RsActionPause)
	if err != nil {
		log.Warnf("deleteArrayVolumeGroup: Failed to pause replication session: %v", err)
	}

	// Remove volumes from group
	if len(arrayVG.Volumes) > 0 {
		volumeIDsToRemove := make([]string, 0)
		for _, v := range arrayVG.Volumes {
			volumeIDsToRemove = append(volumeIDsToRemove, v.ID)
		}
		log.Infof("Removing volumes from VolumeGroup: %v", volumeIDsToRemove)
		err = removeMembersFromVolumeGroup(ctx, arr, arrayVG.ID, volumeIDsToRemove)
		if err != nil {
			log.Errorf("Failed to remove volumes: %v", err)
			return err
		}
	} else {
		log.Infof("No volumes to remove from VolumeGroup %s %s", arrayVG.Name, arrayVG.ID)
	}

	// Remove protection policy
	originalProtectionPolicyID := arrayVG.ProtectionPolicyID
	policyUpdate := gopowerstore.VolumeGroupChangePolicy{ProtectionPolicyID: ""}
	log.Infof("Removing protection policy %s from VolumeGroup %s", originalProtectionPolicyID, arrayVG.ID)
	_, err = arr.Client.UpdateVolumeGroupProtectionPolicy(ctx, arrayVG.ID, &policyUpdate)
	if err != nil {
		if apiErr, ok := err.(gopowerstore.APIError); !ok || !apiErr.NotFound() {
			log.Errorf("Failed to remove protection policy: %v", err)
			return err
		}
	}

	// Wait until protection policy is removed
	log.Infof("Waiting for protection policy %s to be removed from VolumeGroup %s", originalProtectionPolicyID, arrayVG.ID)
	ppRemoved := false
	for i := 0; i < 6; i++ {
		// Respect context cancellation during sleep
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}

		vg, err := arr.Client.GetVolumeGroup(ctx, arrayVG.ID)
		if err != nil {
			if apiErr, ok := err.(gopowerstore.APIError); ok && apiErr.NotFound() {
				// VG doesn't exist, meaning the PP is effectively removed for our purposes
				ppRemoved = true
				break
			}
			log.Errorf("Failed to get VolumeGroup: %v", err)
			return err
		}
		arrayVG = &vg
		if vg.ProtectionPolicyID == "" {
			log.Infof("ProtectionPolicy removed from VolumeGroup %s iteration %d", vg.ID, i)
			ppRemoved = true
			break
		}
	}

	if !ppRemoved {
		return status.Errorf(codes.DeadlineExceeded, "timeout waiting for protection policy %s to be removed from VolumeGroup %s", originalProtectionPolicyID, arrayVG.ID)
	}

	// Delete volume group
	_, err = arr.Client.DeleteVolumeGroup(ctx, arrayVG.ID)
	if err != nil {
		if apiErr, ok := err.(gopowerstore.APIError); !ok || !apiErr.NotFound() {
			log.Errorf("Failed to delete volume group: %v", err)
			return err
		}
	}

	// Delete protection policy
	if originalProtectionPolicyID != "" {
		_, err = arr.Client.DeleteProtectionPolicy(ctx, originalProtectionPolicyID)
		if err != nil {
			log.Warnf("Failed to delete protection policy: %v", err)
		}
	}

	// Delete Replication Rule
	log.Info("Deleting replication rule")
	rr, err := arr.GetClient().GetReplicationRuleByName(ctx, "rr-"+arrayVG.Name)
	if err != nil {
		if apiErr, ok := err.(gopowerstore.APIError); !ok || !apiErr.NotFound() {
			log.Warnf("Error retrieving replication rule: %v", err)
		}
	} else if rr.ID != "" && len(rr.ProtectionPolicies) == 0 {
		_, err = arr.GetClient().DeleteReplicationRule(ctx, rr.ID)
		if err != nil {
			if apiErr, ok := err.(gopowerstore.APIError); !ok || !apiErr.NotFound() {
				log.Warnf("Unable to delete replication rule: %v", err)
			}
		} else {
			log.Info("Successfully deleted replication rule")
		}
	}

	log.Infof("deleteArrayVolumeGroup %s %s succeeded", arrayVG.Name, arrayVG.ID)
	return nil
}
