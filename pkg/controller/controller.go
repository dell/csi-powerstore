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

// Package controller provides CSI specification compatible controller service.
package controller

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	log "github.com/dell/csmlog"
	commonext "github.com/dell/dell-csi-extensions/common"
	podmon "github.com/dell/dell-csi-extensions/podmon"
	csiext "github.com/dell/dell-csi-extensions/replication"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	"github.com/container-storage-interface/spec/lib/go/csi"
	volumegrouprpc "github.com/csi-addons/spec/lib/go/volumegroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

// Interface provides most important controller methods.
// This essentially serves as a wrapper for controller service that is used in ephemeral volumes.
type Interface interface {
	CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error)
	DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error)
	ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error)
	ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error)
	array.Consumer
}

// Service is a controller service that contains array connection information and implements ControllerServer API
type Service struct {
	csi.UnimplementedControllerServer
	csiext.UnimplementedReplicationServer
	Fs fs.Interface

	externalAccess  string
	exclusiveAccess bool
	nfsAutoSelect   bool
	nfsAcls         string

	array.Locker

	replicationContextPrefix      string
	replicationPrefix             string
	isHealthMonitorEnabled        bool
	isAutoRoundOffFsSizeEnabled   bool
	IsCSMDREnabled                bool
	IsCSIAddonsReplicationEnabled bool // Feature flag for CSI-Addons replication support

	// EventRecorder emits Kubernetes events for metro restore milestones
	EventRecorder    record.EventRecorder
	EventBroadcaster record.EventBroadcaster
}

// maxVolumesSizeForArray -  store the maxVolumesSizeForArray
var maxVolumesSizeForArray = make(map[string]int64)

// function variables for mocking during testing of metro replication and deferrals related to metro replication
var (
	isNodeConnectedToArrayFunc               = isNodeConnectedToArray
	unpublishVolumeFunc                      = unpublishVolume
	checkMetroStateFunc                      = array.CheckMetroState
	createOrUpdateJournalEntryFunc           = array.CreateOrUpdateJournalEntry
	selectMetroArrayForCloneFunc             = selectMetroArrayForClone
	isMetroFracturedFunc                     = array.IsMetroFractured
	checkMetroFractureForSnapshotRestoreFunc = checkMetroFractureForSnapshotRestore
	validateSnapshotArrayForMetroFunc        = validateSnapshotArrayForMetro
	newEventRecorderFunc                     = newControllerEventRecorder
)

var mutex = &sync.Mutex{}

// Init is a method that initializes internal variables of controller service
func (s *Service) Init() error {
	ctx := context.Background()
	kubeConfigPath, _ := csictx.LookupEnv(ctx, identifiers.EnvKubeConfigPath)
	_, err := k8sutils.CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %s", err.Error())
	}

	if nat, ok := csictx.LookupEnv(ctx, identifiers.EnvExternalAccess); ok {
		s.externalAccess = nat
	}

	if exclusive, ok := csictx.LookupEnv(ctx, identifiers.EnvExclusiveAccess); ok {
		// Only enable exclusive access if external access is configured
		if s.externalAccess != "" {
			s.exclusiveAccess = strings.EqualFold(exclusive, "true")
		}
	}

	nfsAutoSelect, err := identifiers.ParseNfsAutoSelectEnv(ctx)
	if err != nil {
		return err
	}
	s.nfsAutoSelect = nfsAutoSelect
	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent:    "controller",
		log.FieldOperation:    "Init",
		"auto_select_enabled": s.nfsAutoSelect,
	}).Info("NFS auto-select feature toggle state")

	if replicationContextPrefix, ok := csictx.LookupEnv(ctx, identifiers.EnvReplicationContextPrefix); ok {
		s.replicationContextPrefix = replicationContextPrefix + "/"
	}

	if replicationPrefix, ok := csictx.LookupEnv(ctx, identifiers.EnvReplicationPrefix); ok {
		s.replicationPrefix = replicationPrefix
	}

	if isHealthMonitorEnabled, ok := csictx.LookupEnv(ctx, identifiers.EnvIsHealthMonitorEnabled); ok {
		s.isHealthMonitorEnabled, _ = strconv.ParseBool(isHealthMonitorEnabled)
	}

	s.nfsAcls = ""
	if nfsAcls, ok := csictx.LookupEnv(ctx, identifiers.EnvNfsAcls); ok {
		if nfsAcls != "" {
			s.nfsAcls = nfsAcls
		}
	}

	if isAutoRoundOffFsSizeEnabled, ok := csictx.LookupEnv(ctx, identifiers.EnvAllowAutoRoundOffFilesystemSize); ok {
		log.WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "Init",
			log.FieldProtocol:  "NFS",
		}).Warn("Auto round off Filesystem size has been enabled! This will round off NFS PVC size to 3Gi when the requested size is less than 3Gi.")
		s.isAutoRoundOffFsSizeEnabled, _ = strconv.ParseBool(isAutoRoundOffFsSizeEnabled)
	}

	isPodmonEnabled := false
	if value, ok := csictx.LookupEnv(ctx, identifiers.EnvPodmonEnabled); ok {
		isPodmonEnabled, _ = strconv.ParseBool(value)
	}

	// Load podmon API token for authenticating requests to node podmon API endpoints
	if podmonAPIToken, ok := csictx.LookupEnv(ctx, identifiers.EnvPodmonAPIToken); ok && strings.TrimSpace(podmonAPIToken) != "" {
		identifiers.PodmonAPIToken = strings.TrimSpace(podmonAPIToken)
	} else if isPodmonEnabled {
		log.WithContext(ctx).Warnf("%s is not set; podmon API endpoints will not require authentication", identifiers.EnvPodmonAPIToken)
	}

	// Initialize the event recorder for metro restore milestones
	eventRecorder, eventBroadcaster, err := newEventRecorderFunc(kubeConfigPath)
	if err != nil {
		log.WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "Init",
		}).Warnf("failed to create event recorder for metro restore events: %s (events will not be emitted)", err.Error())
	} else {
		s.EventRecorder = eventRecorder
		s.EventBroadcaster = eventBroadcaster
	}

	return nil
}

// Shutdown cleans up resources when the service is stopping.
// It stops the event broadcaster if it was initialized.
func (s *Service) Shutdown() {
	if s.EventBroadcaster != nil {
		s.EventBroadcaster.Shutdown()
	}
}

func formatCreateVolumeError(err error, endpoint string) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, err.Error())
	}

	message := strings.ToLower(err.Error())
	if strings.Contains(message, "timeout") {
		return status.Errorf(codes.Unavailable,
			"PowerStore endpoint %s is unreachable: %v; check network configuration",
			endpoint, err)
	}
	return err
}

// CreateVolume creates either FileSystem or Volume on storage array.
func (s *Service) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent:  "controller",
		log.FieldOperation:  "CreateVolume",
		log.FieldVolumeName: req.GetName(),
	}).Info("starting volume creation")
	startTime := time.Now()
	params := req.GetParameters()

	if mutableParams := req.GetMutableParameters(); mutableParams != nil {
		if err := validateMutableParamKeys(mutableParams); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid mutable parameter: %s", err)
		}
	}

	// Get array from map
	arrayID, arrayIDSpecified := params[identifiers.KeyArrayID]

	var arr *array.PowerStoreArray
	// If no ArrayID was provided in storage class we just use default array
	if !arrayIDSpecified {
		if _, ok := params["arrayIP"]; ok {
			return nil, status.Error(codes.Internal, "Array IP's been provided, however it is not supported in "+
				"current version. Configure you storage classes according to the documentation")
		}
		arr = s.DefaultArray()
	} else {
		var ok bool
		arr, ok = s.Arrays()[arrayID]
		if !ok {
			return nil, status.Errorf(codes.Internal, "can't find array with provided id %s", arrayID)
		}
	}

	// Check if should use nfs
	useNFS := false
	fsType := req.VolumeCapabilities[0].GetMount().GetFsType()
	useNFS = fsType == "nfs"

	// If capability does not have NFS, check if params request NFS
	// This can happen when running csi-sanity tests
	if !useNFS && params[KeyFsType] == "nfs" {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "CreateVolume",
			log.FieldProtocol:  "NFS",
		}).Info("Request's volume capability does not specify NFS, but params do, using NFS")
		useNFS = true
	}

	if req.VolumeCapabilities[0].GetBlock() != nil {
		// We need to check if user requests raw block access from nfs and prevent that
		fsType, ok := params[KeyFsType]
		// FsType can be empty
		if ok && fsType == "nfs" {
			return nil, status.Errorf(codes.InvalidArgument, "raw block requested from NFS Volume")
		}

		fsType, ok = params[KeyFsTypeOld]
		if ok && fsType == "nfs" {
			return nil, status.Errorf(codes.InvalidArgument, "raw block requested from NFS Volume")
		}
	}

	// Prevent user from creating an NFS volume with incorrect topology(e.g. iscsi, nvme). At least one entry for nfs should be present in the topology, otherwise return an error
	if useNFS && req.AccessibilityRequirements != nil {
		if ok := identifiers.HasRequiredTopology(req.AccessibilityRequirements.Preferred, arr.GetIP(), "nfs"); !ok {
			// if not in preferred, try requisite next
			if ok := identifiers.HasRequiredTopology(req.AccessibilityRequirements.Requisite, arr.GetIP(), "nfs"); !ok {
				return nil, status.Errorf(codes.InvalidArgument, "invalid topology requested for NFS Volume. Please validate your storage class has nfs topology.")
			}
		}
	}

	var creator VolumeCreator
	var protocol string
	var selectedNasName string

	nfsAcls := s.nfsAcls
	if useNFS {
		protocol = "nfs"
		nasParamsName, ok := params[KeyNasName]
		if ok {
			if strings.Contains(nasParamsName, ",") {
				// Comma-separated NAS names
				rawNasList := strings.Split(nasParamsName, ",")
				nasList := make([]string, 0, len(rawNasList))
				for _, nas := range rawNasList {
					trimmed := strings.TrimSpace(nas)
					if trimmed != "" {
						nasList = append(nasList, trimmed)
					}
				}
				leastUsedNas, err := array.GetLeastUsedActiveNAS(ctx, arr, nasList)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "failed to get least used NAS: %s", err)
				}
				selectedNasName = leastUsedNas
			} else {
				// Single NAS name
				selectedNasName = nasParamsName
			}
		} else {
			// No NAS name provided in params
			selectedNasName = arr.GetNasName()
		}

		creator = &NfsCreator{
			nasName:       selectedNasName,
			nfsAutoSelect: s.nfsAutoSelect,
		}

		if params[identifiers.KeyNfsACL] != "" {
			nfsAcls = params[identifiers.KeyNfsACL] // Storage class takes precedence
		} else if arr.NfsAcls != "" {
			nfsAcls = arr.NfsAcls // Secrets next
		}
	} else {
		protocol = "scsi"
		creator = &SCSICreator{}
	}

	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent:  "controller",
		log.FieldOperation:  "CreateVolume",
		log.FieldVolumeName: req.GetName(),
		log.FieldProtocol:   protocol,
		log.FieldArrayID:    arr.Endpoint,
	}).Info("protocol selected")

	var topology []*csi.Topology
	if req.AccessibilityRequirements != nil {
		topology = req.AccessibilityRequirements.Preferred
	}

	if err := creator.CheckName(ctx, req.GetName()); err != nil {
		return nil, err
	}

	sizeInBytes, err := creator.CheckSize(ctx, req.GetCapacityRange(), s.isAutoRoundOffFsSizeEnabled)
	if err != nil {
		return nil, err
	}

	replicationEnabled := params[s.WithRP(KeyReplicationEnabled)]
	repMode := params[s.WithRP(KeyReplicationMode)]
	// Default to ASYNC for backward compatibility
	if repMode == "" {
		repMode = identifiers.AsyncMode
	}
	repMode = strings.ToUpper(repMode)

	var cloneRemoteSystemID string
	var volumeResponse *csi.Volume
	var snapshotArrayID string                        // Stores the array ID where the snapshot resides for metro validation
	var snapshotSourceID string                       // Stores the parsed snapshot local UUID for logging consistency
	var cachedRemoteSystem *gopowerstore.RemoteSystem // Cache remote system for snapshot restore to avoid duplicate API call
	pvcNamespace := params[KeyCSIPVCNamespace]        // PVC namespace for event emission; may be empty if not provided by CO
	pvcName := params[KeyCSIPVCName]                  // PVC name for event emission; use this instead of req.GetName()
	contentSource := req.GetVolumeContentSource()
	if contentSource != nil {
		var volResp *csi.Volume
		var err error

		volumeSource := contentSource.GetVolume()
		if volumeSource != nil {
			log.WithContext(ctx).Infof("volume %s specified as volume content source", volumeSource.VolumeId)
			volumeHandle, parseVolErr := array.ParseVolumeID(ctx, volumeSource.VolumeId, s.DefaultArray(), nil)
			if parseVolErr != nil {
				if apiError, ok := parseVolErr.(gopowerstore.APIError); ok && apiError.NotFound() {
					// Return error code csi-sanity test expects
					log.WithContext(ctx).Errorf("Volume source: %s not found", volumeSource.VolumeId)
					return nil, status.Error(codes.NotFound, parseVolErr.Error())
				}
			}
			volumeSource.VolumeId = volumeHandle.LocalUUID
			if volumeHandle.IsMetro() {

				var remoteSystemName string
				if replicationEnabled == "true" {
					// Convert the remoteStorageName to an arrayID
					var ok bool
					remoteSystemName, ok = params[s.WithRP(KeyReplicationRemoteSystem)]
					if !ok {
						return nil, status.Error(codes.InvalidArgument, "replication enabled but no remote system specified in storage class")
					}
				}
				// Cloning from a Metro replicated volume: select the optimal array for cloning
				selectedArr, selectedSession, err := selectMetroArrayForCloneFunc(ctx, arr, remoteSystemName, arrayID, volumeHandle, s)
				if err != nil {
					code := status.Code(err)
					if code == codes.OK || code == codes.Unknown {
						code = codes.Internal
					}
					return nil, status.Errorf(code, "failed to select metro array for clone: %s", status.Convert(err).Message())
				}
				arr = selectedArr
				cloneRemoteSystemID = selectedSession.RemoteSystemID
				volumeSource.VolumeId = selectedSession.LocalResourceID
			}
			volResp, err = creator.Clone(ctx, volumeSource, req.GetName(), sizeInBytes, req.Parameters, arr.GetClient())
		}
		snapshotSource := contentSource.GetSnapshot()
		if snapshotSource != nil {
			log.WithContext(ctx).Infof("snapshot %s specified as volume content source", snapshotSource.SnapshotId)
			volumeHandle, parseVolErr := array.ParseVolumeID(ctx, snapshotSource.SnapshotId, s.DefaultArray(), nil)
			if parseVolErr != nil {
				if apiError, ok := parseVolErr.(gopowerstore.APIError); ok && apiError.NotFound() {
					// Return error code csi-sanity test expects
					log.WithContext(ctx).Errorf("Snapshot source: %s not found", snapshotSource.SnapshotId)
					return nil, status.Error(codes.NotFound, parseVolErr.Error())
				}
			}
			snapshotSource.SnapshotId = volumeHandle.LocalUUID
			// Store the parsed snapshot ID for logging consistency
			snapshotSourceID = volumeHandle.LocalUUID
			// Store the snapshot's array ID for metro validation later
			snapshotArrayID = volumeHandle.LocalArrayGlobalID

			// Check metro prerequisites before creating volume from snapshot
			if replicationEnabled == "true" && repMode == identifiers.MetroMode {
				// CSM-DR must be enabled for metro operations — check early to avoid creating orphaned volumes
				if !s.IsCSMDREnabled {
					log.WithContext(ctx).Info("Failed to create metro volume from snapshot due to CSM DR not available.")
					return nil, status.Error(codes.InvalidArgument, "Metro replication mode requires CSM-DR to be enabled")
				}

				// Emit event: metro restore started
				s.emitMetroRestoreEvent(corev1.EventTypeNormal, EventReasonMetroRestoreStarted,
					fmt.Sprintf("Starting metro snapshot restore from snapshot %s", snapshotSource.SnapshotId), pvcName, pvcNamespace)

				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent:   "controller",
					log.FieldOperation:   "MetroSnapshotRestore",
					log.FieldVolumeName:  req.GetName(),
					"source_snapshot_id": snapshotSource.SnapshotId,
					"operation_outcome":  "fracture_check_started",
				}).Info("checking metro fracture state before snapshot restore")

				if fractureErr := checkMetroFractureForSnapshotRestoreFunc(ctx, arr.GetClient(), snapshotSource.SnapshotId); fractureErr != nil {
					log.WithContext(ctx).WithFields(log.Fields{
						log.FieldComponent:   "controller",
						log.FieldOperation:   "MetroSnapshotRestore",
						log.FieldVolumeName:  req.GetName(),
						"source_snapshot_id": snapshotSource.SnapshotId,
						"operation_outcome":  "blocked_by_fracture",
					}).Warn("metro snapshot restore blocked: session is fractured")
					// Emit event: fracture blocked
					s.emitMetroRestoreEvent(corev1.EventTypeWarning, EventReasonMetroFractureBlocked,
						"Metro snapshot restore blocked: metro session is fractured", pvcName, pvcNamespace)
					return nil, fractureErr
				}

				// Validate snapshot array is part of the metro pair BEFORE creating the volume (AC8)
				// This prevents creating orphaned volumes when the snapshot is from a different array
				remoteSystemName, ok := params[s.WithRP(KeyReplicationRemoteSystem)]
				if !ok {
					return nil, status.Error(codes.InvalidArgument, "replication enabled but no remote system specified in storage class")
				}
				remoteSystemForValidation, err := arr.Client.GetRemoteSystemByName(ctx, remoteSystemName)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't query remote system by name for array validation: %v", err)
				}
				// Cache the remote system for reuse in MetroMode case (performance optimization)
				cachedRemoteSystem = &remoteSystemForValidation
				if validationErr := validateSnapshotArrayForMetroFunc(ctx, snapshotArrayID, arr.GetGlobalID(), remoteSystemForValidation.SerialNumber); validationErr != nil {
					log.WithContext(ctx).WithFields(log.Fields{
						log.FieldComponent:  "controller",
						log.FieldOperation:  "MetroSnapshotRestore",
						log.FieldVolumeName: req.GetName(),
						"operation_outcome": "array_mismatch",
					}).Warn("metro snapshot restore blocked: snapshot array not in metro pair")
					// Emit event: array mismatch
					s.emitMetroRestoreEvent(corev1.EventTypeWarning, EventReasonMetroArrayMismatch,
						"Snapshot is not from an array in the metro pair", pvcName, pvcNamespace)
					return nil, validationErr
				}
			}

			volResp, err = creator.CreateVolumeFromSnapshot(ctx, snapshotSource,
				req.GetName(), sizeInBytes, req.Parameters, arr.GetClient())
		}
		if err != nil {
			log.WithContext(ctx).Warnf("Failed to create volume: %s from content source: %s", req.GetName(), err.Error())
			resp, err := creator.CheckIfAlreadyExists(ctx, req.GetName(), sizeInBytes, arr.GetClient())
			if err != nil {
				return nil, err
			}
			if snapshotSource != nil {
				volResp = getCSIVolumeFromSnapshot(resp.VolumeId, snapshotSource, sizeInBytes)
			} else {
				volResp = getCSIVolumeFromClone(resp.VolumeId, volumeSource, sizeInBytes)
			}
			volResp.VolumeContext = req.Parameters
		}
		if volResp == nil {
			return nil, err
		}
		if replicationEnabled != "true" || repMode != identifiers.MetroMode {
			// Created a clone with a non-Metro enabled storage class: build the full volume ID and return
			volResp.VolumeId = volResp.VolumeId + "/" + arr.GetGlobalID() + "/" + protocol
			if useNFS {
				// Apply the same topology preservation logic as the main CreateVolume path for consistency.
				if ar := req.AccessibilityRequirements; ar != nil {
					topology = identifiers.GetEligibleNfsAccessibleTopologies(ar.Preferred, ar.Requisite, arr.GetIP())
				} else {
					topology = identifiers.GetNfsTopology(arr.GetIP())
				}
				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  "CreateVolume",
					log.FieldProtocol:   "NFS",
					log.FieldVolumeName: req.GetName(),
				}).Info("modified topology to NFS")
			}
			volResp.AccessibleTopology = topology
			return &csi.CreateVolumeResponse{
				Volume: volResp,
			}, nil
		}
		// Clone is created with a Metro enabled storage class: fall through to the existing Metro enablement code below.
		// cloneRemoteSystemID has been set if a different array was selected for the clone.
		// For Metro clones, we already have volResp from the clone operation, so use it directly
		volumeResponse = volResp
	}

	var vg gopowerstore.VolumeGroup
	var remoteSystem gopowerstore.RemoteSystem
	var vgName string
	isMetroVolume := false
	// Check if replication is enabled
	if replicationEnabled == "true" {

		log.WithContext(ctx).Info("Preparing volume replication")

		remoteSystemName, ok := params[s.WithRP(KeyReplicationRemoteSystem)]
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "replication enabled but no remote system specified in storage class")
		}

		switch repMode {
		case identifiers.SyncMode, identifiers.AsyncMode:
			// handle Sync and Async modes where protection policy with replication rule is applied on volume group
			log.WithContext(ctx).Infof("%s replication mode requested", repMode)
			vgPrefix, ok := params[s.WithRP(KeyReplicationVGPrefix)]
			if !ok {
				return nil, status.Error(codes.InvalidArgument, "replication enabled but no volume group prefix specified in storage class")
			}

			rpo, ok := params[s.WithRP(KeyReplicationRPO)]
			if !ok {
				// If Replication mode is ASYNC and there is no RPO specified, returning an error
				if repMode == identifiers.AsyncMode {
					return nil, status.Error(codes.InvalidArgument, "replication mode is ASYNC but no RPO specified in storage class")
				}
				// If Replication mode is SYNC and there is no RPO, defaulting the value to Zero
				rpo = identifiers.Zero
			}
			rpoEnum := gopowerstore.RPOEnum(rpo)
			if err := rpoEnum.IsValid(); err != nil {
				return nil, status.Error(codes.InvalidArgument, "invalid RPO value")
			}

			// Validating RPO to be non Zero when replication mode is ASYNC
			if repMode == identifiers.AsyncMode && rpo == identifiers.Zero {
				log.WithContext(ctx).Errorf("RPO value for %s cannot be : %s", repMode, rpo)
				return nil, status.Error(codes.InvalidArgument, "replication mode ASYNC requires RPO value to be non Zero")
			}

			// Validating RPO to be Zero whe replication mode is SYNC
			if repMode == identifiers.SyncMode && rpo != identifiers.Zero {
				return nil, status.Error(codes.InvalidArgument, "replication mode SYNC requires RPO value to be Zero")
			}
			namespace := ""
			if ignoreNS, ok := params[s.WithRP(KeyReplicationIgnoreNamespaces)]; ok && ignoreNS == "false" {
				pvcNS, ok := params[KeyCSIPVCNamespace]
				if ok {
					namespace = pvcNS + "-"
				}
			}

			if useNFS {
				vgName = vgPrefix + "-nfs-" + namespace + remoteSystemName + "-" + rpo
			} else {
				vgName = vgPrefix + "-" + namespace + remoteSystemName + "-" + rpo
			}
			if len(vgName) > 128 {
				vgName = vgName[:128]
			}
			if !useNFS {
				vg, err = arr.Client.GetVolumeGroupByName(ctx, vgName)
				if err != nil {
					if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
						log.WithContext(ctx).Infof("Volume group with name %s not found, creating it", vgName)

						// ensure protection policy exists
						pp, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
						if err != nil {
							return nil, status.Errorf(codes.Internal, "can't ensure protection policy exists %s", err.Error())
						}

						group, err := arr.Client.CreateVolumeGroup(ctx, &gopowerstore.VolumeGroupCreate{
							Name:               vgName,
							ProtectionPolicyID: pp,
						})
						if err != nil {
							return nil, status.Errorf(codes.Internal, "can't create volume group: %s", err.Error())
						}

						vg, err = arr.Client.GetVolumeGroup(ctx, group.ID)
						if err != nil {
							return nil, status.Errorf(codes.Internal, "can't query volume group by id %s : %s", group.ID, err.Error())
						}

					} else {
						return nil, status.Errorf(codes.Internal, "can't query volume group by name %s : %s", vgName, err.Error())
					}
				} else {
					// if Replication mode is SYNC, check if the VolumeGroup is write-order consistent
					if repMode == identifiers.SyncMode {
						if !vg.IsWriteOrderConsistent {
							return nil, status.Errorf(codes.Internal, "can't apply protection policy with sync rule if volume group is not write-order consistent")
						}
					}
					// group exists, check that protection policy applied
					if vg.ProtectionPolicyID == "" {
						pp, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
						if err != nil {
							return nil, status.Errorf(codes.Internal, "can't ensure protection policy exists %s", err.Error())
						}
						policyUpdate := gopowerstore.VolumeGroupChangePolicy{ProtectionPolicyID: pp}
						_, err = arr.Client.UpdateVolumeGroupProtectionPolicy(ctx, vg.ID, &policyUpdate)
						if err != nil {
							return nil, status.Errorf(codes.Internal, "can't update volume group policy %s", err.Error())
						}
					}
				}

				// Pass the VolumeGroup to the creator so it can create the new volume inside the vg
				if c, ok := creator.(*SCSICreator); ok {
					c.vg = &vg
				}
			} else {
				pp, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't ensure protection policy exists %s", err.Error())
				}
				log.WithContext(ctx).Infof("Protection policy %s verified or created successfully.", pp)
				err = arr.Client.ModifyNASByName(ctx, &gopowerstore.NASModify{ProtectionPolicyID: pp}, selectedNasName)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't update NAS protection policy %s", err.Error())
				}

				log.WithContext(ctx).Infof("Protection policy %s applied to NAS server %s", pp, remoteSystemName)

			}
		case identifiers.MetroMode:
			// handle Metro mode where metro is configured directly on the volume
			// Note: Metro on volume group support is not added
			log.WithContext(ctx).Info("Metro replication mode requested")

			// Get specified remote system object.
			// For Metro clones, the preferred array may differ from the original; use the UUID returned
			// by SelectMetroArrayForClone rather than the storage class remote system name.
			// For snapshot restores, reuse the cached remote system from earlier validation to avoid duplicate API call.
			if cloneRemoteSystemID != "" {
				remoteSystem, err = arr.Client.GetRemoteSystem(ctx, cloneRemoteSystemID)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't query remote system by id: %v", err)
				}
			} else if cachedRemoteSystem != nil {
				// Reuse the remote system fetched earlier for array validation (performance optimization)
				remoteSystem = *cachedRemoteSystem
			} else {
				remoteSystem, err = arr.Client.GetRemoteSystemByName(ctx, remoteSystemName)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't query remote system by name: %v", err)
				}
			}

			// Note: Array validation for snapshot restore (AC8) is performed earlier in the snapshot
			// processing section, before CreateVolumeFromSnapshot is called. This ensures we don't
			// create orphaned volumes when the snapshot is from a different array.

			isMetroVolume = true
		default:
			return nil, status.Errorf(codes.InvalidArgument, "replication enabled but invalid replication mode specified in storage class")
		}

	}

	params[identifiers.KeyVolumeDescription] = getDescription(req.GetParameters())

	// check if job is already in progress on array, if so, return error and let CO check again
	if useNFS {
		jobs, err := arr.Client.GetInProgressJobsByFsName(ctx, req.GetName())
		if err != nil {
			log.WithContext(ctx).Errorf("Error getting jobs that are in progress for FileSystem: %s error: %s", req.Name, err.Error())
			return nil, status.Errorf(codes.Internal, "Error getting jobs that are in progress for FileSystem: %s error: %s", req.Name, err.Error())
		}
		if len(jobs) > 0 {
			log.WithContext(ctx).Infof("Job already in progress to create FileSystem %s", req.GetName())
			return nil, status.Errorf(codes.AlreadyExists, "Job already in progress to create FileSystem %s", req.GetName())
		}
	}

	// check if vol exists before creating it in the array
	// Skip if we already have volumeResponse from Metro clone operation
	if volumeResponse == nil {
		volumeResponse, err = creator.CheckIfAlreadyExists(ctx, req.GetName(), sizeInBytes, arr.GetClient())
		if err != nil {
			// internal means something went wrong trying to check the volume and request needs to be retried
			if status.Code(err) == codes.Internal || status.Code(err) == codes.AlreadyExists {
				log.WithContext(ctx).Warnf("CheckIfAlreadyExists returned error: %s for vol: %s", err.Error(), req.GetName())
				return nil, err
			}
		}
	}

	if isMetroVolume && !s.IsCSMDREnabled {
		log.WithContext(ctx).Info("Failed to create metro volume due to CSM DR not available.")
		return nil, status.Error(codes.InvalidArgument, "Metro replication mode requires CSM-DR to be enabled")
	}

	if volumeResponse == nil {
		resp, createError := creator.Create(ctx, req, sizeInBytes, arr.GetClient())
		if createError != nil {
			createError = formatCreateVolumeError(createError, arr.Endpoint)
			log.WithContext(ctx).Warnf("create volume for %s failed: '%s'", req.GetName(), createError.Error())
			if useNFS {
				arr.NASCooldownTracker.MarkFailure(selectedNasName)
				return nil, status.Error(codes.ResourceExhausted, createError.Error())
			}
			return nil, createError
		}
		if useNFS {
			arr.NASCooldownTracker.ResetFailure(selectedNasName)
		}
		volumeResponse = getCSIVolume(resp.ID, sizeInBytes)

		// NAA placement verification and event emission (SCSI volumes only)
		naaResolution := creator.GetNAAResolution()
		if naaResolution != nil {
			if naaResolution.Success {
				// Emit NAAResolutionSuccess event
				s.emitNAAPlacementEvent(ctx, corev1.EventTypeNormal, EventReasonNAAResolutionSuccess,
					fmt.Sprintf("NAA ID resolution succeeded for volume %s; volume provisioned with affinity hint", pvcName),
					pvcName, pvcNamespace)

				// Verify placement after volume creation
				placementResult := verifyPlacement(ctx, arr.GetClient(), resp.ID, naaResolution.SourceApplianceID)
				switch placementResult.Outcome {
				case PlacementXCOPYSuccess:
					s.emitNAAPlacementEvent(ctx, corev1.EventTypeNormal, EventReasonXCOPYSuccess,
						fmt.Sprintf("Volume %s placed on same appliance as source; XCOPY-offload eligible", pvcName),
						pvcName, pvcNamespace)
				case PlacementHostCopyFallback:
					s.emitNAAPlacementEvent(ctx, corev1.EventTypeNormal, EventReasonHostCopyFallback,
						fmt.Sprintf("Volume %s placed on different appliance than source; host-copy required", pvcName),
						pvcName, pvcNamespace)
				case PlacementVerificationFailed:
					s.emitNAAPlacementEvent(ctx, corev1.EventTypeWarning, EventReasonPlacementVerificationFailed,
						fmt.Sprintf("Placement verification failed for volume %s; volume created successfully but placement outcome unknown", pvcName),
						pvcName, pvcNamespace)
				}
			} else {
				// NAA resolution failed - emit NAAResolutionFailed event
				s.emitNAAPlacementEvent(ctx, corev1.EventTypeWarning, EventReasonNAAResolutionFailed,
					fmt.Sprintf("NAA ID resolution failed for volume %s; volume provisioned without affinity hint; placement outcome not determined", pvcName),
					pvcName, pvcNamespace)
			}
		}
	}

	metroVolumeIDSuffix := ""
	if isMetroVolume {
		// Configure Metro on volume
		volID := volumeResponse.VolumeId

		metroOperationLabel := "MetroVolumeCreate"
		if snapshotSourceID != "" {
			metroOperationLabel = "MetroSnapshotRestore"
		}

		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent:   "controller",
			log.FieldOperation:   metroOperationLabel,
			log.FieldVolumeName:  req.GetName(),
			"source_snapshot_id": snapshotSourceID,
			"operation_outcome":  "metro_configuration_initiated",
		}).Info("configuring metro on volume")

		// Emit event: metro configuration initiated
		if snapshotSourceID != "" {
			s.emitMetroRestoreEvent(corev1.EventTypeNormal, EventReasonMetroConfigInitiated,
				"Initiating metro configuration on restored volume", pvcName, pvcNamespace)
		}

		metroSession, err := arr.GetClient().ConfigureMetroVolume(ctx, volID, &gopowerstore.MetroConfig{
			RemoteSystemID: remoteSystem.ID,
		})
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.ReplicationSessionAlreadyCreated() { // idempotency check
				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  metroOperationLabel,
					"operation_outcome": "metro_already_configured",
				}).Debug("metro has already been configured on volume")
			} else {
				// Rollback for snapshot/clone restores: delete the restored volume to avoid orphaned non-metro volumes.
				// Note: ConfigureMetroVolume failed, so no metro session or remote volume exists — only the local volume needs cleanup.
				if contentSource != nil {
					log.WithContext(ctx).WithFields(log.Fields{
						log.FieldComponent:   "controller",
						log.FieldOperation:   metroOperationLabel,
						log.FieldVolumeName:  req.GetName(),
						"source_snapshot_id": snapshotSourceID,
						"operation_outcome":  "metro_configuration_failed",
					}).Warn("metro configuration failed, initiating rollback")
					// Emit event: metro configuration failed
					s.emitMetroRestoreEvent(corev1.EventTypeWarning, EventReasonMetroConfigFailed,
						fmt.Sprintf("Metro configuration failed: %s", err.Error()), pvcName, pvcNamespace)
					if _, deleteErr := arr.GetClient().DeleteVolume(ctx, nil, volID); deleteErr != nil {
						log.WithContext(ctx).WithFields(log.Fields{
							log.FieldComponent:  "controller",
							log.FieldOperation:  metroOperationLabel,
							"operation_outcome": "rollback_failed",
						}).Errorf("rollback failed: could not delete volume after metro config failure: %s", deleteErr.Error())
						return nil, status.Errorf(codes.Internal, "can't configure metro on volume: %s; rollback also failed: %s", err.Error(), deleteErr.Error())
					}
					log.WithContext(ctx).WithFields(log.Fields{
						log.FieldComponent:  "controller",
						log.FieldOperation:  metroOperationLabel,
						"operation_outcome": "rollback_succeeded",
					}).Info("rollback succeeded: deleted volume after metro config failure")
					// Emit event: rollback completed
					s.emitMetroRestoreEvent(corev1.EventTypeWarning, EventReasonMetroRestoreRolledBack,
						"Metro restore rolled back: restored volume deleted after metro configuration failure", pvcName, pvcNamespace)
				}
				return nil, status.Errorf(codes.Internal, "can't configure metro on volume: %s", err.Error())
			}
		} else {
			log.WithContext(ctx).WithFields(log.Fields{
				log.FieldComponent:  "controller",
				log.FieldOperation:  metroOperationLabel,
				"metro_session_id":  metroSession.ID,
				"operation_outcome": "metro_configuration_succeeded",
			}).Info("metro session created for volume")
			// Emit event: metro configuration succeeded
			if snapshotSourceID != "" {
				s.emitMetroRestoreEvent(corev1.EventTypeNormal, EventReasonMetroConfigSucceeded,
					"Metro configuration succeeded", pvcName, pvcNamespace)
			}
		}

		// Get the remote volume ID from the replication session.
		replicationSession, err := arr.GetClient().GetReplicationSessionByLocalResourceID(ctx, volID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "could not get metro replication session: %s", err.Error())
		}
		// Confirm the replication session is of the 'volume' type
		if strings.ToLower(replicationSession.ResourceType) != "volume" {
			return nil, status.Errorf(codes.FailedPrecondition, "replication session %s has a resource type %s, wanted type 'volume'",
				replicationSession.ID, replicationSession.ResourceType)
		}

		// For snapshot/clone restores, validate the metro session reached a healthy state (AC-5).
		// A newly configured metro session may be in Synchronizing state before reaching OK.
		// Both OK and Synchronizing are acceptable; other states (e.g. Fractured, Error) indicate
		// the metro pair is not healthy and we should roll back.
		isHealthyState := replicationSession.State == gopowerstore.RsStateOk ||
			replicationSession.State == gopowerstore.RsStateSynchronizing
		if contentSource != nil && !isHealthyState {
			log.WithContext(ctx).WithFields(log.Fields{
				log.FieldComponent:  "controller",
				log.FieldOperation:  metroOperationLabel,
				log.FieldVolumeName: req.GetName(),
				"metro_session_id":  replicationSession.ID,
				"metro_state":       replicationSession.State,
				"operation_outcome": "metro_state_not_ok",
			}).Warn("metro session not in OK state after configuration, rolling back")
			s.emitMetroRestoreEvent(corev1.EventTypeWarning, EventReasonMetroConfigFailed,
				"Metro session not in expected state after configuration, rolling back", pvcName, pvcNamespace)
			if _, deleteErr := arr.GetClient().DeleteVolume(ctx, nil, volID); deleteErr != nil {
				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  metroOperationLabel,
					"operation_outcome": "rollback_failed",
				}).Errorf("rollback failed: could not delete volume after metro state validation: %s", deleteErr.Error())
				return nil, status.Errorf(codes.Internal, "metro session state is %s (expected OK or Synchronizing); rollback also failed: %s",
					replicationSession.State, deleteErr.Error())
			}
			s.emitMetroRestoreEvent(corev1.EventTypeWarning, EventReasonMetroRestoreRolledBack,
				"Metro restore rolled back: session state not healthy after configuration", pvcName, pvcNamespace)
			return nil, status.Errorf(codes.Internal, "metro session state is %s (expected OK or Synchronizing) after configuration", replicationSession.State)
		}

		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  metroOperationLabel,
			"metro_session_id":  replicationSession.ID,
			"metro_state":       replicationSession.State,
			"operation_outcome": "metro_restore_complete",
		}).Info("metro snapshot restore completed successfully")

		// Emit event: metro restore complete
		if snapshotSourceID != "" {
			s.emitMetroRestoreEvent(corev1.EventTypeNormal, EventReasonMetroRestoreComplete,
				"Metro snapshot restore completed successfully", pvcName, pvcNamespace)
		}

		// Build the metro volume handle suffix
		metroVolumeIDSuffix = ":" + replicationSession.RemoteResourceID + "/" + remoteSystem.SerialNumber
	}

	// Fetch the service tag
	serviceTag := GetServiceTag(ctx, req, arr, volumeResponse.VolumeId, protocol)
	volumeResponse.VolumeContext = req.Parameters
	volumeResponse.VolumeContext[identifiers.KeyArrayID] = arr.GetGlobalID()
	volumeResponse.VolumeContext[identifiers.KeyArrayVolumeName] = req.Name
	volumeResponse.VolumeContext[identifiers.KeyProtocol] = protocol
	volumeResponse.VolumeContext[identifiers.KeyServiceTag] = serviceTag

	// For all Metro volumes, update the remoteSystem parameter to reflect the actual remote system
	// This ensures the parameter always matches the authoritative remote system object
	if isMetroVolume {
		volumeResponse.VolumeContext[s.WithRP(KeyReplicationRemoteSystem)] = remoteSystem.Name
	}

	if useNFS {
		volumeResponse.VolumeContext[identifiers.KeyNfsACL] = nfsAcls
		volumeResponse.VolumeContext[identifiers.KeyNasName] = creator.(*NfsCreator).nasName
		// AC-007: Set NAS interface IP in VolumeContext so it appears on the PV via csi-provisioner
		if nasInterfaceIP := creator.(*NfsCreator).nasInterfaceIP; nasInterfaceIP != "" {
			volumeResponse.VolumeContext[identifiers.KeyNasInterfaceIP] = nasInterfaceIP
		}
		// Preserve operator-supplied topology segments, removing only PowerStore block-protocol
		// segments (-fc, -iscsi, -nvmefc, -nvmetcp) so NFS volumes retain placement constraints
		// (zone labels, custom labels) while remaining unlinked from block-only nodes.
		// Fall back to the legacy single -nfs segment when no accessibility requirements are present.
		if ar := req.AccessibilityRequirements; ar != nil {
			topology = identifiers.GetEligibleNfsAccessibleTopologies(ar.Preferred, ar.Requisite, arr.GetIP())
		} else {
			topology = identifiers.GetNfsTopology(arr.GetIP())
		}
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  "CreateVolume",
			log.FieldProtocol:   "NFS",
			log.FieldVolumeName: req.GetName(),
		}).Info("modified topology to NFS")
	}

	volumeResponse.VolumeId = volumeResponse.VolumeId + "/" + arr.GetGlobalID() + "/" + protocol + metroVolumeIDSuffix

	volumeResponse.AccessibleTopology = topology

	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent:  "controller",
		log.FieldOperation:  "CreateVolume",
		log.FieldVolumeName: req.GetName(),
		log.FieldDurationMs: time.Since(startTime).Milliseconds(),
	}).Info("volume creation completed")
	return &csi.CreateVolumeResponse{
		Volume: volumeResponse,
	}, nil
}

// checkMetroFractureForSnapshotRestore checks if the metro session on the source volume
// (parent of the snapshot) is fractured before attempting a metro snapshot restore.
// If fractured, restore should be blocked to avoid creating orphaned non-metro volumes.
// This function fails closed: API errors return codes.Internal to prevent restoring during
// an unverifiable fracture state. Only pre-upgrade snapshots (no parent volume info) skip
// the check, since they have no metro session to verify.
// Note: The client must be the array where the snapshot resides. If the snapshot is on the
// remote array but the client points to the local array, GetVolume will fail and the check
// will return an error, which is the correct defensive behavior.
func checkMetroFractureForSnapshotRestore(ctx context.Context, client gopowerstore.Client, snapshotID string) error {
	// Get the snapshot to find its parent volume
	snapVol, err := client.GetVolume(ctx, snapshotID)
	if err != nil {
		log.WithContext(ctx).Errorf("Failed to get snapshot details for metro fracture check: %s", err.Error())
		return status.Errorf(codes.Internal, "cannot verify metro fracture state: failed to get snapshot %s: %s", snapshotID, err.Error())
	}
	parentVolID := snapVol.ProtectionData.SourceID
	if parentVolID == "" {
		// No parent volume info (e.g., pre-upgrade snapshot); skip fracture check
		return nil
	}
	resp, err := isMetroFracturedFunc(ctx, client, parentVolID)
	if err != nil {
		log.WithContext(ctx).Errorf("Failed to check metro fracture state for parent volume %s: %s", parentVolID, err.Error())
		return status.Errorf(codes.Internal, "cannot verify metro fracture state for parent volume %s: %s", parentVolID, err.Error())
	}
	if resp.IsFractured {
		return status.Error(codes.FailedPrecondition, "Restore blocked: metro session is fractured")
	}
	return nil
}

// validateSnapshotArrayForMetro validates that the snapshot's array is part of the metro pair
// specified in the StorageClass. This prevents confusing errors when a user tries to restore
// a snapshot from Array-A using a metro SC pointing to Array-B and Array-C.
func validateSnapshotArrayForMetro(_ context.Context, snapshotArrayID, localArrayID, remoteArraySerialNumber string) error {
	if snapshotArrayID == "" {
		// Legacy snapshot without array info; skip validation
		return nil
	}
	if snapshotArrayID == localArrayID || snapshotArrayID == remoteArraySerialNumber {
		return nil
	}
	return status.Errorf(codes.InvalidArgument,
		"snapshot on array %s is not part of the metro pair (local: %s, remote: %s). Use a StorageClass matching the snapshot's array",
		snapshotArrayID, localArrayID, remoteArraySerialNumber)
}

func deleteNFSExport(ctx context.Context, client gopowerstore.Client, export gopowerstore.NFSExport) error {
	if export.ID == "" {
		return nil
	}

	_, err := client.DeleteNFSExport(ctx, export.ID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return nil
		}
		return err
	}
	return nil
}

func nfsExportHostEntries(export gopowerstore.NFSExport) []string {
	entries := append([]string{}, export.ROHosts...)
	entries = append(entries, export.RORootHosts...)
	entries = append(entries, export.RWHosts...)
	return append(entries, export.RWRootHosts...)
}

func nfsExportRemovalPayload(export gopowerstore.NFSExport, host string) (gopowerstore.NFSExportModify, int) {
	remove := func(entries []string) []string {
		matched := make([]string, 0, len(entries))
		for _, entry := range entries {
			if identifiers.HostEntryMatchesIP(entry, host) {
				matched = append(matched, entry)
			}
		}
		return matched
	}

	payload := gopowerstore.NFSExportModify{
		RemoveROHosts:     remove(export.ROHosts),
		RemoveRORootHosts: remove(export.RORootHosts),
		RemoveRWHosts:     remove(export.RWHosts),
		RemoveRWRootHosts: remove(export.RWRootHosts),
	}
	return payload, len(payload.RemoveROHosts) + len(payload.RemoveRORootHosts) +
		len(payload.RemoveRWHosts) + len(payload.RemoveRWRootHosts)
}

// DeleteVolume deletes either FileSystem or Volume from storage array.
func (s *Service) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "controller",
		log.FieldOperation: "DeleteVolume",
		log.FieldVolumeID:  id,
	}).Info("starting volume deletion")
	startTime := time.Now()

	volumeHandle, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), nil)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return &csi.DeleteVolumeResponse{}, nil
		}
		return nil, err
	}

	id = volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.Internal, "can't find array with provided id %s", arrayID)
	}

	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "controller",
		log.FieldOperation: "DeleteVolume",
		log.FieldVolumeID:  id,
		log.FieldProtocol:  protocol,
		log.FieldArrayID:   arr.Endpoint,
	}).Info("volume info resolved")

	switch protocol {
	case "nfs":
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "DeleteVolume",
			log.FieldVolumeID:  id,
			log.FieldProtocol:  "nfs",
		}).Info("checking snapshots for NFS volume")
		listSnaps, err := arr.GetClient().GetFsSnapshotsByVolumeID(ctx, id)
		if err != nil {
			return nil, status.Errorf(codes.Unknown, "failure getting snapshot: %s", err.Error())
		}
		if len(listSnaps) > 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"unable to delete FS volume -- snapshots based on this volume still exist: %v",
				listSnaps)
		}

		// The node-specific host entries are removed during ControllerUnpublishVolume.
		// Do not delete an export that still has any clients, since they may be
		// active or have been configured out-of-band.
		nfsExportResp, exportErr := arr.GetClient().GetNFSExportByFileSystemID(ctx, id)
		if exportErr != nil {
			if apiError, ok := exportErr.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.Internal, "failure checking nfs export status for volume deletion: %s", exportErr.Error())
			}
		} else {
			hostEntries := nfsExportHostEntries(nfsExportResp)
			if len(hostEntries) > 0 {
				if s.externalAccess == "" {
					return nil, status.Errorf(codes.FailedPrecondition,
						"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
						id)
				}
				externalAccess, parseErr := identifiers.ParseCIDR(s.externalAccess)
				if parseErr != nil {
					return nil, status.Errorf(codes.FailedPrecondition,
						"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
						id)
				}
				payload, matched := nfsExportRemovalPayload(nfsExportResp, externalAccess)
				if matched != len(hostEntries) {
					return nil, status.Errorf(codes.FailedPrecondition,
						"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
						id)
				}
				if _, modifyErr := arr.GetClient().ModifyNFSExport(ctx, &payload, nfsExportResp.ID); modifyErr != nil {
					if apiError, ok := modifyErr.(gopowerstore.APIError); !ok || !apiError.HostAlreadyRemovedFromNFSExport() {
						return nil, status.Errorf(codes.FailedPrecondition,
							"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
							id)
					}
				}
			}

			// Re-read immediately before deletion so a concurrent publish or unpublish
			// cannot make the initial export check stale. A not-found response is
			// already a safe terminal state for an idempotent delete.
			latestExport, latestErr := arr.GetClient().GetNFSExportByFileSystemID(ctx, id)
			if latestErr != nil {
				if apiError, ok := latestErr.(gopowerstore.APIError); !ok || !apiError.NotFound() {
					return nil, status.Errorf(codes.Internal, "failure rechecking nfs export status for volume deletion: %s", latestErr.Error())
				}
				nfsExportResp = gopowerstore.NFSExport{}
			} else {
				if len(nfsExportHostEntries(latestExport)) > 0 {
					return nil, status.Errorf(codes.FailedPrecondition,
						"filesystem %s cannot be deleted as it has associated NFS or SMB shares.",
						id)
				}
				nfsExportResp = latestExport
			}
			if err := deleteNFSExport(ctx, arr.GetClient(), nfsExportResp); err != nil {
				return nil, status.Errorf(codes.Internal, "failure deleting nfs export: %s", err.Error())
			}
		}
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "DeleteVolume",
			log.FieldVolumeID:  id,
		}).Info("calling DeleteFS API")
		_, err = arr.GetClient().DeleteFS(ctx, id)
		if err == nil {
			log.WithContext(ctx).WithFields(log.Fields{
				log.FieldComponent:  "controller",
				log.FieldOperation:  "DeleteVolume",
				log.FieldVolumeID:   id,
				log.FieldProtocol:   "nfs",
				log.FieldDurationMs: time.Since(startTime).Milliseconds(),
			}).Info("NFS volume deleted successfully")
			return &csi.DeleteVolumeResponse{}, nil
		}
		if apiError, ok := err.(gopowerstore.APIError); ok {
			if apiError.NotFound() {
				return &csi.DeleteVolumeResponse{}, nil
			}
		}
		return nil, err

	case "scsi":
		localDeleted := false
		remoteDeleted := false

		var metroResp *array.MetroFracturedResponse
		var remoteArray *array.PowerStoreArray
		remoteVolumeID := volumeHandle.RemoteUUID
		remoteArrayID := volumeHandle.RemoteArrayGlobalID
		if volumeHandle.IsMetro() {
			if arr, ok := s.Arrays()[remoteArrayID]; ok {
				remoteArray = arr
			} else {
				return nil, status.Errorf(codes.InvalidArgument, "failed to find remote array with ID %s", remoteArrayID)
			}
			metroResp, _, err = array.CheckMetroState(ctx, volumeHandle, arr.GetClient(), remoteArray.GetClient())
			if err != nil {
				if err, ok := err.(gopowerstore.APIError); ok && err.NotFound() {
					// both local and remote attempts to get the metro state failed with NotFound errors
					// indicating the volume is already deleted
					return &csi.DeleteVolumeResponse{}, nil
				}
				return nil, err
			}
			if metroResp.IsFractured {
				log.WithContext(ctx).Warnf("[METRO] metro volume %s is in a fractured state", req.GetVolumeId())
			}
		}

		// Delete local volume
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "DeleteVolume",
			log.FieldVolumeID:  id,
			log.FieldProtocol:  "scsi",
			log.FieldArrayID:   arr.Endpoint,
		}).Info("deleting local SCSI volume")
		err = deleteISCSIVolume(ctx, volumeHandle, arr, id)
		if err == nil {
			log.WithContext(ctx).WithFields(log.Fields{
				log.FieldComponent: "controller",
				log.FieldOperation: "DeleteVolume",
				log.FieldVolumeID:  id,
			}).Info("local SCSI volume deleted successfully")
			localDeleted = true
		} else {
			log.WithContext(ctx).Errorf("failed to delete volume %s: %v", id, err)
		}

		// non-metro or not fractured just return results
		if !volumeHandle.IsMetro() || !metroResp.IsFractured {
			if localDeleted {
				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  "DeleteVolume",
					log.FieldVolumeID:   id,
					log.FieldDurationMs: time.Since(startTime).Milliseconds(),
				}).Info("volume deleted successfully")
				return &csi.DeleteVolumeResponse{}, nil
			}
			return nil, err
		}

		// from here is metro and fractured array
		err = deleteISCSIVolume(ctx, volumeHandle, remoteArray, remoteVolumeID)
		if err == nil {
			remoteDeleted = true
		} else {
			log.WithContext(ctx).Errorf("failed to delete remote volume %s: %v", id, err)
		}

		if localDeleted && remoteDeleted {
			log.WithContext(ctx).WithFields(log.Fields{
				log.FieldComponent:  "controller",
				log.FieldOperation:  "DeleteVolume",
				log.FieldVolumeID:   id,
				log.FieldDurationMs: time.Since(startTime).Milliseconds(),
			}).Info("metro volume deleted successfully")
			return &csi.DeleteVolumeResponse{}, nil
		}
		// return error if anything not deleted and k8s will retry
		return nil, err
	default:
		return nil, status.Errorf(codes.InvalidArgument, "can't figure out protocol")
	}
}

func deleteISCSIVolume(ctx context.Context, _ array.VolumeHandle, arr *array.PowerStoreArray, id string) error {
	vgs, err := arr.GetClient().GetVolumeGroupsByVolumeID(ctx, id)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
			return err
		}
	}

	if len(vgs.VolumeGroup) != 0 {
		// Remove volume from volume group
		// TODO: If volume has multiple volume group then how we should find ours?
		// TODO: Maybe adding volumegroup id/name to volume id can help?
		_, err := arr.GetClient().RemoveMembersFromVolumeGroup(ctx, &gopowerstore.VolumeGroupMembers{VolumeIDs: []string{id}}, vgs.VolumeGroup[0].ID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.VolumeAlreadyRemovedFromVolumeGroup() { // idempotency check
				log.WithContext(ctx).Debugf("Volume %s has already been removed from volume group %s", id, vgs.VolumeGroup[0].ID) // continue to delete volume
			} else {
				return status.Errorf(codes.Internal, "failed to remove volume %s from volume group: %s", id, err.Error())
			}
		}

		// Unassign protection policy
		emptyPolicy := ""
		_, err = arr.GetClient().ModifyVolume(ctx, &gopowerstore.VolumeModify{ProtectionPolicyID: &emptyPolicy}, id)
		if err != nil {
			return err
		}
	}

	volume, err := arr.GetClient().GetVolume(ctx, id)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			log.WithContext(ctx).Infof("Volume %s not found, it may have been deleted.", id)
			return nil
		}
		return status.Errorf(codes.Internal, "failure getting volume: %s", err.Error())
	}

	// TODO: if len(vgs.VolumeGroup == 1) && it is the last volume : delete volume group
	// TODO: What to do with RPO snaps?
	listSnaps, err := arr.GetClient().GetSnapshotsByVolumeID(ctx, id)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
			return status.Errorf(codes.Unknown, "failure getting snapshot: %s", err.Error())
		}
	}

	blockingDeleteSnapshotCount := 0
	for _, snap := range listSnaps {
		// Note: There is no other way to check if it is a metro user snapshot from the response.
		regex := regexp.MustCompile(array.MetroPrefixRegex + volume.Name)
		if !regex.MatchString(snap.Name) {
			log.WithContext(ctx).Warnf("Snapshot detected for metro volume %s, delete this to finish cleanup: %s", volume.Name, snap.Name)
			blockingDeleteSnapshotCount++
		}
	}

	if blockingDeleteSnapshotCount > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"unable to delete volume %s -- %d snapshots based on this volume still exist.", volume.Name, blockingDeleteSnapshotCount)
	}

	// Check if volume has metro session and end it
	if volume.MetroReplicationSessionID != "" {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "EndMetroVolume",
			log.FieldVolumeID:  id,
			"session_id":       volume.MetroReplicationSessionID,
		}).Info("ending metro session")
		endMetroStart := time.Now()
		_, err = arr.GetClient().EndMetroVolume(ctx, id, &gopowerstore.EndMetroVolumeOptions{
			DeleteRemoteVolume: true, // delete remote volume when deleting local volume
		})
		if err != nil {
			log.WithContext(ctx).WithFields(log.Fields{
				log.FieldComponent:  "controller",
				log.FieldOperation:  "EndMetroVolume",
				log.FieldVolumeID:   id,
				log.FieldError:      err.Error(),
				log.FieldDurationMs: time.Since(endMetroStart).Milliseconds(),
			}).Error("EndMetroVolume API call failed")
			return status.Errorf(codes.Internal, "failure ending metro session on volume: %s", err.Error())
		}
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  "EndMetroVolume",
			log.FieldVolumeID:   id,
			log.FieldDurationMs: time.Since(endMetroStart).Milliseconds(),
		}).Info("EndMetroVolume API call succeeded")
	}

	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "controller",
		log.FieldOperation: "DeleteVolume",
		log.FieldVolumeID:  id,
	}).Info("calling DeleteVolume API")
	deleteStart := time.Now()
	_, err = arr.GetClient().DeleteVolume(ctx, nil, id)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok {
			if apiError.NotFound() {
				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  "DeleteVolume",
					log.FieldVolumeID:   id,
					log.FieldDurationMs: time.Since(deleteStart).Milliseconds(),
				}).Info("volume not found (already deleted)")
				return nil
			}
			if apiError.VolumeAttachedToHost() {
				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent:  "controller",
					log.FieldOperation:  "DeleteVolume",
					log.FieldVolumeID:   id,
					log.FieldError:      apiError.Error(),
					log.FieldDurationMs: time.Since(deleteStart).Milliseconds(),
				}).Error("volume still attached to host")
				return status.Errorf(codes.Internal,
					"volume with ID '%s' is still attached to host: %s", id, apiError.Error())
			}
		}
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  "DeleteVolume",
			log.FieldVolumeID:   id,
			log.FieldError:      err.Error(),
			log.FieldDurationMs: time.Since(deleteStart).Milliseconds(),
		}).Error("DeleteVolume API call failed")
	} else {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  "DeleteVolume",
			log.FieldVolumeID:   id,
			log.FieldDurationMs: time.Since(deleteStart).Milliseconds(),
		}).Info("DeleteVolume API call succeeded")
	}
	return err
}

// allKnownMutableParams is the set of all recognized mutable parameter keys.
var allKnownMutableParams = map[string]bool{
	"Description": true, "PerformancePolicyID": true,
	"ProtectionPolicyID": true, "AppType": true,
	"AppTypeOther": true,
}

// knownBlockMutableParams lists valid params for block volumes.
var knownBlockMutableParams = map[string]bool{
	"Description": true, "PerformancePolicyID": true,
	"ProtectionPolicyID": true, "AppType": true,
	"AppTypeOther": true,
}

// knownNFSMutableParams lists valid params for NFS volumes.
var knownNFSMutableParams = map[string]bool{
	"Description": true, "ProtectionPolicyID": true,
	"PerformancePolicyID": true,
}

// validateMutableParamKeys checks that every key is known.
func validateMutableParamKeys(params map[string]string) error {
	for key := range params {
		if !allKnownMutableParams[key] {
			return fmt.Errorf("unknown key %q", key)
		}
	}
	return nil
}

// validateParamsForVolumeType checks params are valid for the given protocol.
func validateParamsForVolumeType(params map[string]string, protocol string) error {
	allowed := knownBlockMutableParams
	if protocol == "nfs" {
		allowed = knownNFSMutableParams
	}
	for key := range params {
		if !allowed[key] {
			return fmt.Errorf("parameter %q is not supported for %s volumes", key, protocol)
		}
	}
	return nil
}

// buildVolumeModify creates a VolumeModify using pointer semantics.
func buildVolumeModify(currentVol gopowerstore.Volume, params map[string]string) *gopowerstore.VolumeModify {
	mod := &gopowerstore.VolumeModify{}

	description := currentVol.Description
	if v, ok := params["Description"]; ok {
		description = v
		mod.Description = &v
	}

	performancePolicyID := currentVol.PerformancePolicyID
	if v, ok := params["PerformancePolicyID"]; ok {
		performancePolicyID = v
		mod.PerformancePolicyID = &v
	}

	protectionPolicyID := currentVol.ProtectionPolicyID
	if v, ok := params["ProtectionPolicyID"]; ok {
		protectionPolicyID = v
		mod.ProtectionPolicyID = &v
	}

	appType := currentVol.AppType
	if v, ok := params["AppType"]; ok {
		// Convert string to AppTypeEnum for comparison, keep original string for API
		appType = gopowerstore.AppTypeEnum(v)
		mod.AppType = &v
	}

	appTypeOther := currentVol.AppTypeOther
	if v, ok := params["AppTypeOther"]; ok {
		appTypeOther = v
		mod.AppTypeOther = &v
	}

	// Idempotency check - skip if all values are unchanged
	if description == currentVol.Description &&
		performancePolicyID == currentVol.PerformancePolicyID &&
		protectionPolicyID == currentVol.ProtectionPolicyID &&
		appType == currentVol.AppType &&
		appTypeOther == currentVol.AppTypeOther {
		return nil
	}

	return mod
}

// buildFSModify creates an FSModify using pointer semantics.
func buildFSModify(currentFS gopowerstore.FileSystem, params map[string]string) *gopowerstore.FSModify {
	mod := &gopowerstore.FSModify{}

	description := currentFS.Description
	if v, ok := params["Description"]; ok {
		description = v
		mod.Description = &v
	}

	protectionPolicyID := currentFS.ProtectionPolicyID
	if v, ok := params["ProtectionPolicyID"]; ok {
		protectionPolicyID = v
		mod.ProtectionPolicyID = &v
	}

	performancePolicyID := currentFS.PerformancePolicyID
	if v, ok := params["PerformancePolicyID"]; ok {
		performancePolicyID = v
		mod.PerformancePolicyID = &v
	}

	// Idempotency check - skip if all values are unchanged
	if description == currentFS.Description &&
		protectionPolicyID == currentFS.ProtectionPolicyID &&
		performancePolicyID == currentFS.PerformancePolicyID {
		return nil
	}

	return mod
}

// ControllerModifyVolume modifies mutable attributes of an existing volume.
// It validates the request parameters against the volume type (block/NFS),
// fetches the current volume state, and applies changes using fetch-then-patch semantics.
func (s *Service) ControllerModifyVolume(ctx context.Context, req *csi.ControllerModifyVolumeRequest) (*csi.ControllerModifyVolumeResponse, error) {
	log.WithContext(ctx).Infof("ControllerModifyVolume called with req: %s", req)

	if req.GetVolumeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "volume_id must not be empty")
	}

	volumeHandle, err := array.ParseVolumeID(ctx, req.GetVolumeId(), s.DefaultArray(), nil)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "failed to parse volume_id %s: %v", req.GetVolumeId(), err)
	}

	params := req.GetMutableParameters()
	if len(params) == 0 {
		return nil, status.Error(codes.InvalidArgument, "mutable_parameters must not be empty")
	}

	if err := validateMutableParamKeys(params); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid mutable parameter: %s", err)
	}

	volID := volumeHandle.LocalUUID
	protocol := volumeHandle.Protocol
	arr, ok := s.Arrays()[volumeHandle.LocalArrayGlobalID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "array not found for volume %s", req.GetVolumeId())
	}
	client := arr.GetClient()

	if err := validateParamsForVolumeType(params, protocol); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s", err)
	}

	switch protocol {
	case "nfs":
		fs, err := client.GetFS(ctx, volID)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "failed to get filesystem %s: %v", volID, err)
		}
		fsModify := buildFSModify(fs, params)
		if fsModify == nil {
			log.WithContext(ctx).Infof("Skipping filesystem modification for volume %s as values are unmodified", req.GetVolumeId())
			return &csi.ControllerModifyVolumeResponse{}, nil
		}
		if _, err := client.ModifyFS(ctx, fsModify, volID); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to modify filesystem %s: %v", volID, err)
		}
	default:
		vol, err := client.GetVolume(ctx, volID)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "failed to get volume %s: %v", volID, err)
		}
		volModify := buildVolumeModify(vol, params)
		if volModify == nil {
			log.WithContext(ctx).Infof("Skipping volume modification for volume %s as values are unmodified", req.GetVolumeId())
			return &csi.ControllerModifyVolumeResponse{}, nil
		}
		if _, err := client.ModifyVolume(ctx, volModify, volID); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to modify volume %s: %v", volID, err)
		}
	}

	log.WithContext(ctx).Infof("ControllerModifyVolume succeeded for volume %s", req.GetVolumeId())
	return &csi.ControllerModifyVolumeResponse{}, nil
}

// ControllerPublishVolume prepares Volume/FileSystem to be consumed by node by attaching/allowing access to the host.
func (s *Service) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	id := req.GetVolumeId()
	kubeNodeID := req.GetNodeId()

	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	if kubeNodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "node ID is required")
	}

	volumeHandle, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), req.VolumeCapability)
	if err != nil {
		log.WithContext(ctx).Error(err.Error())
		return nil, err
	}

	id = volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol
	remoteVolumeID := volumeHandle.RemoteUUID
	remoteArrayID := volumeHandle.RemoteArrayGlobalID

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "failed to find array with ID %s", arrayID)
	}
	remoteArray := &array.PowerStoreArray{}
	if volumeHandle.IsMetro() {
		remoteArray, ok = s.Arrays()[remoteArrayID]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "failed to find remote array with ID %s", remoteArrayID)
		}
	}

	vc := req.GetVolumeCapability()
	if vc == nil {
		return nil, status.Error(codes.InvalidArgument, "volume capability is required")
	}
	am := vc.GetAccessMode()
	if am == nil {
		return nil, status.Error(codes.InvalidArgument, "access mode is required")
	}

	if am.Mode == csi.VolumeCapability_AccessMode_UNKNOWN {
		return nil, status.Error(codes.InvalidArgument, ErrUnknownAccessMode)
	}

	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "controller",
		log.FieldOperation: "ControllerPublishVolume",
		log.FieldVolumeID:  id,
		log.FieldNodeID:    kubeNodeID,
		log.FieldProtocol:  protocol,
		log.FieldArrayID:   arr.Endpoint,
	}).Info("publishing volume to node")

	var publisher VolumePublisher
	if protocol == "nfs" {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "ControllerPublishVolume",
			log.FieldVolumeID:  id,
			log.FieldProtocol:  "nfs",
		}).Info("using NFS publisher")
		publisher = &NfsPublisher{
			ExternalAccess:  s.externalAccess,
			ExclusiveAccess: s.exclusiveAccess,
			NfsAutoSelect:   s.nfsAutoSelect,
		}
	} else {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "ControllerPublishVolume",
			log.FieldVolumeID:  id,
			log.FieldProtocol:  "scsi",
		}).Info("using SCSI publisher")
		publisher = &SCSIPublisher{}
	}

	localDemoted := false
	var metroResp *array.MetroFracturedResponse
	isMetroFractured := false

	if remoteVolumeID != "" {
		ctxLocal, cancelLocal := context.WithTimeout(context.Background(), array.MediumTimeout)
		defer cancelLocal()
		metroResp, localDemoted, err = array.CheckMetroState(ctxLocal, volumeHandle, arr.GetClient(), remoteArray.GetClient())
		if err != nil {
			return nil, err
		}
		isMetroFractured = metroResp.IsFractured
		if isMetroFractured {
			log.WithContext(ctx).Warnf("[METRO] metro volume %s is in a fractured state", req.GetVolumeId())
		}
		if localDemoted {
			log.WithContext(ctx).Warnf("[METRO] metro volume %s has been demoted", req.GetVolumeId())
		}
	} else {
		if err := publisher.CheckIfVolumeExists(ctx, arr.GetClient(), id); err != nil {
			return nil, err
		}
	}

	publishContext := make(map[string]string)
	publishVolumeResponse := &csi.ControllerPublishVolumeResponse{}
	localPublished, remotePublished := false, false

	hostRegisteredLocalArray := arr.HasHostEntry(ctx, kubeNodeID)
	if hostRegisteredLocalArray {
		log.WithContext(ctx).Infof("Volume is being published on node %s for array %s", kubeNodeID, arr.Endpoint)
		ctxLocal, cancelLocal := context.WithTimeout(context.Background(), array.MediumTimeout)
		defer cancelLocal()
		publishReponse, publishErr := publisher.Publish(ctxLocal, publishContext, req, arr.GetClient(), kubeNodeID, id, false)
		if publishErr != nil {
			if isMetroFractured && localDemoted {
				log.WithContext(ctx).Infof("[METRO] Could not publish volume %s on node %s for array %s due to Metro Session Fracture", id, kubeNodeID, arr.Endpoint)
			} else {
				log.WithContext(ctx).Errorf("Failed to publish volume %s on node %s for array %s: %s", id, kubeNodeID, arr.Endpoint, publishErr)
				return nil, publishErr
			}
		} else {
			log.WithContext(ctx).Infof("Local volume %s published, context: %v", id, publishReponse.PublishContext)
			publishVolumeResponse = publishReponse
			localPublished = true
		}
	} else {
		log.WithContext(ctx).Infof("skipping volume publish on node %s for array %s, topology does not match", kubeNodeID, arr.Endpoint)
	}

	hostRegisteredRemoteArray := false
	if volumeHandle.IsMetro() {
		if hostRegisteredRemoteArray = remoteArray.HasHostEntry(ctx, kubeNodeID); hostRegisteredRemoteArray {
			log.WithContext(ctx).Infof("Volume is being published on node %s for remote array %s", kubeNodeID, remoteArray.Endpoint)
			ctxRemote, cancelRemote := context.WithTimeout(context.Background(), array.MediumTimeout)
			defer cancelRemote()
			publishReponse, publishErr := publisher.Publish(ctxRemote, publishContext, req, remoteArray.GetClient(), kubeNodeID, remoteVolumeID, true)
			if publishErr != nil {
				if isMetroFractured && !localDemoted {
					// localDemoted == false  implies local is Promoted and Remote is Demoted.
					log.WithContext(ctx).Infof("[METRO] Could not publish volume %s on node %s for array %s due to Metro Session Fracture", remoteVolumeID, kubeNodeID, remoteArray.Endpoint)
				} else {
					// remote is Promoted
					log.WithContext(ctx).Errorf("Failed to publish volume %s on node %s for array %s: %s", id, kubeNodeID, remoteArray.Endpoint, publishErr)
					return nil, publishErr
				}
			} else {
				log.WithContext(ctx).Infof("Remote volume %s published, context: %v", remoteVolumeID, publishReponse.PublishContext)
				remotePublished = true
				publishVolumeResponse = publishReponse
			}
		} else {
			log.WithContext(ctx).Debugf("skipping volume publish on node %s for remote array %s, topology does not match", kubeNodeID, remoteArray.Endpoint)
		}
	}

	// at least one publish should succeed for non-metro, non-uniform metro, and uniform metro
	// if a publish fails for uniform metro, the failed request will be deferred by adding to the volume journal
	if !localPublished && !remotePublished {
		return nil, status.Error(codes.Internal, "failed to publish volume")
	}

	// Handling Uniform Metro Fracture cases. Other failures would have returned error before this point.
	// Deferred operations are relevant only for Uniform metro in a fractured state and when only one side of metro volume was published
	// and other side was not.
	// Uniform metro is confirmed by a metro volume handle, and host connectivity from the kubeNodeID to both arrays.
	if volumeHandle.IsMetro() && hostRegisteredLocalArray && hostRegisteredRemoteArray {
		if (localPublished && !remotePublished) || (!localPublished && remotePublished) {
			deferredRequest, err := proto.Marshal(req)
			if err != nil {
				log.WithContext(ctx).Errorf("[METRO] Error marshalling req: %s", err.Error())
			}
			deferredArrayID := arrayID
			if !remotePublished {
				deferredArrayID = remoteArrayID
			}

			err = createOrUpdateJournalEntryFunc(ctx, metroResp.VolumeName, volumeHandle, deferredArrayID, kubeNodeID, "ControllerPublishVolume", deferredRequest)
			if err != nil {
				log.WithContext(ctx).Errorf("Could not create journal entry for operation %s for volume %s node %s array %s", "ControllerPublishVolume", id, kubeNodeID, arr.Endpoint)
			}
		}
	}

	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "controller",
		log.FieldOperation: "ControllerPublishVolume",
		log.FieldVolumeID:  id,
		log.FieldNodeID:    kubeNodeID,
	}).Info("publish completed")
	return publishVolumeResponse, nil
}

// ControllerUnpublishVolume prepares Volume/FileSystem to be deleted by unattaching/disabling access to the host.
func (s *Service) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	kubeNodeID := req.GetNodeId()
	if kubeNodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "node ID is required")
	}
	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "controller",
		log.FieldOperation: "ControllerUnpublishVolume",
		log.FieldVolumeID:  id,
		log.FieldNodeID:    kubeNodeID,
	}).Info("unpublishing volume from node")

	volumeHandle, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), nil)
	if err != nil {
		log.WithContext(ctx).Error(err.Error())
		return nil, err
	}
	arrayID := volumeHandle.LocalArrayGlobalID
	remoteArrayID := volumeHandle.RemoteArrayGlobalID

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "cannot find array %s", arrayID)
	}
	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "controller",
		log.FieldOperation: "ControllerUnpublishVolume",
		log.FieldVolumeID:  id,
		log.FieldProtocol:  volumeHandle.Protocol,
		log.FieldArrayID:   arr.Endpoint,
	}).Info("volume info resolved")
	var remoteArray *array.PowerStoreArray
	isMetroFractured := false
	localDemoted := false
	metroResp := &array.MetroFracturedResponse{
		IsFractured: false,
	}

	if volumeHandle.IsMetro() {
		remoteArray, ok = s.Arrays()[remoteArrayID]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "cannot find remote array %s", remoteArrayID)
		}

		metroResp, localDemoted, err = checkMetroStateFunc(ctx, volumeHandle, arr.GetClient(), remoteArray.GetClient())
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok {
				if !apiError.NotFound() {
					return nil, err
				}

				// Not found due to potentially deleted volume through UI. Still need to unpublish.
				log.WithContext(ctx).Infof("[Metro] Volume with ID %s not found", id)
			}
		}

		if metroResp != nil {
			isMetroFractured = metroResp.IsFractured
		}

		if isMetroFractured {
			log.WithContext(ctx).Warnf("[METRO] metro volume %s is in a fractured state", req.GetVolumeId())
		}

		if localDemoted {
			log.WithContext(ctx).Warnf("[METRO] metro volume %s has been demoted", req.GetVolumeId())
		}
	}

	localVolumeUnpublished := false
	remoteVolumeUnpublished := false
	response := &csi.ControllerUnpublishVolumeResponse{}

	// Check if it is Metro volume and with newer secret configuation
	nodeConnectedToLocalArray := isNodeConnectedToArrayFunc(ctx, kubeNodeID, arr)
	if nodeConnectedToLocalArray {
		log.WithContext(ctx).Debugf("Volume is being unpublished on node %s for array %s", kubeNodeID, arr.Endpoint)
		ctxLocal, cancelLocal := context.WithTimeout(context.Background(), array.MediumTimeout)
		defer cancelLocal()
		resp, unpublishErr := unpublishVolumeFunc(ctxLocal, kubeNodeID, arr, &volumeHandle, nil)
		if unpublishErr != nil {
			if isMetroFractured && localDemoted {
				// expected failure if Metro is Fractured and local array is down
				log.WithContext(ctx).Infof("[METRO] Could not unpublish volume %s on node %s for array %s due to Metro Session Fracture", id, kubeNodeID, arr.Endpoint)
			} else {
				log.WithContext(ctx).Errorf("Failed to unpublish volume %s  for array %s: %s", id, arr.Endpoint, err)
				return nil, unpublishErr
			}
		} else {
			log.WithContext(ctx).Infof("Unpublished volume %s for array %s", id, arr.Endpoint)
			localVolumeUnpublished = true
			response = resp
		}
	}
	nodeConnectedToRemoteArray := false
	if volumeHandle.IsMetro() {
		nodeConnectedToRemoteArray = isNodeConnectedToArrayFunc(ctx, kubeNodeID, remoteArray)
		if nodeConnectedToRemoteArray {
			log.WithContext(ctx).Debugf("Volume is being unpublished on node %s for remote array %s", kubeNodeID, remoteArray.Endpoint)
			ctxRemote, cancelRemote := context.WithTimeout(context.Background(), array.MediumTimeout)
			defer cancelRemote()
			resp, unpublishErr := unpublishVolumeFunc(ctxRemote, kubeNodeID, nil, &volumeHandle, remoteArray)
			if unpublishErr != nil {
				if isMetroFractured && !localDemoted {
					// expected failure if Metro is Fractured and remote array is down
					log.WithContext(ctx).Infof("[METRO] Could not unpublish volume %s on node %s for array %s due to Metro Session Fracture", id, kubeNodeID, remoteArray.Endpoint)
				} else {
					log.WithContext(ctx).Errorf("Failed to unpublish volume %s for array %s: %s", id, remoteArray.Endpoint, err)
					return nil, unpublishErr
				}
			} else {
				log.WithContext(ctx).Infof("Unpublished volume %s for array %s", id, remoteArray.Endpoint)
				remoteVolumeUnpublished = true
				response = resp
			}
		}
	}
	if !localVolumeUnpublished && !remoteVolumeUnpublished {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "controller",
			log.FieldOperation: "ControllerUnpublishVolume",
			log.FieldVolumeID:  id,
			log.FieldNodeID:    kubeNodeID,
		}).Error("failed to unpublish volume")
		return nil, status.Error(codes.Internal, "failed to unpublish volume")
	}

	if volumeHandle.IsMetro() && nodeConnectedToLocalArray && nodeConnectedToRemoteArray {
		if (localVolumeUnpublished && !remoteVolumeUnpublished) || (!localVolumeUnpublished && remoteVolumeUnpublished) {
			deferredRequest, err := proto.Marshal(req)
			if err != nil {
				log.WithContext(ctx).Errorf("[METRO] Error marshalling req: %s", err.Error())
				return nil, err
			}

			deferredArrayID := arrayID
			if !remoteVolumeUnpublished {
				deferredArrayID = remoteArrayID
			}

			err = createOrUpdateJournalEntryFunc(ctx, metroResp.VolumeName, volumeHandle, deferredArrayID, kubeNodeID, "ControllerUnpublishVolume", deferredRequest)
			if err != nil {
				log.WithContext(ctx).Errorf("Could not create journal entry for operation %s for volume %s node %s array %s", "ControllerUnpublishVolume", id, kubeNodeID, arrayID)
				return nil, err
			}

			log.WithContext(ctx).Infof("[METRO] Metro volume %s created journal entry for operation %s for volume %s node %s array %s", id, "ControllerUnpublishVolume", id, kubeNodeID, arrayID)
		}
	}

	return response, nil
}

func isNodeConnectedToArray(ctx context.Context, kubeNodeID string, arr *array.PowerStoreArray) bool {
	return arr.HasHostEntry(ctx, kubeNodeID)
}

// unpublishVolume removes the mount to the target path and unpublishes the volume
func unpublishVolume(ctx context.Context, kubeNodeID string, arr *array.PowerStoreArray, volumeHandle *array.VolumeHandle, remoteArray *array.PowerStoreArray) (*csi.ControllerUnpublishVolumeResponse, error) {
	if arr == nil && remoteArray == nil {
		return &csi.ControllerUnpublishVolumeResponse{}, errors.New("no array information for controller unpublish")
	}

	id := volumeHandle.LocalUUID
	protocol := volumeHandle.Protocol
	remoteVolumeID := volumeHandle.RemoteUUID

	switch protocol {
	case "scsi":
		// unpublish can be for remote array only
		if arr != nil {
			_, err := arr.GetClient().GetVolume(ctx, id)
			if err != nil {
				if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
					return &csi.ControllerUnpublishVolumeResponse{}, nil
				}
			}
			node, err := arr.GetClient().GetHostByName(ctx, kubeNodeID)
			if err != nil {
				if apiError, ok := err.(gopowerstore.APIError); ok && apiError.HostIsNotExist() {
					// We need additional check here since we can just have host without ip in it
					ipList := identifiers.GetIPListFromString(kubeNodeID)
					if len(ipList) == 0 {
						return nil, errors.New("can't find IP in nodeID")
					}
					ip := ipList[len(ipList)-1]
					nodeID := kubeNodeID[:len(kubeNodeID)-len(ip)-1]
					node, err = arr.GetClient().GetHostByName(ctx, nodeID)
					if err != nil {
						return nil, status.Errorf(codes.NotFound, "host with k8s node ID '%s' not found", kubeNodeID)
					}
				} else {
					return nil, status.Errorf(codes.Internal,
						"failure checking host '%s' status for volume unpublishing: %s", kubeNodeID, err.Error())
				}
			}

			err = detachVolumeFromHost(ctx, node.ID, id, arr.GetClient())
			if err != nil {
				return nil, err
			}
			log.Debugf("Volume is unpublished on node %s for array %s", kubeNodeID, arr.Endpoint)
		}

		if remoteVolumeID != "" && remoteArray != nil { // For Remote Metro volume
			_, err := remoteArray.GetClient().GetVolume(ctx, remoteVolumeID)
			if err != nil {
				if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
					return &csi.ControllerUnpublishVolumeResponse{}, nil
				}
			}
			node, err := remoteArray.GetClient().GetHostByName(ctx, kubeNodeID)
			if err != nil {
				return nil, status.Errorf(codes.Internal,
					"failure checking host '%s' status for volume unpublishing on remote array: %s", kubeNodeID, err.Error())
			}
			err = detachVolumeFromHost(ctx, node.ID, remoteVolumeID, remoteArray.GetClient())
			if err != nil {
				return nil, err
			}
			log.Debugf("Volume is unpublished on node %s for array %s", kubeNodeID, remoteArray.Endpoint)
		}

		return &csi.ControllerUnpublishVolumeResponse{}, nil
	case "nfs":
		fs, err := arr.GetClient().GetFS(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
				return &csi.ControllerUnpublishVolumeResponse{}, nil
			}
			return nil, status.Errorf(codes.Unknown, "failure checking volume status for volume unpublishing: %s", err.Error())
		}

		// Parse volumeID to get an IP
		ipList := identifiers.GetIPListFromString(kubeNodeID)
		if ipList == nil {
			return nil, errors.New("can't find IP in nodeID")
		}
		ip := ipList[0]

		export, err := arr.GetClient().GetNFSExportByFileSystemID(ctx, fs.ID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
				return &csi.ControllerUnpublishVolumeResponse{}, nil
			}
			return nil, status.Errorf(codes.Internal,
				"failure checking nfs export status for volume unpublishing: %s", err.Error())
		}

		// Remove only the current node's entries, preserving other clients on the export.
		var modifyHostPayload gopowerstore.NFSExportModify
		modifyHostPayload.RemoveROHosts = identifiers.HostEntriesForIP(export.ROHosts, ip)
		modifyHostPayload.RemoveRORootHosts = identifiers.HostEntriesForIP(export.RORootHosts, ip)
		modifyHostPayload.RemoveRWHosts = identifiers.HostEntriesForIP(export.RWHosts, ip)
		modifyHostPayload.RemoveRWRootHosts = identifiers.HostEntriesForIP(export.RWRootHosts, ip)
		// Detach only the current node from the NFS export. Other clients remain protected.
		if len(modifyHostPayload.RemoveROHosts) > 0 ||
			len(modifyHostPayload.RemoveRORootHosts) > 0 ||
			len(modifyHostPayload.RemoveRWHosts) > 0 ||
			len(modifyHostPayload.RemoveRWRootHosts) > 0 {
			_, err = arr.GetClient().ModifyNFSExport(ctx, &modifyHostPayload, export.ID)
			if err != nil {
				if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.HostAlreadyRemovedFromNFSExport() {
					log.WithFields(log.Fields{
						log.FieldComponent: "controller",
						log.FieldOperation: "ControllerUnpublishVolume",
						log.FieldProtocol:  "NFS",
						log.FieldError:     err.Error(),
					}).Debug("error modifying NFS export during unpublish")
					return nil, status.Errorf(codes.Internal,
						"failure when removing host from nfs export: %s", err.Error())
				}
			}
		}
		return &csi.ControllerUnpublishVolumeResponse{}, nil
	}

	return nil, status.Errorf(codes.InvalidArgument, "can't figure out protocol")
}

// GetServiceTag returns the service tag associated with an appliance
func GetServiceTag(ctx context.Context, req *csi.CreateVolumeRequest, arr *array.PowerStoreArray, volID string, protocol string) string {
	var ap gopowerstore.ApplianceInstance
	var vol gopowerstore.Volume
	var f gopowerstore.FileSystem
	var nas gopowerstore.NAS
	var applianceName string
	var err error

	// Check if appliance id is present in PVC manifest
	if applianceID, ok := req.Parameters["appliance_id"]; ok {
		// Fetching appliance information using the appliance id
		ap, err = arr.Client.GetAppliance(ctx, applianceID)
		if err != nil {
			log.WithContext(ctx).Warnf("Received error while calling GetAppliance %s", err.Error())
		}
	} else {
		if protocol != "nfs" {
			vol, err = arr.Client.GetVolume(ctx, volID)
			if err != nil {
				log.WithContext(ctx).Warnf("Received error while calling GetVolume %s", err.Error())
			}
			if vol.ApplianceID == "" {
				log.WithContext(ctx).Warn("Unable to fetch ApplianceID from the volume")
			} else {
				ap, err = arr.Client.GetAppliance(ctx, vol.ApplianceID)
				if err != nil {
					log.WithContext(ctx).Warnf("Received error while calling GetAppliance %s", err.Error())
				}
			}
		} else {
			f, err = arr.Client.GetFS(ctx, volID)
			if err != nil {
				log.WithContext(ctx).Warnf("Received error while calling GetFS %s", err.Error())
			}
			if f.NasServerID == "" {
				log.WithContext(ctx).Warn("Unable to fetch the NasServerID from the file system")
			} else {
				nas, err = arr.Client.GetNAS(ctx, f.NasServerID)
				if err != nil {
					log.WithContext(ctx).Warnf("Received error while calling GetNAS %s", err.Error())
				}
				if nas.CurrentNodeID == "" {
					log.WithContext(ctx).Warn("Unable to fetch the CurrentNodeId from the nas server")
				} else {
					// Removing "-node-X" from the end of CurrentNodeId to get Appliance Name
					applianceName = strings.Split(nas.CurrentNodeID, "-node-")[0]
					// Fetching appliance information using the appliance name
					ap, err = arr.Client.GetApplianceByName(ctx, applianceName)
					if err != nil {
						log.WithContext(ctx).Warnf("Received error while calling GetApplianceByName %s", err.Error())
					}
				}
			}
		}
	}
	return ap.ServiceTag
}

// ValidateVolumeCapabilities checks if capabilities found in request are supported by driver.
func (s *Service) ValidateVolumeCapabilities(ctx context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	var (
		supported = true
		isBlock   = accTypeIsBlock(req.VolumeCapabilities)
		reason    string
	)
	// Check that all access types are valid
	if !checkValidAccessTypes(req.VolumeCapabilities) {
		return &csi.ValidateVolumeCapabilitiesResponse{
			Confirmed: nil,
			Message:   ErrUnknownAccessType,
		}, status.Error(codes.Internal, ErrUnknownAccessType)
	}

	for _, vc := range req.VolumeCapabilities {
		am := vc.GetAccessMode()
		if am == nil {
			continue
		}
		switch am.Mode {
		case csi.VolumeCapability_AccessMode_UNKNOWN:
			supported = false
			reason = ErrUnknownAccessMode
		// SINGLE_NODE_WRITER to be deprecated in future
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_SINGLE_WRITER,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_MULTI_WRITER,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY,
			csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY:
			// supported, no action needed
		case csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER,
			csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER:
			if !isBlock {
				supported = false
				reason = ErrNoMultiNodeWriter
			}
		default:
			// This is to guard against new access modes not understood
			supported = false
			reason = ErrUnknownAccessMode
		}
	}
	// for sanity
	id := req.GetVolumeId()
	volumeHandle, err := array.ParseVolumeID(ctx, id, s.DefaultArray(), nil)
	if err != nil {
		return &csi.ValidateVolumeCapabilitiesResponse{}, status.Error(codes.NotFound, "No such volume")
	}

	id = volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	proto := volumeHandle.Protocol

	if proto == "nfs" {
		_, err := s.Arrays()[arrayID].Client.GetFS(ctx, id)
		if err != nil {
			return &csi.ValidateVolumeCapabilitiesResponse{
				Confirmed: nil,
				Message:   "Failed to get volume",
			}, status.Error(codes.NotFound, "Failed to get volume")
		}
	} else {
		_, err := s.Arrays()[arrayID].Client.GetVolume(ctx, id)
		if err != nil {
			return &csi.ValidateVolumeCapabilitiesResponse{
				Confirmed: nil,
				Message:   "Failed to get volume",
			}, status.Error(codes.NotFound, "Failed to get volume")
		}

	}

	if supported {
		return &csi.ValidateVolumeCapabilitiesResponse{
			Confirmed: &csi.ValidateVolumeCapabilitiesResponse_Confirmed{
				VolumeContext:      req.VolumeContext,
				VolumeCapabilities: req.VolumeCapabilities,
				Parameters:         req.Parameters,
			},
			Message: reason,
		}, nil
	}
	return &csi.ValidateVolumeCapabilitiesResponse{
		Confirmed: nil,
		Message:   reason,
	}, status.Error(codes.Internal, reason)
}

// ListVolumes returns all accessible volumes from the storage array.
func (s *Service) ListVolumes(ctx context.Context, req *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error) {
	var (
		startToken int
		maxEntries = int(req.GetMaxEntries())
	)

	if v := req.GetStartingToken(); v != "" {
		i, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, status.Errorf(codes.Aborted, "unable to parse StartingToken: %v into uint32", v)
		}
		startToken = int(i)
	}

	// Call the common listVolumes code
	entries, nextToken, err := s.listPowerStoreVolumes(ctx, startToken, maxEntries)
	if err != nil {
		return nil, err
	}

	return &csi.ListVolumesResponse{
		Entries:   entries,
		NextToken: nextToken,
	}, nil
}

// GetCapacity returns available capacity for a storage array.
func (s *Service) GetCapacity(ctx context.Context, req *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error) {
	params := req.GetParameters()

	// Get array from map
	arrayID, ok := params[identifiers.KeyArrayID]

	var arr *array.PowerStoreArray
	// If no ArrayIP was provided in storage class we just use default array
	if !ok {
		arr = s.DefaultArray()
	} else {
		arr, ok = s.Arrays()[arrayID]
		if !ok {
			return nil, status.Errorf(codes.Internal, "can't find array with provided id %s", arrayID)
		}
	}
	capacity, err := arr.Client.GetCapacity(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	maxVolSize := getMaximumVolumeSize(ctx, arr)
	if maxVolSize < 0 {
		return &csi.GetCapacityResponse{
			AvailableCapacity: capacity,
		}, nil
	}
	maxVol := wrapperspb.Int64(maxVolSize)
	return &csi.GetCapacityResponse{
		AvailableCapacity: capacity,
		MaximumVolumeSize: maxVol,
	}, nil
}

func getMaximumVolumeSize(ctx context.Context, arr *array.PowerStoreArray) int64 {
	valueInCache, found := getCachedMaximumVolumeSize(arr.GlobalID)
	if !found || valueInCache < 0 {
		defaultHeaders := arr.Client.GetCustomHTTPHeaders()
		if defaultHeaders == nil {
			defaultHeaders = api.NewSafeHeader().GetHeader()
		}
		customHeaders := defaultHeaders
		customHeaders.Add("DELL-VISIBILITY", "internal")
		arr.Client.SetCustomHTTPHeaders(customHeaders)

		value, err := arr.Client.GetMaxVolumeSize(ctx)
		if err != nil {
			log.WithContext(ctx).Debug(fmt.Sprintf("GetMaxVolumeSize returning: %v for Array having GlobalId %s", err, arr.GlobalID))
		}
		// reset custom header
		customHeaders.Del("DELL-VISIBILITY")
		arr.Client.SetCustomHTTPHeaders(customHeaders)
		// Add a new entry to the MaximumVolumeSize
		cacheMaximumVolumeSize(arr.GlobalID, value)
		valueInCache = value
	}
	return valueInCache
}

func getCachedMaximumVolumeSize(key string) (int64, bool) {
	mutex.Lock()
	defer mutex.Unlock()

	value, found := maxVolumesSizeForArray[key]
	return value, found
}

func cacheMaximumVolumeSize(key string, value int64) {
	mutex.Lock()
	defer mutex.Unlock()

	maxVolumesSizeForArray[key] = value
}

// ControllerGetCapabilities returns list of capabilities that are supported by the driver.
func (s *Service) ControllerGetCapabilities(_ context.Context, _ *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	newCap := func(capability csi.ControllerServiceCapability_RPC_Type) *csi.ControllerServiceCapability {
		return &csi.ControllerServiceCapability{
			Type: &csi.ControllerServiceCapability_Rpc{
				Rpc: &csi.ControllerServiceCapability_RPC{
					Type: capability,
				},
			},
		}
	}

	var capabilities []*csi.ControllerServiceCapability
	for _, capability := range []csi.ControllerServiceCapability_RPC_Type{
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
		csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME,
		csi.ControllerServiceCapability_RPC_GET_CAPACITY,
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_SNAPSHOT,
		csi.ControllerServiceCapability_RPC_LIST_SNAPSHOTS,
		csi.ControllerServiceCapability_RPC_CLONE_VOLUME,
		csi.ControllerServiceCapability_RPC_EXPAND_VOLUME,
		csi.ControllerServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
		csi.ControllerServiceCapability_RPC_MODIFY_VOLUME,
	} {
		capabilities = append(capabilities, newCap(capability))
	}

	if s.isHealthMonitorEnabled {
		for _, capability := range []csi.ControllerServiceCapability_RPC_Type{
			csi.ControllerServiceCapability_RPC_GET_VOLUME,
			csi.ControllerServiceCapability_RPC_LIST_VOLUMES,
			csi.ControllerServiceCapability_RPC_LIST_VOLUMES_PUBLISHED_NODES,
			csi.ControllerServiceCapability_RPC_VOLUME_CONDITION,
		} {
			capabilities = append(capabilities, newCap(capability))
		}
	}

	return &csi.ControllerGetCapabilitiesResponse{
		Capabilities: capabilities,
	}, nil
}

// CreateSnapshot creates a snapshot of the Volume or FileSystem.
func (s *Service) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	snapName := req.GetName()
	if err := volumeNameValidation(snapName); err != nil {
		return nil, err
	}

	// Validate snapshot volume sourceVolID
	sourceVolID := req.GetSourceVolumeId()
	if sourceVolID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "volume ID to be snapped is required")
	}

	volumeHandle, err := array.ParseVolumeID(ctx, sourceVolID, s.DefaultArray(), nil)
	if err != nil {
		return nil, err
	}

	id := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given ID")
	}

	var snapshotter VolumeSnapshotter
	var sourceVolumeSize int64

	if protocol == "nfs" {
		f, err := arr.GetClient().GetFS(ctx, id)
		if err == nil {
			sourceVolumeSize = f.SizeTotal - ReservedSize
		} else {
			return &csi.CreateSnapshotResponse{}, status.Errorf(codes.Internal,
				"can't find source volume '%s': %s", id, err.Error())
		}
		snapshotter = &NfsSnapshotter{}
	} else {
		f, err := arr.GetClient().GetVolume(ctx, id)
		if err == nil {
			sourceVolumeSize = f.Size
		} else {
			return &csi.CreateSnapshotResponse{}, status.Errorf(codes.Internal,
				"can't find source volume '%s': %s", id, err.Error())
		}
		snapshotter = &SCSISnapshotter{}
	}

	var snapResponse *csi.Snapshot

	// Check if snapshot with provided name already exists but has a different source volume id
	existingSnapshot, err := snapshotter.GetExistingSnapshot(ctx, snapName, arr.GetClient())
	if err == nil {
		if existingSnapshot.GetSourceID() != id {
			return nil, status.Errorf(codes.AlreadyExists,
				"snapshot with name '%s' exists, but SourceVolumeId %s doesn't match", snapName, id)
		}
		snapResponse = getCSISnapshot(existingSnapshot.GetID(), id, existingSnapshot.GetSize())
	} else {
		resp, err := snapshotter.Create(ctx, snapName, id, arr.GetClient())
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.SnapshotNameIsAlreadyUse() {
				existingSnapshot, err := snapshotter.GetExistingSnapshot(ctx, snapName, arr.GetClient())
				if err != nil {
					return nil, err
				}
				snapResponse = getCSISnapshot(existingSnapshot.GetID(), id, existingSnapshot.GetSize())
			} else {
				return nil, status.Error(codes.Internal, err.Error())
			}
		} else {
			snapResponse = getCSISnapshot(resp.ID, id, sourceVolumeSize)
		}
	}

	snapResponse.SnapshotId = snapResponse.SnapshotId + "/" + arrayID + "/" + protocol
	return &csi.CreateSnapshotResponse{
		Snapshot: snapResponse,
	}, nil
}

// DeleteSnapshot deletes a snapshot of the Volume or FileSystem.
func (s *Service) DeleteSnapshot(ctx context.Context, req *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	snapID := req.GetSnapshotId()
	if snapID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "snapshot ID to be deleted is required")
	}

	volumeHandle, err := array.ParseVolumeID(ctx, snapID, s.DefaultArray(), nil)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			return &csi.DeleteSnapshotResponse{}, nil
		}
		return nil, err
	}

	id := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given ID")
	}

	if protocol == "nfs" {
		_, err = arr.GetClient().GetFsSnapshot(ctx, id)
		if err == nil {
			_, err := arr.GetClient().DeleteFsSnapshot(ctx, id)
			if err == nil {
				return &csi.DeleteSnapshotResponse{}, nil
			}
			if apiError, ok := err.(gopowerstore.APIError); ok {
				if apiError.NotFound() {
					return &csi.DeleteSnapshotResponse{}, nil
				}
			}
			return nil, err
		}
	} else {
		snap, err := arr.GetClient().GetSnapshot(ctx, id)
		if err == nil {
			// we will check whether this snapshot is a part of volume group snapshot, if yes then we will delete the volume group snapshot
			vgs, err := arr.GetClient().GetVolumeGroupsByVolumeID(ctx, snap.ID)
			if len(vgs.VolumeGroup) != 0 && err == nil { // This means this snap is a part of VGS
				_, err = arr.GetClient().DeleteVolumeGroup(ctx, vgs.VolumeGroup[0].ID)
				if err == nil {
					return &csi.DeleteSnapshotResponse{}, nil
				}
			}
			_, err = arr.GetClient().DeleteSnapshot(ctx, nil, id)
			if err == nil {
				return &csi.DeleteSnapshotResponse{}, nil
			}
			if apiError, ok := err.(gopowerstore.APIError); ok {
				if apiError.NotFound() {
					return &csi.DeleteSnapshotResponse{}, nil
				}
			}
			return nil, err
		}
	}

	if apiError, ok := err.(gopowerstore.APIError); ok {
		if apiError.NotFound() {
			return &csi.DeleteSnapshotResponse{}, nil
		}
	}
	return nil, err
}

// ListSnapshots list all accessible snapshots from the storage array.
func (s *Service) ListSnapshots(ctx context.Context, req *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	var (
		startToken  int
		maxEntries  = int(req.GetMaxEntries())
		snapshotID  string
		sourceVolID string
	)

	if req.SnapshotId != "" {
		snapshotID = req.SnapshotId
	}

	if req.SourceVolumeId != "" {
		sourceVolID = req.SourceVolumeId
	}

	if v := req.GetStartingToken(); v != "" {
		i, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, status.Errorf(codes.Aborted, "unable to parse StartingToken: %v into uint32", v)
		}
		startToken = int(i)
	}
	// Call the common listVolumes code
	source, nextToken, err := s.listPowerStoreSnapshots(ctx, startToken, maxEntries, snapshotID, sourceVolID)
	if err != nil {
		return nil, err
	}
	if len(source) == 0 {
		return &csi.ListSnapshotsResponse{}, nil
	}

	// Process the source volumes and make CSI Volumes
	entries := make([]*csi.ListSnapshotsResponse_Entry, len(source))
	for i, snap := range source {
		size := snap.GetSize()
		// Correct size of filesystem snapshot
		if snap.GetType() == FilesystemSnapshotType {
			size = size - ReservedSize
		}
		entries[i] = &csi.ListSnapshotsResponse_Entry{
			Snapshot: getCSISnapshot(snap.GetID(), snap.GetSourceID(), size),
		}
	}

	return &csi.ListSnapshotsResponse{
		Entries:   entries,
		NextToken: nextToken,
	}, nil
}

// return the local and remote array IDs from the source Metro volume
func getLocalAndRemoteArrays(volumeHandle array.VolumeHandle, s *Service) (*array.PowerStoreArray, *array.PowerStoreArray, error) {
	localArray, ok := s.Arrays()[volumeHandle.LocalArrayGlobalID]
	if !ok {
		return nil, nil, fmt.Errorf("local array %s not found", volumeHandle.LocalArrayGlobalID)
	}

	remoteArray, ok := s.Arrays()[volumeHandle.RemoteArrayGlobalID]
	if !ok {
		return nil, nil, fmt.Errorf("remote array %s not found", volumeHandle.RemoteArrayGlobalID)
	}

	return localArray, remoteArray, nil
}

// selectMetroArrayForClone resolves the local and remote arrays from the volume handle
// and delegates to array.SelectMetroArrayForClone to select the optimal array for cloning.
func selectMetroArrayForClone(ctx context.Context, arr *array.PowerStoreArray,
	remoteSystemName string, scArr1 string, volumeHandle array.VolumeHandle, s *Service,
) (*array.PowerStoreArray, *gopowerstore.ReplicationSession, error) {
	// Non-Metro SC: the target StorageClass has no replication parameters.
	// Validate scArr1 (the SC arrayID) directly against the Metro source arrays — no remote
	// system lookup is needed. Clone from the matched array after checking its state.
	if remoteSystemName == "" {
		if scArr1 != volumeHandle.LocalArrayGlobalID && scArr1 != volumeHandle.RemoteArrayGlobalID {
			return nil, nil, status.Errorf(codes.InvalidArgument, "No matching arrays in the storage class")
		}
		localArray, remoteArray, err := getLocalAndRemoteArrays(volumeHandle, s)
		if err != nil {
			return nil, nil, err
		}
		var arrToCloneFrom *array.PowerStoreArray
		var arrToCloneFromUUID string
		if scArr1 == volumeHandle.LocalArrayGlobalID {
			arrToCloneFrom = localArray
			arrToCloneFromUUID = volumeHandle.LocalUUID
		} else {
			arrToCloneFrom = remoteArray
			arrToCloneFromUUID = volumeHandle.RemoteUUID
		}
		ctxArr, cancelArr := context.WithTimeout(ctx, array.ShortTimeout)
		defer cancelArr()
		sourceVol, err := arrToCloneFrom.GetClient().GetVolume(ctxArr, arrToCloneFromUUID)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get source volume from array")
		}
		if sourceVol.MetroReplicationSessionID == "" {
			return nil, nil, fmt.Errorf("source volume is not a metro volume")
		}
		session, err := array.DetermineIfArrayCanClone(ctx, sourceVol.MetroReplicationSessionID, arrToCloneFrom)
		return arrToCloneFrom, session, err
	}

	// Metro SC path: obtain the arrayID of the remoteSystem, use shortTimeout
	ctxRemoteSystem, cancelRemoteSystem := context.WithTimeout(ctx, array.ShortTimeout)
	defer cancelRemoteSystem()
	remoteSystem, err := arr.Client.GetRemoteSystemByName(ctxRemoteSystem, remoteSystemName)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "can't query remote system by name: %v", err)
	}
	scArr2 := remoteSystem.SerialNumber

	// General Validation:
	//  If no sc Array matches either volumeHandle arrays, (no match)
	//    fail
	//  else if scArrayA matches one of them and scArray2 matches the other one (both match)
	//    then clone from the best one (current code)
	//  else if scArrayA matches one volumeHandle arrays (one match)
	//    clone from scArrayA, enable metro on the array that is shared i.e. A-B B-C enable metro on B
	//  else // scArrayB matches one volumeHandle arrays (one match)
	//    clone from scArrayB, enable metro on the array that is shared i.e. A-B B-C enable metro on B

	// if no sc array matches then fail
	if (scArr1 != volumeHandle.LocalArrayGlobalID && scArr1 != volumeHandle.RemoteArrayGlobalID) &&
		(scArr2 != volumeHandle.LocalArrayGlobalID && scArr2 != volumeHandle.RemoteArrayGlobalID) {
		// fail
		return nil, nil, status.Errorf(codes.InvalidArgument, "No matching arrays in the storage class")
	}

	localArray, remoteArray, err := getLocalAndRemoteArrays(volumeHandle, s)
	if err != nil {
		return nil, nil, err
	}

	// if both source volume arrays match the arrays from the sc, pick the best one to clone from
	if (scArr1 == volumeHandle.LocalArrayGlobalID || scArr1 == volumeHandle.RemoteArrayGlobalID) &&
		(scArr2 == volumeHandle.LocalArrayGlobalID || scArr2 == volumeHandle.RemoteArrayGlobalID) {
		// Get the metro replication session ID from the source volume
		// Try local array first, fallback to remote array if local is offline
		// NOTE: Use separate child contexts with scoped timeouts to prevent the local array
		// call from consuming the entire parent CSI timeout before reaching the remote fallback
		ctxLocal, cancelLocal := context.WithTimeout(ctx, array.ShortTimeout)
		defer cancelLocal()
		sourceVol, err := localArray.GetClient().GetVolume(ctxLocal, volumeHandle.LocalUUID)
		if err != nil {
			log.Warnf("Unable to get volume from local array: %v, trying remote array", err)
			// We should not query localArray again, since it's either unreachable or has no knowledge of the volume
			localArray = nil

			ctxRemote, cancelRemote := context.WithTimeout(ctx, array.ShortTimeout)
			defer cancelRemote()
			sourceVol, err = remoteArray.GetClient().GetVolume(ctxRemote, volumeHandle.RemoteUUID)
			if err != nil {
				log.Errorf("Unable to get volume from remote array: %v", err)
				return nil, nil, fmt.Errorf("unable to get source volume from either local or remote array")
			}
		}

		if sourceVol.MetroReplicationSessionID == "" {
			return nil, nil, fmt.Errorf("source volume is not a metro volume")
		}

		return array.SelectMetroArrayForClone(ctx, sourceVol.MetroReplicationSessionID, localArray, remoteArray)
	}

	// If only one of the arrays match then clone from the matched array only, check if it is
	// online and has a Data Transfer state == Active/Active OR
	// LocalResourceState == Promoted/FromPromoted

	var arrToCloneFrom *array.PowerStoreArray
	var arrToCloneFromUUID string

	if (volumeHandle.LocalArrayGlobalID == scArr1) || (volumeHandle.LocalArrayGlobalID == scArr2) {
		// clone from local Array
		arrToCloneFrom = localArray
		arrToCloneFromUUID = volumeHandle.LocalUUID
	} else if (volumeHandle.RemoteArrayGlobalID == scArr1) || (volumeHandle.RemoteArrayGlobalID == scArr2) {
		// clone from remote array
		arrToCloneFrom = remoteArray
		arrToCloneFromUUID = volumeHandle.RemoteUUID
	}
	ctxOneArr, cancelOneArr := context.WithTimeout(ctx, array.ShortTimeout)
	defer cancelOneArr()
	sourceVol, err := arrToCloneFrom.GetClient().GetVolume(ctxOneArr, arrToCloneFromUUID)
	if err != nil {
		log.Errorf("Unable to get volume from array: %v", err)
		return nil, nil, fmt.Errorf("unable to get source volume from array")
	}
	if sourceVol.MetroReplicationSessionID == "" {
		return nil, nil, fmt.Errorf("source volume is not a metro volume")
	}
	session, err := array.DetermineIfArrayCanClone(ctx, sourceVol.MetroReplicationSessionID, arrToCloneFrom)
	return arrToCloneFrom, session, err
}

func GetMetroSessionState(ctx context.Context, metroSessionID string, arr *array.PowerStoreArray) (gopowerstore.RSStateEnum, error) {
	metroSession, err := arr.Client.GetReplicationSessionByID(ctx, metroSessionID)
	if err != nil {
		return "", fmt.Errorf("could not get metro replication session %s: %w", metroSessionID, err)
	}
	return metroSession.State, nil
}

// ControllerExpandVolume resizes Volume or FileSystem by increasing available volume capacity in the storage array.
func (s *Service) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	startTime := time.Now()

	volumeHandle, err := array.ParseVolumeID(ctx, req.VolumeId, s.DefaultArray(), nil)
	if err != nil {
		return nil, status.Errorf(codes.OutOfRange, "unable to parse the volume id")
	}

	id := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol
	remoteVolumeID := volumeHandle.RemoteUUID

	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "controller",
		log.FieldOperation: "ControllerExpandVolume",
		log.FieldVolumeID:  id,
		log.FieldProtocol:  protocol,
		log.FieldArrayID:   arrayID,
	}).Info("starting volume expansion")

	requiredBytes := req.GetCapacityRange().GetRequiredBytes()
	if requiredBytes > MaxVolumeSizeBytes {
		return nil, status.Errorf(codes.OutOfRange, "volume exceeds allowed limit")
	}

	localArr, ok := s.Arrays()[arrayID]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unable to find array with ID %s", arrayID)
	}
	client := localArr.Client

	if protocol == "scsi" {
		vol, err := client.GetVolume(ctx, id)
		if err != nil {
			return nil, status.Error(codes.NotFound, "detected SCSI protocol but wasn't able to fetch the volume info")
		}

		isMetro := remoteVolumeID != ""
		if isMetro && vol.MetroReplicationSessionID == "" {
			return nil, status.Errorf(codes.Internal,
				"failed to expand the volume %s because the metro replication session ID is empty for metro volume", vol.Name)
		}

		if vol.Size < requiredBytes {
			expandClient := client
			expandID := id

			if isMetro {
				// Log PowerStore version for observability
				majorMinorVersion, vErr := client.GetSoftwareMajorMinorVersion(ctx)
				if vErr != nil {
					log.WithContext(ctx).Warnf("[METRO EXPAND] Volume %q: Failed to determine PowerStore version: %v", vol.Name, vErr)
				} else {
					log.WithContext(ctx).Infof("[METRO EXPAND] Volume %q: PowerStore version %.1f detected", vol.Name, majorMinorVersion)
				}

				// Always use site selection to expand on the Metro_Preferred + online array.
				// Even PowerStore 5.0+ requires expanding from the preferred site.
				remoteArrayID := volumeHandle.RemoteArrayGlobalID
				remoteArray, rErr := s.GetOneArray(remoteArrayID)
				if rErr != nil {
					return nil, status.Errorf(codes.Internal,
						"failed to retrieve remote array %s for metro volume %q expansion: %v", remoteArrayID, vol.Name, rErr)
				}

				log.WithContext(ctx).Debugf("[METRO EXPAND] Volume %q: Selecting preferred array between local %s and remote %s for expansion",
					vol.Name, localArr.GetGlobalID(), remoteArrayID)

				selectedArray, selectedSession, sErr := array.SelectMetroArrayForExpansion(ctx, vol.MetroReplicationSessionID, localArr, remoteArray)
				if sErr != nil {
					return nil, status.Errorf(codes.Internal,
						"failed to select expansion target for metro volume %q: %v", vol.Name, sErr)
				}

				expandClient = selectedArray.GetClient()
				expandID = selectedSession.LocalResourceID
				log.WithContext(ctx).Infof("[METRO EXPAND] Volume %q: Selected array %s (Metro_Preferred) for expansion", vol.Name, selectedArray.GetGlobalID())
			}

			_, err = expandClient.ModifyVolume(context.Background(), &gopowerstore.VolumeModify{Size: requiredBytes}, expandID)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "unable to modify volume size: %s", err.Error())
			}
			log.WithContext(ctx).WithFields(log.Fields{
				log.FieldComponent:  "controller",
				log.FieldOperation:  "ControllerExpandVolume",
				log.FieldVolumeID:   id,
				log.FieldProtocol:   protocol,
				log.FieldArrayID:    arrayID,
				log.FieldDurationMs: time.Since(startTime).Milliseconds(),
			}).Info("SCSI volume expanded successfully")
			return &csi.ControllerExpandVolumeResponse{CapacityBytes: requiredBytes, NodeExpansionRequired: true}, nil
		}

		// Idempotent case: volume already at or above required size
		// Return actual current size — never return 0
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent:  "controller",
			log.FieldOperation:  "ControllerExpandVolume",
			log.FieldVolumeID:   id,
			log.FieldProtocol:   protocol,
			log.FieldArrayID:    arrayID,
			log.FieldDurationMs: time.Since(startTime).Milliseconds(),
		}).Info("SCSI volume already at required size")
		return &csi.ControllerExpandVolumeResponse{CapacityBytes: vol.Size, NodeExpansionRequired: true}, nil
	}

	fs, err := client.GetFS(ctx, id)
	if err == nil {
		if fs.SizeTotal < requiredBytes {
			_, err = client.ModifyFS(context.Background(), &gopowerstore.FSModify{Size: int(requiredBytes + ReservedSize)}, id)
			if err != nil {
				return nil, err
			}
		}
	}
	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent:  "controller",
		log.FieldOperation:  "ControllerExpandVolume",
		log.FieldVolumeID:   id,
		log.FieldProtocol:   protocol,
		log.FieldArrayID:    arrayID,
		log.FieldDurationMs: time.Since(startTime).Milliseconds(),
	}).Info("NFS volume expansion completed")
	return &csi.ControllerExpandVolumeResponse{CapacityBytes: requiredBytes, NodeExpansionRequired: false}, nil
}

// ControllerGetVolume fetch current information about a volume
func (s *Service) ControllerGetVolume(ctx context.Context, req *csi.ControllerGetVolumeRequest) (*csi.ControllerGetVolumeResponse, error) {
	volumeHandle, err := array.ParseVolumeID(ctx, req.VolumeId, s.DefaultArray(), nil)
	if err != nil {
		return nil, status.Errorf(codes.OutOfRange, "unable to parse the volume id")
	}

	id := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	protocol := volumeHandle.Protocol

	var hosts []string
	abnormal := false
	message := ""
	if protocol == "nfs" {
		// check if filesystem exists
		fs, err := s.Arrays()[arrayID].Client.GetFS(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.NotFound, "failed to find filesystem %s with error: %v", id, err.Error())
			}
			abnormal = true
			message = fmt.Sprintf("Filesystem %s is not found", id)
		} else {
			// get exports for filesystem if exists
			nfsExport, err := s.Arrays()[arrayID].Client.GetNFSExportByFileSystemID(ctx, fs.ID)
			if err != nil {
				if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
					return nil, status.Errorf(codes.NotFound, "failed to find nfs export for filesystem with error: %v", err.Error())
				}
			} else {
				// get hosts publish to export
				hosts = append(nfsExport.ROHosts, nfsExport.RORootHosts...)
				hosts = append(hosts, nfsExport.RWHosts...)
				hosts = append(hosts, nfsExport.RWRootHosts...)
			}
		}
	} else {
		// check if volume exists
		vol, err := s.Arrays()[arrayID].Client.GetVolume(ctx, id)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.NotFound, "failed to find volume %s with error: %v", id, err.Error())
			}
			abnormal = true
			message = fmt.Sprintf("Volume %s is not found", id)
		} else {
			// get hosts published to volume
			hostMappings, err := s.Arrays()[arrayID].Client.GetHostVolumeMappingByVolumeID(ctx, id)
			if err != nil {
				return nil, status.Errorf(codes.NotFound, "failed to get host volume mapping for volume: %s with error: %v", id, err.Error())
			}
			for _, hostMapping := range hostMappings {
				host, err := s.Arrays()[arrayID].Client.GetHost(ctx, hostMapping.HostID)
				if err != nil {
					if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
						return nil, status.Errorf(codes.NotFound, "failed to get host: %s with error: %v", hostMapping.HostID, err.Error())
					}
				} else {
					hosts = append(hosts, host.Name)
				}
			}
			// check if volume is in ready state
			if vol.State != gopowerstore.VolumeStateEnumReady {
				abnormal = true
				message = fmt.Sprintf("Volume %s is in %s state", id, string(vol.State))
			}
		}
	}

	resp := &csi.ControllerGetVolumeResponse{
		Volume: &csi.Volume{
			VolumeId: id,
		},
		Status: &csi.ControllerGetVolumeResponse_VolumeStatus{
			PublishedNodeIds: hosts,
			VolumeCondition: &csi.VolumeCondition{
				Abnormal: abnormal,
				Message:  message,
			},
		},
	}
	return resp, nil
}

// RegisterAdditionalServers registers replication, podmon, and snapshot metadata extensions
func (s *Service) RegisterAdditionalServers(server *grpc.Server) {
	// In node mode, the controller service (s) is nil, so we need to check before accessing it
	if s == nil {
		log.Info("Controller service is nil (node mode), skipping additional server registration")
		return
	}

	csiext.RegisterReplicationServer(server, s)
	podmon.RegisterPodmonServer(server, s)
	csi.RegisterSnapshotMetadataServer(server, &snapshotMetadataServer{})

	// Register CSI-Addons servers if enabled
	if s.IsCSIAddonsReplicationEnabled {
		// Register CSI-Addons Identity server (required for sidecar probing)
		identityServer := NewCSIAddonsIdentityServer(s)
		RegisterCSIAddonsIdentityServer(server, identityServer)
		log.Info("CSI-Addons identity server registered")

		// Register CSI-Addons Replication server
		csiAddonsServer := NewCSIAddonsReplicationServer(s)
		RegisterCSIAddonsReplicationServer(server, csiAddonsServer)
		log.Info("CSI-Addons replication server registered")

		// Register CSI-Addons VolumeGroup server
		volumeGroupServer := NewCSIAddonsVolumeGroupServer(s)
		volumegrouprpc.RegisterControllerServer(server, volumeGroupServer)
		log.Info("CSI-Addons volumegroup controller server registered")
	}
}

// ProbeController probes the controller service
func (s *Service) ProbeController(ctx context.Context, _ *commonext.ProbeControllerRequest) (*commonext.ProbeControllerResponse, error) {
	ready := new(wrapperspb.BoolValue)
	ready.Value = true
	rep := new(commonext.ProbeControllerResponse)
	rep.Ready = ready
	rep.Name = identifiers.Name
	rep.VendorVersion = identifiers.ManifestSemver
	identifiers.Manifest["semver"] = identifiers.ManifestSemver
	rep.Manifest = identifiers.Manifest

	log.WithContext(ctx).Debug(fmt.Sprintf("ProbeController returning: %v", rep.Ready.GetValue()))
	return rep, nil
}

func (s *Service) listPowerStoreVolumes(ctx context.Context, startToken, maxEntries int) ([]*csi.ListVolumesResponse_Entry, string, error) {
	var volResponse []*csi.ListVolumesResponse_Entry

	// Pre-fetch host-volume mappings and hosts for every array to avoid numerous API calls
	mappingsByArray := make(map[string][]gopowerstore.HostVolumeMapping)
	hostnamesByArray := make(map[string]map[string]string) // arrayID -> hostID -> hostName

	for arrayID, arr := range s.Arrays() {
		log.Debugf("ListVolumes: getting host-volume mappings for array %s", arrayID)
		maps, err := arr.GetClient().GetHostVolumeMappings(ctx)
		if err != nil {
			log.Warnf("ListVolumes: failed to fetch host-volume mappings for array %s: %v", arrayID, err)
			continue
		}
		mappingsByArray[arrayID] = maps

		log.Debugf("ListVolumes: getting hosts for array %s", arrayID)
		hosts, err := arr.GetClient().GetHosts(ctx)
		if err != nil {
			log.Warnf("ListVolumes: failed to fetch hosts for array %s: %v", arrayID, err)
			continue
		}

		hostnamesByID := make(map[string]string, len(hosts))
		for _, host := range hosts {
			if host.Name != "" {
				hostnamesByID[host.ID] = host.Name
			}
		}
		hostnamesByArray[arrayID] = hostnamesByID
	}

	// ---------------------------
	// Block Volumes (SCSI)
	// ---------------------------
	for arrayID, arr := range s.Arrays() {
		log.Debugf("ListVolumes: getting block volumes for array %s", arrayID)
		vols, err := arr.GetClient().GetVolumes(ctx)
		if err != nil {
			return nil, "", status.Errorf(codes.Internal, "unable to list volumes: %s", err.Error())
		}

		// for each volume build CSI-style volume id and populate published node ids
		hostVolumeMapping, ok := mappingsByArray[arrayID]
		if !ok {
			log.Warnf("ListVolumes: no host-volume mappings found for array %s", arrayID)
			continue
		}
		hostMap, ok := hostnamesByArray[arrayID]
		if !ok {
			log.Warnf("ListVolumes: no hosts found for array %s", arrayID)
			continue
		}
		for _, vol := range vols {
			// build CSI volumeID so it matches PV.spec.csi.volumeHandle
			// format: "<volumeGUID>/<arrayID>/scsi"
			fullVolumeID := fmt.Sprintf("%s/%s/scsi", vol.ID, arrayID)

			entry := &csi.ListVolumesResponse_Entry{
				Volume: &csi.Volume{
					CapacityBytes: int64(vol.Size),
					VolumeId:      fullVolumeID,
				},
			}

			// Populate PublishedNodeIds from host_volume_mapping -> host -> host.Name
			var nodes []string
			for _, mapping := range hostVolumeMapping {
				if mapping.VolumeID == vol.ID && mapping.HostID != "" {
					if name, ok := hostMap[mapping.HostID]; ok && name != "" {
						nodes = append(nodes, name)
					}
				}
			}
			if len(nodes) > 0 {
				entry.Status = &csi.ListVolumesResponse_VolumeStatus{
					PublishedNodeIds: nodes,
				}
			}
			volResponse = append(volResponse, entry)
		}
	}

	// ---------------------------
	// FileSystems (NFS)
	// ---------------------------
	for arrayID, arr := range s.Arrays() {
		log.Debugf("ListVolumes: getting filesystems for array %s", arrayID)
		fsList, err := arr.GetClient().ListFS(ctx)
		if err != nil {
			return nil, "", status.Errorf(codes.Internal, "unable to list filesystems: %s", err.Error())
		}
		for _, fs := range fsList {
			// NFS volumeID format: "<fsGUID>/<arrayID>/nfs"
			fullVolumeID := fmt.Sprintf("%s/%s/nfs", fs.ID, arrayID)
			entry := &csi.ListVolumesResponse_Entry{
				Volume: &csi.Volume{
					CapacityBytes: int64(fs.SizeTotal),
					VolumeId:      fullVolumeID,
				},
			}
			// NFS does not have host mappings in the same way: leaving Status nil is fine
			volResponse = append(volResponse, entry)
		}
	}

	if startToken > len(volResponse) {
		return nil, "", status.Errorf(codes.Aborted, "startingToken=%d > len(volumes)=%d", startToken, len(volResponse))
	}

	remaining := len(volResponse) - startToken

	if maxEntries == 0 || maxEntries > remaining {
		maxEntries = remaining
	}

	// Cap the number of entries returned in a single response.
	// This prevents extremely large CSI responses, which can increase memory usage
	// and impact ListVolumes performance on clusters with many volumes.
	if maxEntries > 700 {
		maxEntries = 700
	}

	nextToken := startToken + maxEntries
	nextTokenStr := ""
	if nextToken < len(volResponse) {
		nextTokenStr = fmt.Sprintf("%d", nextToken)
	}
	log.Debugf("ListVolumes: returning %d volumes", len(volResponse[startToken:nextToken]))

	return volResponse[startToken:nextToken], nextTokenStr, nil
}

func (s *Service) listPowerStoreSnapshots(ctx context.Context, startToken, maxEntries int, snapID, srcID string) ([]GeneralSnapshot, string, error) {
	var generalSnapshots []GeneralSnapshot

	if snapID == "" && srcID == "" {
		log.WithContext(ctx).Info("Requested all snapshots, iterating through arrays")
		for _, arr := range s.Arrays() {
			// List block snapshots
			snaps, err := arr.GetClient().GetSnapshots(ctx)
			if err != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to list block snapshots: %s", err.Error())
			}

			for _, snap := range snaps {
				generalSnapshots = append(generalSnapshots, VolumeSnapshot(snap))
			}

			// List filesystem snapshots too
			fsSnaps, err := arr.GetClient().GetFsSnapshots(ctx)
			if err != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to list filesystem snapshots: %s", err.Error())
			}

			for _, snap := range fsSnaps {
				generalSnapshots = append(generalSnapshots, FilesystemSnapshot(snap))
			}
		}
	} else if snapID != "" {
		log.WithContext(ctx).Infof("Requested snapshot via snapshot id %s", snapID)
		volumeHandle, err := array.ParseVolumeID(ctx, snapID, s.DefaultArray(), nil)
		if err != nil {
			log.WithContext(ctx).Error(err.Error())
			return []GeneralSnapshot{}, "", nil
		}

		id := volumeHandle.LocalUUID
		arrayID := volumeHandle.LocalArrayGlobalID
		protocol := volumeHandle.Protocol

		arr, ok := s.Arrays()[arrayID]
		if !ok {
			return nil, "", status.Errorf(codes.Internal, "unable to get array with arrayID %s", arrayID)
		}

		if protocol == "nfs" {
			fsSnapshot, getErr := arr.GetClient().GetFsSnapshot(ctx, id)
			if apiError, ok := getErr.(gopowerstore.APIError); ok && apiError.NotFound() {
				// given snapshot id does not exist, should return empty response
				return generalSnapshots, "", nil
			}
			if getErr != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to get filesystem snapshot: %s", getErr.Error())
			}

			log.WithContext(ctx).Infof("%+v", fsSnapshot)

			fsSnapshot.ID = fsSnapshot.ID + "/" + arrayID + "/" + protocol
			generalSnapshots = append(generalSnapshots, FilesystemSnapshot(fsSnapshot))
		} else {
			blockSnap, getErr := arr.GetClient().GetSnapshot(ctx, id)
			if apiError, ok := getErr.(gopowerstore.APIError); ok && apiError.NotFound() {
				// given snapshot id does not exist, should return empty response
				return generalSnapshots, "", nil
			}
			if getErr != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to get block snapshot: %s", getErr.Error())
			}
			blockSnap.ID = blockSnap.ID + "/" + arrayID + "/" + protocol
			generalSnapshots = append(generalSnapshots, VolumeSnapshot(blockSnap))
		}
	} else {
		log.WithContext(ctx).Infof("Requested snapshot via source id %s", srcID)
		// This works VGS on single default array, But for multiple array scenario this default array should be changed to dynamic array
		volumeHandle, err := array.ParseVolumeID(ctx, srcID, s.DefaultArray(), nil)
		if err != nil {
			log.WithContext(ctx).Error(err.Error())
			return []GeneralSnapshot{}, "", nil
		}

		id := volumeHandle.LocalUUID
		arrayID := volumeHandle.LocalArrayGlobalID
		protocol := volumeHandle.Protocol

		arr, ok := s.Arrays()[arrayID]
		if !ok {
			return nil, "", status.Errorf(codes.Internal, "unable to get array with arrayID %s", arrayID)
		}
		if protocol == "nfs" {
			snaps, err := arr.GetClient().GetFsSnapshotsByVolumeID(ctx, id)
			if err != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to list filesystem snapshots: %s", err.Error())
			}
			for _, snap := range snaps {
				generalSnapshots = append(generalSnapshots, FilesystemSnapshot(snap))
			}
		} else {
			snaps, err := arr.GetClient().GetSnapshotsByVolumeID(ctx, id)
			if err != nil {
				return nil, "", status.Errorf(codes.Internal, "unable to list block snapshots: %s", err.Error())
			}
			for _, snap := range snaps {
				generalSnapshots = append(generalSnapshots, VolumeSnapshot(snap))
			}
		}
	}

	if startToken > len(generalSnapshots) {
		return nil, "", status.Errorf(codes.Aborted, "startingToken=%d > len(generalSnapshots)=%d", startToken, len(generalSnapshots))
	}
	// Discern the number of remaining entries.
	rem := len(generalSnapshots) - startToken

	// If maxEntries is 0 or greater than the number of remaining entries then
	// set max entries to the number of remaining entries.
	if maxEntries == 0 || maxEntries > rem {
		maxEntries = rem
	}

	// We can't really return more per page
	if maxEntries > 300 {
		maxEntries = 300
	}

	// Compute the next starting point; if at end reset
	nextToken := startToken + maxEntries
	nextTokenStr := ""
	if nextToken < (startToken + rem) {
		nextTokenStr = fmt.Sprintf("%d", nextToken)
	}

	return generalSnapshots[startToken : startToken+maxEntries], nextTokenStr, nil
}
