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

package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	log "github.com/dell/csmlog"
	"github.com/dell/gobrick"
	"github.com/dell/gopowerstore"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

const (
	procMountsPath    = "/proc/self/mountinfo"
	procMountsRetries = 15
)

// VolumeStager allows to node stage a volume
type VolumeStager interface {
	Stage(ctx context.Context, req *csi.NodeStageVolumeRequest, stagingPath string, nodeID string, logFields log.Fields, fs fs.Interface, id string, isRemote bool, client gopowerstore.Client) (*csi.NodeStageVolumeResponse, error)
}

// ReachableEndPoint checks if the endpoint is reachable or not
var ReachableEndPoint = identifiers.ReachableEndPoint

// SCSIStager implementation of NodeVolumeStager for SCSI based (FC, iSCSI) volumes
type SCSIStager struct {
	useFC          bool
	useNVME        bool
	iscsiConnector ISCSIConnector
	nvmeConnector  NVMEConnector
	fcConnector    FcConnector
}

// Stage stages volume by connecting it through either FC or iSCSI and creating bind mount to staging path
func (s *SCSIStager) Stage(ctx context.Context, req *csi.NodeStageVolumeRequest, stagingPath string, nodeID string,
	logFields log.Fields, fs fs.Interface, id string, isRemote bool, client gopowerstore.Client,
) (*csi.NodeStageVolumeResponse, error) {
	orginalContext := req.PublishContext
	volume, err := client.GetVolume(ctx, id)
	if err != nil {
		return nil, err
	}
	targetMap := make(map[string]string)
	err = s.AddTargetsInfoToMap(targetMap, volume.ApplianceID, client, isRemote)
	if err != nil {
		return nil, err
	}

	if !isRemote {
		wwn := orginalContext[identifiers.TargetMapDeviceWWN]
		lun, ok := orginalContext[identifiers.TargetMapLUNAddress]
		if !ok {
			wwn = strings.TrimPrefix(volume.Wwn, identifiers.WWNPrefix)
			lun, err = getLunAddressFromArray(ctx, client, id, nodeID)
			if err != nil {
				return nil, err
			}
		}
		targetMap[identifiers.TargetMapDeviceWWN] = wwn
		targetMap[identifiers.TargetMapLUNAddress] = lun
	} else {
		wwn := orginalContext[identifiers.TargetMapRemoteDeviceWWN]
		lun, ok := orginalContext[identifiers.TargetMapRemoteLUNAddress]
		if !ok {
			wwn = strings.TrimPrefix(volume.Wwn, identifiers.WWNPrefix)
			lun, err = getLunAddressFromArray(ctx, client, id, nodeID)
			if err != nil {
				return nil, err
			}
		}
		targetMap[identifiers.TargetMapRemoteDeviceWWN] = wwn
		targetMap[identifiers.TargetMapRemoteLUNAddress] = lun
	}

	publishContext, err := readSCSIInfoFromPublishContext(targetMap, s.useFC, s.useNVME, isRemote)
	if err != nil {
		return nil, err
	}

	logFields["ID"] = id
	if s.useNVME {
		if s.useFC {
			logFields["Targets"] = publishContext.nvmefcTargets
		} else {
			logFields["Targets"] = publishContext.nvmetcpTargets
		}
	} else {
		logFields["Targets"] = publishContext.iscsiTargets
	}
	logFields["WWN"] = publishContext.deviceWWN
	logFields["Lun"] = publishContext.volumeLUNAddress
	logFields["StagingPath"] = stagingPath

	found, ready, err := isReadyToPublish(ctx, stagingPath, fs)
	if err != nil {
		return nil, err
	}
	if ready {
		log.WithContext(ctx).WithOperation("NodeStageVolume").Info("device already staged")
		if isRemote {
			// Ensure the secondary array sessions are scanned and the LUN is discovered -
			// then skip the bind-mount step (since it was already done by the primary LUN staging).
			log.WithContext(ctx).WithOperation("NodeStageVolume").Info("connecting remote device")
			if _, err := s.connectDevice(ctx, publishContext); err != nil {
				log.WithContext(ctx).WithOperation("NodeStageVolume").Errorf("failed to connect remote device: %s", err)
				return nil, status.Errorf(codes.Internal, "failed to connect remote device: %s", err)
			}
		}
		return &csi.NodeStageVolumeResponse{}, nil
	} else if found {
		log.WithContext(ctx).WithOperation("NodeStageVolume").Warn("volume found in staging path but it is not ready for publish, try to unmount it and retry staging again")
		_, err := unstageVolume(ctx, stagingPath, id, logFields, fs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to unmount volume: %s", err.Error())
		}
	}

	devicePath, err := s.connectDevice(ctx, publishContext)
	if err != nil {
		return nil, err
	}

	logFields["DevicePath"] = devicePath

	log.WithContext(ctx).WithOperation("NodeStageVolume").Info("start staging")
	if _, err := fs.MkFileIdempotent(stagingPath); err != nil {
		return nil, status.Errorf(codes.Internal, "can't create target file %s: %s",
			stagingPath, err.Error())
	}
	log.WithContext(ctx).WithOperation("NodeStageVolume").Info("target path successfully created")

	mntFlags := identifiers.GetMountFlags(req.GetVolumeCapability())
	if err := fs.GetUtil().BindMount(ctx, devicePath, stagingPath, mntFlags...); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error bind disk %s to target path: %s", devicePath, err.Error())
	}

	log.WithContext(ctx).WithOperation("NodeStageVolume").Info("stage complete")
	return &csi.NodeStageVolumeResponse{}, nil
}

func getLunAddressFromArray(ctx context.Context, client gopowerstore.Client, id string, nodeID string) (string, error) {
	log.WithContext(ctx).Infof("GetHostVolumeMappingByVolumeID for volId %s host %s", id, nodeID)
	var node gopowerstore.Host
	node, err := client.GetHostByName(ctx, nodeID)
	if err != nil {
		return "", status.Errorf(codes.Internal,
			"failed to find host '%s' during staging: %s", nodeID, err.Error())
	}
	mapping, err := client.GetHostVolumeMappingByVolumeID(ctx, id)
	if err != nil {
		return "", status.Errorf(codes.Internal,
			"failed to get mapping for volume with ID '%s' during staging: %s", id, err.Error())
	}
	for _, m := range mapping {
		if m.HostID == node.ID {
			lun := strconv.FormatInt(m.LogicalUnitNumber, 10)
			return lun, nil
		}
	}
	return "", status.Errorf(codes.Internal,
		"failed to get LUN for volume with ID '%s' during staging", id)
}

// nfsAutoSelectMetadata holds metadata persisted at <staging_target_path>/.nfs-autoselect.json
// for reliable cleanup during NodeUnstageVolume.
type nfsAutoSelectMetadata struct {
	NasIP            string `json:"nasIP"`
	ExportID         string `json:"exportID"`
	DiscoveredNodeIP string `json:"discoveredNodeIP"`
	NasName          string `json:"nasName"`
	HostsListType    string `json:"hostsListType"` // "RWRootHosts" or "RWHosts"
}

// NFS auto-select K8s event reason constants (FR-6.1)
const (
	// EventReasonNFSAutoSelectIP is emitted on the PVC after successful storage-network IP discovery and export modification.
	EventReasonNFSAutoSelectIP = "NFSAutoSelectIP"
	// EventReasonNFSAutoSelectFallback is emitted on the PVC when the routing query returns the management IP (flat network)
	// or when getOutboundIP fails and the driver falls back to the management IP.
	EventReasonNFSAutoSelectFallback = "NFSAutoSelectFallback"
	// EventReasonNFSExportHostLimit is emitted on the PVC when the NFS export host entry count exceeds 80% of the 128-entry limit.
	EventReasonNFSExportHostLimit = "NFSExportHostLimit"

	// nfsExportMaxHosts is the maximum number of host entries supported by a PowerStore NFS export.
	nfsExportMaxHosts = 128
	// nfsExportHostWarnThreshold is the host entry count threshold (~80% of limit) to emit warning events.
	nfsExportHostWarnThreshold = 100
)

// NFSStager implementation of NodeVolumeStager for NFS volumes
type NFSStager struct {
	array         *array.PowerStoreArray
	nfsAutoSelect bool
	nodeID        string
	managementIP  string
	eventRecorder record.EventRecorder
}

// emitNFSAutoSelectEvent emits a Kubernetes event on the PVC for NFS auto-select decisions.
// It is a no-op when the event recorder is nil or PVC name is empty.
func (n *NFSStager) emitNFSAutoSelectEvent(ctx context.Context, publishContext map[string]string, eventType, reason, message string) {
	if n.eventRecorder == nil {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "emitNFSAutoSelectEvent",
		}).Warn("NFS auto-select: event recorder is nil, skipping event emission")
		return
	}
	pvcName := publishContext[controller.KeyCSIPVCName]
	pvcNamespace := publishContext[controller.KeyCSIPVCNamespace]
	if pvcName == "" {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "emitNFSAutoSelectEvent",
		}).Warn("NFS auto-select: PVC name not found in publishContext, skipping event emission")
		return
	}
	if pvcNamespace == "" {
		pvcNamespace = "default"
	}
	ref := &corev1.ObjectReference{
		APIVersion: "v1",
		Kind:       "PersistentVolumeClaim",
		Name:       pvcName,
		Namespace:  pvcNamespace,
	}
	n.eventRecorder.Event(ref, eventType, reason, message)
	log.WithContext(ctx).WithFields(log.Fields{
		log.FieldComponent: "node",
		log.FieldOperation: "emitNFSAutoSelectEvent",
		"pvcName":          pvcName,
		"pvcNamespace":     pvcNamespace,
		"eventType":        eventType,
		"reason":           reason,
	}).Info("NFS auto-select: K8s event emitted")
}

// Stage stages volume by mounting volumes as nfs to the staging path
func (n *NFSStager) Stage(ctx context.Context, req *csi.NodeStageVolumeRequest, stagingPath string, _ string,
	logFields log.Fields, fs fs.Interface, id string, _ bool, _ gopowerstore.Client,
) (*csi.NodeStageVolumeResponse, error) {
	hostIP := req.PublishContext[identifiers.KeyHostIP]
	exportID := req.PublishContext[identifiers.KeyExportID]
	nfsExport := req.PublishContext[identifiers.KeyNfsExportPath]
	allowRoot := req.PublishContext[identifiers.KeyAllowRoot]
	nasName := req.PublishContext[identifiers.KeyNasName]

	natIP := ""
	if ip, ok := req.PublishContext[identifiers.KeyNatIP]; ok {
		natIP = ip
	}

	logFields["NfsExportPath"] = nfsExport
	logFields["StagingPath"] = req.GetStagingTargetPath()
	logFields["ID"] = id
	logFields["AllowRoot"] = allowRoot
	logFields["ExportID"] = exportID
	logFields["HostIP"] = hostIP
	logFields["NatIP"] = natIP
	logFields["NFSv4ACLs"] = req.PublishContext[identifiers.KeyNfsACL]
	logFields["NasName"] = nasName

	found, err := isReadyToPublishNFS(ctx, stagingPath, fs)
	if err != nil {
		return nil, err
	}

	if found {
		log.WithContext(ctx).WithFields(logFields).Info("device already staged")
		return &csi.NodeStageVolumeResponse{}, nil
	}

	// NFS auto-select: discover storage-network source IP and add to export before mount.
	// The controller sets NfsAutoSelect=true in publishContext only when auto-select is
	// enabled AND exclusiveAccess is not set. This prevents node-side IP discovery when
	// the controller manages host access exclusively via externalAccess CIDRs.
	if n.nfsAutoSelect && req.PublishContext[identifiers.KeyNfsAutoSelect] == "true" {
		if err := n.handleAutoSelect(ctx, req, stagingPath, logFields, fs); err != nil {
			return nil, err
		}
	}

	if err := fs.MkdirAll(stagingPath, 0o750); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create target folder %s: %s", stagingPath, err.Error())
	}
	log.WithContext(ctx).WithFields(logFields).Info("stage path successfully created")

	mntFlags := identifiers.GetMountFlags(req.GetVolumeCapability())
	if err := fs.GetUtil().Mount(ctx, nfsExport, stagingPath, "", mntFlags...); err != nil {
		return nil, status.Errorf(codes.Internal,
			"error mount nfs share %s to target path: %s", nfsExport, err.Error())
	}

	// Create folder with 1777 in nfs share so every user can use it
	if err := fs.MkdirAll(filepath.Join(stagingPath, commonNfsVolumeFolder), 0o750); err != nil {
		return nil, status.Errorf(codes.Internal,
			"can't create common folder %s: %s", filepath.Join(stagingPath, "volume"), err.Error())
	}

	mode := os.ModePerm
	acls := req.PublishContext[identifiers.KeyNfsACL]
	aclsConfigured := false
	if acls != "" {
		if posixMode(acls) {
			perm, err := strconv.ParseUint(acls, 8, 32)
			if err == nil {
				mode = os.FileMode(perm) // #nosec: G115 false positive
			} else {
				log.WithContext(ctx).WithFields(logFields).Warn("can't parse file mode, invalid mode specified. Default mode permissions will be set.")
			}
		} else {
			aclsConfigured, err = validateAndSetACLs(ctx, &NFSv4ACLs{}, nasName, n.array.GetClient(), acls, filepath.Join(stagingPath, commonNfsVolumeFolder))
			if err != nil || !aclsConfigured {
				return nil, err
			}
		}
	}

	if !aclsConfigured {
		if err := fs.Chmod(filepath.Join(stagingPath, commonNfsVolumeFolder), os.ModeSticky|mode); err != nil {
			return nil, status.Errorf(codes.Internal,
				"can't change permissions of folder %s: %s", filepath.Join(stagingPath, "volume"), err.Error())
		}
	}

	if allowRoot == "false" {
		log.WithContext(ctx).WithFields(logFields).WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "NFSStager.Stage",
			log.FieldProtocol:  "NFS",
		}).Info("removing allow root from NFS export")
		var hostsToRemove []string
		var hostsToAdd []string

		if hostIP != "" {
			hostEntry, formatErr := identifiers.FormatNFSHostEntry(hostIP)
			if formatErr != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid NFS host IP %q: %s", hostIP, formatErr.Error())
			}
			hostsToRemove = append(hostsToRemove, hostEntry)
			hostsToAdd = append(hostsToAdd, hostIP)
		}

		if natIP != "" {
			hostsToRemove = append(hostsToRemove, natIP)
			hostsToAdd = append(hostsToAdd, natIP)
		}

		// Modify NFS export to RW with `root_squashing`
		_, err = n.array.GetClient().ModifyNFSExport(ctx, &gopowerstore.NFSExportModify{
			RemoveRWRootHosts: hostsToRemove,
			AddRWHosts:        hostsToAdd,
		}, exportID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
				return nil, status.Errorf(codes.Internal, "failure when modifying nfs export: %s", err.Error())
			}
		}
	}

	log.WithContext(ctx).WithFields(logFields).WithFields(log.Fields{
		log.FieldComponent: "node",
		log.FieldOperation: "NFSStager.Stage",
		log.FieldProtocol:  "NFS",
	}).Info("NFS share successfully mounted")
	return &csi.NodeStageVolumeResponse{}, nil
}

// handleAutoSelect implements NFS source-IP auto-discovery and export modification
// for the NFS auto-select feature (ER-K8S-JA18622-001-powerstore-nfs-auto-selection Phase 1).
func (n *NFSStager) handleAutoSelect(ctx context.Context, req *csi.NodeStageVolumeRequest,
	stagingPath string, logFields log.Fields, fsAPI fs.Interface,
) error {
	nfsExport := req.PublishContext[identifiers.KeyNfsExportPath]
	exportID := req.PublishContext[identifiers.KeyExportID]
	allowRoot := req.PublishContext[identifiers.KeyAllowRoot]
	nasName := req.PublishContext[identifiers.KeyNasName]

	// FR-3(a): Validate NfsExportPath — return error if key missing or IP component empty
	if nfsExport == "" {
		return status.Error(codes.InvalidArgument,
			"NfsExportPath is missing from publishContext; cannot perform NFS auto-select IP discovery")
	}

	nasIP, err := identifiers.ParseNFSExportPath(nfsExport)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	autoSelectFields := log.Fields{
		log.FieldComponent:    "node",
		log.FieldOperation:    "NFSStager.handleAutoSelect",
		"nas_server":          nasName,
		"file_interface_ip":   nasIP,
		"auto_select_enabled": true,
	}

	// FR-3(c): Discover storage-network source IP via kernel routing query
	discoveredIP, err := getOutboundIP(nasIP, "", fsAPI)
	hostsListType := "RWRootHosts"
	if allowRoot == "false" {
		hostsListType = "RWHosts"
	}

	if err != nil {
		// FR-4: Hard-error fallback — use first IP from kubeNodeID
		fallbackIP := identifiers.GetIPListFromString(n.nodeID)
		if len(fallbackIP) == 0 {
			return status.Errorf(codes.Internal,
				"NFS auto-select: getOutboundIP failed (%s) and no fallback IP available from kubeNodeID %q",
				err.Error(), n.nodeID)
		}
		discoveredIP = nil // will use fallbackIP below
		log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).WithFields(log.Fields{
			"discovered_node_ip": fallbackIP[0],
			"management_node_ip": n.managementIP,
			log.FieldError:       err.Error(),
		}).Warn("NFS auto-select: getOutboundIP failed, fallback to kubeNodeID IP")

		// FR-6.1: Emit NFSAutoSelectFallback Warning event on the PVC
		n.emitNFSAutoSelectEvent(ctx, req.PublishContext, corev1.EventTypeWarning, EventReasonNFSAutoSelectFallback,
			fmt.Sprintf("NFS auto-select: routing query failed for NAS interface %s, using management IP %s", nasIP, fallbackIP[0]))

		// Use the fallback IP for export modification
		return n.modifyExportAndPersist(ctx, fallbackIP[0], nasIP, nasName, exportID, hostsListType,
			stagingPath, req.PublishContext, logFields, autoSelectFields, fsAPI)
	}

	discoveredIPStr := discoveredIP.String()
	autoSelectFields["discovered_node_ip"] = discoveredIPStr
	autoSelectFields["management_node_ip"] = n.managementIP

	// FR-4: Flat-network fallback — discovered IP == management IP
	if discoveredIPStr == n.managementIP {
		log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).
			Warn("NFS auto-select: discovered IP matches management IP (flat network fallback), proceeding with existing behavior")

		// FR-6.1: Emit NFSAutoSelectFallback Warning event on the PVC
		n.emitNFSAutoSelectEvent(ctx, req.PublishContext, corev1.EventTypeWarning, EventReasonNFSAutoSelectFallback,
			fmt.Sprintf("NFS auto-select: routing query returned management IP for NAS=%s; no dedicated storage NIC detected", nasName))
	}

	log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).
		Info("NFS auto-select: discovered storage-network source IP")

	return n.modifyExportAndPersist(ctx, discoveredIPStr, nasIP, nasName, exportID, hostsListType,
		stagingPath, req.PublishContext, logFields, autoSelectFields, fsAPI)
}

// modifyExportAndPersist adds the discovered IP to the NFS export and persists metadata.
func (n *NFSStager) modifyExportAndPersist(ctx context.Context,
	discoveredIP, nasIP, nasName, exportID, hostsListType, stagingPath string,
	publishContext map[string]string, logFields, autoSelectFields log.Fields, fsAPI fs.Interface,
) error {
	client := n.array.GetClient()

	// FR-5: Check export host entry count before modification
	export, err := client.GetNFSExport(ctx, exportID)
	if err != nil {
		// If we can't get the export to check count, log warning and proceed
		log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).WithFields(log.Fields{
			log.FieldError: err.Error(),
		}).Warn("NFS auto-select: failed to get NFS export for host-limit check, proceeding with modification")
	} else {
		totalHosts := len(export.RWRootHosts) + len(export.RWHosts) + len(export.ROHosts) + len(export.RORootHosts)
		if totalHosts > nfsExportHostWarnThreshold {
			log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).WithFields(log.Fields{
				"host_count": totalHosts,
				"host_limit": nfsExportMaxHosts,
			}).Warnf("NFS auto-select: export host entry count exceeds %d (80%% of %d-entry PowerStore limit)",
				nfsExportHostWarnThreshold, nfsExportMaxHosts)

			// FR-6.1: Emit NFSExportHostLimit Warning event on the PVC
			n.emitNFSAutoSelectEvent(ctx, publishContext, corev1.EventTypeWarning, EventReasonNFSExportHostLimit,
				fmt.Sprintf("NFS export %s (NAS=%s) host entry count (%d/%d) exceeds 80%% of limit",
					exportID, nasName, totalHosts, nfsExportMaxHosts))
		}
	}

	// FR-3(e): Add discovered IP to the correct host list
	ipWithMask, err := identifiers.FormatNFSHostEntry(discoveredIP)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "NFS auto-select: %s", err.Error())
	}
	var modifyReq *gopowerstore.NFSExportModify
	if hostsListType == "RWHosts" {
		modifyReq = &gopowerstore.NFSExportModify{
			AddRWHosts: []string{ipWithMask},
		}
	} else {
		modifyReq = &gopowerstore.NFSExportModify{
			AddRWRootHosts: []string{ipWithMask},
		}
	}

	_, err = client.ModifyNFSExport(ctx, modifyReq, exportID)
	if err != nil {
		// FR-3(f): Treat HostAlreadyPresentInNFSExport API errors as success
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.HostAlreadyPresentInNFSExport() {
			log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).
				Info("NFS auto-select: host IP already present in NFS export, treating as success")
		} else {
			return status.Errorf(codes.Internal,
				"NFS auto-select: failed to add discovered IP %s to NFS export %s: %s",
				discoveredIP, exportID, err.Error())
		}
	} else {
		log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).WithFields(log.Fields{
			"hosts_list_type": hostsListType,
		}).Info("NFS auto-select: successfully added discovered IP to NFS export")
	}

	// FR-6.1: Emit NFSAutoSelectIP Normal event on the PVC after successful export modification
	n.emitNFSAutoSelectEvent(ctx, publishContext, corev1.EventTypeNormal, EventReasonNFSAutoSelectIP,
		fmt.Sprintf("NFS auto-select: NAS=%s Interface=%s DiscoveredNodeIP=%s (management IP=%s)",
			nasName, nasIP, discoveredIP, n.managementIP))

	// FR-3(g): Persist metadata to .nfs-autoselect.json
	metadata := nfsAutoSelectMetadata{
		NasIP:            nasIP,
		ExportID:         exportID,
		DiscoveredNodeIP: discoveredIP,
		NasName:          nasName,
		HostsListType:    hostsListType,
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).WithFields(log.Fields{
			log.FieldError: err.Error(),
		}).Warn("NFS auto-select: failed to marshal metadata, unstage will fall back to rediscovery")
	} else {
		// Write metadata as a sibling file to the staging path (not inside the NFS mount).
		// This ensures the file persists on local disk and survives unmount for cleanup.
		metadataPath := stagingPath + ".nfs-autoselect.json"
		if err := fsAPI.WriteFile(metadataPath, metadataBytes, 0o600); err != nil {
			log.WithContext(ctx).WithFields(logFields).WithFields(autoSelectFields).WithFields(log.Fields{
				log.FieldError: err.Error(),
			}).Warn("NFS auto-select: failed to write metadata file, unstage will fall back to rediscovery")
		}
	}

	return nil
}

// handleNFSAutoSelectCleanup reads the .nfs-autoselect.json metadata file written during
// Stage and removes the discovered node IP from the NFS export. This function is called
// during NodeUnstageVolume for NFS volumes. Errors are logged but do not fail the unstage
// operation — the export host entry will be orphaned and cleaned up by the next stage.
func handleNFSAutoSelectCleanup(ctx context.Context, stagingPath string,
	arr *array.PowerStoreArray, fsAPI fs.Interface, logFields log.Fields,
) {
	metadataPath := stagingPath + ".nfs-autoselect.json"
	data, err := fsAPI.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No metadata file means auto-select was not used for this volume
			return
		}
		log.WithContext(ctx).WithFields(logFields).WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "handleNFSAutoSelectCleanup",
			log.FieldError:     err.Error(),
		}).Warn("NFS auto-select cleanup: failed to read metadata file, skipping export cleanup")
		return
	}

	var metadata nfsAutoSelectMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		log.WithContext(ctx).WithFields(logFields).WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "handleNFSAutoSelectCleanup",
			log.FieldError:     err.Error(),
		}).Warn("NFS auto-select cleanup: malformed metadata file, removing file without export cleanup")
		_ = fsAPI.Remove(metadataPath)
		return
	}

	cleanupFields := log.Fields{
		log.FieldComponent:   "node",
		log.FieldOperation:   "handleNFSAutoSelectCleanup",
		"discovered_node_ip": metadata.DiscoveredNodeIP,
		"export_id":          metadata.ExportID,
		"nas_name":           metadata.NasName,
		"hosts_list_type":    metadata.HostsListType,
	}

	// Remove discovered IP from NFS export
	ipWithMask, err := identifiers.FormatNFSHostEntry(metadata.DiscoveredNodeIP)
	if err != nil {
		log.WithContext(ctx).WithFields(logFields).WithFields(cleanupFields).WithFields(log.Fields{
			log.FieldError: err.Error(),
		}).Warn("NFS auto-select cleanup: invalid discovered node IP")
		_ = fsAPI.Remove(metadataPath)
		return
	}
	var modifyReq *gopowerstore.NFSExportModify
	if metadata.HostsListType == "RWHosts" {
		modifyReq = &gopowerstore.NFSExportModify{
			RemoveRWHosts: []string{ipWithMask},
		}
	} else {
		modifyReq = &gopowerstore.NFSExportModify{
			RemoveRWRootHosts: []string{ipWithMask},
		}
	}

	client := arr.GetClient()
	_, err = client.ModifyNFSExport(ctx, modifyReq, metadata.ExportID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
			log.WithContext(ctx).WithFields(logFields).WithFields(cleanupFields).
				Info("NFS auto-select cleanup: export not found (already deleted), skipping host removal")
		} else {
			log.WithContext(ctx).WithFields(logFields).WithFields(cleanupFields).WithFields(log.Fields{
				log.FieldError: err.Error(),
			}).Warn("NFS auto-select cleanup: failed to remove host from NFS export, IP may remain as orphaned entry")
		}
	} else {
		log.WithContext(ctx).WithFields(logFields).WithFields(cleanupFields).
			Info("NFS auto-select cleanup: successfully removed discovered IP from NFS export")
	}

	// Remove metadata file
	if err := fsAPI.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		log.WithContext(ctx).WithFields(logFields).WithFields(cleanupFields).WithFields(log.Fields{
			log.FieldError: err.Error(),
		}).Warn("NFS auto-select cleanup: failed to remove metadata file")
	}
}

type scsiPublishContextData struct {
	deviceWWN        string
	volumeLUNAddress string
	iscsiTargets     []gobrick.ISCSITargetInfo
	nvmetcpTargets   []gobrick.NVMeTargetInfo
	nvmefcTargets    []gobrick.NVMeTargetInfo
	fcTargets        []gobrick.FCTargetInfo
}

func readSCSIInfoFromPublishContext(publishContext map[string]string, useFC bool, useNVMe bool, isRemote bool) (scsiPublishContextData, error) {
	// Get publishContext
	var data scsiPublishContextData
	deviceWwnKey := identifiers.TargetMapDeviceWWN
	lunAddressKey := identifiers.TargetMapLUNAddress
	if isRemote {
		deviceWwnKey = identifiers.TargetMapRemoteDeviceWWN
		lunAddressKey = identifiers.TargetMapRemoteLUNAddress
	}

	deviceWWN, ok := publishContext[deviceWwnKey]
	if !ok || deviceWWN == "" {
		return data, status.Error(codes.InvalidArgument, "deviceWWN must be in publish context")
	}
	volumeLUNAddress, ok := publishContext[lunAddressKey]
	if !ok || volumeLUNAddress == "" {
		return data, status.Error(codes.InvalidArgument, "volumeLUNAddress must be in publish context")
	}

	iscsiTargets := readISCSITargetsFromPublishContext(publishContext, isRemote)
	if len(iscsiTargets) == 0 && !useFC && !useNVMe {
		return data, status.Error(codes.InvalidArgument, "iscsiTargets data must be in publish context")
	}
	nvmeTCPTargets := readNVMETCPTargetsFromPublishContext(publishContext, isRemote)
	if len(nvmeTCPTargets) == 0 && useNVMe && !useFC {
		return data, status.Error(codes.InvalidArgument, "NVMeTCP Targets data must be in publish context")
	}
	nvmeFCTargets := readNVMEFCTargetsFromPublishContext(publishContext, isRemote)
	if len(nvmeFCTargets) == 0 && useNVMe && useFC {
		return data, status.Error(codes.InvalidArgument, "NVMeFC Targets data must be in publish context")
	}
	fcTargets := readFCTargetsFromPublishContext(publishContext, isRemote)
	if len(fcTargets) == 0 && useFC && !useNVMe {
		return data, status.Error(codes.InvalidArgument, "fcTargets data must be in publish context")
	}
	return scsiPublishContextData{
		deviceWWN: deviceWWN, volumeLUNAddress: volumeLUNAddress,
		iscsiTargets: iscsiTargets, nvmetcpTargets: nvmeTCPTargets, nvmefcTargets: nvmeFCTargets, fcTargets: fcTargets,
	}, nil
}

func readISCSITargetsFromPublishContext(pc map[string]string, isRemote bool) []gobrick.ISCSITargetInfo {
	var targets []gobrick.ISCSITargetInfo
	iscsiTargetsKey := identifiers.TargetMapISCSITargetsPrefix
	iscsiPortalsKey := identifiers.TargetMapISCSIPortalsPrefix
	if isRemote {
		iscsiTargetsKey = identifiers.TargetMapRemoteISCSITargetsPrefix
		iscsiPortalsKey = identifiers.TargetMapRemoteISCSIPortalsPrefix
	}
	for i := 0; ; i++ {
		target := gobrick.ISCSITargetInfo{}
		t, tfound := pc[fmt.Sprintf("%s%d", iscsiTargetsKey, i)]
		if tfound {
			target.Target = t
		}
		p, pfound := pc[fmt.Sprintf("%s%d", iscsiPortalsKey, i)]
		if pfound {
			target.Portal = p
		}
		if !tfound || !pfound {
			break
		}

		if ReachableEndPoint(p) {
			// if the portals from the context (set in NodeStageVolume) is not reachable from the nodes
			targets = append(targets, target)
		}
	}
	log.WithFields(log.Fields{
		log.FieldComponent: "node",
		log.FieldOperation: "readISCSITargetsFromPublishContext",
		log.FieldProtocol:  "iSCSI",
		"targets":          fmt.Sprintf("%v", targets),
	}).Info("iSCSI targets read from context")
	return targets
}

func readNVMETCPTargetsFromPublishContext(pc map[string]string, isRemote bool) []gobrick.NVMeTargetInfo {
	var targets []gobrick.NVMeTargetInfo
	nvmeTCPTargetsKey := identifiers.TargetMapNVMETCPTargetsPrefix
	nvmeTCPPortalsKey := identifiers.TargetMapNVMETCPPortalsPrefix
	if isRemote {
		nvmeTCPTargetsKey = identifiers.TargetMapRemoteNVMETCPTargetsPrefix
		nvmeTCPPortalsKey = identifiers.TargetMapRemoteNVMETCPPortalsPrefix
	}
	for i := 0; ; i++ {
		target := gobrick.NVMeTargetInfo{}
		t, tfound := pc[fmt.Sprintf("%s%d", nvmeTCPTargetsKey, i)]
		if tfound {
			target.Target = t
		}
		p, pfound := pc[fmt.Sprintf("%s%d", nvmeTCPPortalsKey, i)]
		if pfound {
			target.Portal = p
		}
		if !tfound || !pfound {
			break
		}
		targets = append(targets, target)
	}
	log.WithFields(log.Fields{
		log.FieldComponent: "node",
		log.FieldOperation: "readNVMETCPTargetsFromPublishContext",
		log.FieldProtocol:  "NVMeTCP",
		"targets":          fmt.Sprintf("%v", targets),
	}).Info("NVMeTCP targets read from context")
	return targets
}

func readNVMEFCTargetsFromPublishContext(pc map[string]string, isRemote bool) []gobrick.NVMeTargetInfo {
	var targets []gobrick.NVMeTargetInfo
	nvmeFcTargetsKey := identifiers.TargetMapNVMEFCTargetsPrefix
	nvmeFcPortalsKey := identifiers.TargetMapNVMEFCPortalsPrefix
	if isRemote {
		nvmeFcTargetsKey = identifiers.TargetMapRemoteNVMEFCTargetsPrefix
		nvmeFcPortalsKey = identifiers.TargetMapRemoteNVMEFCPortalsPrefix
	}
	for i := 0; ; i++ {
		target := gobrick.NVMeTargetInfo{}
		t, tfound := pc[fmt.Sprintf("%s%d", nvmeFcTargetsKey, i)]
		if tfound {
			target.Target = t
		}
		p, pfound := pc[fmt.Sprintf("%s%d", nvmeFcPortalsKey, i)]
		if pfound {
			target.Portal = p
		}
		if !tfound || !pfound {
			break
		}
		targets = append(targets, target)
	}
	log.WithFields(log.Fields{
		log.FieldComponent: "node",
		log.FieldOperation: "readNVMEFCTargetsFromPublishContext",
		log.FieldProtocol:  "NVMeFC",
		"targets":          fmt.Sprintf("%v", targets),
	}).Info("NVMeFC targets read from context")
	return targets
}

func readFCTargetsFromPublishContext(pc map[string]string, isRemote bool) []gobrick.FCTargetInfo {
	var targets []gobrick.FCTargetInfo
	fcWwpnKey := identifiers.TargetMapFCWWPNPrefix
	if isRemote {
		fcWwpnKey = identifiers.TargetMapRemoteFCWWPNPrefix
	}
	for i := 0; ; i++ {
		wwpn, tfound := pc[fmt.Sprintf("%s%d", fcWwpnKey, i)]
		if !tfound {
			break
		}
		targets = append(targets, gobrick.FCTargetInfo{WWPN: wwpn})
	}
	log.WithFields(log.Fields{
		log.FieldComponent: "node",
		log.FieldOperation: "readFCTargetsFromPublishContext",
		log.FieldProtocol:  "FC",
		"targets":          fmt.Sprintf("%v", targets),
	}).Info("FC targets read from context")
	return targets
}

func (s *SCSIStager) connectDevice(ctx context.Context, data scsiPublishContextData) (string, error) {
	var err error
	lun, err := strconv.Atoi(data.volumeLUNAddress)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to convert lun number to int: %s", err.Error())
		return "", status.Errorf(codes.Internal,
			"failed to convert lun number to int: %s", err.Error())
	}
	wwn := data.deviceWWN
	var device gobrick.Device
	if s.useNVME {
		device, err = s.connectNVMEDevice(ctx, wwn, data, s.useFC)
	} else if s.useFC {
		device, err = s.connectFCDevice(ctx, lun, data)
	} else {
		device, err = s.connectISCSIDevice(ctx, lun, data)
	}

	if err != nil {
		log.WithContext(ctx).Errorf("Unable to find device after multiple discovery attempts: %s", err.Error())
		return "", status.Errorf(codes.Internal,
			"unable to find device after multiple discovery attempts: %s", err.Error())
	}
	devicePath := path.Join("/dev/", device.Name)
	return devicePath, nil
}

func (s *SCSIStager) connectISCSIDevice(_ context.Context,
	lun int, data scsiPublishContextData,
) (gobrick.Device, error) {
	var targets []gobrick.ISCSITargetInfo
	for _, t := range data.iscsiTargets {
		targets = append(targets, gobrick.ISCSITargetInfo{Target: t.Target, Portal: t.Portal})
	}
	// separate context to prevent 15 seconds cancel from kubernetes
	connectorCtx, cFunc := context.WithTimeout(context.Background(), time.Second*120)
	defer cFunc()

	return s.iscsiConnector.ConnectVolume(connectorCtx, gobrick.ISCSIVolumeInfo{
		Targets: targets,
		Lun:     lun,
	})
}

func (s *SCSIStager) connectNVMEDevice(_ context.Context,
	wwn string, data scsiPublishContextData, useFC bool,
) (gobrick.Device, error) {
	var targets []gobrick.NVMeTargetInfo

	if useFC {
		for _, t := range data.nvmefcTargets {
			targets = append(targets, gobrick.NVMeTargetInfo{Target: t.Target, Portal: t.Portal})
		}
	} else {
		for _, t := range data.nvmetcpTargets {
			targets = append(targets, gobrick.NVMeTargetInfo{Target: t.Target, Portal: t.Portal})
		}
	}
	// separate context to prevent 15 seconds cancel from kubernetes
	connectorCtx, cFunc := context.WithTimeout(context.Background(), time.Second*120)
	defer cFunc()

	return s.nvmeConnector.ConnectVolume(connectorCtx, gobrick.NVMeVolumeInfo{
		Targets: targets,
		WWN:     wwn,
	}, useFC)
}

func (s *SCSIStager) connectFCDevice(_ context.Context,
	lun int, data scsiPublishContextData,
) (gobrick.Device, error) {
	var targets []gobrick.FCTargetInfo

	for _, t := range data.fcTargets {
		targets = append(targets, gobrick.FCTargetInfo{WWPN: t.WWPN})
	}
	// separate context to prevent 15 seconds cancel from kubernetes
	connectorCtx, cFunc := context.WithTimeout(context.Background(), time.Second*120)
	defer cFunc()

	return s.fcConnector.ConnectVolume(connectorCtx, gobrick.FCVolumeInfo{
		Targets: targets,
		Lun:     lun,
	})
}

func isReadyToPublish(ctx context.Context, stagingPath string, fs fs.Interface) (bool, bool, error) {
	stageInfo, found, err := getTargetMount(ctx, stagingPath, fs)
	if err != nil {
		return found, false, err
	}
	if !found {
		log.WithContext(ctx).Warn("staged device not found")
		return found, false, nil
	}

	if strings.HasSuffix(stageInfo.Source, "deleted") {
		log.WithContext(ctx).Warn("staged device linked with deleted path")
		return found, false, nil
	}

	devFS, err := fs.GetUtil().GetDiskFormat(ctx, stagingPath)
	if err != nil {
		return found, false, err
	}
	return found, devFS != "mpath_member", nil
}

func isReadyToPublishNFS(ctx context.Context, stagingPath string, fs fs.Interface) (bool, error) {
	stageInfo, found, err := getTargetMount(ctx, stagingPath, fs)
	if err != nil {
		return found, err
	}
	if !found {
		log.WithContext(ctx).Warn("staged device not found")
		return found, nil
	}

	if strings.HasSuffix(stageInfo.Source, "deleted") {
		log.WithContext(ctx).Warn("staged device linked with deleted path")
		return found, nil
	}

	return found, nil
}

func (s *SCSIStager) AddTargetsInfoToMap(
	targetMap map[string]string, volumeApplianceID string, client gopowerstore.Client, isRemote bool,
) error {
	iscsiPortalsKey := identifiers.TargetMapISCSIPortalsPrefix
	iscsiTargetsKey := identifiers.TargetMapISCSITargetsPrefix
	fcWwpnKey := identifiers.TargetMapFCWWPNPrefix
	nvmeFcPortalsKey := identifiers.TargetMapNVMEFCPortalsPrefix
	nvmeFcTargetsKey := identifiers.TargetMapNVMEFCTargetsPrefix
	nvmeTCPPortalsKey := identifiers.TargetMapNVMETCPPortalsPrefix
	nvmeTCPTargetsKey := identifiers.TargetMapNVMETCPTargetsPrefix
	if isRemote {
		iscsiPortalsKey = identifiers.TargetMapRemoteISCSIPortalsPrefix
		iscsiTargetsKey = identifiers.TargetMapRemoteISCSITargetsPrefix
		fcWwpnKey = identifiers.TargetMapRemoteFCWWPNPrefix
		nvmeFcPortalsKey = identifiers.TargetMapRemoteNVMEFCPortalsPrefix
		nvmeFcTargetsKey = identifiers.TargetMapRemoteNVMEFCTargetsPrefix
		nvmeTCPPortalsKey = identifiers.TargetMapRemoteNVMETCPPortalsPrefix
		nvmeTCPTargetsKey = identifiers.TargetMapRemoteNVMETCPTargetsPrefix
	}

	iscsiTargetsInfo, err := identifiers.GetISCSITargetsInfoFromStorage(client, volumeApplianceID)
	if err != nil {
		log.WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "addTargetsInfoToPublishContext",
			log.FieldProtocol:  "iSCSI",
			log.FieldError:     err.Error(),
		}).Error("unable to get iSCSI targets from array")
	}
	for i, t := range iscsiTargetsInfo {
		targetMap[fmt.Sprintf("%s%d", iscsiPortalsKey, i)] = t.Portal
		targetMap[fmt.Sprintf("%s%d", iscsiTargetsKey, i)] = t.Target
	}
	fcTargetsInfo, err := identifiers.GetFCTargetsInfoFromStorage(client, volumeApplianceID)
	if err != nil {
		log.WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "addTargetsInfoToPublishContext",
			log.FieldProtocol:  "FC",
			log.FieldError:     err.Error(),
		}).Error("unable to get FC targets from array")
	}
	for i, t := range fcTargetsInfo {
		targetMap[fmt.Sprintf("%s%d", fcWwpnKey, i)] = t.WWPN
	}

	nvmefcTargetInfo, err := identifiers.GetNVMEFCTargetInfoFromStorage(client, volumeApplianceID)
	if err != nil {
		log.WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "addTargetsInfoToPublishContext",
			log.FieldProtocol:  "NVMeFC",
			log.FieldError:     err.Error(),
		}).Error("unable to get NVMeFC targets from array")
	}
	for i, t := range nvmefcTargetInfo {
		targetMap[fmt.Sprintf("%s%d", nvmeFcPortalsKey, i)] = t.Portal
		targetMap[fmt.Sprintf("%s%d", nvmeFcTargetsKey, i)] = t.Target
	}

	nvmetcpTargetInfo, err := identifiers.GetNVMETCPTargetsInfoFromStorage(client, volumeApplianceID)
	if err != nil {
		log.WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "addTargetsInfoToPublishContext",
			log.FieldProtocol:  "NVMeTCP",
			log.FieldError:     err.Error(),
		}).Error("unable to get NVMeTCP targets from array")
	}
	for i, t := range nvmetcpTargetInfo {
		targetMap[fmt.Sprintf("%s%d", nvmeTCPPortalsKey, i)] = t.Portal
		targetMap[fmt.Sprintf("%s%d", nvmeTCPTargetsKey, i)] = t.Target
	}

	// If the system is not capable of any protocol, then we will through the error
	if len(iscsiTargetsInfo) == 0 && len(fcTargetsInfo) == 0 && len(nvmefcTargetInfo) == 0 && len(nvmetcpTargetInfo) == 0 {
		return errors.New("unable to get targets for any protocol")
	}
	return nil
}
