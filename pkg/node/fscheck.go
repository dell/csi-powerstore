/*
 *
 * Copyright © 2025-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-metadata-retriever/retriever"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	fs "github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csmlog"
	"github.com/dell/gofsutil"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	typedv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

const (
	fsCheckModeCheckOnly      = "checkonly"
	fsCheckModeCheckAndRepair = "checkandrepair"
	clientConnectionTimeSec   = 100
	fsCheckFailed             = "FSCheckFailed"
)

// FsCheckRunner holds the resolved FS check configuration for a single publish operation.
type FsCheckRunner struct {
	// fs check feature toggle
	enabled bool
	// lowercased fs check mode
	mode              string
	pvName            string
	pvcName           string
	pvcNamespace      string
	fullVolumeID      string
	metadataRetriever retriever.MetadataRetrieverClient
	eventRecorder     record.EventRecorder
	fsDevice          string
	fsType            string
	log               *csmlog.CsmLog
}

// fsCheckPVCObserver bridges gofsutil.FSCheckObserver events to structured logs and Kubernetes PVC events.
type fsCheckPVCObserver struct {
	pvcName       string
	pvcNamespace  string
	eventRecorder record.EventRecorder
	logger        *csmlog.CsmLog
	timedOut      bool
}

// OnEvent is called by gofsutil.FSChecker during check/repair lifecycle.
func (o *fsCheckPVCObserver) OnEvent(message string) {
	o.logger.Infof("FS check event: %s", message)

	if o.eventRecorder == nil || o.pvcName == "" {
		eRecorderStr := ""
		if o.eventRecorder == nil {
			eRecorderStr = "eventRecorder is nil"
		}
		o.logger.Warnf("FS check event: %s pvcName (%s) %s", eRecorderStr, o.pvcName, message)
		return
	}

	eventType := corev1.EventTypeNormal
	reason := "FSCheck"

	switch message {
	case gofsutil.StartedFSCheckEvent:
		reason = "FSCheckStarted"
	case gofsutil.FoundNoErrorsEvent:
		reason = "FSCheckSucceeded"
	case gofsutil.FinishedFSRepairEvent:
		reason = "FSCheckRepaired"
	case gofsutil.FoundErrorsEvent, gofsutil.FSCheckFailedEvent:
		eventType = corev1.EventTypeWarning
		reason = fsCheckFailed
	case gofsutil.FSCheckTimedOutEvent, gofsutil.FSRepairTimedOutEvent:
		eventType = corev1.EventTypeWarning
		reason = "FSCheckTimedOut"
		o.timedOut = true
		o.logger.Errorf("FS Check timed out on pvc:%s", o.pvcName)
	case gofsutil.FSRepairFailedEvent:
		eventType = corev1.EventTypeWarning
		reason = "FSRepairFailed"
	case gofsutil.StartFSRepairEvent:
		reason = "FSRepairStarted"
	case gofsutil.FoundDirtyLogEvent:
		reason = "FSCheckFoundDirtyLog"
	case gofsutil.StartLogReplayEvent:
		reason = "FSLogReplayStarted"
	case gofsutil.LogReplayFailedEvent:
		eventType = corev1.EventTypeWarning
		reason = "FSLogReplayFailed"
	case gofsutil.LogReplayDoneEvent:
		reason = "FSLogReplayDone"
	}

	pvcRef := &corev1.ObjectReference{
		Kind:      "PersistentVolumeClaim",
		Name:      o.pvcName,
		Namespace: o.pvcNamespace,
	}
	o.eventRecorder.Event(pvcRef, eventType, reason, message)
}

// validatePreconditions checks if FS check should be skipped based on filesystem type,
// access mode, and mount status. Returns empty string if FS check should proceed,
// otherwise returns the reason for skipping.
func (fsck *FsCheckRunner) validatePreconditions(ctx context.Context, accessMode csi.VolumeCapability_AccessMode_Mode, fsI fs.Interface) (string, error) {
	fsType := fsck.fsType

	// Validate file system type first
	if fsType == "" {
		return "newly formatted volume", nil
	}
	if fsType != "xfs" && fsType != "ext4" && fsType != "ext3" && fsType != "ext2" {
		return "unsupported file system type " + fsType, nil
	}

	// Validate volume access mode - should not be mounted on multiple nodes
	switch accessMode {
	case csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY,
		csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY,
		csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER,
		csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER:

		return "unsupported volume access mode " + accessMode.String(), nil
	}

	// Make sure the volume is not yet mounted
	mounts, err := getMounts(ctx, fsI)
	if err != nil {
		return "", fmt.Errorf("failed to get mounts: %v", err)
	}
	for _, m := range mounts {
		if m.Device == fsck.fsDevice || m.Source == fsck.fsDevice {
			return "volume already mounted on this node at " + m.Path, nil
		}
	}

	return "", nil
}

// Find skip reasons first, if it's ok to fscheck
// then check for pvc labels and then check for global
func (fsck *FsCheckRunner) CheckFileSystem(
	ctx context.Context,
	accessMode csi.VolumeCapability_AccessMode_Mode,
	fsI fs.Interface,
) error {
	skipReason, err := fsck.validatePreconditions(ctx, accessMode, fsI)
	if err != nil {
		return fmt.Errorf("failed to validate preconditions: %v", err)
	}
	if skipReason != "" {
		fsck.log.Infof("Skipping FS check: %s", skipReason)
		return nil
	}

	err = fsck.resolveEffectiveSettings(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve effective fs check settings: %v", err)
	}
	if fsck.enabled {
		if err := fsck.run(ctx); err != nil {
			return fmt.Errorf("FS check failed: %w", err)
		}
	}

	return nil
}

// getFSCheckerFunc is a variable to allow mocking in tests.
var getFSCheckerFunc = gofsutil.GetFSChecker

// run executes the FS check flow and returns an error if the volume should not be mounted.
func (fsck *FsCheckRunner) run(ctx context.Context) error {
	doRepair := fsck.mode == fsCheckModeCheckAndRepair

	observer := &fsCheckPVCObserver{
		pvcName:       fsck.pvcName,
		pvcNamespace:  fsck.pvcNamespace,
		eventRecorder: fsck.eventRecorder,
		logger:        fsck.log,
	}

	fsDev := fsck.fsDevice
	fsType := fsck.fsType

	checker, err := getFSCheckerFunc(fsDev, fsType, observer)
	if err != nil {
		return fmt.Errorf("failed to create FSChecker for device %s (fs: %s): %v", fsDev, fsType, err)
	}

	fsck.log.Infof("Running FS check on %s (fs: %s, doRepair: %v)", fsDev, fsType, doRepair)

	err = checker.Check(ctx, doRepair)
	if err != nil {
		if observer.timedOut {
			return status.Errorf(codes.Aborted,
				"File system check timed out on device %s (volume ID: %s, fs: %s). Will retry on next publish volume attempt.",
				fsDev, fsck.fullVolumeID, fsType)
		}

		errMsg := fmt.Sprintf("File system check failed on device %s (volume ID: %s, fs: %s): %v. "+
			"Manual intervention required. Do not attempt to mount this volume until the file system has been repaired.",
			fsDev, fsck.fullVolumeID, fsType, err)
		fsck.log.Error(errMsg)

		if fsck.pvcName != "" && fsck.pvcNamespace != "" {
			pvcRef := &corev1.ObjectReference{
				Kind:      "PersistentVolumeClaim",
				Name:      fsck.pvcName,
				Namespace: fsck.pvcNamespace,
			}
			if fsck.eventRecorder != nil {
				fsck.eventRecorder.Event(pvcRef, corev1.EventTypeWarning, fsCheckFailed,
					fmt.Sprintf("File system on device %s (fs: %s) cannot be mounted safely. Manual intervention required.", fsck.fsDevice, fsck.fsType))
			}
		}

		return status.Error(codes.Internal, errMsg)
	}

	fsck.log.Infof("FS check completed successfully on %s (fs: %s)", fsDev, fsType)
	return nil
}

// newNodeEventRecorder creates a record.EventRecorder for the node service FS check events.
var newNodeEventRecorder = func(kubeConfigPath string) (record.EventRecorder, error) {
	kubeclient, err := k8sutils.CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client for FS check events: %w", err)
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&typedv1core.EventSinkImpl{Interface: kubeclient.Clientset.CoreV1().Events("")})

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add scheme for FS check events: %w", err)
	}

	eventRecorder := eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: "csi-powerstore-node"})
	return eventRecorder, nil
}

// NewFSCheckRunner creates a new FsCheckRunner instance with the provided configuration
// and initializes its metadata retriever and event recorder.
func NewFSCheckRunner(opts *Opts, volumeContext map[string]string, fullVolumeID string) *FsCheckRunner {
	fsck := &FsCheckRunner{
		enabled:           opts.FsCheckEnabled,
		mode:              strings.ToLower(opts.FsCheckMode),
		pvName:            volumeContext[controller.KeyCSIPVName],
		pvcName:           volumeContext[controller.KeyCSIPVCName],
		pvcNamespace:      volumeContext[controller.KeyCSIPVCNamespace],
		fullVolumeID:      fullVolumeID,
		metadataRetriever: initFsCheckMetadataRetriever(),
		eventRecorder:     initFsCheckEventRecorder(opts.KubeConfigPath),
		log:               log, // default is the package level logger
	}

	return fsck
}

var (
	// Cached metadata retriever client shared across all FsCheckRunner instances
	cachedMetadataRetriever retriever.MetadataRetrieverClient
	metadataRetrieverOnce   sync.Once

	// Cached event recorder shared across all FsCheckRunner instances
	cachedEventRecorder record.EventRecorder
	eventRecorderOnce   sync.Once
)

// initFsCheckMetadataRetriever initializes the metadata retriever.
// Returns a cached singleton instance.
func initFsCheckMetadataRetriever() retriever.MetadataRetrieverClient {
	metadataRetrieverOnce.Do(func() {
		cachedMetadataRetriever = retriever.NewMetadataRetrieverClient(nil, clientConnectionTimeSec*time.Second)
	})
	return cachedMetadataRetriever
}

// initFsCheckEventRecorder initializes the Kubernetes event recorder for FS check events.
// Returns a cached singleton instance.
func initFsCheckEventRecorder(kubeConfigPath string) record.EventRecorder {
	eventRecorderOnce.Do(func() {
		recorder, err := newNodeEventRecorder(kubeConfigPath)
		if err != nil {
			log.Errorf("Failed to initialize FS check event recorder: %v - PVC events will not be posted", err)
			return
		}
		cachedEventRecorder = recorder
	})
	return cachedEventRecorder
}

// SetLogger sets the logger for the FsCheckRunner instance.
func (fsck *FsCheckRunner) SetLogger(logger *csmlog.CsmLog) {
	fsck.log = logger
}

var pvNameFromPathRegex = regexp.MustCompile(`/.*/pods/[^/]+/volumes/kubernetes\.io~csi/([^/]+)/mount`)

// ResolvePVNameFromTargetPath extracts the PV name from the target path
// and sets it on the context if PvName is not already set.
func (fsck *FsCheckRunner) ResolvePVNameFromTargetPath(targetPath string) {
	if fsck.pvName != "" {
		// Use the existing value
		return
	}
	// Fall back to parsing the PV name from the target path
	// Expected format: <kubelet-dir>/pods/<pod-uid>/volumes/kubernetes.io~csi/<pv-name>/mount
	matches := pvNameFromPathRegex.FindStringSubmatch(targetPath)
	if len(matches) > 1 {
		fsck.pvName = matches[1]
	}
	if fsck.pvName == "" {
		// Metadata retriever will be fall back to the slowest method - listing all PVs in the cluster
		fsck.log.Warnf("Could not parse PV name from target path %s, will iterate over all PVs", targetPath)
	}
}

// resolveEffectiveSettings resolves the effective FS check configuration
// for a volume by using the global (driver level) settings as the base and
// overriding them with the PVC level settings (PVC labels), if set.
func (fsck *FsCheckRunner) resolveEffectiveSettings(ctx context.Context) error {
	resp, err := fsck.metadataRetriever.GetPVCLabelsByPVName(ctx, &retriever.GetPVCLabelsByPVNameRequest{
		PVName:       fsck.pvName,
		VolumeHandle: fsck.fullVolumeID,
		PVCName:      fsck.pvcName,
		PVCNamespace: fsck.pvcNamespace,
	})
	if err != nil {
		return fmt.Errorf("could not retrieve PVC labels: %v", err)
	}
	// Metadata retriever always returns the actual PVC name and namespace in the successful response
	fsck.pvcName = resp.PVCName
	fsck.pvcNamespace = resp.PVCNamespace
	fsck.pvName = resp.PVName

	// Determine the effective FS check Enabled option
	val, ok := resp.Parameters[identifiers.PvcLabelFsCheckEnabled]
	if ok {
		val = strings.ToLower(val)
		if val == "true" || val == "false" {
			fsck.enabled = (val == "true")
		} else {
			fsck.log.Warnf("Invalid PVC label value %q for %s, using global FS check setting.", val, identifiers.PvcLabelFsCheckEnabled)
		}
	}

	if fsck.enabled {
		// Determine the effective FS check Mode option
		val, ok = resp.Parameters[identifiers.PvcLabelFsCheckMode]
		if ok {
			val = strings.ToLower(val)
			if val == fsCheckModeCheckOnly || val == fsCheckModeCheckAndRepair {
				fsck.mode = val
			} else {
				fsck.log.Warnf("Invalid PVC label value %q for %s, using global FS check setting", val, identifiers.PvcLabelFsCheckMode)
			}
		}
	}

	return nil
}
