/*
 *
 * Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csmlog"
	"github.com/dell/gofsutil"
	"github.com/robfig/cron/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

// ---- Annotation key constants ----

const (
	// LabelPrefix is the prefix for space reclamation PVC labels.
	LabelPrefix = "space-reclamation.csi.dell.com/"
	// LabelEnabled controls per-PVC opt-in/opt-out via labels for filesystem volumes.
	LabelEnabled = LabelPrefix + "enabled"
	// LabelBlockReclaim controls per-PVC opt-in for block volumes.
	LabelBlockReclaim = LabelPrefix + "block-reclaim"
	// AnnotationPrefix is the prefix for all space reclamation PVC annotations.
	AnnotationPrefix = "space-reclamation.csi.dell.com/"
	// AnnotationLastRunTime records the last reclamation timestamp.
	AnnotationLastRunTime = AnnotationPrefix + "last-run-time"
	// AnnotationBytesReclaim records bytes reclaimed.
	AnnotationBytesReclaim = AnnotationPrefix + "bytes-reclaimed"
	// AnnotationDuration records the reclamation duration in seconds.
	AnnotationDuration = AnnotationPrefix + "duration-seconds"
	// AnnotationStatus records the reclamation status.
	AnnotationStatus = AnnotationPrefix + "status"
	// AnnotationErrorMsg records any error message.
	AnnotationErrorMsg = AnnotationPrefix + "error-message"
	// AnnotationNode records the node that performed reclamation.
	AnnotationNode = AnnotationPrefix + "node"
)

// ---- Event reason constants ----

const (
	// EventReasonCompleted is the event reason for successful reclamation.
	EventReasonCompleted = "SpaceReclamationCompleted"
	// EventReasonFailed is the event reason for failed reclamation.
	EventReasonFailed = "SpaceReclamationFailed"
	// EventReasonTimeout is the event reason for timed-out reclamation.
	EventReasonTimeout = "SpaceReclamationTimeout"
	// EventReasonUnsupported is the event reason for unsupported devices.
	EventReasonUnsupported = "SpaceReclamationUnsupported"
)

// ---- Volume mode constants ----

// VolumeMode distinguishes filesystem from raw block volumes.
type VolumeMode corev1.PersistentVolumeMode

// Volume mode constants
const (
	VolumeModeFilesystem VolumeMode = VolumeMode(corev1.PersistentVolumeFilesystem)
	VolumeModeBlock      VolumeMode = VolumeMode(corev1.PersistentVolumeBlock)
)

// ---- Configuration ----

// SpaceReclamationConfig holds configuration for the space reclamation feature.
type SpaceReclamationConfig struct {
	// Enabled gates the entire subsystem.
	Enabled bool
	// Schedule is a cron expression (5-field). Default: "0 2 * * 0".
	Schedule string
	// MaxConcurrentVolumes is the max parallel reclamation jobs per node. Default: 2.
	MaxConcurrentVolumes int
	// TimeoutSeconds is the per-volume timeout. Default: 14400.
	TimeoutSeconds int
	// NodeName is the Kubernetes node name (from downward API or env var).
	NodeName string
}

// getEnvString reads an environment variable and returns a default if unset or empty.
func getEnvString(key, defaultVal string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val
}

// getEnvBool reads an environment variable as a boolean, returning a default on error or empty.
func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return defaultVal
	}
	return b
}

// getEnvInt reads an environment variable as an int, returning a default on error, empty, or negative.
func getEnvInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	if i < 0 {
		return defaultVal
	}
	return i
}

// ReadSpaceReclamationConfig reads configuration from environment variables.
func ReadSpaceReclamationConfig() SpaceReclamationConfig {
	log := csmlog.GetLogger()
	cfg := SpaceReclamationConfig{
		Enabled:              getEnvBool(identifiers.EnvSpaceReclamationEnabled, false),
		Schedule:             getEnvString(identifiers.EnvSpaceReclamationSchedule, "0 2 * * 0"),
		MaxConcurrentVolumes: getEnvInt(identifiers.EnvSpaceReclamationMaxConcurrent, 2),
		TimeoutSeconds:       getEnvInt(identifiers.EnvSpaceReclamationTimeout, 14400),
		NodeName:             getEnvString(identifiers.EnvKubeNodeName, ""),
	}
	log.Infof("SpaceReclamation: configuration loaded - Enabled=%v, Schedule=%q, MaxConcurrentVolumes=%d, TimeoutSeconds=%d, NodeName=%q",
		cfg.Enabled, cfg.Schedule, cfg.MaxConcurrentVolumes, cfg.TimeoutSeconds, cfg.NodeName)
	if !cfg.Enabled {
		log.Infof("SpaceReclamation: feature is disabled via configuration")
	}
	return cfg
}

// ---- Volume Info ----

// VolumeInfo stores metadata about a staged volume for reclamation.
type VolumeInfo struct {
	VolumeID     string
	StagingPath  string     // Mount point for filesystem PVs; device path for block PVs
	DevicePath   string     // Underlying block device (e.g., /dev/sda, /dev/dm-0)
	VolumeMode   VolumeMode // Filesystem or Block
	PVName       string     // PersistentVolume name
	PVCName      string
	PVCNamespace string
	PVC          *corev1.PersistentVolumeClaim // PVC object (fetched in RunOnce, reused in reclaimVolume)
}

// ---- Reclamation Result ----

// ReclamationResult represents the outcome of a reclamation operation.
type ReclamationResult struct {
	Status         string // "success", "error", "timeout", "unsupported", "skipped"
	BytesReclaimed int64
	Duration       time.Duration
	ErrorMessage   string // populated on failure
	NodeName       string
}

// ---- PVC Annotator ----

// PVCAnnotator updates PVC annotations with reclamation results.
type PVCAnnotator struct {
	client   kubernetes.Interface
	maxRetry int
}

// NewPVCAnnotator creates a new PVCAnnotator.
func NewPVCAnnotator(client kubernetes.Interface) *PVCAnnotator {
	return &PVCAnnotator{
		client:   client,
		maxRetry: 3,
	}
}

// Annotate updates the PVC with reclamation result annotations.
// It handles 404 (PVC not found) and 409 (conflict, retry) responses.
func (a *PVCAnnotator) Annotate(ctx context.Context, pvcName, pvcNamespace string, result *ReclamationResult) error {
	var lastErr error
	for attempt := 0; attempt <= a.maxRetry; attempt++ {
		// GET the latest PVC
		pvc, err := a.client.CoreV1().PersistentVolumeClaims(pvcNamespace).Get(ctx, pvcName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get PVC %s/%s: %w", pvcNamespace, pvcName, err)
		}

		// Merge annotations
		if pvc.Annotations == nil {
			pvc.Annotations = make(map[string]string)
		}
		pvc.Annotations[AnnotationStatus] = result.Status
		pvc.Annotations[AnnotationLastRunTime] = time.Now().UTC().Format(time.RFC3339)
		pvc.Annotations[AnnotationBytesReclaim] = strconv.FormatInt(result.BytesReclaimed, 10)
		pvc.Annotations[AnnotationDuration] = strconv.FormatInt(int64(result.Duration/time.Second), 10)
		pvc.Annotations[AnnotationNode] = result.NodeName
		if result.ErrorMessage != "" {
			pvc.Annotations[AnnotationErrorMsg] = result.ErrorMessage
		} else {
			// Clear error message on success to remove stale error states
			delete(pvc.Annotations, AnnotationErrorMsg)
		}

		// UPDATE the PVC
		_, err = a.client.CoreV1().PersistentVolumeClaims(pvcNamespace).Update(ctx, pvc, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		lastErr = err
		// Retry on conflict (409)
		if strings.Contains(err.Error(), "the object has been modified") || strings.Contains(err.Error(), "Conflict") {
			continue
		}
		return fmt.Errorf("failed to update PVC %s/%s: %w", pvcNamespace, pvcName, err)
	}
	return lastErr
}

func discoverBlockDeviceFromCSIStaging(pvName string) (string, error) {
	// According to Kubernetes CSI raw block volume semantics,
	// kubelet exposes the block device as a single device node named "dev"
	// under the volumeDevices/<pvName>/ directory.
	// This path is kubelet-defined and consistent across CSI drivers.
	devDir := filepath.Join("/var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices", pvName, "dev")

	entries, err := osReadDirFunc(devDir)
	if err != nil {
		return "", fmt.Errorf("failed to read dev directory %s: %w", devDir, err)
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeDevice != 0 {
			devPath := filepath.Join(devDir, entry.Name())

			// Get device major/minor numbers
			stat, err := osStatFunc(devPath)
			if err != nil {
				return "", fmt.Errorf("failed to stat device %s: %w", devPath, err)
			}

			sysStat, ok := stat.Sys().(*syscall.Stat_t)
			if !ok {
				return "", fmt.Errorf("failed to get device stat for %s", devPath)
			}

			major := uint64(sysStat.Rdev / 256)
			minor := uint64(sysStat.Rdev % 256)

			// Find the actual device in /dev by major/minor
			actualPath, err := findDeviceByMajorMinorFunc(major, minor)
			if err != nil {
				return "", fmt.Errorf("failed to find device by major/minor: %w", err)
			}

			return actualPath, nil
		}
	}
	return "", fmt.Errorf("no device found in %s", devDir)
}

func findDeviceByMajorMinor(major, minor uint64) (string, error) {
	// Read /sys/dev/block/major:minor to get the device name
	devBlockPath := fmt.Sprintf("/sys/dev/block/%d:%d", major, minor)

	realPath, err := filepath.EvalSymlinks(devBlockPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve sysfs symlink: %w", err)
	}

	// The symlink points to something like ../../dm-0
	devName := filepath.Base(realPath)

	// Construct /dev path
	devPath := "/dev/" + devName

	// If it's a dm device, try to resolve to /dev/mapper/* for better compatibility
	if strings.HasPrefix(devName, "dm-") {
		mapperPath := filepath.Join("/dev/mapper", getMapperName(devName))
		if _, err := os.Stat(mapperPath); err == nil {
			return mapperPath, nil
		}
	}

	// Verify the device exists
	if _, err := os.Stat(devPath); err != nil {
		return "", fmt.Errorf("device path %s does not exist: %w", devPath, err)
	}

	return devPath, nil
}

func getMapperName(dmDevice string) string {
	// Read /sys/block/dm-*/dm/name to get the mapper name
	namePath := fmt.Sprintf("/sys/block/%s/dm/name", dmDevice)
	if data, err := os.ReadFile(namePath); err == nil {
		return strings.TrimSpace(string(data))
	}
	return dmDevice
}

func getVolumeIDFromCsiVolumeID(csiHandle string) string {
	// PowerStore: use full handle as stable identifier
	return csiHandle
}

// ---- Event Emitter ----

// EventEmitter creates Kubernetes Events on PVCs.
type EventEmitter struct {
	recorder record.EventRecorder
}

// NewEventEmitter creates a new EventEmitter with a Kubernetes event recorder.
func NewEventEmitter(clientset kubernetes.Interface, driverName string) *EventEmitter {
	if clientset == nil {
		return &EventEmitter{}
	}
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{
		Interface: clientset.CoreV1().Events(""),
	})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: driverName})
	return &EventEmitter{recorder: recorder}
}

// EmitSuccess records a successful reclamation event on the PVC.
func (e *EventEmitter) EmitSuccess(pvc *corev1.PersistentVolumeClaim, bytesReclaimed int64, duration time.Duration) {
	if e.recorder == nil {
		return
	}
	msg := fmt.Sprintf("Space reclamation completed: %d bytes reclaimed in %.2fs", bytesReclaimed, duration.Seconds())
	e.recorder.Event(pvc, corev1.EventTypeNormal, EventReasonCompleted, msg)
}

// EmitFailure records a failed reclamation event on the PVC.
func (e *EventEmitter) EmitFailure(pvc *corev1.PersistentVolumeClaim, err error) {
	if e.recorder == nil {
		return
	}
	msg := fmt.Sprintf("Space reclamation failed: %v", err)
	e.recorder.Event(pvc, corev1.EventTypeWarning, EventReasonFailed, msg)
}

// EmitTimeout records a timed-out reclamation event on the PVC.
func (e *EventEmitter) EmitTimeout(pvc *corev1.PersistentVolumeClaim, timeout time.Duration) {
	if e.recorder == nil {
		return
	}
	msg := fmt.Sprintf("Space reclamation timed out after %v", timeout)
	e.recorder.Event(pvc, corev1.EventTypeWarning, EventReasonTimeout, msg)
}

// EmitUnsupported records an unsupported-device reclamation event on the PVC.
func (e *EventEmitter) EmitUnsupported(pvc *corev1.PersistentVolumeClaim, reason string) {
	if e.recorder == nil {
		return
	}
	msg := fmt.Sprintf("Device does not support space reclamation: %s", reason)
	e.recorder.Event(pvc, corev1.EventTypeWarning, EventReasonUnsupported, msg)
}

func IsEligible(globalEnabled bool, labels map[string]string, volumeMode VolumeMode) (bool, string) {
	// Block mode requires explicit opt-in via label
	if volumeMode == VolumeModeBlock {
		if labels == nil {
			return false, "block mode requires explicit opt-in label (labels are not present)"
		}

		val, ok := labels[LabelBlockReclaim]
		if !ok {
			return false, fmt.Sprintf(
				"block mode requires explicit opt-in label (%s is missing)",
				LabelBlockReclaim,
			)
		}

		if !strings.EqualFold(val, "true") {
			return false, fmt.Sprintf(
				"block mode requires explicit opt-in label (%s=%s, must be 'true')",
				LabelBlockReclaim, val,
			)
		}

		return true, ""
	}

	// Filesystem mode: explicit label takes precedence, otherwise follow global config
	if labels == nil {
		if globalEnabled {
			return true, ""
		}
		return false, "global disabled"
	}
	val, ok := labels[LabelEnabled]
	if !ok {
		if globalEnabled {
			return true, ""
		}
		return false, "global disabled"
	}
	if strings.EqualFold(val, "true") {
		return true, ""
	}
	return false, fmt.Sprintf("label is '%s' (must be 'true' to override global)", val)
}

// ---- Injectable function variables (overridable in tests) ----

// validateDiscardSysfsFunc is overridable in tests to avoid real sysfs reads.
// var validateDiscardSysfsFunc = validateDiscardSysfs

// checkDiscardSupportFunc is overridable in tests to avoid real sysfs reads.
var checkDiscardSupportFunc = func(ctx context.Context, devicePath string) (*gofsutil.DiscardCapability, error) {
	return gofsutil.CheckDiscardSupport(ctx, devicePath)
}

// osReadDirFunc is overridable in tests to mock directory reading.
var osReadDirFunc = os.ReadDir

// osStatFunc is overridable in tests to mock file stat operations.
var osStatFunc = os.Stat

// findDeviceByMajorMinorFunc is overridable in tests to mock device discovery.
var findDeviceByMajorMinorFunc = findDeviceByMajorMinor

// getMountsFunc is overridable in tests to mock mount scanning.
var getMountsFunc = gofsutil.GetMounts

// getVolumeIDFromCsiVolumeIDFunc is overridable in tests to mock volume ID extraction.
var getVolumeIDFromCsiVolumeIDFunc = getVolumeIDFromCsiVolumeID

// isEligibleFunc is overridable in tests to mock eligibility checking.
var isEligibleFunc = IsEligible

// discoverBlockDeviceFromCSIStagingFunc is overridable in tests to mock block device discovery.
var discoverBlockDeviceFromCSIStagingFunc = discoverBlockDeviceFromCSIStaging

// fstrimFunc is overridable in tests to mock fstrim operations.
var fstrimFunc = gofsutil.Fstrim

// blkdiscardFunc is overridable in tests to mock blkdiscard operations.
var blkdiscardFunc = gofsutil.Blkdiscard

// ---- Space Reclamation Manager ----

// SpaceReclamationManager orchestrates periodic space reclamation on staged volumes.
type SpaceReclamationManager struct {
	config          SpaceReclamationConfig
	annotator       *PVCAnnotator
	emitter         *EventEmitter
	k8sClient       kubernetes.Interface
	semaphore       chan struct{}
	volumeLocks     sync.Map
	ctx             context.Context
	cronSched       *cron.Cron
	running         atomic.Bool // Flag to prevent overlapping RunOnce cycles
	currentSchedule string
}

// NewSpaceReclamationManager creates a new SpaceReclamationManager.
// Returns error if the cron schedule expression is invalid.
func NewSpaceReclamationManager(
	ctx context.Context,
	config SpaceReclamationConfig,
	k8sClient kubernetes.Interface,
	nodeName string,
) (*SpaceReclamationManager, error) {
	log := csmlog.GetLogger()
	// Validate the cron expression by attempting to parse it
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(config.Schedule)
	if err != nil {
		log.Errorf("Invalid cron schedule %q: %v", config.Schedule, err)
		return nil, fmt.Errorf("invalid cron schedule %q: %w", config.Schedule, err)
	}
	log.Infof("SpaceReclamation: cron schedule %q validated successfully (next run would be: %v)", config.Schedule, schedule.Next(time.Now()))

	config.NodeName = nodeName

	semSize := config.MaxConcurrentVolumes
	if semSize <= 0 {
		log.Infof("SpaceReclamation: MaxConcurrentVolumes is %d, using default of 1", semSize)
		semSize = 1
	}

	mgr := &SpaceReclamationManager{
		config:          config,
		annotator:       NewPVCAnnotator(k8sClient),
		emitter:         NewEventEmitter(k8sClient, identifiers.Name),
		k8sClient:       k8sClient,
		semaphore:       make(chan struct{}, semSize),
		ctx:             ctx,
		currentSchedule: config.Schedule,
	}
	log.Infof("SpaceReclamation: manager initialized for node %s with concurrency limit %d", nodeName, semSize)
	return mgr, nil
}

func (m *SpaceReclamationManager) Start() error {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

	if m.cronSched != nil {
		m.cronSched.Stop()
		log.Infof("SpaceReclamation: stopped previous scheduler before starting with new schedule")
	}

	m.cronSched = cron.New(cron.WithParser(parser))
	_, err := m.cronSched.AddFunc(m.config.Schedule, m.RunOnce)
	if err != nil {
		log.Errorf("SpaceReclamation: failed to add cron job: %v", err)
		return fmt.Errorf("failed to add cron job: %w", err)
	}

	m.currentSchedule = m.config.Schedule
	m.cronSched.Start()

	log.Infof("SpaceReclamation: scheduler started with schedule %q on node %s", m.currentSchedule, m.config.NodeName)
	return nil
}

func (m *SpaceReclamationManager) RunOnce() {
	log := csmlog.GetLogger()
	log.Info("SpaceReclamation: starting RunOnce cycle")

	if !m.running.CompareAndSwap(false, true) {
		log.Warn("SpaceReclamation: previous run still in progress, skipping this cycle")
		return
	}
	defer m.running.Store(false)

	ctx, cancel := context.WithTimeout(
		m.ctx,
		time.Duration(m.config.TimeoutSeconds)*time.Second,
	)
	defer cancel()

	// Step 1: List PVs in the cluster (field selector on status.phase not supported, filter client-side)
	pvList, err := m.k8sClient.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Errorf("SpaceReclamation: failed to list PersistentVolumes: %v", err)
		return
	}
	log.Infof("SpaceReclamation: found %d total PVs", len(pvList.Items))

	// Step 2: Build device -> mount map (filesystem PVs)
	mounts, err := getMountsFunc(ctx)
	if err != nil {
		log.Errorf("SpaceReclamation: failed to get mounts: %v", err)
		return
	}
	log.Infof("SpaceReclamation: found %d total mounts", len(mounts))
	log.Infof("SpaceReclamation: mounts: %v", mounts)

	deviceToMount := map[string]string{}
	for _, mnt := range mounts {
		// PowerStore CSI globalmount root is backed by devtmpfs.
		// fstrim must NOT run on devtmpfs.
		if mnt.Device == "devtmpfs" {
			continue
		}

		// skip non-csi mounts
		if !strings.Contains(mnt.Path, "/var/lib/kubelet/pods/") &&
			!strings.Contains(mnt.Path, "/var/lib/kubelet/plugins/kubernetes.io/csi/") {
			continue
		}

		// Prefer the actual filesystem mount (ext4/xfs), which for PowerStore
		// appears at the pod publish path.
		if cur, ok := deviceToMount[mnt.Device]; !ok ||
			(strings.Contains(mnt.Path, "/var/lib/kubelet/pods/") &&
				!strings.Contains(cur, "/var/lib/kubelet/pods/")) {
			deviceToMount[mnt.Device] = mnt.Path
		}
	}

	var wg sync.WaitGroup
	var processedCount int
	var skippedCount int

	// Step 3: Process PVs
	for i := range pvList.Items {
		pv := &pvList.Items[i]
		var volID string
		var volMode VolumeMode
		var eligible bool
		var reason string

		// Early checks before accessing nested fields
		if pv.Spec.CSI == nil || pv.Spec.CSI.Driver != identifiers.Name {
			log.Infof("SpaceReclamation: Volume %s is not a CSI volume or uses wrong driver, skipping", pv.Name)
			continue
		}

		// Filter: only process Bound PVs
		if pv.Status.Phase != corev1.VolumeBound {
			continue
		}

		skipPV := false
		for _, am := range pv.Spec.AccessModes {
			if am == corev1.ReadWriteMany {
				log.Infof("SpaceReclamation: Volume %s (ReadWriteMany) is not supported for space reclamation", pv.Name)
				skipPV = true
				break
			}
		}
		if skipPV {
			continue
		}

		pvcRef := pv.Spec.ClaimRef
		if pvcRef == nil {
			continue
		}

		csiHandle := pv.Spec.CSI.VolumeHandle
		pvc, err := m.k8sClient.CoreV1().
			PersistentVolumeClaims(pvcRef.Namespace).
			Get(ctx, pvcRef.Name, metav1.GetOptions{})
		if err != nil {
			continue
		}

		if pvc.Spec.VolumeMode != nil {
			volMode = VolumeMode(*pvc.Spec.VolumeMode)
		} else {
			volMode = VolumeModeFilesystem
		}

		// Only process filesystem volumes with supported filesystems (xfs, ext4)
		if volMode == VolumeModeFilesystem && pv.Spec.CSI != nil {
			fsType := strings.ToLower(pv.Spec.CSI.FSType)
			if fsType != "xfs" && fsType != "ext4" {
				log.Infof("SpaceReclamation: Volume %s has unsupported filesystem type %s (only xfs and ext4 are supported)", pv.Name, pv.Spec.CSI.FSType)
				continue
			}
		}

		eligible, reason = isEligibleFunc(m.config.Enabled, pvc.Labels, volMode)
		if !eligible {
			skippedCount++
			log.Infof("SpaceReclamation: PV %s is not eligible for reclamation (reason: %s)", pv.Name, reason)
			continue
		}
		log.Infof("SpaceReclamation: PV %s is eligible for reclamation.", pv.Name)

		volID = getVolumeIDFromCsiVolumeIDFunc(csiHandle)
		if volID == "" {
			continue
		}

		// ---------------- Filesystem ----------------
		if volMode == VolumeModeFilesystem {
			for dev, path := range deviceToMount {
				cleanPath := filepath.Clean(path)
				parts := strings.Split(cleanPath, string(os.PathSeparator))
				if len(parts) >= 2 &&
					parts[len(parts)-1] == "mount" &&
					parts[len(parts)-2] == pv.Name {
					processedCount++
					wg.Add(1)
					log.Infof("SpaceReclamation: submitting reclamation job for PV %s (VolumeID: %s, Device: %s, Path: %s, Mode: Filesystem)",
						pv.Name, volID, dev, path)
					go func(device, mount string) {
						defer wg.Done()
						m.reclaimVolume(ctx, &VolumeInfo{
							VolumeID:     volID,
							DevicePath:   device,
							StagingPath:  mount,
							VolumeMode:   VolumeModeFilesystem,
							PVName:       pv.Name,
							PVCName:      pvcRef.Name,
							PVCNamespace: pvcRef.Namespace,
							PVC:          pvc,
						})
					}(dev, path)
					break
				}
			}
			continue
		}

		// ---------------- Block ----------------
		if volMode == VolumeModeBlock {
			dev, err := discoverBlockDeviceFromCSIStagingFunc(pv.Name)
			if err != nil {
				continue
			}
			log.Infof("SpaceReclamation: PV %s resolved to device %s", pv.Name, dev)

			volInfo := &VolumeInfo{
				VolumeID:     volID,
				DevicePath:   dev,
				StagingPath:  dev,
				VolumeMode:   VolumeModeBlock,
				PVName:       pv.Name,
				PVCName:      pvc.Name,
				PVCNamespace: pvc.Namespace,
				PVC:          pvc,
			}

			capability, err := checkDiscardSupportFunc(ctx, volInfo.DevicePath)
			if err != nil {
				reason := fmt.Sprintf("failed to check discard support: %v", err)
				m.handleUnsupported(ctx, volInfo, reason)
				continue
			}
			if capability != nil && !capability.Supported {
				m.handleUnsupported(ctx, volInfo, capability.Reason)
				continue
			}

			processedCount++
			wg.Add(1)
			log.Infof("SpaceReclamation: submitting reclamation job for PV %s (VolumeID: %s, Device: %s, Mode: Block)",
				pv.Name, volID, dev)

			go func(vol *VolumeInfo) {
				defer wg.Done()
				m.reclaimVolume(ctx, vol)
			}(volInfo)
		}
	}

	wg.Wait()
	log.Infof("SpaceReclamation: completed RunOnce cycle - processed=%d, skipped=%d", processedCount, skippedCount)
}

func (m *SpaceReclamationManager) handleUnsupported(
	ctx context.Context,
	vol *VolumeInfo,
	reason string,
) {
	log := csmlog.GetLogger()
	log.Infof(
		"SpaceReclamation: volume %s does not support discard (device: %s, reason: %s)",
		vol.VolumeID, vol.DevicePath, reason,
	)

	result := &ReclamationResult{
		Status:       "unsupported",
		ErrorMessage: reason,
		NodeName:     m.config.NodeName,
	}

	if m.annotator != nil && m.k8sClient != nil && vol.PVCName != "" {
		_ = m.annotator.Annotate(ctx, vol.PVCName, vol.PVCNamespace, result)
	}

	if m.emitter != nil && vol.PVC != nil {
		m.emitter.EmitUnsupported(vol.PVC, reason)
	}
}

// reclaimVolume performs space reclamation on a single volume.
func (m *SpaceReclamationManager) reclaimVolume(ctx context.Context, vol *VolumeInfo) {
	log := csmlog.GetLogger()

	// Acquire semaphore for concurrency control
	log.Infof("SpaceReclamation: Volume %s (ID: %s) attempting to acquire semaphore", vol.PVName, vol.VolumeID)
	select {
	case m.semaphore <- struct{}{}:
		defer func() { <-m.semaphore }()
		log.Infof("SpaceReclamation: Volume %s (ID: %s) acquired semaphore", vol.PVName, vol.VolumeID)
	case <-m.ctx.Done():
		return
	}

	// Acquire per-volume mutex to prevent duplicate jobs
	// LoadOrStore will store a new mutex only if the key does not exist.
	// This avoids an unnecessary allocation when a reclamation is already in progress.
	actual, _ := m.volumeLocks.LoadOrStore(vol.VolumeID, &sync.Mutex{})
	actualMu := actual.(*sync.Mutex)
	if !actualMu.TryLock() {
		log.Infof("SpaceReclamation: Volume %s (ID: %s) skipped - another reclamation already in progress", vol.PVName, vol.VolumeID)
		return // Another reclamation is already running for this volume
	}
	defer func() {
		actualMu.Unlock()
		// Remove the mutex from the map after completion to allow subsequent runs
		m.volumeLocks.Delete(vol.VolumeID)
	}()
	log.Infof("SpaceReclamation: Volume %s (ID: %s) acquired per-volume mutex, starting reclamation on node %s", vol.PVName, vol.VolumeID, m.config.NodeName)

	// Check if device supports discard operations
	// Block volumes require discard capability checks.
	// Filesystem volumes rely on fstrim and do NOT need block discard validation.

	var bytesReclaimed int64
	var reclaimErr error
	start := time.Now()

	// Execute the reclamation operation
	switch vol.VolumeMode {
	case VolumeModeFilesystem:
		var fstrimResult *gofsutil.FstrimResult
		log.Infof("SpaceReclamation: calling fstrim on %s for volume %s (ID: %s)", vol.StagingPath, vol.PVName, vol.VolumeID)
		fstrimResult, reclaimErr = fstrimFunc(ctx, vol.StagingPath)
		if reclaimErr == nil && fstrimResult != nil {
			bytesReclaimed = fstrimResult.BytesTrimmed
		}
	case VolumeModeBlock:
		var blkResult *gofsutil.BlkdiscardResult
		log.Infof("SpaceReclamation: calling blkdiscard on %s for volume %s (ID: %s)", vol.DevicePath, vol.PVName, vol.VolumeID)
		blkResult, reclaimErr = blkdiscardFunc(ctx, vol.DevicePath)
		if reclaimErr == nil && blkResult != nil {
			bytesReclaimed = blkResult.BytesDiscarded
		}
	default:
		return
	}

	duration := time.Since(start)

	// Build the result
	var result *ReclamationResult
	if reclaimErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result = &ReclamationResult{
				Status:       "timeout",
				ErrorMessage: fmt.Sprintf("operation timed out after %v", time.Duration(m.config.TimeoutSeconds)*time.Second),
				NodeName:     m.config.NodeName,
				Duration:     duration,
			}
		} else {
			result = &ReclamationResult{
				Status:       "error",
				ErrorMessage: reclaimErr.Error(),
				NodeName:     m.config.NodeName,
				Duration:     duration,
			}
		}
	} else {
		result = &ReclamationResult{
			Status:         "success",
			BytesReclaimed: bytesReclaimed,
			Duration:       duration,
			NodeName:       m.config.NodeName,
		}
	}

	// Annotate the PVC with results
	// Use a fresh context with a short timeout to ensure annotations are written
	// even if the reclamation operation context has timed out
	annotateCtx := ctx
	if ctx.Err() != nil {
		var annotateCancel context.CancelFunc
		annotateCtx, annotateCancel = context.WithTimeout(m.ctx, 10*time.Second)
		defer annotateCancel()
	}
	if m.annotator != nil && m.k8sClient != nil && vol.PVCName != "" {
		_ = m.annotator.Annotate(annotateCtx, vol.PVCName, vol.PVCNamespace, result)
	}

	// Emit Kubernetes event based on result status
	if m.emitter != nil && vol.PVC != nil {
		switch result.Status {
		case "success":
			m.emitter.EmitSuccess(vol.PVC, result.BytesReclaimed, result.Duration)
		case "timeout":
			m.emitter.EmitTimeout(vol.PVC, time.Duration(m.config.TimeoutSeconds)*time.Second)
		case "error":
			m.emitter.EmitFailure(vol.PVC, errors.New(result.ErrorMessage))
		}
	}

	log.Infof("SpaceReclamation: completed reclamation for volume %s (PVC: %s/%s, PV: %s) - Status: %s, BytesReclaimed: %d, Duration: %v, Node: %s",
		vol.VolumeID, vol.PVCNamespace, vol.PVCName, vol.PVName, result.Status, result.BytesReclaimed, result.Duration, m.config.NodeName)
}

// initSpaceReclamation reads env and initializes the space reclamation manager.
// This is called from BeforeServe when in node mode.
func initSpaceReclamation(ctx context.Context, s *Service, k8sClient kubernetes.Interface) {
	log := csmlog.GetLogger()
	cfg := ReadSpaceReclamationConfig()
	mgr, err := NewSpaceReclamationManager(ctx, cfg, k8sClient, cfg.NodeName)
	if err != nil {
		log.Errorf("Failed to create SpaceReclamationManager: %v", err)
		return
	}
	if err := mgr.Start(); err != nil {
		log.Errorf("Failed to start SpaceReclamationManager: %v", err)
		return
	}
	s.spaceReclaimMgr = mgr
}
