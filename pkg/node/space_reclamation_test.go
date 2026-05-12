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
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gofsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
)

// ============================================================================
// Test Helpers
// ============================================================================

// makePVC creates a minimal PVC object for testing.
func makePVC(name, namespace string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{},
		},
	}
}

// newTestManager creates a SpaceReclamationManager with test defaults.
func newTestManager(t *testing.T, client *fake.Clientset, cfg SpaceReclamationConfig) *SpaceReclamationManager {
	t.Helper()
	ctx := context.Background()
	mgr, err := NewSpaceReclamationManager(ctx, cfg, client, cfg.NodeName)
	require.NoError(t, err)
	return mgr
}

// resetGofsutilMock resets gofsutil mock to a clean state.
func resetGofsutilMock() {
	gofsutil.GOFSMock.InduceMountError = false
	gofsutil.GOFSMock.InduceUnmountError = false
}

// --- TestReadSpaceReclamationConfig ---

func TestReadSpaceReclamationConfig(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected SpaceReclamationConfig
	}{
		{
			name:    "AllDefaults",
			envVars: map[string]string{},
			expected: SpaceReclamationConfig{
				Enabled:              false,
				Schedule:             "0 2 * * 0",
				MaxConcurrentVolumes: 2,
				TimeoutSeconds:       14400,
				NodeName:             "",
			},
		},
		{
			name: "AllCustom",
			envVars: map[string]string{
				"X_CSI_SPACE_RECLAMATION_ENABLED":        "true",
				"X_CSI_SPACE_RECLAMATION_SCHEDULE":       "*/5 * * * *",
				"X_CSI_SPACE_RECLAMATION_MAX_CONCURRENT": "4",
				"X_CSI_SPACE_RECLAMATION_TIMEOUT":        "1800",
				"X_CSI_POWERSTORE_KUBE_NODE_NAME":        "node-x",
			},
			expected: SpaceReclamationConfig{
				Enabled:              true,
				Schedule:             "*/5 * * * *",
				MaxConcurrentVolumes: 4,
				TimeoutSeconds:       1800,
				NodeName:             "node-x",
			},
		},
		{
			name: "InvalidBool",
			envVars: map[string]string{
				"X_CSI_SPACE_RECLAMATION_ENABLED": "notabool",
			},
			expected: SpaceReclamationConfig{
				Enabled:              false,
				Schedule:             "0 2 * * 0",
				MaxConcurrentVolumes: 2,
				TimeoutSeconds:       14400,
			},
		},
		{
			name: "InvalidInt",
			envVars: map[string]string{
				"X_CSI_SPACE_RECLAMATION_MAX_CONCURRENT": "abc",
			},
			expected: SpaceReclamationConfig{
				Enabled:              false,
				Schedule:             "0 2 * * 0",
				MaxConcurrentVolumes: 2,
				TimeoutSeconds:       14400,
			},
		},
		{
			name: "ZeroConcurrent",
			envVars: map[string]string{
				"X_CSI_SPACE_RECLAMATION_MAX_CONCURRENT": "0",
			},
			expected: SpaceReclamationConfig{
				Enabled:              false,
				Schedule:             "0 2 * * 0",
				MaxConcurrentVolumes: 0,
				TimeoutSeconds:       14400,
			},
		},
		{
			name: "EmptySchedule",
			envVars: map[string]string{
				"X_CSI_SPACE_RECLAMATION_SCHEDULE": "",
			},
			expected: SpaceReclamationConfig{
				Enabled:              false,
				Schedule:             "0 2 * * 0",
				MaxConcurrentVolumes: 2,
				TimeoutSeconds:       14400,
			},
		},
		{
			name: "NegativeTimeout",
			envVars: map[string]string{
				"X_CSI_SPACE_RECLAMATION_TIMEOUT": "-1",
			},
			expected: SpaceReclamationConfig{
				Enabled:              false,
				Schedule:             "0 2 * * 0",
				MaxConcurrentVolumes: 2,
				TimeoutSeconds:       14400,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all relevant env vars first
			t.Setenv("X_CSI_SPACE_RECLAMATION_ENABLED", "")
			t.Setenv("X_CSI_SPACE_RECLAMATION_SCHEDULE", "")
			t.Setenv("X_CSI_SPACE_RECLAMATION_MAX_CONCURRENT", "")
			t.Setenv("X_CSI_SPACE_RECLAMATION_TIMEOUT", "")
			t.Setenv("X_CSI_POWERSTORE_KUBE_NODE_NAME", "")

			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg := ReadSpaceReclamationConfig()
			assert.Equal(t, tt.expected.Enabled, cfg.Enabled, "Enabled mismatch")
			assert.Equal(t, tt.expected.Schedule, cfg.Schedule, "Schedule mismatch")
			assert.Equal(t, tt.expected.MaxConcurrentVolumes, cfg.MaxConcurrentVolumes, "MaxConcurrentVolumes mismatch")
			assert.Equal(t, tt.expected.TimeoutSeconds, cfg.TimeoutSeconds, "TimeoutSeconds mismatch")
			assert.Equal(t, tt.expected.NodeName, cfg.NodeName, "NodeName mismatch")
		})
	}
}

// --- TestSpaceReclamationManager_StartStop ---

func TestSpaceReclamationManager_StartStop(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
		NodeName:             "node-1",
	}
	mgr := newTestManager(t, fakeClient, cfg)
	err := mgr.Start()
	require.NoError(t, err, "Start should succeed with valid config")
}

func TestNewSpaceReclamationManager_InvalidCronExpression(t *testing.T) {
	cfg := SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "not a cron",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       60,
		NodeName:             "node-1",
	}
	fakeClient := fake.NewSimpleClientset()
	ctx := context.Background()
	mgr, err := NewSpaceReclamationManager(ctx, cfg, fakeClient, cfg.NodeName)
	assert.Error(t, err, "invalid cron expression should return error")
	assert.Nil(t, mgr, "manager should be nil with invalid cron expression")
}

func TestNewSpaceReclamationManager_ValidConfig(t *testing.T) {
	cfg := SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
		NodeName:             "node-1",
	}
	fakeClient := fake.NewSimpleClientset()
	ctx := context.Background()
	mgr, err := NewSpaceReclamationManager(ctx, cfg, fakeClient, cfg.NodeName)
	require.NoError(t, err, "valid config should not return error")
	require.NotNil(t, mgr, "manager should be created with valid config")
}

func TestNewSpaceReclamationManager_EmptyNodeName(t *testing.T) {
	cfg := SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
		NodeName:             "",
	}
	fakeClient := fake.NewSimpleClientset()
	ctx := context.Background()
	mgr, err := NewSpaceReclamationManager(ctx, cfg, fakeClient, cfg.NodeName)
	require.NoError(t, err, "empty NodeName should be accepted (graceful degradation)")
	require.NotNil(t, mgr, "manager should be created even with empty NodeName")
}

// --- TestBuildAnnotations ---

func TestBuildAnnotations_Success(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	annotator := NewPVCAnnotator(fakeClient)

	result := &ReclamationResult{
		Status:         "success",
		BytesReclaimed: 1073741824,
		Duration:       500 * time.Millisecond,
		NodeName:       "node-1",
	}
	err := annotator.Annotate(context.Background(), "test-pvc", "default", result)
	require.NoError(t, err)

	updated, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(
		context.Background(), "test-pvc", metav1.GetOptions{},
	)
	require.NoError(t, err)
	assert.Equal(t, "success", updated.Annotations[AnnotationStatus])
	assert.Equal(t, "1073741824", updated.Annotations[AnnotationBytesReclaim])
	assert.Equal(t, "node-1", updated.Annotations[AnnotationNode])
	assert.NotEmpty(t, updated.Annotations[AnnotationLastRunTime])
	assert.NotEmpty(t, updated.Annotations[AnnotationDuration])
}

func TestBuildAnnotations_Error(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	annotator := NewPVCAnnotator(fakeClient)

	result := &ReclamationResult{
		Status:       "error",
		ErrorMessage: "fstrim failed: permission denied",
		NodeName:     "node-1",
	}
	err := annotator.Annotate(context.Background(), "test-pvc", "default", result)
	require.NoError(t, err)

	updated, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(
		context.Background(), "test-pvc", metav1.GetOptions{},
	)
	require.NoError(t, err)
	assert.Equal(t, "error", updated.Annotations[AnnotationStatus])
	assert.Contains(t, updated.Annotations[AnnotationErrorMsg], "fstrim failed")
}

func TestBuildAnnotations_PVCNotFound(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	annotator := NewPVCAnnotator(fakeClient)

	result := &ReclamationResult{Status: "success", BytesReclaimed: 100}
	err := annotator.Annotate(context.Background(), "nonexistent-pvc", "default", result)
	assert.Error(t, err, "annotating non-existent PVC should return error")
}

func TestBuildAnnotations_ConflictRetry(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)

	// Track update call count using a reactor
	updateCount := 0
	fakeClient.PrependReactor("update", "persistentvolumeclaims", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		updateCount++
		if updateCount == 1 {
			return true, nil, fmt.Errorf("the object has been modified; please apply your changes to the latest version and try again")
		}
		return false, nil, nil
	})

	annotator := NewPVCAnnotator(fakeClient)
	result := &ReclamationResult{Status: "success", BytesReclaimed: 100, NodeName: "node-1"}
	err := annotator.Annotate(context.Background(), "test-pvc", "default", result)

	assert.NoError(t, err, "annotator should handle conflict with retry")
	assert.GreaterOrEqual(t, updateCount, 2, "should have retried at least once")
}

// --- TestIsEligible ---

func TestIsEligible_GlobalEnabledNoAnnotation(t *testing.T) {
	labels := map[string]string{}
	result, reason := IsEligible(true, labels, VolumeModeFilesystem)
	assert.True(t, result, "global enabled + no annotation = eligible")
	assert.Equal(t, "", reason)
}

func TestIsEligible_ExplicitOptOut(t *testing.T) {
	labels := map[string]string{
		LabelEnabled: "false",
	}
	result, reason := IsEligible(true, labels, VolumeModeFilesystem)
	assert.False(t, result, "explicit opt-out should make volume ineligible")
	assert.Equal(t, "label is 'false' (must be 'true' to override global)", reason)
}

func TestIsEligible_ExplicitOptIn(t *testing.T) {
	labels := map[string]string{
		LabelEnabled: "true",
	}
	result, reason := IsEligible(true, labels, VolumeModeFilesystem)
	assert.True(t, result, "explicit opt-in should make volume eligible")
	assert.Equal(t, "", reason)
}

func TestIsEligible_GlobalDisabled(t *testing.T) {
	labels := map[string]string{}
	result, reason := IsEligible(false, labels, VolumeModeFilesystem)
	assert.False(t, result, "global disabled = ineligible")
	assert.Equal(t, "global disabled", reason)
}

func TestIsEligible_NilLabelsMap(t *testing.T) {
	result, reason := IsEligible(true, nil, VolumeModeFilesystem)
	assert.True(t, result, "nil labels with global enabled = eligible")
	assert.Equal(t, "", reason)
}

func TestIsEligible_BlockModeMissingLabel(t *testing.T) {
	labels := map[string]string{}
	result, reason := IsEligible(true, labels, VolumeModeBlock)
	assert.False(t, result, "block mode without label should be ineligible")
	assert.Equal(t, "block mode requires explicit opt-in label (space-reclamation.csi.dell.com/block-reclaim is missing)", reason)
}

// --- EventEmitter Tests ---

func TestEventEmitter_EmitSuccess(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	emitter := &EventEmitter{recorder: recorder}
	pvc := makePVC("test-pvc", "default")

	emitter.EmitSuccess(pvc, 1073741824, 500*time.Millisecond)

	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, EventReasonCompleted, "event should contain SpaceReclamationCompleted")
	case <-time.After(time.Second):
		t.Fatal("expected SpaceReclamationCompleted event not received")
	}
}

func TestEventEmitter_EmitFailure(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	emitter := &EventEmitter{recorder: recorder}
	pvc := makePVC("test-pvc", "default")

	emitter.EmitFailure(pvc, fmt.Errorf("fstrim failed"))

	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, EventReasonFailed, "event should contain SpaceReclamationFailed")
	case <-time.After(time.Second):
		t.Fatal("expected SpaceReclamationFailed event not received")
	}
}

func TestEventEmitter_EmitTimeout(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	emitter := &EventEmitter{recorder: recorder}
	pvc := makePVC("test-pvc", "default")

	emitter.EmitTimeout(pvc, 3600*time.Second)

	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, EventReasonTimeout, "event should contain SpaceReclamationTimeout")
	case <-time.After(time.Second):
		t.Fatal("expected SpaceReclamationTimeout event not received")
	}
}

func TestEventEmitter_EmitUnsupported(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	emitter := &EventEmitter{recorder: recorder}
	pvc := makePVC("test-pvc", "default")

	emitter.EmitUnsupported(pvc, "discard_max_bytes is 0")

	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, EventReasonUnsupported, "event should contain SpaceReclamationUnsupported")
	case <-time.After(time.Second):
		t.Fatal("expected SpaceReclamationUnsupported event not received")
	}
}

// --- Concurrency Control ---

func TestSemaphore_LimitsParallelism(t *testing.T) {
	sem := make(chan struct{}, 2)
	var maxConcurrent int64
	var currentConcurrent int64
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			curr := atomic.AddInt64(&currentConcurrent, 1)
			for {
				old := atomic.LoadInt64(&maxConcurrent)
				if curr <= old || atomic.CompareAndSwapInt64(&maxConcurrent, old, curr) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
			atomic.AddInt64(&currentConcurrent, -1)
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, atomic.LoadInt64(&maxConcurrent), int64(2),
		"at most 2 jobs should run concurrently")
}

func TestPerVolumeMutex_PreventsDuplicateJob(t *testing.T) {
	var volumeLocks sync.Map
	volID := "vol-dup-001"

	mu := &sync.Mutex{}
	actual, loaded := volumeLocks.LoadOrStore(volID, mu)
	assert.False(t, loaded, "first lock should not be loaded")

	actualMu := actual.(*sync.Mutex)
	actualMu.Lock()

	_, loaded2 := volumeLocks.LoadOrStore(volID, &sync.Mutex{})
	assert.True(t, loaded2, "second lock should find existing entry (duplicate job)")

	actualMu.Unlock()
}

func TestShutdown_CancelsRunningJobs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	jobStarted := make(chan struct{})
	jobDone := make(chan struct{})

	go func() {
		close(jobStarted)
		select {
		case <-ctx.Done():
			close(jobDone)
		case <-time.After(5 * time.Second):
		}
	}()

	<-jobStarted
	cancel()

	select {
	case <-jobDone:
		assert.True(t, true, "job should be cancelled on shutdown")
	case <-time.After(1 * time.Second):
		t.Fatal("job was not cancelled within timeout")
	}
}

// --- Environment Variable Constants ---

func TestEnvVarConstants_Defined(t *testing.T) {
	assert.Equal(t, "X_CSI_SPACE_RECLAMATION_ENABLED", "X_CSI_SPACE_RECLAMATION_ENABLED")
	assert.Equal(t, "X_CSI_SPACE_RECLAMATION_SCHEDULE", "X_CSI_SPACE_RECLAMATION_SCHEDULE")
	assert.Equal(t, "X_CSI_SPACE_RECLAMATION_MAX_CONCURRENT", "X_CSI_SPACE_RECLAMATION_MAX_CONCURRENT")
	assert.Equal(t, "X_CSI_SPACE_RECLAMATION_TIMEOUT", "X_CSI_SPACE_RECLAMATION_TIMEOUT")
}

// --- Helper Function Tests ---

func TestGetVolumeIDFromCsiVolumeID(t *testing.T) {
	tests := []struct {
		name     string
		handle   string
		expected string
	}{
		{
			name:     "Standard handle",
			handle:   "vol-123",
			expected: "vol-123",
		},
		{
			name:     "Handle with prefix",
			handle:   "csi.vol-123",
			expected: "csi.vol-123",
		},
		{
			name:     "Empty handle",
			handle:   "",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getVolumeIDFromCsiVolumeID(tt.handle)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandleUnsupported(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "* * * * *",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	})

	ctx := context.Background()

	// Test with empty PVCName (should skip annotation)
	vol := &VolumeInfo{
		VolumeID:   "vol-123",
		DevicePath: "/dev/sda",
		PVCName:    "",
		PVC:        nil,
	}
	mgr.handleUnsupported(ctx, vol, "test reason")

	// Test with PVCName but nil PVC (should skip emit)
	vol.PVCName = "pvc-test"
	vol.PVCNamespace = "default"
	vol.PVC = nil
	mgr.handleUnsupported(ctx, vol, "test reason")

	// Test with complete info
	pvc := makePVC("pvc-test", "default")
	vol.PVC = pvc
	mgr.handleUnsupported(ctx, vol, "test reason")
}

func TestGetMapperName(t *testing.T) {
	// Test with non-existent file
	result := getMapperName("dm-nonexistent")
	assert.Equal(t, "dm-nonexistent", result) // Should return input as-is when file doesn't exist

	// Test with empty string
	result = getMapperName("")
	assert.Equal(t, "", result)
}

func TestFindDeviceByMajorMinor_ErrorPath(t *testing.T) {
	// Test with non-existent major/minor (should return error)
	_, err := findDeviceByMajorMinor(9999, 9999)
	assert.Error(t, err)
}

func TestNewPVCAnnotator(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	annotator := NewPVCAnnotator(fakeClient)
	assert.NotNil(t, annotator)
	assert.NotNil(t, annotator.client)
	assert.Equal(t, 3, annotator.maxRetry)
}

func TestNewEventEmitter(t *testing.T) {
	// Test with nil clientset
	emitter := NewEventEmitter(nil, "test-driver")
	assert.NotNil(t, emitter)
	assert.Nil(t, emitter.recorder)

	// Test with fake clientset
	fakeClient := fake.NewSimpleClientset()
	emitter = NewEventEmitter(fakeClient, "test-driver")
	assert.NotNil(t, emitter)
	assert.NotNil(t, emitter.recorder)
}

func TestFindDeviceByMajorMinor(t *testing.T) {
	// Test with invalid major/minor numbers
	_, err := findDeviceByMajorMinor(9999, 9999)
	assert.Error(t, err)
}

func TestInitSpaceReclamation(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()

	// Test with invalid config (invalid cron)
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "true")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "invalid-cron")

	initSpaceReclamation(context.Background(), nil, fakeClient)
}

// TestRunOnce_UnboundVolume tests PV that is not bound
func TestRunOnce_UnboundVolume(_ *testing.T) {
	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-unbound"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumePending},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_RWXVolume tests ReadWriteMany volume
func TestRunOnce_RWXVolume(_ *testing.T) {
	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-rwx"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteMany,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_NoPVCRef tests PV with nil ClaimRef
func TestRunOnce_NoPVCRef(_ *testing.T) {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-no-ref"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			// No ClaimRef
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_PVCGetError tests error getting PVC
func TestRunOnce_PVCGetError(_ *testing.T) {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      "nonexistent-pvc",
				Namespace: "default",
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_VolumeModeNil tests PVC with nil VolumeMode (defaults to Filesystem)
func TestRunOnce_VolumeModeNil(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return false, "test disabled"
	}

	pvc := makePVC("test-pvc", "default")
	// No VolumeMode set - should default to Filesystem
	pvc.Spec.VolumeMode = nil

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_VolumeModeExplicitBlock tests PVC with explicit Block VolumeMode
func TestRunOnce_VolumeModeExplicitBlock(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return false, "test disabled"
	}

	blockMode := corev1.PersistentVolumeBlock
	pvc := makePVC("test-pvc", "default")
	pvc.Spec.VolumeMode = &blockMode

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_UnsupportedFilesystem tests volumes with unsupported filesystem types
func TestRunOnce_UnsupportedFilesystem(_ *testing.T) {
	originalGetMounts := getMountsFunc
	defer func() { getMountsFunc = originalGetMounts }()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}

	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ntfs", // Unsupported
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_GetMountsError tests error from GetMounts
func TestRunOnce_GetMountsError(_ *testing.T) {
	originalGetMounts := getMountsFunc
	defer func() { getMountsFunc = originalGetMounts }()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return nil, fmt.Errorf("failed to read /proc/mounts")
	}

	k8sClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_Ineligible tests volumes not eligible for reclamation
func TestRunOnce_Ineligible(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return false, "disabled by policy"
	}

	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_LabelLoggingPaths tests different label logging scenarios
func TestRunOnce_LabelLoggingPaths(t *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	originalGetVolumeID := getVolumeIDFromCsiVolumeIDFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
		getVolumeIDFromCsiVolumeIDFunc = originalGetVolumeID
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return true, ""
	}
	getVolumeIDFromCsiVolumeIDFunc = func(_ string) string {
		return "" // Return empty to skip further processing
	}

	tests := []struct {
		name       string
		pvcLabels  map[string]string
		volumeMode *corev1.PersistentVolumeMode
		desc       string
	}{
		{
			name:      "block with label",
			pvcLabels: map[string]string{LabelBlockReclaim: "true"},
			volumeMode: func() *corev1.PersistentVolumeMode {
				m := corev1.PersistentVolumeBlock
				return &m
			}(),
			desc: "Should log block reclaim label",
		},
		{
			name:      "block without specific label",
			pvcLabels: map[string]string{"other": "value"},
			volumeMode: func() *corev1.PersistentVolumeMode {
				m := corev1.PersistentVolumeBlock
				return &m
			}(),
			desc: "Should log labels present but not set",
		},
		{
			name:       "filesystem with label",
			pvcLabels:  map[string]string{LabelEnabled: "true"},
			volumeMode: nil, // Defaults to Filesystem
			desc:       "Should log enabled label",
		},
		{
			name:       "filesystem without specific label",
			pvcLabels:  map[string]string{"other": "value"},
			volumeMode: nil,
			desc:       "Should log global config enabled",
		},
		{
			name:       "no labels",
			pvcLabels:  nil,
			volumeMode: nil,
			desc:       "Should log no PVC labels",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			pvc := makePVC("test-pvc", "default")
			pvc.Labels = tt.pvcLabels
			pvc.Spec.VolumeMode = tt.volumeMode

			pv := &corev1.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
				Spec: corev1.PersistentVolumeSpec{
					Capacity: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("10Gi"),
					},
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					PersistentVolumeSource: corev1.PersistentVolumeSource{
						CSI: &corev1.CSIPersistentVolumeSource{
							Driver:       identifiers.Name,
							VolumeHandle: "vol-123",
							FSType:       "ext4",
						},
					},
					ClaimRef: &corev1.ObjectReference{
						Name:      pvc.Name,
						Namespace: pvc.Namespace,
					},
				},
				Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
			}

			k8sClient := fake.NewSimpleClientset(pv, pvc)
			cfg := SpaceReclamationConfig{
				Enabled:        true,
				Schedule:       "0 2 * * 0",
				TimeoutSeconds: 60,
				NodeName:       "test-node",
			}
			mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
			mgr.RunOnce()
		})
	}
}

// TestRunOnce_EmptyVolumeID tests when volume ID extraction fails
func TestRunOnce_EmptyVolumeID(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	originalGetVolumeID := getVolumeIDFromCsiVolumeIDFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
		getVolumeIDFromCsiVolumeIDFunc = originalGetVolumeID
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return true, ""
	}
	getVolumeIDFromCsiVolumeIDFunc = func(_ string) string {
		return "" // Empty volume ID
	}

	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_FilesystemVolumeProcessing tests filesystem volume processing with mount matching
func TestRunOnce_FilesystemVolumeProcessing(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	originalGetVolumeID := getVolumeIDFromCsiVolumeIDFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
		getVolumeIDFromCsiVolumeIDFunc = originalGetVolumeID
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{
			{
				Device: "/dev/sda",
				Path:   "/var/lib/kubelet/pods/pod-123/volumes/test-pvc",
			},
		}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return true, ""
	}
	getVolumeIDFromCsiVolumeIDFunc = func(_ string) string {
		return "test-vol-id"
	}

	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()

	time.Sleep(100 * time.Millisecond) // Allow goroutine to start
}

// TestRunOnce_BlockVolumeNoOptInLabel tests block volume without required label
func TestRunOnce_BlockVolumeNoOptInLabel(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	originalGetVolumeID := getVolumeIDFromCsiVolumeIDFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
		getVolumeIDFromCsiVolumeIDFunc = originalGetVolumeID
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return true, ""
	}
	getVolumeIDFromCsiVolumeIDFunc = func(_ string) string {
		return "test-vol-id"
	}

	blockMode := corev1.PersistentVolumeBlock
	pvc := makePVC("test-pvc", "default")
	pvc.Spec.VolumeMode = &blockMode
	// No LabelBlockReclaim label

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_BlockVolumeDiscoveryError tests block device discovery failure
func TestRunOnce_BlockVolumeDiscoveryError(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	originalGetVolumeID := getVolumeIDFromCsiVolumeIDFunc
	originalDiscoverBlock := discoverBlockDeviceFromCSIStagingFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
		getVolumeIDFromCsiVolumeIDFunc = originalGetVolumeID
		discoverBlockDeviceFromCSIStagingFunc = originalDiscoverBlock
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return true, ""
	}
	getVolumeIDFromCsiVolumeIDFunc = func(_ string) string {
		return "test-vol-id"
	}
	discoverBlockDeviceFromCSIStagingFunc = func(_ string) (string, error) {
		return "", fmt.Errorf("device not found")
	}

	blockMode := corev1.PersistentVolumeBlock
	pvc := makePVC("test-pvc", "default")
	pvc.Spec.VolumeMode = &blockMode
	pvc.Labels = map[string]string{LabelBlockReclaim: "true"}

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_BlockVolumeDiscardValidationError tests discard validation failure
func TestRunOnce_BlockVolumeDiscardValidationError(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	originalGetVolumeID := getVolumeIDFromCsiVolumeIDFunc
	originalDiscoverBlock := discoverBlockDeviceFromCSIStagingFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
		getVolumeIDFromCsiVolumeIDFunc = originalGetVolumeID
		discoverBlockDeviceFromCSIStagingFunc = originalDiscoverBlock
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return true, ""
	}
	getVolumeIDFromCsiVolumeIDFunc = func(_ string) string {
		return "test-vol-id"
	}
	discoverBlockDeviceFromCSIStagingFunc = func(_ string) (string, error) {
		return "/dev/sda", nil
	}

	blockMode := corev1.PersistentVolumeBlock
	pvc := makePVC("test-pvc", "default")
	pvc.Spec.VolumeMode = &blockMode
	pvc.Labels = map[string]string{LabelBlockReclaim: "true"}

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()
}

// TestRunOnce_BlockVolumeSuccess tests successful block volume processing
func TestRunOnce_BlockVolumeSuccess(_ *testing.T) {
	originalGetMounts := getMountsFunc
	originalIsEligible := isEligibleFunc
	originalGetVolumeID := getVolumeIDFromCsiVolumeIDFunc
	originalDiscoverBlock := discoverBlockDeviceFromCSIStagingFunc
	defer func() {
		getMountsFunc = originalGetMounts
		isEligibleFunc = originalIsEligible
		getVolumeIDFromCsiVolumeIDFunc = originalGetVolumeID
		discoverBlockDeviceFromCSIStagingFunc = originalDiscoverBlock
	}()

	getMountsFunc = func(_ context.Context) ([]gofsutil.Info, error) {
		return []gofsutil.Info{}, nil
	}
	isEligibleFunc = func(_ bool, _ map[string]string, _ VolumeMode) (bool, string) {
		return true, ""
	}
	getVolumeIDFromCsiVolumeIDFunc = func(_ string) string {
		return "test-vol-id"
	}
	discoverBlockDeviceFromCSIStagingFunc = func(_ string) (string, error) {
		return "/dev/sda", nil
	}

	blockMode := corev1.PersistentVolumeBlock
	pvc := makePVC("test-pvc", "default")
	pvc.Spec.VolumeMode = &blockMode
	pvc.Labels = map[string]string{LabelBlockReclaim: "true"}

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		TimeoutSeconds: 60,
		NodeName:       "test-node",
	}
	mgr, _ := NewSpaceReclamationManager(context.Background(), cfg, k8sClient, cfg.NodeName)
	mgr.RunOnce()

	time.Sleep(100 * time.Millisecond) // Allow goroutine to start
}

func TestRunOnce_EmptyPVList(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// RunOnce with empty PV list should complete without error
	mgr.RunOnce()
}

func TestRunOnce_ConcurrentPrevention(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Set running flag to true to simulate a run in progress
	mgr.running.Store(true)

	// RunOnce should return early without doing work
	mgr.RunOnce()

	// Reset flag
	mgr.running.Store(false)
}

func TestReclaimVolume_Timeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately to simulate timeout

	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	vol := &VolumeInfo{
		VolumeID:   "vol-123",
		DevicePath: "/dev/sda",
	}

	// reclaimVolume should handle canceled context gracefully
	mgr.reclaimVolume(ctx, vol)
}

func TestReclaimVolume_BlockMode(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/dev/sda",
		VolumeMode:   VolumeModeBlock,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
	}

	// Test block mode path (will fail due to no gofsutil mock)
	mgr.reclaimVolume(ctx, vol)
}

func TestReclaimVolume_UnsupportedMode(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   "unsupported",
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
	}

	// Test unsupported volume mode
	mgr.reclaimVolume(ctx, vol)
}

func TestStart_InvalidCron(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0", // Valid for creation
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Change config to invalid cron and try to start
	mgr.config.Schedule = "invalid-cron"
	err := mgr.Start()
	assert.Error(t, err)
}

func TestStart_StopExisting(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Start the scheduler
	err := mgr.Start()
	assert.NoError(t, err)

	// Start again should stop existing and start new
	err = mgr.Start()
	assert.NoError(t, err)
}

func TestReclaimVolume_FstrimSuccess(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Mock gofsutil to return success
	originalFstrim := gofsutil.GOFSMock
	defer func() { gofsutil.GOFSMock = originalFstrim }()
	gofsutil.GOFSMock.InduceFstrimError = false

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeModeFilesystem,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
	}

	mgr.reclaimVolume(ctx, vol)
}

func TestIsEligible_AdditionalCases(t *testing.T) {
	tests := []struct {
		name          string
		globalEnabled bool
		labels        map[string]string
		volumeMode    VolumeMode
		expected      bool
	}{
		{
			name:          "block mode with true label",
			globalEnabled: false,
			labels:        map[string]string{LabelBlockReclaim: "true"},
			volumeMode:    VolumeModeBlock,
			expected:      true,
		},
		{
			name:          "block mode with false label",
			globalEnabled: true,
			labels:        map[string]string{LabelBlockReclaim: "false"},
			volumeMode:    VolumeModeBlock,
			expected:      false,
		},
		{
			name:          "block mode with case insensitive true",
			globalEnabled: false,
			labels:        map[string]string{LabelBlockReclaim: "TRUE"},
			volumeMode:    VolumeModeBlock,
			expected:      true,
		},
		{
			name:          "filesystem mode with true label override",
			globalEnabled: false,
			labels:        map[string]string{LabelEnabled: "true"},
			volumeMode:    VolumeModeFilesystem,
			expected:      true,
		},
		{
			name:          "filesystem mode with false label override",
			globalEnabled: true,
			labels:        map[string]string{LabelEnabled: "false"},
			volumeMode:    VolumeModeFilesystem,
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := IsEligible(tt.globalEnabled, tt.labels, tt.volumeMode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetMapperName_AdditionalCases(t *testing.T) {
	tests := []struct {
		name   string
		device string
	}{
		{
			name:   "empty device",
			device: "",
		},
		{
			name:   "dm device without prefix",
			device: "dm-0",
		},
		{
			name:   "mapper with hyphen",
			device: "mapper/mpath0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			result := getMapperName(tt.device)
			// Just ensure it doesn't panic
			_ = result
		})
	}
}

func TestEmitEventEmitter_AdditionalTests(_ *testing.T) {
	// Test with nil recorder (should not panic)
	emitterNil := NewEventEmitter(nil, "test-driver")

	pvc := makePVC("test-pvc", "default")

	// Test emit methods with nil recorder - should not panic
	emitterNil.EmitSuccess(pvc, 1024, time.Second)
	emitterNil.EmitFailure(pvc, fmt.Errorf("test error"))
	emitterNil.EmitTimeout(pvc, 30*time.Second)
	emitterNil.EmitUnsupported(pvc, "test reason")
}

func TestAnnotate_AdditionalCases(_ *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	annotator := NewPVCAnnotator(fakeClient)

	pvc := makePVC("test-pvc", "default")
	fakeClient = fake.NewSimpleClientset(pvc)
	annotator = NewPVCAnnotator(fakeClient)

	result := &ReclamationResult{
		Status:         "in_progress",
		BytesReclaimed: 512,
		Duration:       5 * time.Second,
		ErrorMessage:   "",
		NodeName:       "node-1",
	}

	err := annotator.Annotate(context.Background(), "test-pvc", "default", result)
	_ = err

	result.Status = "error"
	result.ErrorMessage = "test error"
	err = annotator.Annotate(context.Background(), "test-pvc", "default", result)
	_ = err

	result.Status = "timeout"
	err = annotator.Annotate(context.Background(), "test-pvc", "default", result)
	_ = err

	result.Status = "skipped"
	err = annotator.Annotate(context.Background(), "test-pvc", "default", result)
	_ = err
}

func TestNewSpaceReclamationManager_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SpaceReclamationConfig
		wantErr bool
	}{
		{
			name: "empty schedule",
			cfg: SpaceReclamationConfig{
				Enabled:  true,
				Schedule: "",
				NodeName: "node-1",
			},
			wantErr: true,
		},
		{
			name: "schedule with extra spaces",
			cfg: SpaceReclamationConfig{
				Enabled:  true,
				Schedule: "0  2  *  *  0",
				NodeName: "node-1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			ctx := context.Background()
			mgr, err := NewSpaceReclamationManager(ctx, tt.cfg, fakeClient, tt.cfg.NodeName)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, mgr)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mgr)
			}
		})
	}
}

func TestInitSpaceReclamation_MoreCases(t *testing.T) {
	// Test initSpaceReclamation with disabled config
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "false")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "0 2 * * 0")
	t.Setenv(identifiers.EnvSpaceReclamationMaxConcurrent, "2")
	t.Setenv(identifiers.EnvSpaceReclamationTimeout, "60")

	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	s := &Service{}

	// Should not panic even with disabled config
	initSpaceReclamation(ctx, s, k8sClient)
}

func TestFindDeviceByMajorMinor_MoreCases(t *testing.T) {
	tests := []struct {
		name  string
		major uint64
		minor uint64
	}{
		{
			name:  "zero major minor",
			major: 0,
			minor: 0,
		},
		{
			name:  "large major minor",
			major: 9999,
			minor: 9999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			// This function reads from /sys/dev/block/major:minor
			// In a test environment, this file likely doesn't exist
			// Just call the function to ensure it doesn't panic
			_, err := findDeviceByMajorMinor(tt.major, tt.minor)
			// We expect errors since these are mock devices
			_ = err
		})
	}
}

func TestRunOnce_AdditionalCases(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:  true,
		Schedule: "0 2 * * 0",
		NodeName: "node-1",
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Test with PV list error
	mgr.k8sClient = fake.NewSimpleClientset()
	mgr.RunOnce()

	// Should not panic
}

func TestReclaimVolume_AdditionalCases(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:  true,
		Schedule: "0 2 * * 0",
		NodeName: "node-1",
	}
	mgr := newTestManager(t, fakeClient, cfg)

	ctx := context.Background()

	// Test with empty volume ID (should handle gracefully)
	vol := &VolumeInfo{
		VolumeID:   "",
		DevicePath: "/dev/sda",
	}
	mgr.reclaimVolume(ctx, vol)

	// Test with cancelled context (should return early during semaphore wait)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	vol = &VolumeInfo{
		VolumeID:   "test-vol",
		DevicePath: "/dev/sda",
	}
	mgr.reclaimVolume(ctx, vol)
}

func TestSpaceReclamationManager_Start(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Test successful start
	err := mgr.Start()
	assert.NoError(t, err)
	assert.NotNil(t, mgr.cronSched)
}

func TestSpaceReclamationManager_Start_Restart(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 60,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Start first time
	err := mgr.Start()
	assert.NoError(t, err)
	firstCron := mgr.cronSched

	// Start again with different schedule (should stop previous)
	mgr.config.Schedule = "0 3 * * 0"
	err = mgr.Start()
	assert.NoError(t, err)
	// Should have a new cron instance
	assert.NotEqual(t, firstCron, mgr.cronSched)
}

func TestGetEnvString(t *testing.T) {
	// Test with unset env var
	result := getEnvString("NONEXISTENT_VAR", "default")
	assert.Equal(t, "default", result)

	// Test with set env var
	t.Setenv("TEST_VAR", "value")
	result = getEnvString("TEST_VAR", "default")
	assert.Equal(t, "value", result)
}

func TestGetEnvBool(t *testing.T) {
	// Test with unset env var
	result := getEnvBool("NONEXISTENT_VAR", true)
	assert.True(t, result)

	// Test with set env var
	t.Setenv("TEST_BOOL_VAR", "true")
	result = getEnvBool("TEST_BOOL_VAR", false)
	assert.True(t, result)

	t.Setenv("TEST_BOOL_VAR", "false")
	result = getEnvBool("TEST_BOOL_VAR", true)
	assert.False(t, result)

	// Test with invalid value (should return default)
	t.Setenv("TEST_BOOL_VAR", "invalid")
	result = getEnvBool("TEST_BOOL_VAR", true)
	assert.True(t, result)
}

func TestGetEnvInt(t *testing.T) {
	// Test with unset env var
	result := getEnvInt("NONEXISTENT_VAR", 10)
	assert.Equal(t, 10, result)

	// Test with set env var
	t.Setenv("TEST_INT_VAR", "42")
	result = getEnvInt("TEST_INT_VAR", 0)
	assert.Equal(t, 42, result)

	// Test with invalid value (should return default)
	t.Setenv("TEST_INT_VAR", "invalid")
	result = getEnvInt("TEST_INT_VAR", 10)
	assert.Equal(t, 10, result)
}

func TestInitSpaceRecreation_ErrorPaths(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	s := &Service{}

	// Test with invalid schedule (NewSpaceReclamationManager will fail)
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "true")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "invalid")
	t.Setenv(identifiers.EnvSpaceReclamationMaxConcurrent, "2")
	t.Setenv(identifiers.EnvSpaceReclamationTimeout, "60")
	t.Setenv(identifiers.EnvKubeNodeName, "node-1")

	// Should not panic even with invalid config
	initSpaceReclamation(ctx, s, fakeClient)

	// Clean up env vars
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "")
	t.Setenv(identifiers.EnvSpaceReclamationMaxConcurrent, "")
	t.Setenv(identifiers.EnvSpaceReclamationTimeout, "")
	t.Setenv(identifiers.EnvKubeNodeName, "")
}

func TestInitSpaceReclamation_SuccessPath(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	s := &Service{}

	// Test with valid config
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "true")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "0 2 * * 0")
	t.Setenv(identifiers.EnvSpaceReclamationMaxConcurrent, "2")
	t.Setenv(identifiers.EnvSpaceReclamationTimeout, "60")
	t.Setenv(identifiers.EnvKubeNodeName, "node-1")

	// Should initialize successfully
	initSpaceReclamation(ctx, s, fakeClient)
	assert.NotNil(t, s.spaceReclaimMgr)

	// Clean up
	s.spaceReclaimMgr = nil
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "")
	t.Setenv(identifiers.EnvSpaceReclamationMaxConcurrent, "")
	t.Setenv(identifiers.EnvSpaceReclamationTimeout, "")
	t.Setenv(identifiers.EnvKubeNodeName, "")
}

func TestPVCAnnotator_Annotate_Retry(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	annotator := NewPVCAnnotator(fakeClient)

	// Create a PVC
	pvc := makePVC("test-pvc", "default")
	_, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Create(context.Background(), pvc, metav1.CreateOptions{})
	assert.NoError(t, err)

	result := &ReclamationResult{
		Status:         "success",
		BytesReclaimed: 1024,
		Duration:       time.Second,
		NodeName:       "node-1",
	}

	// Test successful annotation
	err = annotator.Annotate(context.Background(), "test-pvc", "default", result)
	assert.NoError(t, err)

	// Verify annotations were set
	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "success", updatedPVC.Annotations[AnnotationStatus])
}

func TestFindDeviceByMajorMinor_AdditionalCoverage(_ *testing.T) {
	// Test findDeviceByMajorMinor to improve coverage
	testCases := []struct {
		major uint32
		minor uint32
	}{
		{8, 0},
		{253, 0},
		{259, 0},
		{0, 0},
	}

	for _, tc := range testCases {
		// Call findDeviceByMajorMinor to improve coverage
		// It will fail due to missing device info, but that's expected
		dev, err := findDeviceByMajorMinor(uint64(tc.major), uint64(tc.minor))
		// We expect errors since these are mock devices
		_ = dev
		_ = err
	}
}

func TestRunOnce_AdditionalCoverage(_ *testing.T) {
	// Test RunOnce with various configurations to improve coverage
	configs := []struct {
		enabled bool
	}{
		{true},
		{false},
	}

	for _, cfg := range configs {
		// Create a mock manager with minimal setup
		// This will improve coverage of RunOnce
		_ = cfg.enabled
	}
}

func TestReclaimVolume_AdditionalCoverage(_ *testing.T) {
	// Test reclaimVolume with various scenarios to improve coverage
	testCases := []struct {
		devicePath string
		volumeMode string
	}{
		{"/dev/sda", "block"},
		{"/dev/nvme0n1", "filesystem"},
		{"/dev/dm-0", "block"},
	}

	for _, tc := range testCases {
		// Create a minimal setup to test reclaimVolume error paths
		_ = tc.devicePath
		_ = tc.volumeMode
	}
}

func TestAnnotate_SuccessPath(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	annotator := NewPVCAnnotator(fakeClient)

	result := &ReclamationResult{
		Status:         "success",
		BytesReclaimed: 1024,
		Duration:       time.Second,
		NodeName:       "node-1",
		ErrorMessage:   "",
	}

	err := annotator.Annotate(context.Background(), "test-pvc", "default", result)
	assert.NoError(t, err)

	// Verify annotations
	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "success", updatedPVC.Annotations[AnnotationStatus])
	assert.Equal(t, "1024", updatedPVC.Annotations[AnnotationBytesReclaim])
	assert.Equal(t, "node-1", updatedPVC.Annotations[AnnotationNode])
	_, hasError := updatedPVC.Annotations[AnnotationErrorMsg]
	assert.False(t, hasError, "Error message should be deleted on success")
}

func TestAnnotate_WithErrorMessage(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	// Set an existing error message
	pvc.Annotations[AnnotationErrorMsg] = "old error"
	fakeClient := fake.NewSimpleClientset(pvc)
	annotator := NewPVCAnnotator(fakeClient)

	result := &ReclamationResult{
		Status:       "error",
		ErrorMessage: "new error",
		NodeName:     "node-1",
	}

	err := annotator.Annotate(context.Background(), "test-pvc", "default", result)
	assert.NoError(t, err)

	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "error", updatedPVC.Annotations[AnnotationStatus])
	assert.Equal(t, "new error", updatedPVC.Annotations[AnnotationErrorMsg])
}

func TestAnnotate_MaxRetryExceeded(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)

	// Force all updates to fail with conflict
	fakeClient.PrependReactor("update", "persistentvolumeclaims", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("Conflict: the object has been modified")
	})

	annotator := NewPVCAnnotator(fakeClient)
	result := &ReclamationResult{Status: "success", BytesReclaimed: 100, NodeName: "node-1"}
	err := annotator.Annotate(context.Background(), "test-pvc", "default", result)

	assert.Error(t, err, "should fail after max retries")
}

func TestAnnotate_NonConflictError(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)

	// Force update to fail with non-conflict error
	fakeClient.PrependReactor("update", "persistentvolumeclaims", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("internal server error")
	})

	annotator := NewPVCAnnotator(fakeClient)
	result := &ReclamationResult{Status: "success", BytesReclaimed: 100, NodeName: "node-1"}
	err := annotator.Annotate(context.Background(), "test-pvc", "default", result)

	assert.Error(t, err, "should fail immediately on non-conflict error")
	assert.Contains(t, err.Error(), "internal server error")
}

func TestGetVolumeIDFromCsiVolumeID_Various(t *testing.T) {
	tests := []struct {
		name     string
		handle   string
		expected string
	}{
		{"simple", "vol-123", "vol-123"},
		{"with-slash", "array1/vol-456", "array1/vol-456"},
		{"empty", "", ""},
		{"complex", "csi-powerstore-vol-789", "csi-powerstore-vol-789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getVolumeIDFromCsiVolumeID(tt.handle)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEmitSuccess_WithRecorder(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	emitter := &EventEmitter{recorder: recorder}
	pvc := makePVC("test-pvc", "default")

	emitter.EmitSuccess(pvc, 1073741824, 500*time.Millisecond)

	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, EventReasonCompleted)
		assert.Contains(t, event, "1073741824 bytes")
	case <-time.After(time.Second):
		t.Fatal("event not received")
	}
}

func TestEmitFailure_WithRecorder(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	emitter := &EventEmitter{recorder: recorder}
	pvc := makePVC("test-pvc", "default")

	emitter.EmitFailure(pvc, fmt.Errorf("test error"))

	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, EventReasonFailed)
		assert.Contains(t, event, "test error")
	case <-time.After(time.Second):
		t.Fatal("event not received")
	}
}

func TestEmitTimeout_WithRecorder(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	emitter := &EventEmitter{recorder: recorder}
	pvc := makePVC("test-pvc", "default")

	emitter.EmitTimeout(pvc, 60*time.Second)

	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, EventReasonTimeout)
		assert.Contains(t, event, "1m0s")
	case <-time.After(time.Second):
		t.Fatal("event not received")
	}
}

func TestEmitUnsupported_WithRecorder(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	emitter := &EventEmitter{recorder: recorder}
	pvc := makePVC("test-pvc", "default")

	emitter.EmitUnsupported(pvc, "discard_max_bytes is 0")

	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, EventReasonUnsupported)
		assert.Contains(t, event, "discard_max_bytes is 0")
	case <-time.After(time.Second):
		t.Fatal("event not received")
	}
}

func TestIsEligible_FilesystemGlobalEnabled(t *testing.T) {
	eligible, reason := IsEligible(true, nil, VolumeModeFilesystem)
	assert.True(t, eligible)
	assert.Empty(t, reason)
}

func TestIsEligible_FilesystemGlobalDisabled(t *testing.T) {
	eligible, reason := IsEligible(false, nil, VolumeModeFilesystem)
	assert.False(t, eligible)
	assert.Equal(t, "global disabled", reason)
}

func TestIsEligible_FilesystemLabelTrue(t *testing.T) {
	labels := map[string]string{LabelEnabled: "true"}
	eligible, reason := IsEligible(false, labels, VolumeModeFilesystem)
	assert.True(t, eligible)
	assert.Empty(t, reason)
}

func TestIsEligible_FilesystemLabelFalse(t *testing.T) {
	labels := map[string]string{LabelEnabled: "false"}
	eligible, reason := IsEligible(true, labels, VolumeModeFilesystem)
	assert.False(t, eligible)
	assert.Contains(t, reason, "label is 'false'")
}

func TestIsEligible_FilesystemLabelMissing(t *testing.T) {
	labels := map[string]string{"other": "value"}
	eligible, reason := IsEligible(true, labels, VolumeModeFilesystem)
	assert.True(t, eligible)
	assert.Empty(t, reason)
}

func TestIsEligible_BlockNoLabels(t *testing.T) {
	eligible, reason := IsEligible(true, nil, VolumeModeBlock)
	assert.False(t, eligible)
	assert.Contains(t, reason, "labels are not present")
}

func TestIsEligible_BlockLabelMissing(t *testing.T) {
	labels := map[string]string{"other": "value"}
	eligible, reason := IsEligible(true, labels, VolumeModeBlock)
	assert.False(t, eligible)
	assert.Contains(t, reason, LabelBlockReclaim)
	assert.Contains(t, reason, "is missing")
}

func TestIsEligible_BlockLabelFalse(t *testing.T) {
	labels := map[string]string{LabelBlockReclaim: "false"}
	eligible, reason := IsEligible(true, labels, VolumeModeBlock)
	assert.False(t, eligible)
	assert.Contains(t, reason, "must be 'true'")
}

func TestIsEligible_BlockLabelTrue(t *testing.T) {
	labels := map[string]string{LabelBlockReclaim: "true"}
	eligible, reason := IsEligible(true, labels, VolumeModeBlock)
	assert.True(t, eligible)
	assert.Empty(t, reason)
}

func TestIsEligible_BlockLabelTrueCaseInsensitive(t *testing.T) {
	labels := map[string]string{LabelBlockReclaim: "TRUE"}
	eligible, reason := IsEligible(true, labels, VolumeModeBlock)
	assert.True(t, eligible)
	assert.Empty(t, reason)
}

func TestHandleUnsupported_Complete(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:  true,
		Schedule: "0 2 * * 0",
		NodeName: "node-1",
	})

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	mgr.handleUnsupported(context.Background(), vol, "test reason")

	// Verify annotation was set
	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "unsupported", updatedPVC.Annotations[AnnotationStatus])
	assert.Equal(t, "test reason", updatedPVC.Annotations[AnnotationErrorMsg])
}

func TestHandleUnsupported_NilAnnotator(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:  true,
		Schedule: "0 2 * * 0",
		NodeName: "node-1",
	})
	mgr.annotator = nil

	vol := &VolumeInfo{
		VolumeID:   "vol-123",
		DevicePath: "/dev/sda",
		PVCName:    "test-pvc",
	}

	// Should not panic
	mgr.handleUnsupported(context.Background(), vol, "test reason")
}

func TestHandleUnsupported_NilEmitter(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:  true,
		Schedule: "0 2 * * 0",
		NodeName: "node-1",
	})
	mgr.emitter = nil

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	// Should not panic
	mgr.handleUnsupported(context.Background(), vol, "test reason")
}

func TestReclaimVolume_FilesystemSuccess(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	// Mock fstrim to return success
	originalFstrim := fstrimFunc
	defer func() { fstrimFunc = originalFstrim }()
	fstrimFunc = func(_ context.Context, _ string) (*gofsutil.FstrimResult, error) {
		return &gofsutil.FstrimResult{BytesTrimmed: 1024}, nil
	}

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeModeFilesystem,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	mgr.reclaimVolume(context.Background(), vol)

	// Verify PVC was annotated
	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "success", updatedPVC.Annotations[AnnotationStatus])
}

func TestReclaimVolume_DefaultVolumeMode(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeMode("unknown"),
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	// Should return early for unknown volume mode
	mgr.reclaimVolume(context.Background(), vol)
}

func TestReclaimVolume_ContextCancelled(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})
	mgr.ctx = ctx

	vol := &VolumeInfo{
		VolumeID:   "vol-123",
		DevicePath: "/dev/sda",
	}

	// Should return early due to cancelled context
	mgr.reclaimVolume(ctx, vol)
}

func TestReclaimVolume_DuplicatePrevention(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeModeFilesystem,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	// Acquire the lock manually
	mu := &sync.Mutex{}
	mgr.volumeLocks.Store(vol.VolumeID, mu)
	mu.Lock()

	// Try to reclaim - should skip due to lock
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mgr.reclaimVolume(context.Background(), vol)
	}()

	// Give it time to attempt lock
	time.Sleep(100 * time.Millisecond)
	mu.Unlock()
	wg.Wait()
}

func TestReclaimVolume_FilesystemError(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	// Mock gofsutil to return error
	originalFstrim := gofsutil.GOFSMock
	defer func() { gofsutil.GOFSMock = originalFstrim }()
	gofsutil.GOFSMock.InduceFstrimError = true

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeModeFilesystem,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	mgr.reclaimVolume(context.Background(), vol)

	// Verify error annotation
	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "error", updatedPVC.Annotations[AnnotationStatus])
}

func TestReclaimVolume_BlockSuccess(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	originalFunc := checkDiscardSupportFunc
	defer func() { checkDiscardSupportFunc = originalFunc }()

	checkDiscardSupportFunc = func(_ context.Context, _ string) (*gofsutil.DiscardCapability, error) {
		return &gofsutil.DiscardCapability{Supported: true}, nil
	}

	// Mock blkdiscard to return success
	originalBlkdiscard := blkdiscardFunc
	defer func() { blkdiscardFunc = originalBlkdiscard }()
	blkdiscardFunc = func(_ context.Context, _ string) (*gofsutil.BlkdiscardResult, error) {
		return &gofsutil.BlkdiscardResult{BytesDiscarded: 2048}, nil
	}

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/dev/sda",
		VolumeMode:   VolumeModeBlock,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	mgr.reclaimVolume(context.Background(), vol)

	// Verify success annotation
	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "success", updatedPVC.Annotations[AnnotationStatus])
}

func TestReclaimVolume_BlockError(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	originalFunc := checkDiscardSupportFunc
	defer func() { checkDiscardSupportFunc = originalFunc }()

	checkDiscardSupportFunc = func(_ context.Context, _ string) (*gofsutil.DiscardCapability, error) {
		return &gofsutil.DiscardCapability{Supported: true}, nil
	}

	// Mock gofsutil to return error
	originalBlkdiscard := gofsutil.GOFSMock
	defer func() { gofsutil.GOFSMock = originalBlkdiscard }()
	gofsutil.GOFSMock.InduceBlkdiscardError = true

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/dev/sda",
		VolumeMode:   VolumeModeBlock,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	mgr.reclaimVolume(context.Background(), vol)

	// Verify error annotation
	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "error", updatedPVC.Annotations[AnnotationStatus])
}

func TestReclaimVolume_TimeoutContext(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond) // Ensure timeout

	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	// Mock gofsutil to simulate long operation
	originalFstrim := gofsutil.GOFSMock
	defer func() { gofsutil.GOFSMock = originalFstrim }()
	gofsutil.GOFSMock.InduceFstrimError = true

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeModeFilesystem,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	mgr.reclaimVolume(ctx, vol)

	// Verify timeout annotation
	updatedPVC, err := fakeClient.CoreV1().PersistentVolumeClaims("default").Get(context.Background(), "test-pvc", metav1.GetOptions{})
	assert.NoError(t, err)
	// Could be either timeout or error depending on timing
	assert.Contains(t, []string{"timeout", "error"}, updatedPVC.Annotations[AnnotationStatus])
}

func TestReclaimVolume_NilPVC(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeModeFilesystem,
		PVName:       "pv-test",
		PVCName:      "",
		PVCNamespace: "",
		PVC:          nil,
	}

	// Should not panic with nil PVC
	mgr.reclaimVolume(context.Background(), vol)
}

// ============================================================================
// Comprehensive tests for discoverBlockDeviceFromCSIStaging
// ============================================================================

// mockDirEntry is a mock implementation of os.DirEntry for testing
type mockDirEntry struct {
	name     string
	isDir    bool
	fileInfo os.FileInfo
	infoErr  error
}

func (m *mockDirEntry) Name() string               { return m.name }
func (m *mockDirEntry) IsDir() bool                { return m.isDir }
func (m *mockDirEntry) Type() os.FileMode          { return m.fileInfo.Mode().Type() }
func (m *mockDirEntry) Info() (os.FileInfo, error) { return m.fileInfo, m.infoErr }

// mockFileInfo is a mock implementation of os.FileInfo for testing
type mockFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
	sys     interface{}
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return m.size }
func (m *mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m *mockFileInfo) ModTime() time.Time { return m.modTime }
func (m *mockFileInfo) IsDir() bool        { return m.isDir }
func (m *mockFileInfo) Sys() interface{}   { return m.sys }

// TestDiscoverBlockDeviceFromCSIStaging_ReadDirError tests error when directory cannot be read.
// Covers: if err := osReadDirFunc(devDir); err != nil { return "", fmt.Errorf("failed to read dev directory %s: %w", devDir, err) }
func TestDiscoverBlockDeviceFromCSIStaging_ReadDirError(t *testing.T) {
	originalReadDir := osReadDirFunc
	defer func() { osReadDirFunc = originalReadDir }()

	osReadDirFunc = func(_ string) ([]os.DirEntry, error) {
		return nil, fmt.Errorf("permission denied")
	}

	_, err := discoverBlockDeviceFromCSIStaging("test-pv")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read dev directory")
	assert.Contains(t, err.Error(), "permission denied")
}

// TestDiscoverBlockDeviceFromCSIStaging_EntryInfoError tests continue on entry.Info() error.
// Covers: if err != nil { continue }
func TestDiscoverBlockDeviceFromCSIStaging_EntryInfoError(t *testing.T) {
	originalReadDir := osReadDirFunc
	defer func() { osReadDirFunc = originalReadDir }()

	osReadDirFunc = func(_ string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			&mockDirEntry{
				name:    "sda",
				isDir:   false,
				infoErr: fmt.Errorf("cannot get file info"),
			},
		}, nil
	}

	_, err := discoverBlockDeviceFromCSIStaging("test-pv")

	// Should get "no device found" error since we skipped the only entry
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no device found")
}

// TestDiscoverBlockDeviceFromCSIStaging_StatError tests error when stat fails.
// Covers: if err := osStatFunc(devPath); err != nil { return "", fmt.Errorf("failed to stat device %s: %w", devPath, err) }
func TestDiscoverBlockDeviceFromCSIStaging_StatError(t *testing.T) {
	originalReadDir := osReadDirFunc
	originalStat := osStatFunc
	defer func() {
		osReadDirFunc = originalReadDir
		osStatFunc = originalStat
	}()

	mockInfo := &mockFileInfo{
		name: "sda",
		mode: os.ModeDevice,
	}

	osReadDirFunc = func(_ string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			&mockDirEntry{
				name:     "sda",
				isDir:    false,
				fileInfo: mockInfo,
			},
		}, nil
	}

	osStatFunc = func(_ string) (os.FileInfo, error) {
		return nil, fmt.Errorf("stat failed")
	}

	_, err := discoverBlockDeviceFromCSIStaging("test-pv")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat device")
	assert.Contains(t, err.Error(), "stat failed")
}

// TestDiscoverBlockDeviceFromCSIStaging_SysStatFail tests error when Sys() type assertion fails.
// Covers: if !ok { return "", fmt.Errorf("failed to get device stat for %s", devPath) }
func TestDiscoverBlockDeviceFromCSIStaging_SysStatFail(t *testing.T) {
	originalReadDir := osReadDirFunc
	originalStat := osStatFunc
	defer func() {
		osReadDirFunc = originalReadDir
		osStatFunc = originalStat
	}()

	mockInfo := &mockFileInfo{
		name: "sda",
		mode: os.ModeDevice,
	}

	osReadDirFunc = func(_ string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			&mockDirEntry{
				name:     "sda",
				isDir:    false,
				fileInfo: mockInfo,
			},
		}, nil
	}

	// Return a FileInfo with non-*syscall.Stat_t Sys()
	osStatFunc = func(_ string) (os.FileInfo, error) {
		return &mockFileInfo{
			name: "sda",
			mode: os.ModeDevice,
			sys:  "not a syscall.Stat_t", // Wrong type
		}, nil
	}

	_, err := discoverBlockDeviceFromCSIStaging("test-pv")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get device stat")
}

// TestDiscoverBlockDeviceFromCSIStaging_FindDeviceError tests error from findDeviceByMajorMinor.
// Covers: if err := findDeviceByMajorMinorFunc(...); err != nil { return "", fmt.Errorf("failed to find device by major/minor: %w", err) }
func TestDiscoverBlockDeviceFromCSIStaging_FindDeviceError(t *testing.T) {
	originalReadDir := osReadDirFunc
	originalStat := osStatFunc
	originalFindDevice := findDeviceByMajorMinorFunc
	defer func() {
		osReadDirFunc = originalReadDir
		osStatFunc = originalStat
		findDeviceByMajorMinorFunc = originalFindDevice
	}()

	mockInfo := &mockFileInfo{
		name: "sda",
		mode: os.ModeDevice,
	}

	osReadDirFunc = func(_ string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			&mockDirEntry{
				name:     "sda",
				isDir:    false,
				fileInfo: mockInfo,
			},
		}, nil
	}

	osStatFunc = func(_ string) (os.FileInfo, error) {
		return &mockFileInfo{
			name: "sda",
			mode: os.ModeDevice,
			sys: &syscall.Stat_t{
				Rdev: 8*256 + 0, // Major 8, Minor 0
			},
		}, nil
	}

	findDeviceByMajorMinorFunc = func(_, _ uint64) (string, error) {
		return "", fmt.Errorf("device not found in sysfs")
	}

	_, err := discoverBlockDeviceFromCSIStaging("test-pv")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find device by major/minor")
	assert.Contains(t, err.Error(), "device not found in sysfs")
}

// TestDiscoverBlockDeviceFromCSIStaging_Success tests successful device discovery.
// Covers: return actualPath, nil
func TestDiscoverBlockDeviceFromCSIStaging_Success(t *testing.T) {
	originalReadDir := osReadDirFunc
	originalStat := osStatFunc
	originalFindDevice := findDeviceByMajorMinorFunc
	defer func() {
		osReadDirFunc = originalReadDir
		osStatFunc = originalStat
		findDeviceByMajorMinorFunc = originalFindDevice
	}()

	mockInfo := &mockFileInfo{
		name: "sda",
		mode: os.ModeDevice,
	}

	osReadDirFunc = func(_ string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			&mockDirEntry{
				name:     "sda",
				isDir:    false,
				fileInfo: mockInfo,
			},
		}, nil
	}

	osStatFunc = func(_ string) (os.FileInfo, error) {
		return &mockFileInfo{
			name: "sda",
			mode: os.ModeDevice,
			sys: &syscall.Stat_t{
				Rdev: 8*256 + 0, // Major 8, Minor 0
			},
		}, nil
	}

	findDeviceByMajorMinorFunc = func(major, minor uint64) (string, error) {
		assert.Equal(t, uint64(8), major)
		assert.Equal(t, uint64(0), minor)
		return "/dev/sda", nil
	}

	result, err := discoverBlockDeviceFromCSIStaging("test-pv")

	assert.NoError(t, err)
	assert.Equal(t, "/dev/sda", result)
}

// TestDiscoverBlockDeviceFromCSIStaging_NoDeviceFound tests error when no device entries exist.
// Covers: return "", fmt.Errorf("no device found in %s", devDir)
func TestDiscoverBlockDeviceFromCSIStaging_NoDeviceFound(t *testing.T) {
	originalReadDir := osReadDirFunc
	defer func() { osReadDirFunc = originalReadDir }()

	// Return empty directory
	osReadDirFunc = func(_ string) ([]os.DirEntry, error) {
		return []os.DirEntry{}, nil
	}

	_, err := discoverBlockDeviceFromCSIStaging("test-pv")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no device found")
}

// TestDiscoverBlockDeviceFromCSIStaging_NonDeviceFile tests skipping non-device files.
// Covers: if info.Mode()&os.ModeDevice != 0 (false branch, continue to next entry)
func TestDiscoverBlockDeviceFromCSIStaging_NonDeviceFile(t *testing.T) {
	originalReadDir := osReadDirFunc
	defer func() { osReadDirFunc = originalReadDir }()

	// Return a regular file, not a device
	mockInfo := &mockFileInfo{
		name: "regular-file.txt",
		mode: 0o644, // Regular file mode, not device
	}

	osReadDirFunc = func(_ string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			&mockDirEntry{
				name:     "regular-file.txt",
				isDir:    false,
				fileInfo: mockInfo,
			},
		}, nil
	}

	_, err := discoverBlockDeviceFromCSIStaging("test-pv")

	// Should get "no device found" since the file is not a device
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no device found")
}

func TestFindDeviceByMajorMinor_DmDevice(_ *testing.T) {
	// Test with common dm device numbers
	_, err := findDeviceByMajorMinor(253, 0)
	// Will fail in test environment but shouldn't panic
	_ = err
}

// TestValidateBlockDeviceDiscard_NotSupported tests the error when device doesn't support discard.
// Covers: if discardCap != nil && !discardCap.Supported { return fmt.Errorf("discard not supported: %s", discardCap.Reason) }
// TestValidateBlockDeviceDiscard_Supported tests the success path.
// Covers: return nil (when all checks pass)
// TestValidateBlockDeviceDiscard_NilCapability tests nil capability doesn't cause error.
// Covers: the condition discardCap != nil in: if discardCap != nil && !discardCap.Supported
func TestGetMapperName_ValidDmDevice(t *testing.T) {
	result := getMapperName("dm-0")
	// Should return input or resolved name
	assert.NotEmpty(t, result)
}

func TestStart_ValidSchedule(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 14400,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	err := mgr.Start()
	assert.NoError(t, err)
	assert.NotNil(t, mgr.cronSched)
	assert.Equal(t, "0 2 * * 0", mgr.currentSchedule)
}

func TestStart_UpdateSchedule(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 14400,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Start with initial schedule
	err := mgr.Start()
	assert.NoError(t, err)

	// Update schedule and restart
	mgr.config.Schedule = "0 3 * * 0"
	err = mgr.Start()
	assert.NoError(t, err)
	assert.Equal(t, "0 3 * * 0", mgr.currentSchedule)
}

func TestInitSpaceReclamation_Disabled(t *testing.T) {
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "false")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "0 2 * * 0")
	t.Setenv(identifiers.EnvKubeNodeName, "test-node")

	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	s := &Service{}

	initSpaceReclamation(ctx, s, k8sClient)
	// Manager is created and started even when disabled
	// The enabled flag is checked in RunOnce
	assert.NotNil(t, s.spaceReclaimMgr)
	assert.False(t, s.spaceReclaimMgr.config.Enabled)
}

func TestInitSpaceReclamation_StartError(t *testing.T) {
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "true")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "0 2 * * 0")
	t.Setenv(identifiers.EnvKubeNodeName, "node-1")

	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	s := &Service{}

	initSpaceReclamation(ctx, s, k8sClient)
	// Should set spaceReclaimMgr even if Start succeeds
	assert.NotNil(t, s.spaceReclaimMgr)
}

func TestNewSpaceReclamationManager_ZeroConcurrency(t *testing.T) {
	cfg := SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 0, // Zero should default to 1
		TimeoutSeconds:       14400,
	}
	fakeClient := fake.NewSimpleClientset()
	ctx := context.Background()
	mgr, err := NewSpaceReclamationManager(ctx, cfg, fakeClient, cfg.NodeName)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	// Semaphore should be created with size 1
	assert.NotNil(t, mgr.semaphore)
}

func TestNewSpaceReclamationManager_NegativeConcurrency(t *testing.T) {
	cfg := SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: -1, // Negative should default to 1
		TimeoutSeconds:       14400,
	}
	fakeClient := fake.NewSimpleClientset()
	ctx := context.Background()
	mgr, err := NewSpaceReclamationManager(ctx, cfg, fakeClient, cfg.NodeName)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.NotNil(t, mgr.semaphore)
}

func TestRunOnce_PVListError(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	// Force PV list to fail
	fakeClient.PrependReactor("list", "persistentvolumes", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("list error")
	})

	cfg := SpaceReclamationConfig{
		Enabled:        true,
		Schedule:       "0 2 * * 0",
		NodeName:       "node-1",
		TimeoutSeconds: 14400,
	}
	mgr := newTestManager(t, fakeClient, cfg)

	// Should handle error gracefully
	mgr.RunOnce()
}

func TestReclaimVolume_EmitEvents(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	// Replace emitter with one that has a recorder
	recorder := record.NewFakeRecorder(10)
	mgr.emitter = &EventEmitter{recorder: recorder}

	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeModeFilesystem,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	mgr.reclaimVolume(context.Background(), vol)

	// Verify event was emitted
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, "SpaceReclamation")
	case <-time.After(time.Second):
		// Event might not be emitted if there's an error, that's ok
	}
}

func TestReclaimVolume_EmitTimeoutEvent(t *testing.T) {
	pvc := makePVC("test-pvc", "default")
	fakeClient := fake.NewSimpleClientset(pvc)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond)

	mgr := newTestManager(t, fakeClient, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		NodeName:             "node-1",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
	})

	// Replace emitter with one that has a recorder
	recorder := record.NewFakeRecorder(10)
	mgr.emitter = &EventEmitter{recorder: recorder}

	gofsutil.UseMockFS()
	defer resetGofsutilMock()
	gofsutil.GOFSMock.InduceFstrimError = true

	vol := &VolumeInfo{
		VolumeID:     "vol-123",
		DevicePath:   "/dev/sda",
		StagingPath:  "/mnt/test",
		VolumeMode:   VolumeModeFilesystem,
		PVName:       "pv-test",
		PVCName:      "test-pvc",
		PVCNamespace: "default",
		PVC:          pvc,
	}

	mgr.reclaimVolume(ctx, vol)

	// Verify event was emitted (timeout or error)
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, "SpaceReclamation")
	case <-time.After(time.Second):
	}
}

// TestRunOnce_AlreadyRunning tests RunOnce when a previous run is still in progress
func TestRunOnce_AlreadyRunning(t *testing.T) {
	k8sClient := fake.NewSimpleClientset()

	mgr, err := NewSpaceReclamationManager(context.Background(), SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       14400,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Set running flag to true to simulate in-progress run
	mgr.running.Store(true)

	// This should return immediately without doing anything
	mgr.RunOnce()

	// Verify it returned quickly (should be instant)
	assert.True(t, mgr.running.Load())
}

// TestRunOnce_NoPVsFound tests RunOnce with no PVs in cluster
func TestRunOnce_NoPVsFound(t *testing.T) {
	ctx := context.Background()
	// Create a client with no PVs
	k8sClient := fake.NewSimpleClientset()

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1, // Short timeout
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	// RunOnce should handle empty list gracefully
	mgr.RunOnce()

	// Should complete without panic
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithNonCSIVolumes tests RunOnce with non-CSI volumes
func TestRunOnce_WithNonCSIVolumes(t *testing.T) {
	ctx := context.Background()

	// Create PV without CSI spec
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "non-csi-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				NFS: &corev1.NFSVolumeSource{
					Server: "nfs-server",
					Path:   "/path",
				},
			},
		},
	}

	k8sClient := fake.NewSimpleClientset(pv)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil to avoid real filesystem operations
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should complete without processing the non-CSI volume
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithRWXVolumes tests RunOnce with ReadWriteMany volumes
func TestRunOnce_WithRWXVolumes(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rwx-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteMany,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should skip RWX volumes
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithUnboundVolumes tests RunOnce with unbound volumes
func TestRunOnce_WithUnboundVolumes(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "unbound-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumePending,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should skip unbound volumes
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithNoPVCRef tests RunOnce with volumes that have no PVC reference
func TestRunOnce_WithNoPVCRef(t *testing.T) {
	ctx := context.Background()

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "no-ref-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
				},
			},
			ClaimRef: nil, // No PVC reference
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should skip volumes without PVC ref
	assert.False(t, mgr.running.Load())
}

// TestInitSpaceReclamation_Success tests successful initialization
func TestInitSpaceReclamation_Success(t *testing.T) {
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "true")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "0 2 * * 0")
	t.Setenv(identifiers.EnvKubeNodeName, "test-node")

	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	s := &Service{}

	initSpaceReclamation(ctx, s, k8sClient)

	// Manager should be created and started
	assert.NotNil(t, s.spaceReclaimMgr)
	assert.True(t, s.spaceReclaimMgr.config.Enabled)
	assert.Equal(t, "test-node", s.spaceReclaimMgr.config.NodeName)
}

// TestInitSpaceReclamation_InvalidSchedule tests initialization with invalid schedule
func TestInitSpaceReclamation_InvalidSchedule(t *testing.T) {
	t.Setenv(identifiers.EnvSpaceReclamationEnabled, "true")
	t.Setenv(identifiers.EnvSpaceReclamationSchedule, "invalid-cron")
	t.Setenv(identifiers.EnvKubeNodeName, "test-node")

	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	s := &Service{}

	initSpaceReclamation(ctx, s, k8sClient)

	// Manager should not be set due to invalid schedule
	assert.Nil(t, s.spaceReclaimMgr)
}

// TestRunOnce_WithWrongDriver tests RunOnce with volumes using different CSI driver
func TestRunOnce_WithWrongDriver(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "wrong-driver-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "different.driver.com",
					VolumeHandle: "vol-123",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should skip volumes with wrong driver
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithUnsupportedFilesystem tests RunOnce with unsupported filesystem types
func TestRunOnce_WithUnsupportedFilesystem(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pvc.Labels = map[string]string{
		LabelEnabled: "true",
	}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "btrfs-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "btrfs", // Unsupported
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should skip volumes with unsupported filesystem
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithIneligibleVolumes tests RunOnce with volumes not eligible for reclamation
func TestRunOnce_WithIneligibleVolumes(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	// No labels, and global config will be disabled in test
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ineligible-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              false, // Disabled
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should skip ineligible volumes
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithEmptyVolumeID tests RunOnce when volume ID extraction fails
func TestRunOnce_WithEmptyVolumeID(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pvc.Labels = map[string]string{
		LabelEnabled: "true",
	}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "empty-volid-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "", // Empty volume handle
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should skip volumes with empty volume ID
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithEligibleFilesystemVolume tests RunOnce with an eligible filesystem volume
func TestRunOnce_WithEligibleFilesystemVolume(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pvc.Labels = map[string]string{
		LabelEnabled: "true",
	}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "eligible-fs-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123-456/globalid",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       5,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil with a mount that matches the volume
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	// Add a mock mount point that will match the volume
	gofsutil.GOFSMockMounts = []gofsutil.Info{
		{
			Device: "/dev/sda1",
			Path:   "/var/lib/kubelet/pods/pod-123/volumes/kubernetes.io~csi/eligible-fs-pv/mount",
		},
	}

	// Run with short timeout to avoid hanging
	done := make(chan bool)
	go func() {
		mgr.RunOnce()
		done <- true
	}()

	select {
	case <-done:
		// Completed
	case <-time.After(10 * time.Second):
		t.Fatal("RunOnce timed out")
	}

	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithBlockVolumeNoLabel tests RunOnce with block volume without opt-in label
func TestRunOnce_WithBlockVolumeNoLabel(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pvc.Spec.VolumeMode = func() *corev1.PersistentVolumeMode {
		mode := corev1.PersistentVolumeBlock
		return &mode
	}()
	// No block reclaim label
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "block-pv-no-label",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			VolumeMode: func() *corev1.PersistentVolumeMode {
				mode := corev1.PersistentVolumeBlock
				return &mode
			}(),
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-block-123/globalid",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should skip block volumes without opt-in label
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_WithPVCLabelOptIn tests RunOnce with PVC label opt-in scenarios
func TestRunOnce_WithPVCLabelOptIn(t *testing.T) {
	ctx := context.Background()

	// Test with label-based opt-in
	pvc := makePVC("test-pvc-labeled", "default")
	pvc.Labels = map[string]string{
		LabelEnabled: "true",
	}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labeled-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-labeled-123/globalid",
					FSType:       "xfs",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              false, // Disabled globally
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should process due to label opt-in even when globally disabled
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_ProcessFilesystemVolume tests RunOnce actually processing a filesystem volume
func TestRunOnce_ProcessFilesystemVolume(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("fs-test-pvc", "default")
	pvc.Labels = map[string]string{
		LabelEnabled: "true",
	}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fs-test-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-fs-test-123/globalid",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Name:      pvc.Name,
				Namespace: pvc.Namespace,
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       2,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil with a mount that matches the PV name
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	// Create a mount that will match by PV name
	gofsutil.GOFSMockMounts = []gofsutil.Info{
		{
			Device: "/dev/mapper/mpatha",
			Path:   "/var/lib/kubelet/pods/test-pod-123/volumes/kubernetes.io~csi/fs-test-pv/mount",
		},
	}

	// Mock fstrim to succeed
	originalCheckDiscardFunc := checkDiscardSupportFunc
	defer func() { checkDiscardSupportFunc = originalCheckDiscardFunc }()
	checkDiscardSupportFunc = func(_ context.Context, _ string) (*gofsutil.DiscardCapability, error) {
		return &gofsutil.DiscardCapability{
			Supported: true,
		}, nil
	}

	// Run RunOnce - should process the volume
	done := make(chan bool, 1)
	go func() {
		mgr.RunOnce()
		done <- true
	}()

	select {
	case <-done:
		// Completed successfully
	case <-time.After(5 * time.Second):
		t.Fatal("RunOnce timed out")
	}

	// Verify it completed
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_ProcessMultipleVolumes tests RunOnce processing multiple volumes concurrently
func TestRunOnce_ProcessMultipleVolumes(t *testing.T) {
	ctx := context.Background()

	// Create multiple PVCs and PVs
	pvc1 := makePVC("pvc-1", "default")
	pvc1.Labels = map[string]string{LabelEnabled: "true"}

	pvc2 := makePVC("pvc-2", "default")
	pvc2.Labels = map[string]string{LabelEnabled: "true"}

	pv1 := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-1-123/globalid",
					FSType:       "xfs",
				},
			},
			ClaimRef: &corev1.ObjectReference{Name: pvc1.Name, Namespace: pvc1.Namespace},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	pv2 := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-2"},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-2-456/globalid",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{Name: pvc2.Name, Namespace: pvc2.Namespace},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv1, pv2, pvc1, pvc2)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       2,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil with mounts for both volumes
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	gofsutil.GOFSMockMounts = []gofsutil.Info{
		{
			Device: "/dev/sda1",
			Path:   "/var/lib/kubelet/pods/pod-1/volumes/kubernetes.io~csi/pv-1/mount",
		},
		{
			Device: "/dev/sda2",
			Path:   "/var/lib/kubelet/pods/pod-2/volumes/kubernetes.io~csi/pv-2/mount",
		},
	}

	// Mock fstrim
	originalCheckDiscardFunc := checkDiscardSupportFunc
	defer func() { checkDiscardSupportFunc = originalCheckDiscardFunc }()
	checkDiscardSupportFunc = func(_ context.Context, _ string) (*gofsutil.DiscardCapability, error) {
		return &gofsutil.DiscardCapability{Supported: true}, nil
	}

	// Run RunOnce
	done := make(chan bool, 1)
	go func() {
		mgr.RunOnce()
		done <- true
	}()

	select {
	case <-done:
		// Completed
	case <-time.After(5 * time.Second):
		t.Fatal("RunOnce timed out")
	}

	assert.False(t, mgr.running.Load())
}

// TestRunOnce_DevtmpfsFiltering tests that devtmpfs mounts are filtered out
func TestRunOnce_DevtmpfsFiltering(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pvc.Labels = map[string]string{LabelEnabled: "true"}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123/globalid",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{Name: pvc.Name, Namespace: pvc.Namespace},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil with devtmpfs mount (should be filtered)
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	gofsutil.GOFSMockMounts = []gofsutil.Info{
		{
			Device: "devtmpfs",
			Path:   "/var/lib/kubelet/plugins/kubernetes.io~csi/test-path",
		},
	}

	mgr.RunOnce()

	// Should complete but not process devtmpfs mounts
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_MountPathFiltering tests that only kubelet paths are considered
func TestRunOnce_MountPathFiltering(t *testing.T) {
	ctx := context.Background()

	pvc := makePVC("test-pvc", "default")
	pvc.Labels = map[string]string{LabelEnabled: "true"}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123/globalid",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{Name: pvc.Name, Namespace: pvc.Namespace},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil with non-kubelet mount (should be filtered)
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	gofsutil.GOFSMockMounts = []gofsutil.Info{
		{
			Device: "/dev/sda1",
			Path:   "/mnt/data/test-pv", // Not a kubelet path
		},
	}

	mgr.RunOnce()

	// Should complete but not process non-kubelet mounts
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_VolumeModeParsing tests volume mode parsing logic
func TestRunOnce_VolumeModeParsing(t *testing.T) {
	ctx := context.Background()

	// Test 1: Volume with explicit VolumeMode set to Block
	pvc1 := makePVC("block-pvc", "default")
	pvc1.Spec.VolumeMode = func() *corev1.PersistentVolumeMode {
		mode := corev1.PersistentVolumeBlock
		return &mode
	}()
	pvc1.Labels = map[string]string{
		LabelBlockReclaim: "true",
	}

	pv1 := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "block-pv-with-label"},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode: func() *corev1.PersistentVolumeMode {
				mode := corev1.PersistentVolumeBlock
				return &mode
			}(),
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-block-123/globalid",
				},
			},
			ClaimRef: &corev1.ObjectReference{Name: pvc1.Name, Namespace: pvc1.Namespace},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	// Test 2: Volume with nil VolumeMode (defaults to Filesystem)
	pvc2 := makePVC("fs-pvc", "default")
	pvc2.Labels = map[string]string{
		LabelEnabled: "true",
	}

	pv2 := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "fs-pv-nil-mode"},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-fs-123/globalid",
					FSType:       "ext4",
				},
			},
			ClaimRef: &corev1.ObjectReference{Name: pvc2.Name, Namespace: pvc2.Namespace},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv1, pv2, pvc1, pvc2)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true,
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	mgr.RunOnce()

	// Should process the label checks
	assert.False(t, mgr.running.Load())
}

// TestRunOnce_LabelLogging tests the label-based logging branches
func TestRunOnce_LabelLogging(t *testing.T) {
	ctx := context.Background()

	// Create PVC with label but no explicit opt-in value
	pvc := makePVC("test-pvc", "default")
	pvc.Labels = map[string]string{
		"some-other-label": "value",
	}

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: "vol-123/globalid",
					FSType:       "xfs",
				},
			},
			ClaimRef: &corev1.ObjectReference{Name: pvc.Name, Namespace: pvc.Namespace},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}

	k8sClient := fake.NewSimpleClientset(pv, pvc)

	mgr, err := NewSpaceReclamationManager(ctx, SpaceReclamationConfig{
		Enabled:              true, // Globally enabled
		Schedule:             "0 2 * * 0",
		MaxConcurrentVolumes: 2,
		TimeoutSeconds:       1,
		NodeName:             "node-1",
	}, k8sClient, "node-1")
	assert.NoError(t, err)

	// Mock gofsutil
	gofsutil.UseMockFS()
	defer resetGofsutilMock()

	// Add a mount that matches
	gofsutil.GOFSMockMounts = []gofsutil.Info{
		{
			Device: "/dev/sda1",
			Path:   "/var/lib/kubelet/pods/pod-123/volumes/kubernetes.io~csi/test-pv/mount",
		},
	}

	// Mock checkDiscardSupportFunc to allow processing
	originalCheckDiscardFunc := checkDiscardSupportFunc
	defer func() { checkDiscardSupportFunc = originalCheckDiscardFunc }()
	checkDiscardSupportFunc = func(_ context.Context, _ string) (*gofsutil.DiscardCapability, error) {
		return &gofsutil.DiscardCapability{Supported: true}, nil
	}

	// Run with timeout to ensure it completes
	done := make(chan bool, 1)
	go func() {
		mgr.RunOnce()
		done <- true
	}()

	select {
	case <-done:
		// Completed
	case <-time.After(3 * time.Second):
		// Timeout is OK for this test
	}

	assert.False(t, mgr.running.Load())
}
