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
	"errors"
	"sync"
	"testing"

	"github.com/dell/csi-metadata-retriever/retriever"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/gofsutil"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
)

func TestResolvePVNameFromTargetPath(t *testing.T) {
	tests := []struct {
		name       string
		targetPath string
		expected   string
	}{
		{
			name:       "standard kubelet path",
			targetPath: "/var/lib/kubelet/pods/abc-123/volumes/kubernetes.io~csi/pvc-deadbeef/mount",
			expected:   "pvc-deadbeef",
		},
		{
			name:       "custom kubelet path",
			targetPath: "/custom/kubelet/pods/uid/volumes/kubernetes.io~csi/my-pv-name/mount",
			expected:   "my-pv-name",
		},
		{
			name:       "no csi segment",
			targetPath: "/var/lib/kubelet/pods/abc-123/volumes/nfs/pvc-deadbeef/mount",
			expected:   "",
		},
		{
			name:       "empty path",
			targetPath: "",
			expected:   "",
		},
		{
			name:       "path ending at pv name without trailing slash",
			targetPath: "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~csi/pv-name",
			expected:   "",
		},
		{
			name:       "path with only csi segment and nothing after",
			targetPath: "/volumes/kubernetes.io~csi/",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsck := &FsCheckRunner{}
			fsck.ResolvePVNameFromTargetPath(tt.targetPath)
			assert.Equal(t, tt.expected, fsck.pvName)
		})
	}
}

func TestResolvePVNameFromTargetPath_PresetPVName(t *testing.T) {
	fsck := &FsCheckRunner{pvName: "already-set"}
	fsck.ResolvePVNameFromTargetPath("/var/lib/kubelet/pods/uid/volumes/kubernetes.io~csi/pv-name/mount")
	assert.Equal(t, "already-set", fsck.pvName, "should not override pre-set pvName")
}

func TestResolveEffectiveSettings_NoPVName(t *testing.T) {
	m := new(MockMetadataRetrieverClient)
	m.On("GetPVCLabelsByPVName", mock.Anything, mock.Anything).Return(
		&retriever.GetPVCLabelsByPVNameResponse{
			Parameters: map[string]string{},
		}, nil,
	)
	fsck := &FsCheckRunner{enabled: true, mode: "checkonly", metadataRetriever: m}
	err := fsck.resolveEffectiveSettings(context.Background())
	assert.NoError(t, err)
	assert.True(t, fsck.enabled)
	assert.Equal(t, "checkonly", fsck.mode)
}

func TestResolveEffectiveSettings_LookupError(t *testing.T) {
	m := new(MockMetadataRetrieverClient)
	m.On("GetPVCLabelsByPVName", mock.Anything, mock.Anything).Return(
		(*retriever.GetPVCLabelsByPVNameResponse)(nil), errors.New("rpc error"),
	)

	fsck := &FsCheckRunner{
		enabled:           true,
		mode:              "checkonly",
		pvName:            "pv-name",
		fullVolumeID:      "vol-id",
		metadataRetriever: m,
	}
	err := fsck.resolveEffectiveSettings(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not retrieve PVC labels")
}

func TestResolveEffectiveSettings_WithValidPVCLabels(t *testing.T) {
	m := new(MockMetadataRetrieverClient)
	m.On("GetPVCLabelsByPVName", mock.Anything, mock.Anything).Return(
		&retriever.GetPVCLabelsByPVNameResponse{
			PVCName: "my-pvc",
			Parameters: map[string]string{
				"csi.dell.com/fs_check_enabled": "true",
				"csi.dell.com/fs_check_mode":    "checkAndRepair",
			},
		}, nil,
	)

	fsck := &FsCheckRunner{
		enabled:           false,
		mode:              "checkonly",
		pvName:            "pv-name",
		fullVolumeID:      "vol-id",
		metadataRetriever: m,
	}
	err := fsck.resolveEffectiveSettings(context.Background())
	assert.NoError(t, err)
	assert.True(t, fsck.enabled)
	assert.Equal(t, "checkandrepair", fsck.mode)
	assert.Equal(t, "my-pvc", fsck.pvcName)
}

func TestResolveEffectiveSettings_NoValidPVCLabels(t *testing.T) {
	m := new(MockMetadataRetrieverClient)
	m.On("GetPVCLabelsByPVName", mock.Anything, mock.Anything).Return(
		&retriever.GetPVCLabelsByPVNameResponse{
			PVCName:    "my-pvc",
			Parameters: map[string]string{},
		}, nil,
	)

	fsck := &FsCheckRunner{
		enabled:           true,
		mode:              "checkonly",
		pvName:            "pv-name",
		fullVolumeID:      "vol-id",
		metadataRetriever: m,
	}
	err := fsck.resolveEffectiveSettings(context.Background())
	assert.NoError(t, err)
	assert.True(t, fsck.enabled)
	assert.Equal(t, "checkonly", fsck.mode)
}

func TestResolveEffectiveSettings_PVCLabelOverridesEnabled(t *testing.T) {
	tests := []struct {
		name            string
		globalEnabled   bool
		globalMode      string
		pvcLabels       map[string]string
		expectedEnabled bool
		expectedMode    string
	}{
		{
			name:          "PVC label overrides enabled to true",
			globalEnabled: false,
			globalMode:    "checkonly",
			pvcLabels: map[string]string{
				"csi.dell.com/fs_check_enabled": "true",
			},
			expectedEnabled: true,
			expectedMode:    "checkonly",
		},
		{
			name:          "PVC label overrides enabled to false",
			globalEnabled: true,
			globalMode:    "checkonly",
			pvcLabels: map[string]string{
				"csi.dell.com/fs_check_enabled": "false",
			},
			expectedEnabled: false,
			expectedMode:    "checkonly",
		},
		{
			name:          "PVC label overrides mode",
			globalEnabled: true,
			globalMode:    "checkonly",
			pvcLabels: map[string]string{
				"csi.dell.com/fs_check_mode": "checkAndRepair",
			},
			expectedEnabled: true,
			expectedMode:    "checkandrepair",
		},
		{
			name:          "invalid PVC enabled label uses global",
			globalEnabled: true,
			globalMode:    "checkonly",
			pvcLabels: map[string]string{
				"csi.dell.com/fs_check_enabled": "invalid",
			},
			expectedEnabled: true,
			expectedMode:    "checkonly",
		},
		{
			name:          "invalid PVC mode label uses global",
			globalEnabled: true,
			globalMode:    "checkandrepair",
			pvcLabels: map[string]string{
				"csi.dell.com/fs_check_mode": "invalid",
			},
			expectedEnabled: true,
			expectedMode:    "checkandrepair",
		},
		{
			name:          "both labels override",
			globalEnabled: false,
			globalMode:    "checkonly",
			pvcLabels: map[string]string{
				"csi.dell.com/fs_check_enabled": "true",
				"csi.dell.com/fs_check_mode":    "checkAndRepair",
			},
			expectedEnabled: true,
			expectedMode:    "checkandrepair",
		},
		{
			name:          "case insensitive enabled",
			globalEnabled: false,
			globalMode:    "checkonly",
			pvcLabels: map[string]string{
				"csi.dell.com/fs_check_enabled": "TRUE",
			},
			expectedEnabled: true,
			expectedMode:    "checkonly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(MockMetadataRetrieverClient)
			m.On("GetPVCLabelsByPVName", mock.Anything, mock.Anything).Return(
				&retriever.GetPVCLabelsByPVNameResponse{
					PVCName:    "my-pvc",
					Parameters: tt.pvcLabels,
				}, nil,
			)

			fsck := &FsCheckRunner{
				enabled:           tt.globalEnabled,
				mode:              tt.globalMode,
				pvName:            "pv-name",
				fullVolumeID:      "vol-id",
				metadataRetriever: m,
			}
			err := fsck.resolveEffectiveSettings(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedEnabled, fsck.enabled)
			assert.Equal(t, tt.expectedMode, fsck.mode)
		})
	}
}

func TestCheckFileSystem_SkipReasons(t *testing.T) {
	// These test cases all trigger early returns (skip) with nil error,
	// passing nil for fs.Interface is safe since it is not reached for fs type / access mode skips.
	tests := []struct {
		name       string
		curFS      string
		accessMode csi.VolumeCapability_AccessMode_Mode
	}{
		{
			name:       "skip for empty fs (newly formatted)",
			curFS:      "",
			accessMode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		},
		{
			name:       "skip for read-only access mode",
			curFS:      "ext4",
			accessMode: csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY,
		},
		{
			name:       "skip for multi-node reader only",
			curFS:      "ext4",
			accessMode: csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY,
		},
		{
			name:       "skip for multi-node multi-writer",
			curFS:      "xfs",
			accessMode: csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER,
		},
		{
			name:       "skip for multi-node single-writer",
			curFS:      "ext4",
			accessMode: csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER,
		},
		{
			name:       "skip for unsupported filesystem ntfs",
			curFS:      "ntfs",
			accessMode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		},
		{
			name:       "skip for unsupported filesystem btrfs",
			curFS:      "btrfs",
			accessMode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		},
		{
			name:       "skip for unsupported filesystem nfs",
			curFS:      "nfs",
			accessMode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsck := &FsCheckRunner{
				enabled:  true,
				mode:     "checkonly",
				fsType:   tt.curFS,
				fsDevice: "/dev/sda",
			}
			skipReason, err := fsck.validatePreconditions(context.Background(), tt.accessMode, nil)
			assert.NoError(t, err, "skip condition should return nil error")
			assert.NotEmpty(t, skipReason, "should have a skip reason")
		})
	}
}

func TestRun_UnsupportedFS(t *testing.T) {
	origGetFSChecker := getFSCheckerFunc
	defer func() { getFSCheckerFunc = origGetFSChecker }()

	getFSCheckerFunc = func(_, _ string, _ gofsutil.FSCheckObserver) (gofsutil.FSChecker, error) {
		return nil, assert.AnError
	}

	fsck := &FsCheckRunner{
		enabled:      true,
		mode:         "checkonly",
		fsDevice:     "/dev/sda",
		fsType:       "ntfs",
		fullVolumeID: "vol-123",
	}
	err := fsck.run(context.Background())
	assert.Error(t, err, "unsupported FS should now return hard error, not skip")
	assert.Contains(t, err.Error(), "failed to create FSChecker")
}

func TestRun_Success(t *testing.T) {
	origExec := gofsutil.OSExecFn
	defer func() { gofsutil.OSExecFn = origExec }()

	// e2fsck -n returns 0 → no errors
	gofsutil.OSExecFn = func(_ context.Context, _ string, _ ...string) (int, error) {
		return 0, nil
	}

	fsck := &FsCheckRunner{
		enabled:      true,
		mode:         "checkonly",
		fsDevice:     "/dev/sda",
		fsType:       "ext4",
		fullVolumeID: "vol-123",
		pvcName:      "my-pvc",
	}
	err := fsck.run(context.Background())
	assert.NoError(t, err)
}

func TestRun_CheckFails(t *testing.T) {
	origExec := gofsutil.OSExecFn
	defer func() { gofsutil.OSExecFn = origExec }()

	// e2fsck -n returns 4 → unrepairable errors
	gofsutil.OSExecFn = func(_ context.Context, _ string, _ ...string) (int, error) {
		return 4, errors.New("exit status 4")
	}

	fsck := &FsCheckRunner{
		enabled:      true,
		mode:         "checkonly",
		fsDevice:     "/dev/sda",
		fsType:       "ext4",
		fullVolumeID: "vol-123",
		pvcName:      "my-pvc",
	}
	err := fsck.run(context.Background())
	assert.Error(t, err)
}

func TestFsCheckPVCObserver_OnEvent(t *testing.T) {
	observer := &fsCheckPVCObserver{
		pvcName: "",
	}

	// Should not panic even with nil event recorder and empty PVC name.
	// timedOut is only set inside the switch which requires eventRecorder+pvcName,
	// so it remains false for all events when those are absent.
	observer.OnEvent(gofsutil.StartedFSCheckEvent)
	observer.OnEvent(gofsutil.FoundNoErrorsEvent)
	observer.OnEvent(gofsutil.FSCheckTimedOutEvent)
	assert.False(t, observer.timedOut)
}

func TestFsCheckPVCObserver_OnEvent_WithRecorder(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	broadcaster := record.NewBroadcaster()
	recorder := broadcaster.NewRecorder(scheme, corev1.EventSource{Component: "test"})

	observer := &fsCheckPVCObserver{
		pvcName:       "my-pvc",
		pvcNamespace:  "default",
		eventRecorder: recorder,
	}

	events := []string{
		gofsutil.StartedFSCheckEvent,
		gofsutil.FoundNoErrorsEvent,
		gofsutil.FinishedFSRepairEvent,
		gofsutil.FoundErrorsEvent,
		gofsutil.FSCheckFailedEvent,
		gofsutil.FSCheckTimedOutEvent,
		gofsutil.FSRepairTimedOutEvent,
		gofsutil.FSRepairFailedEvent,
		gofsutil.StartFSRepairEvent,
		gofsutil.FoundDirtyLogEvent,
		gofsutil.StartLogReplayEvent,
		gofsutil.LogReplayFailedEvent,
		gofsutil.LogReplayDoneEvent,
		"unknown-event",
	}

	for _, ev := range events {
		observer.OnEvent(ev)
	}
	assert.True(t, observer.timedOut)
}

func TestCheckFileSystem_GetMountsError(t *testing.T) {
	fsMockLocal := new(mocks.FsInterface)
	fsMockLocal.On("ReadFile", mock.Anything).Return([]byte{}, errors.New("read error"))
	fsMockLocal.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, errors.New("parse error"))

	fsck := &FsCheckRunner{
		enabled:  true,
		mode:     "checkonly",
		fsType:   "ext4",
		fsDevice: "/dev/sda",
	}
	err := fsck.CheckFileSystem(context.Background(),
		csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER, fsMockLocal)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get mounts")
}

func TestCheckFileSystem_AlreadyMounted(t *testing.T) {
	fsMockLocal := new(mocks.FsInterface)
	fsMockLocal.On("ReadFile", mock.Anything).Return([]byte{}, nil)
	fsMockLocal.On("ParseProcMounts", mock.Anything, mock.Anything).Return(
		[]gofsutil.Info{{Device: "/dev/sda", Path: "/mnt/target"}}, nil,
	)

	fsck := &FsCheckRunner{
		enabled:  true,
		mode:     "checkonly",
		fsType:   "ext4",
		fsDevice: "/dev/sda",
	}
	err := fsck.CheckFileSystem(context.Background(),
		csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER, fsMockLocal)
	assert.NoError(t, err)
}

func TestCheckFileSystem_NoSkipSupportedFS(t *testing.T) {
	supportedFilesystems := []string{"ext4", "ext3", "ext2", "xfs"}
	for _, fsType := range supportedFilesystems {
		t.Run("runs fscheck for "+fsType, func(t *testing.T) {
			fsMockLocal := new(mocks.FsInterface)
			fsMockLocal.On("ReadFile", mock.Anything).Return([]byte{}, nil)
			fsMockLocal.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)

			m := new(MockMetadataRetrieverClient)
			m.On("GetPVCLabelsByPVName", mock.Anything, mock.Anything).Return(
				&retriever.GetPVCLabelsByPVNameResponse{
					PVCName:    "my-pvc",
					Parameters: map[string]string{},
				}, nil,
			)

			origExec := gofsutil.OSExecFn
			defer func() { gofsutil.OSExecFn = origExec }()
			gofsutil.OSExecFn = func(_ context.Context, _ string, _ ...string) (int, error) {
				return 0, nil
			}

			fsck := &FsCheckRunner{
				enabled:           true,
				mode:              "checkonly",
				fsType:            fsType,
				fsDevice:          "/dev/sda",
				fullVolumeID:      "vol-123",
				pvName:            "pv-name",
				metadataRetriever: m,
			}
			err := fsck.CheckFileSystem(context.Background(),
				csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER, fsMockLocal)
			assert.NoError(t, err, "supported FS %s with passing check should return nil", fsType)
		})
	}
}

func TestCheckFileSystem_FsCheckEnabled_Fails(t *testing.T) {
	fsMockLocal := new(mocks.FsInterface)
	fsMockLocal.On("ReadFile", mock.Anything).Return([]byte{}, nil)
	fsMockLocal.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)

	m := new(MockMetadataRetrieverClient)
	m.On("GetPVCLabelsByPVName", mock.Anything, mock.Anything).Return(
		&retriever.GetPVCLabelsByPVNameResponse{
			PVCName: "my-pvc",
			Parameters: map[string]string{
				"csi.dell.com/fs_check_enabled": "true",
			},
		}, nil,
	)

	origExec := gofsutil.OSExecFn
	defer func() { gofsutil.OSExecFn = origExec }()
	gofsutil.OSExecFn = func(_ context.Context, _ string, _ ...string) (int, error) {
		return 4, errors.New("exit status 4")
	}

	fsck := &FsCheckRunner{
		enabled:           true,
		mode:              "checkonly",
		fsType:            "ext4",
		fsDevice:          "/dev/sda",
		fullVolumeID:      "vol-123",
		pvName:            "pv-name",
		metadataRetriever: m,
	}
	err := fsck.CheckFileSystem(context.Background(),
		csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER, fsMockLocal)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "FS check failed")
}

func TestCheckFileSystem_FsCheckDisabled(t *testing.T) {
	fsMockLocal := new(mocks.FsInterface)
	fsMockLocal.On("ReadFile", mock.Anything).Return([]byte{}, nil)
	fsMockLocal.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)

	m := new(MockMetadataRetrieverClient)
	m.On("GetPVCLabelsByPVName", mock.Anything, mock.Anything).Return(
		&retriever.GetPVCLabelsByPVNameResponse{
			PVCName:    "my-pvc",
			Parameters: map[string]string{},
		}, nil,
	)

	fsck := &FsCheckRunner{
		enabled:           false,
		mode:              "checkonly",
		fsType:            "ext4",
		fsDevice:          "/dev/sda",
		fullVolumeID:      "vol-123",
		pvName:            "pv-name",
		metadataRetriever: m,
	}
	err := fsck.CheckFileSystem(context.Background(),
		csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER, fsMockLocal)
	assert.NoError(t, err)
}

func TestRun_TimedOut(t *testing.T) {
	origExec := gofsutil.OSExecFn
	defer func() { gofsutil.OSExecFn = origExec }()

	// e2fsck rc=32 + non-nil err -> isCanceledByUser() -> FSCheckTimedOutEvent
	gofsutil.OSExecFn = func(_ context.Context, _ string, _ ...string) (int, error) {
		return 32, errors.New("signal: killed")
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	broadcaster := record.NewBroadcaster()
	recorder := broadcaster.NewRecorder(scheme, corev1.EventSource{Component: "test"})

	fsck := &FsCheckRunner{
		enabled:       true,
		mode:          "checkonly",
		fsDevice:      "/dev/sda",
		fsType:        "ext4",
		fullVolumeID:  "vol-123",
		pvcName:       "my-pvc",
		eventRecorder: recorder,
	}
	err := fsck.run(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "publish volume attempt")
}

func TestRun_FailWithEventRecorder(t *testing.T) {
	origExec := gofsutil.OSExecFn
	defer func() { gofsutil.OSExecFn = origExec }()

	// e2fsck exit code 4 + non-nil err → isFoundErrors() -> FoundErrorsEvent
	gofsutil.OSExecFn = func(_ context.Context, _ string, _ ...string) (int, error) {
		return 4, errors.New("exit status 4")
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	broadcaster := record.NewBroadcaster()
	recorder := broadcaster.NewRecorder(scheme, corev1.EventSource{Component: "test"})

	fsck := &FsCheckRunner{
		enabled:       true,
		mode:          "checkonly",
		fsDevice:      "/dev/sda",
		fsType:        "ext4",
		fullVolumeID:  "vol-123",
		pvcName:       "my-pvc",
		eventRecorder: recorder,
	}
	err := fsck.run(context.Background())
	assert.Error(t, err)
}

func TestRun_FailWithNilEventRecorder(t *testing.T) {
	origExec := gofsutil.OSExecFn
	defer func() { gofsutil.OSExecFn = origExec }()

	// e2fsck exit code 4 + non-nil err → isFoundErrors() -> FoundErrorsEvent
	gofsutil.OSExecFn = func(_ context.Context, _ string, _ ...string) (int, error) {
		return 4, errors.New("exit status 4")
	}

	fsck := &FsCheckRunner{
		enabled:       true,
		mode:          "checkonly",
		fsDevice:      "/dev/sda",
		fsType:        "ext4",
		fullVolumeID:  "vol-123",
		pvcName:       "my-pvc",
		pvcNamespace:  "default",
		eventRecorder: nil, // This is the key - nil event recorder
	}

	// This should NOT panic even with nil eventRecorder (tests our fix)
	err := fsck.run(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Manual intervention required")
}

func TestRun_FailWithFSCheckerError(t *testing.T) {
	origGetFSChecker := getFSCheckerFunc
	defer func() { getFSCheckerFunc = origGetFSChecker }()

	// Mock getFSCheckerFunc to return an error (simulating unsupported FS type)
	getFSCheckerFunc = func(_, _ string, _ gofsutil.FSCheckObserver) (gofsutil.FSChecker, error) {
		return nil, errors.New("unsupported file system type")
	}

	fsck := &FsCheckRunner{
		enabled:       true,
		mode:          "checkonly",
		fsDevice:      "/dev/sda",
		fsType:        "ext4",
		fullVolumeID:  "vol-123",
		pvcName:       "my-pvc",
		pvcNamespace:  "default",
		eventRecorder: nil,
	}

	// This should return a hard error, not silently skip
	err := fsck.run(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create FSChecker")
	assert.Contains(t, err.Error(), "unsupported file system type")
}

func TestInitFsCheckEventRecorder_Error(t *testing.T) {
	origFn := newNodeEventRecorder
	defer func() { newNodeEventRecorder = origFn }()

	newNodeEventRecorder = func(_ string) (record.EventRecorder, error) {
		return nil, errors.New("k8s unavailable")
	}

	// Reset the singleton so the test exercises the init path
	eventRecorderOnce = sync.Once{}
	cachedEventRecorder = nil

	recorder := initFsCheckEventRecorder("/fake/path")
	assert.Nil(t, recorder)
}

func TestInitFsCheckMetadataRetriever(t *testing.T) {
	// Reset the singleton so the test exercises the init path
	metadataRetrieverOnce = sync.Once{}
	cachedMetadataRetriever = nil

	client := initFsCheckMetadataRetriever()
	assert.NotNil(t, client)

	// Reset again to not affect other tests
	metadataRetrieverOnce = sync.Once{}
	cachedMetadataRetriever = nil
}
