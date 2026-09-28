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

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestExtractVolumeID(t *testing.T) {
	tests := []struct {
		name   string
		handle string
		want   string
	}{
		{name: "empty", handle: "", want: ""},
		{name: "volume only", handle: "vol-1", want: "vol-1"},
		{name: "volume and array", handle: "vol-1/array-1", want: "vol-1"},
		{name: "leading slash", handle: "/array-1", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractVolumeID(tt.handle))
		})
	}
}

func TestK8sMetadataChecker_IsDriverManagedAndRefreshCache(t *testing.T) {
	pv1 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}
	pv2 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-2"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "other-driver",
					VolumeHandle: "vol-2/array-2",
				},
			},
		},
	}
	pv3 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-3"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "",
				},
			},
		},
	}

	client := fake.NewSimpleClientset(&pv1, &pv2, &pv3)
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	managed, err := checker.IsDriverManaged(context.Background(), "")
	require.NoError(t, err)
	assert.False(t, managed)

	managed, err = checker.IsDriverManaged(context.Background(), "vol-1")
	require.NoError(t, err)
	assert.False(t, managed)

	require.NoError(t, checker.RefreshCache(context.Background()))

	managed, err = checker.IsDriverManaged(context.Background(), "vol-1")
	require.NoError(t, err)
	assert.True(t, managed)

	managed, err = checker.IsDriverManaged(context.Background(), "vol-2")
	require.NoError(t, err)
	assert.False(t, managed)
}

func TestK8sMetadataChecker_NilClient(t *testing.T) {
	checker := NewK8sMetadataChecker(nil, "csi-powerstore")

	managed, err := checker.IsDriverManaged(context.Background(), "vol-1")
	require.Error(t, err)
	assert.False(t, managed)
}

func TestNewK8sMetadataChecker(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	assert.NotNil(t, checker)
	assert.NotNil(t, checker.k8sClient)
	assert.Equal(t, "csi-powerstore", checker.driverName)
	assert.NotNil(t, checker.volumeIDCache)
}

func TestNewK8sMetadataChecker_NilClient(t *testing.T) {
	checker := NewK8sMetadataChecker(nil, "csi-powerstore")

	assert.NotNil(t, checker)
	assert.Nil(t, checker.k8sClient)
	assert.Equal(t, "csi-powerstore", checker.driverName)
	assert.NotNil(t, checker.volumeIDCache)
}

func TestK8sMetadataChecker_RefreshCache(t *testing.T) {
	pv1 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}

	client := fake.NewSimpleClientset(&pv1)
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)
}

func TestK8sMetadataChecker_RefreshCache_Empty(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)
}

func TestK8sMetadataChecker_RefreshCache_MultiplePVs(t *testing.T) {
	pv1 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}
	pv2 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-2"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-2/array-2",
				},
			},
		},
	}
	pv3 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-3"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "other-driver",
					VolumeHandle: "vol-3/array-3",
				},
			},
		},
	}

	client := fake.NewSimpleClientset(&pv1, &pv2, &pv3)
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	// Check that only csi-powerstore volumes are cached
	managed1, _ := checker.IsDriverManaged(context.Background(), "vol-1")
	managed2, _ := checker.IsDriverManaged(context.Background(), "vol-2")
	managed3, _ := checker.IsDriverManaged(context.Background(), "vol-3")

	assert.True(t, managed1)
	assert.True(t, managed2)
	assert.False(t, managed3)
}

func TestK8sMetadataChecker_IsDriverManaged_NotInCache(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Without calling RefreshCache, nothing should be in cache
	managed, err := checker.IsDriverManaged(context.Background(), "vol-1")
	require.NoError(t, err)
	assert.False(t, managed)
}

func TestK8sMetadataChecker_IsDriverManaged_EmptyVolumeID(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	managed, err := checker.IsDriverManaged(context.Background(), "")
	require.NoError(t, err)
	assert.False(t, managed)
}

func TestK8sMetadataChecker_IsDriverManaged_CacheHit(t *testing.T) {
	pv1 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}

	client := fake.NewSimpleClientset(&pv1)
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Populate cache
	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	// Check cache hit
	managed, err := checker.IsDriverManaged(context.Background(), "vol-1")
	require.NoError(t, err)
	assert.True(t, managed)
}

func TestK8sMetadataChecker_IsDriverManaged_NonCSI(t *testing.T) {
	pv1 := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/hostpath",
				},
			},
		},
	}

	client := fake.NewSimpleClientset(&pv1)
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	managed, err := checker.IsDriverManaged(context.Background(), "vol-1")
	require.NoError(t, err)
	assert.False(t, managed)
}

func TestK8sMetadataChecker_GetProtocol(t *testing.T) {
	tests := []struct {
		name               string
		pvVolumeAttributes map[string]string
		wantProtocol       string
	}{
		{
			name:               "NVMeTCP protocol",
			pvVolumeAttributes: map[string]string{"Protocol": "NVMeTCP"},
			wantProtocol:       "NVMeTCP",
		},
		{
			name:               "iSCSI protocol",
			pvVolumeAttributes: map[string]string{"Protocol": "iSCSI"},
			wantProtocol:       "iSCSI",
		},
		{
			name:               "FC protocol",
			pvVolumeAttributes: map[string]string{"Protocol": "FC"},
			wantProtocol:       "FC",
		},
		{
			name:               "NFS protocol",
			pvVolumeAttributes: map[string]string{"Protocol": "nfs"},
			wantProtocol:       "NFS",
		},
		{
			name:               "no VolumeAttributes",
			pvVolumeAttributes: nil,
			wantProtocol:       "unknown",
		},
		{
			name:               "VolumeAttributes without Protocol",
			pvVolumeAttributes: map[string]string{"arrayID": "PSabc123"},
			wantProtocol:       "unknown",
		},
		{
			name:               "generic scsi protocol without node affinity",
			pvVolumeAttributes: map[string]string{"Protocol": "scsi"},
			wantProtocol:       "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pv := corev1.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
				Spec: corev1.PersistentVolumeSpec{
					PersistentVolumeSource: corev1.PersistentVolumeSource{
						CSI: &corev1.CSIPersistentVolumeSource{
							Driver:           "csi-powerstore",
							VolumeHandle:     "vol-1/array-1",
							VolumeAttributes: tt.pvVolumeAttributes,
						},
					},
				},
			}

			client := fake.NewSimpleClientset(&pv)
			checker := NewK8sMetadataChecker(client, "csi-powerstore")

			err := checker.RefreshCache(context.Background())
			require.NoError(t, err)

			protocol := checker.GetProtocol(context.Background(), "vol-1")
			assert.Equal(t, tt.wantProtocol, protocol)
		})
	}
}

func TestK8sMetadataChecker_GetProtocol_GenericSCSIUsesNodeAffinity(t *testing.T) {
	pv := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1/array-1",
					VolumeAttributes: map[string]string{"Protocol": "scsi"},
				},
			},
			NodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "csi-powerstore.dellemc.com/10.247.27.44-fc",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"true"},
								},
							},
						},
					},
				},
			},
		},
	}

	client := fake.NewSimpleClientset(&pv)
	checker := NewK8sMetadataChecker(client, "csi-powerstore")
	require.NoError(t, checker.RefreshCache(context.Background()))

	assert.Equal(t, "FC", checker.GetProtocol(context.Background(), "vol-1"))
}

func TestExtractProtocolFromNodeAffinity(t *testing.T) {
	tests := []struct {
		name         string
		nodeAffinity *corev1.VolumeNodeAffinity
		expected     string
	}{
		{
			name:         "nil nodeAffinity",
			nodeAffinity: nil,
			expected:     "",
		},
		{
			name:         "nil required",
			nodeAffinity: &corev1.VolumeNodeAffinity{},
			expected:     "",
		},
		{
			name: "iSCSI protocol",
			nodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "csi-powerstore.dellemc.com/10.247.27.44-iscsi",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"true"},
								},
							},
						},
					},
				},
			},
			expected: "iSCSI",
		},
		{
			name: "FC protocol",
			nodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "csi-powerstore.dellemc.com/10.247.27.44-fc",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"true"},
								},
							},
						},
					},
				},
			},
			expected: "FC",
		},
		{
			name: "NVMeTCP protocol",
			nodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "csi-powerstore.dellemc.com/10.247.27.44-nvme-tcp",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"true"},
								},
							},
						},
					},
				},
			},
			expected: "NVMeTCP",
		},
		{
			name: "NFS protocol",
			nodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "csi-powerstore.dellemc.com/10.247.27.44-nfs",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"true"},
								},
							},
						},
					},
				},
			},
			expected: "NFS",
		},
		{
			name: "unknown label",
			nodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "some-other-label",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"true"},
								},
							},
						},
					},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractProtocolFromNodeAffinity(tt.nodeAffinity)
			if result != tt.expected {
				t.Errorf("extractProtocolFromNodeAffinity() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestResolvePVProtocol(t *testing.T) {
	nvmeFCAffinity := &corev1.VolumeNodeAffinity{
		Required: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{
					MatchExpressions: []corev1.NodeSelectorRequirement{
						{
							Key:      "csi-powerstore.dellemc.com/10.247.27.44-nvme-fc",
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{"true"},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name         string
		protocol     string
		nodeAffinity *corev1.VolumeNodeAffinity
		expected     string
	}{
		{
			name:     "normalizes concrete NFS",
			protocol: "nfs",
			expected: "NFS",
		},
		{
			name:         "derives generic scsi from node affinity",
			protocol:     "scsi",
			nodeAffinity: nvmeFCAffinity,
			expected:     "NVMeFC",
		},
		{
			name:     "drops invalid protocol",
			protocol: "bogus",
			expected: "",
		},
		{
			name:     "empty generic without affinity remains unresolved",
			protocol: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolvePVProtocol(tt.protocol, tt.nodeAffinity))
		})
	}
}

func TestK8sMetadataChecker_GetProtocol_NotInCache(t *testing.T) {
	pv := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1/array-1",
					VolumeAttributes: map[string]string{"Protocol": "NVMeTCP"},
				},
			},
		},
	}

	client := fake.NewSimpleClientset(&pv)
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Don't call RefreshCache, so cache is empty
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	assert.Equal(t, "unknown", protocol)
}

func TestExtractVolumeIDFromPV(t *testing.T) {
	tests := []struct {
		name     string
		pv       *corev1.PersistentVolume
		expected string
	}{
		{
			name:     "nil PV",
			pv:       nil,
			expected: "",
		},
		{
			name:     "nil CSI",
			pv:       &corev1.PersistentVolume{},
			expected: "",
		},
		{
			name: "valid CSI volume handle",
			pv: &corev1.PersistentVolume{
				Spec: corev1.PersistentVolumeSpec{
					PersistentVolumeSource: corev1.PersistentVolumeSource{
						CSI: &corev1.CSIPersistentVolumeSource{
							VolumeHandle: "vol-1/array-1",
						},
					},
				},
			},
			expected: "vol-1",
		},
		{
			name: "CSI with empty volume handle",
			pv: &corev1.PersistentVolume{
				Spec: corev1.PersistentVolumeSpec{
					PersistentVolumeSource: corev1.PersistentVolumeSource{
						CSI: &corev1.CSIPersistentVolumeSource{
							VolumeHandle: "",
						},
					},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVolumeIDFromPV(tt.pv)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestK8sMetadataChecker_IsDriverManagedByName_NilClient(t *testing.T) {
	checker := NewK8sMetadataChecker(nil, "csi-powerstore")

	managed, err := checker.IsDriverManagedByName(context.Background(), "test-pv")
	assert.Error(t, err)
	assert.False(t, managed)
	assert.Contains(t, err.Error(), "kubernetes client not initialized")
}

func TestK8sMetadataChecker_IsDriverManagedByName_EmptyVolumeName(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	managed, err := checker.IsDriverManagedByName(context.Background(), "")
	assert.NoError(t, err)
	assert.False(t, managed)
}

func TestK8sMetadataChecker_Stop(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Stop should not panic even if not started
	assert.NotPanics(t, func() {
		checker.Stop()
	})
}

func TestK8sMetadataChecker_MarkDeleteCompleteByName(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// MarkDeleteCompleteByName should not panic
	assert.NotPanics(t, func() {
		checker.MarkDeleteCompleteByName("test-volume")
	})
}

func TestK8sMetadataChecker_MarkDeleteComplete_NormalizesVolumeHandle(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	checker.volumeIDCache["vol-1"] = true
	checker.volumeNameCache["vol-1"] = true
	checker.protocolCache["vol-1"] = "NFS"
	checker.pendingDeletion["vol-1"] = time.Now()

	checker.MarkDeleteComplete("vol-1/array-1/nfs")

	assert.NotContains(t, checker.volumeIDCache, "vol-1")
	assert.NotContains(t, checker.volumeNameCache, "vol-1")
	assert.Contains(t, checker.protocolCache, "vol-1") // Protocol is preserved for metrics
	assert.Equal(t, "NFS", checker.protocolCache["vol-1"])
	assert.NotContains(t, checker.pendingDeletion, "vol-1")
}

func TestK8sMetadataChecker_GetProtocol_WithPendingDeletion(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Simulate a volume that was added to cache and then marked for pending deletion
	checker.protocolCache["vol-1"] = "NVMeTCP"
	checker.pendingDeletion["vol-1"] = time.Now()

	// GetProtocol should return the protocol from cache even though it's in pending deletion
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	assert.Equal(t, "NVMeTCP", protocol)
}

func TestK8sMetadataChecker_GetProtocol_WithPendingDeletionAndFullVolumeHandle(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Simulate a volume with full volume handle in cache and pending deletion
	checker.protocolCache["vol-1"] = "iSCSI"
	checker.pendingDeletion["vol-1"] = time.Now()

	// GetProtocol should work with full volume handle (vol-1/array-1/scsi)
	protocol := checker.GetProtocol(context.Background(), "vol-1/array-1/scsi")
	assert.Equal(t, "iSCSI", protocol)
}

func TestK8sMetadataChecker_GetProtocol_PendingDeletionWithoutProtocolInCache(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Simulate a volume in pending deletion but protocol not in cache (edge case)
	checker.pendingDeletion["vol-1"] = time.Now()
	// Don't add protocol to cache

	// GetProtocol should return unknown since protocol is not in cache
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	assert.Equal(t, "unknown", protocol)
}

func TestK8sMetadataChecker_GetProtocol_NotInPendingDeletion(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add protocol to cache but NOT in pending deletion
	checker.protocolCache["vol-1"] = "NFS"

	// GetProtocol should return protocol normally
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	assert.Equal(t, "NFS", protocol)
}

func TestK8sMetadataChecker_Start(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start should not panic (though it won't actually start the informer without proper setup)
	assert.NotPanics(t, func() {
		err := checker.Start(ctx)
		// It might fail due to missing RBAC or other setup, but shouldn't panic
		_ = err
	})
}

func TestK8sMetadataChecker_handlePVAdd(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}

	// handlePVAdd should not panic
	assert.NotPanics(t, func() {
		checker.handlePVAdd(pv)
	})
}

func TestK8sMetadataChecker_handlePVUpdate(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	oldPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}

	newPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}

	// handlePVUpdate should not panic
	assert.NotPanics(t, func() {
		checker.handlePVUpdate(oldPV, newPV)
	})
}

func TestK8sMetadataChecker_handlePVDelete(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}

	// handlePVDelete should not panic
	assert.NotPanics(t, func() {
		checker.handlePVDelete(pv)
	})
}

func TestK8sMetadataChecker_cleanupStaleEntries(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add some stale entries
	checker.pendingDeletion["vol-1"] = time.Now().Add(-time.Hour)
	checker.pendingDeletion["vol-2"] = time.Now().Add(-time.Minute)

	// Add to cache
	checker.cacheMu.Lock()
	checker.volumeIDCache["vol-1"] = true
	checker.volumeIDCache["vol-2"] = true
	checker.cacheMu.Unlock()

	// cleanupStaleEntries should not panic
	assert.NotPanics(t, func() {
		checker.cleanupStaleEntries()
	})
}

func TestK8sMetadataChecker_cleanupStaleEntries_Empty(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// cleanupStaleEntries with empty cache should not panic
	assert.NotPanics(t, func() {
		checker.cleanupStaleEntries()
	})
}

func TestK8sMetadataChecker_GetProtocol_NilClient(t *testing.T) {
	checker := NewK8sMetadataChecker(nil, "csi-powerstore")

	protocol := checker.GetProtocol(context.Background(), "vol-1")
	assert.Equal(t, "unknown", protocol)
}

func TestK8sMetadataChecker_GetProtocol_PendingDeletion(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a protocol entry and mark volume as pending deletion
	checker.cacheMu.Lock()
	checker.protocolCache["vol-1"] = "iSCSI"
	checker.cacheMu.Unlock()

	checker.pendingMutex.Lock()
	checker.pendingDeletion["vol-1"] = time.Now()
	checker.pendingMutex.Unlock()

	// GetProtocol should return the protocol from cache even though it's pending deletion
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	require.Equal(t, "iSCSI", protocol)
}

func TestK8sMetadataChecker_GetProtocol_PendingDeletionNoProtocol(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Mark volume as pending deletion but don't add protocol to cache
	checker.pendingMutex.Lock()
	checker.pendingDeletion["vol-1"] = time.Now()
	checker.pendingMutex.Unlock()

	// GetProtocol should return "unknown" since protocol is not in cache
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	require.Equal(t, "unknown", protocol)
}

func TestK8sMetadataChecker_GetProtocol_EmptyVolumeID(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	protocol := checker.GetProtocol(context.Background(), "")
	assert.Equal(t, "unknown", protocol)
}

func TestK8sMetadataChecker_GetProtocol_InvalidVolumeID(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Test with invalid volume ID format
	protocol := checker.GetProtocol(context.Background(), "invalid-format")
	assert.Equal(t, "unknown", protocol)
}

func TestK8sMetadataChecker_handlePVAdd_WithProtocol(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1/array-1",
					VolumeAttributes: map[string]string{"Protocol": "iSCSI"},
				},
			},
		},
	}

	// handlePVAdd should cache the protocol
	assert.NotPanics(t, func() {
		checker.handlePVAdd(pv)
	})

	// Verify protocol was cached
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	assert.Equal(t, "iSCSI", protocol)
}

func TestK8sMetadataChecker_handlePVAdd_NoCSI(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				// No CSI source
			},
		},
	}

	// handlePVAdd with non-CSI PV should not panic
	assert.NotPanics(t, func() {
		checker.handlePVAdd(pv)
	})
}

func TestK8sMetadataChecker_handlePVAdd_WrongDriver(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "wrong-driver",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}

	// handlePVAdd with wrong driver should not panic
	assert.NotPanics(t, func() {
		checker.handlePVAdd(pv)
	})
}

func TestK8sMetadataChecker_handlePVUpdate_WithProtocol(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	oldPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1/array-1",
					VolumeAttributes: map[string]string{"Protocol": "iSCSI"},
				},
			},
		},
	}

	newPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1/array-1",
					VolumeAttributes: map[string]string{"Protocol": "FC"},
				},
			},
		},
	}

	// handlePVUpdate should update the cached protocol
	assert.NotPanics(t, func() {
		checker.handlePVUpdate(oldPV, newPV)
	})

	// Verify protocol was updated
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	assert.Equal(t, "FC", protocol)
}

func TestK8sMetadataChecker_handlePVUpdate_NoCSI(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	oldPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				// No CSI source
			},
		},
	}

	newPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1/array-1",
					VolumeAttributes: map[string]string{"Protocol": "FC"},
				},
			},
		},
	}

	// handlePVUpdate with old PV without CSI should not panic
	assert.NotPanics(t, func() {
		checker.handlePVUpdate(oldPV, newPV)
	})
}

func TestK8sMetadataChecker_handlePVDelete_WithCache(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// First add the volume to cache
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1/array-1",
					VolumeAttributes: map[string]string{"Protocol": "iSCSI"},
				},
			},
		},
	}
	checker.handlePVAdd(pv)

	// Verify it's in cache
	managed, err := checker.IsDriverManaged(context.Background(), "vol-1")
	require.NoError(t, err)
	assert.True(t, managed)

	// Now delete it
	checker.handlePVDelete(pv)

	// Verify it's marked for deletion
	assert.Contains(t, checker.pendingDeletion, "vol-1")
}

func TestK8sMetadataChecker_handlePVDelete_NoCSI(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				// No CSI source
			},
		},
	}

	// handlePVDelete with non-CSI PV should not panic
	assert.NotPanics(t, func() {
		checker.handlePVDelete(pv)
	})
}

func TestK8sMetadataChecker_handlePVDelete_WrongDriver(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "wrong-driver",
					VolumeHandle: "vol-1/array-1",
				},
			},
		},
	}

	// handlePVDelete with wrong driver should not panic
	assert.NotPanics(t, func() {
		checker.handlePVDelete(pv)
	})
}

func TestK8sMetadataChecker_handlePVDelete_NotInCache(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1/array-1",
					VolumeAttributes: map[string]string{"Protocol": "iSCSI"},
				},
			},
		},
	}

	// handlePVDelete with volume not in cache should not panic
	assert.NotPanics(t, func() {
		checker.handlePVDelete(pv)
	})
}

func TestPVFromDelete(t *testing.T) {
	tests := []struct {
		name   string
		obj    interface{}
		wantPV *corev1.PersistentVolume
		wantOK bool
	}{
		{
			name:   "direct PV",
			obj:    &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "test-pv"}},
			wantPV: &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "test-pv"}},
			wantOK: true,
		},
		{
			name: "DeletedFinalStateUnknown",
			obj: cache.DeletedFinalStateUnknown{
				Obj: &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "test-pv"}},
			},
			wantPV: &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "test-pv"}},
			wantOK: true,
		},
		{
			name:   "wrong type",
			obj:    "not a PV",
			wantPV: nil,
			wantOK: false,
		},
		{
			name:   "nil",
			obj:    nil,
			wantPV: nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPV, gotOK := pvFromDelete(tt.obj)
			assert.Equal(t, tt.wantOK, gotOK)
			if tt.wantPV != nil {
				assert.Equal(t, tt.wantPV.Name, gotPV.Name)
			} else {
				assert.Nil(t, gotPV)
			}
		})
	}
}

func TestVolumeAttachmentFromDelete(t *testing.T) {
	tests := []struct {
		name   string
		obj    interface{}
		wantVA *storagev1.VolumeAttachment
		wantOK bool
	}{
		{
			name: "direct VolumeAttachment",
			obj: &storagev1.VolumeAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-va"},
			},
			wantVA: &storagev1.VolumeAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-va"},
			},
			wantOK: true,
		},
		{
			name: "DeletedFinalStateUnknown",
			obj: cache.DeletedFinalStateUnknown{
				Obj: &storagev1.VolumeAttachment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-va"},
				},
			},
			wantVA: &storagev1.VolumeAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-va"},
			},
			wantOK: true,
		},
		{
			name:   "wrong type",
			obj:    "not a VolumeAttachment",
			wantVA: nil,
			wantOK: false,
		},
		{
			name:   "nil",
			obj:    nil,
			wantVA: nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVA, gotOK := volumeAttachmentFromDelete(tt.obj)
			assert.Equal(t, tt.wantOK, gotOK)
			if tt.wantVA != nil {
				assert.Equal(t, tt.wantVA.Name, gotVA.Name)
			} else {
				assert.Nil(t, gotVA)
			}
		})
	}
}

func TestK8sMetadataChecker_GetAttachmentStateForVolumeID_MultiArrayValidation(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with arrayID in volumeHandle
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/PSc26835c9a0ba/scsi",
				},
			},
		},
	}

	// Simulate PV add
	checker.handlePVAdd(pv)

	// Add a VolumeAttachment
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &pv.Name,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	// Simulate VolumeAttachment add
	checker.handleVolumeAttachmentAdd(va)

	// Test with matching globalID
	attached, err := checker.GetAttachmentStateForVolumeID(context.Background(), "vol-1/PSc26835c9a0ba/scsi", "PSc26835c9a0ba")
	require.NoError(t, err)
	require.True(t, attached)

	// Test with non-matching globalID (different array)
	attached, err = checker.GetAttachmentStateForVolumeID(context.Background(), "vol-1/PSc26835c9a0ba/scsi", "PSdifferent-array")
	require.NoError(t, err)
	require.False(t, attached, "Should return detached when arrayID doesn't match globalID")
}

func TestK8sMetadataChecker_GetAttachmentStateForVolumeID_NoArrayID(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV without arrayID in volumeHandle
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1",
				},
			},
		},
	}

	// Simulate PV add
	checker.handlePVAdd(pv)

	// Add a VolumeAttachment
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &pv.Name,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	// Simulate VolumeAttachment add
	checker.handleVolumeAttachmentAdd(va)

	// Test without arrayID - should work regardless of globalID
	attached, err := checker.GetAttachmentStateForVolumeID(context.Background(), "vol-1", "any-global-id")
	require.NoError(t, err)
	require.True(t, attached)
}

func TestK8sMetadataChecker_CleanupStaleEntries(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Set a short grace period for testing
	checker.gracePeriod = 100 * time.Millisecond

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "csi-powerstore",
					VolumeHandle:     "vol-1",
					VolumeAttributes: map[string]string{"Protocol": "iSCSI"},
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Verify volume is in cache
	checker.cacheMu.RLock()
	_, exists := checker.volumeIDCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.True(t, exists)

	// Mark as pending deletion
	checker.handlePVDelete(pv)

	// Wait for grace period
	time.Sleep(150 * time.Millisecond)

	// Run cleanup
	checker.cleanupStaleEntries()

	// Verify volume was cleaned up
	checker.cacheMu.RLock()
	_, exists = checker.volumeIDCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.False(t, exists, "Volume should be cleaned up after grace period")
}

func TestExtractArrayID_AllProtocols(t *testing.T) {
	tests := []struct {
		name         string
		volumeHandle string
		wantArrayID  string
	}{
		{name: "iSCSI", volumeHandle: "vol-1/PSc26835c9a0ba/scsi", wantArrayID: "PSc26835c9a0ba"},
		{name: "NFS", volumeHandle: "vol-1/PSc26835c9a0ba/nfs", wantArrayID: "PSc26835c9a0ba"},
		{name: "no protocol", volumeHandle: "vol-1/PSc26835c9a0ba", wantArrayID: "PSc26835c9a0ba"},
		{name: "no arrayID", volumeHandle: "vol-1", wantArrayID: ""},
		{name: "empty", volumeHandle: "", wantArrayID: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractArrayID(tt.volumeHandle)
			assert.Equal(t, tt.wantArrayID, got)
		})
	}
}

func TestK8sMetadataChecker_handleVolumeAttachmentUpdate(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Add a VolumeAttachment with attached=false
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &pv.Name,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: false,
		},
	}

	checker.handleVolumeAttachmentAdd(va)

	// Update to attached=true (create a new object for oldVA to simulate change)
	oldVA := va.DeepCopy()
	va.Status.Attached = true
	checker.handleVolumeAttachmentUpdate(oldVA, va)

	// Verify cache was updated
	checker.cacheMu.RLock()
	attached := checker.attachmentCache[pv.Name]
	checker.cacheMu.RUnlock()
	require.True(t, attached)
}

func TestK8sMetadataChecker_handleVolumeAttachmentDelete(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Add a VolumeAttachment
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &pv.Name,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	checker.handleVolumeAttachmentAdd(va)

	// Verify cache has the attachment
	checker.cacheMu.RLock()
	_, exists := checker.attachmentCache[pv.Name]
	checker.cacheMu.RUnlock()
	require.True(t, exists)

	// Delete the VolumeAttachment
	checker.handleVolumeAttachmentDelete(va)

	// Verify cache was cleaned
	checker.cacheMu.RLock()
	_, exists = checker.attachmentCache[pv.Name]
	checker.cacheMu.RUnlock()
	require.False(t, exists, "Attachment should be removed from cache after deletion")
}

func TestK8sMetadataChecker_GetAttachmentStateForPVName_NotFound(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Try to get attachment state for a PV that doesn't exist
	attached, err := checker.GetAttachmentStateForPVName(context.Background(), "nonexistent-pv")
	require.NoError(t, err)
	require.False(t, attached, "Should return false for non-existent PV")
}

func TestK8sMetadataChecker_GetAttachmentStateForVolumeID_NotFound(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Try to get attachment state for a volume that doesn't exist
	attached, err := checker.GetAttachmentStateForVolumeID(context.Background(), "nonexistent-vol", "any-global-id")
	require.Error(t, err)
	require.False(t, attached, "Should return false and error for non-existent volume")
}

func TestK8sMetadataChecker_GetAttachmentStateForVolumeID_NilClient(t *testing.T) {
	checker := NewK8sMetadataChecker(nil, "csi-powerstore")

	attached, err := checker.GetAttachmentStateForVolumeID(context.Background(), "vol-1", "global-id")
	require.Error(t, err)
	require.False(t, attached, "Should return error when client is nil")
}

func TestK8sMetadataChecker_GetAttachmentStateForPVName_NilClient(t *testing.T) {
	checker := NewK8sMetadataChecker(nil, "csi-powerstore")

	attached, err := checker.GetAttachmentStateForPVName(context.Background(), "pv-1")
	require.Error(t, err)
	require.False(t, attached, "Should return error when client is nil")
}

func TestK8sMetadataChecker_IsDriverManaged_NilClient(t *testing.T) {
	checker := NewK8sMetadataChecker(nil, "csi-powerstore")

	managed, err := checker.IsDriverManaged(context.Background(), "vol-1")
	require.Error(t, err)
	require.False(t, managed, "Should return error when client is nil")
}

func TestK8sMetadataChecker_Start_Stop(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Start the informer
	err := checker.Start(context.Background())
	require.NoError(t, err)

	// Stop to clean up
	checker.Stop()
}

func TestK8sMetadataChecker_Start_Twice(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Start the informer
	err := checker.Start(context.Background())
	require.NoError(t, err)

	// Start again - should not error (idempotent)
	err = checker.Start(context.Background())
	require.NoError(t, err)

	// Stop to clean up
	checker.Stop()
}

func TestK8sMetadataChecker_Stop_WithoutStart(_ *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Stop without starting - should not panic
	checker.Stop()
}

func TestK8sMetadataChecker_handlePVDelete_WithVolumeHandle(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Verify volume is in cache
	checker.cacheMu.RLock()
	_, exists := checker.volumeIDCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.True(t, exists)

	// Delete the PV
	checker.handlePVDelete(pv)

	// Verify volume is marked as pending deletion
	checker.pendingMutex.RLock()
	_, pendingExists := checker.pendingDeletion["vol-1"]
	checker.pendingMutex.RUnlock()
	require.True(t, pendingExists)
}

func TestK8sMetadataChecker_handlePVDelete_AlreadyPending(_ *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
				},
			},
		},
	}

	checker.handlePVAdd(pv)
	checker.handlePVDelete(pv)

	// Delete again - should not panic
	checker.handlePVDelete(pv)
}

func TestK8sMetadataChecker_GetAttachmentStateForPVName_WithAttachment(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Add a VolumeAttachment with attached=true
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &pv.Name,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	checker.handleVolumeAttachmentAdd(va)

	// Get attachment state
	attached, err := checker.GetAttachmentStateForPVName(context.Background(), "test-pv")
	require.NoError(t, err)
	require.True(t, attached)
}

func TestK8sMetadataChecker_GetAttachmentStateForPVName_Detached(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Add a VolumeAttachment with attached=false
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &pv.Name,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: false,
		},
	}

	checker.handleVolumeAttachmentAdd(va)

	// Get attachment state
	attached, err := checker.GetAttachmentStateForPVName(context.Background(), "test-pv")
	require.NoError(t, err)
	require.False(t, attached)
}

func TestK8sMetadataChecker_handleVolumeAttachmentUpdate_NoStatusChange(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Add a VolumeAttachment with attached=true
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &pv.Name,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	checker.handleVolumeAttachmentAdd(va)

	// Update with no status change (same object)
	checker.handleVolumeAttachmentUpdate(va, va)

	// Verify cache is still true
	checker.cacheMu.RLock()
	attached := checker.attachmentCache[pv.Name]
	checker.cacheMu.RUnlock()
	require.True(t, attached)
}

func TestK8sMetadataChecker_handleVolumeAttachmentUpdate_WrongAttacher(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a VolumeAttachment with wrong attacher
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "wrong-driver",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &[]string{"test-pv"}[0],
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	// Update with wrong attacher - should be ignored
	checker.handleVolumeAttachmentUpdate(va, va)

	// Verify cache is empty
	checker.cacheMu.RLock()
	_, exists := checker.attachmentCache["test-pv"]
	checker.cacheMu.RUnlock()
	require.False(t, exists)
}

func TestK8sMetadataChecker_handleVolumeAttachmentDelete_WrongAttacher(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a VolumeAttachment with wrong attacher
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "wrong-driver",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &[]string{"test-pv"}[0],
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	// Delete with wrong attacher - should be ignored
	checker.handleVolumeAttachmentDelete(va)

	// Verify cache is empty
	checker.cacheMu.RLock()
	_, exists := checker.attachmentCache["test-pv"]
	checker.cacheMu.RUnlock()
	require.False(t, exists)
}

func TestK8sMetadataChecker_GetProtocol_WithProtocol(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with protocol
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
					VolumeAttributes: map[string]string{
						"Protocol": "iSCSI",
					},
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Get protocol
	protocol := checker.GetProtocol(context.Background(), "vol-1")
	require.Equal(t, "iSCSI", protocol)
}

func TestK8sMetadataChecker_handleVolumeAttachmentAdd_WrongAttacher(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a VolumeAttachment with wrong attacher
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "wrong-driver",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &[]string{"test-pv"}[0],
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	// Add with wrong attacher - should be ignored
	checker.handleVolumeAttachmentAdd(va)

	// Verify cache is empty
	checker.cacheMu.RLock()
	_, exists := checker.attachmentCache["test-pv"]
	checker.cacheMu.RUnlock()
	require.False(t, exists)
}

func TestK8sMetadataChecker_handlePVAdd_EmptyVolumeHandle(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with empty volumeHandle
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "",
				},
			},
		},
	}

	// Add with empty volumeHandle - should be ignored
	checker.handlePVAdd(pv)

	// Verify cache is empty
	checker.cacheMu.RLock()
	_, exists := checker.volumeIDCache[""]
	checker.cacheMu.RUnlock()
	require.False(t, exists)
}

func TestK8sMetadataChecker_handlePVDelete_EmptyVolumeHandle(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with empty volumeHandle
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "",
				},
			},
		},
	}

	// Delete with empty volumeHandle - should not panic
	checker.handlePVDelete(pv)

	// Verify pending deletion is empty
	checker.pendingMutex.RLock()
	_, exists := checker.pendingDeletion[""]
	checker.pendingMutex.RUnlock()
	require.False(t, exists)
}

func TestK8sMetadataChecker_handleVolumeAttachmentAdd_NilPVName(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a VolumeAttachment with nil PVName
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: nil,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	// Add with nil PVName - should not panic
	checker.handleVolumeAttachmentAdd(va)

	// Verify cache is empty
	checker.cacheMu.RLock()
	require.Len(t, checker.attachmentCache, 0)
	checker.cacheMu.RUnlock()
}

func TestK8sMetadataChecker_handleVolumeAttachmentUpdate_NilPVName(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a VolumeAttachment with nil PVName
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: nil,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	// Update with nil PVName - should not panic
	checker.handleVolumeAttachmentUpdate(va, va)

	// Verify cache is empty
	checker.cacheMu.RLock()
	require.Len(t, checker.attachmentCache, 0)
	checker.cacheMu.RUnlock()
}

func TestK8sMetadataChecker_handleVolumeAttachmentDelete_NilPVName(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a VolumeAttachment with nil PVName
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: nil,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	// Delete with nil PVName - should not panic
	checker.handleVolumeAttachmentDelete(va)

	// Verify cache is empty
	checker.cacheMu.RLock()
	require.Len(t, checker.attachmentCache, 0)
	checker.cacheMu.RUnlock()
}

func TestK8sMetadataChecker_GetAttachmentStateForVolumeID_EmptyVolumeID(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Get attachment state for empty volumeID
	attached, err := checker.GetAttachmentStateForVolumeID(context.Background(), "", "global-id")
	require.NoError(t, err)
	require.False(t, attached)
}

func TestK8sMetadataChecker_GetAttachmentStateForPVName_EmptyPVName(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Get attachment state for empty PVName
	attached, err := checker.GetAttachmentStateForPVName(context.Background(), "")
	require.NoError(t, err)
	require.False(t, attached)
}

func TestK8sMetadataChecker_handlePVUpdate_NilCSI(_ *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with nil CSI
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: nil,
			},
		},
	}

	// Update with nil CSI - should not panic
	checker.handlePVUpdate(pv, pv)
}

func TestK8sMetadataChecker_handlePVUpdate_NoRelevantChanges(_ *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Update with no changes - should be skipped
	checker.handlePVUpdate(pv, pv)
}

func TestK8sMetadataChecker_handlePVUpdate_VolumeHandleChange(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Update with volumeHandle change
	newPV := pv.DeepCopy()
	newPV.Spec.CSI.VolumeHandle = "vol-2/array1/scsi"
	checker.handlePVUpdate(pv, newPV)

	// Verify new volume is in cache
	checker.cacheMu.RLock()
	_, exists := checker.volumeIDCache["vol-2"]
	checker.cacheMu.RUnlock()
	require.True(t, exists)
}

func TestK8sMetadataChecker_startCleanupRoutine(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Start the cleanup routine
	checker.startCleanupRoutine()

	// Add a volume to pending deletion
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
				},
			},
		},
	}

	checker.handlePVAdd(pv)
	checker.handlePVDelete(pv)

	// Verify volume is in pending deletion
	checker.pendingMutex.RLock()
	_, pendingExists := checker.pendingDeletion["vol-1"]
	checker.pendingMutex.RUnlock()
	require.True(t, pendingExists)

	// Manually trigger cleanup
	checker.cleanupStaleEntries()

	// Verify volume is still in pending deletion (grace period not exceeded)
	checker.pendingMutex.RLock()
	_, pendingExists = checker.pendingDeletion["vol-1"]
	checker.pendingMutex.RUnlock()
	require.True(t, pendingExists)
}

func TestK8sMetadataChecker_MarkDeleteComplete_WithEmptyVolumeID(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a volume to cache
	checker.volumeIDCache[""] = true
	checker.pendingDeletion[""] = time.Now()

	// Mark as delete complete with empty volume ID
	checker.MarkDeleteComplete("")

	// Verify empty volume ID was removed from caches
	checker.cacheMu.RLock()
	_, inVolumeCache := checker.volumeIDCache[""]
	checker.cacheMu.RUnlock()
	require.False(t, inVolumeCache, "Empty volume ID should be removed from volume cache")

	checker.pendingMutex.RLock()
	_, inPending := checker.pendingDeletion[""]
	checker.pendingMutex.RUnlock()
	require.False(t, inPending, "Empty volume ID should be removed from pending deletion")
}

func TestK8sMetadataChecker_MarkDeleteComplete_RemovesFromPending(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
				},
			},
		},
	}

	checker.handlePVAdd(pv)
	checker.handlePVDelete(pv)

	// Verify volume is in pending deletion
	checker.pendingMutex.RLock()
	_, pendingExists := checker.pendingDeletion["vol-1"]
	checker.pendingMutex.RUnlock()
	require.True(t, pendingExists)

	// Mark as delete complete
	checker.MarkDeleteComplete("vol-1")

	// Verify volume is removed from pending deletion
	checker.pendingMutex.RLock()
	_, pendingExists = checker.pendingDeletion["vol-1"]
	checker.pendingMutex.RUnlock()
	require.False(t, pendingExists)
}

func TestK8sMetadataChecker_GetAttachmentStateForVolumeID_ArrayIDMatch(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with arrayID
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/PSc26835c9a0ba/scsi",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Add a VolumeAttachment
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-1"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi-powerstore",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: &pv.Name,
			},
		},
		Status: storagev1.VolumeAttachmentStatus{
			Attached: true,
		},
	}

	checker.handleVolumeAttachmentAdd(va)

	// Get attachment state with matching arrayID
	attached, err := checker.GetAttachmentStateForVolumeID(context.Background(), "vol-1/PSc26835c9a0ba/scsi", "PSc26835c9a0ba")
	require.NoError(t, err)
	require.True(t, attached)
}

func TestK8sMetadataChecker_handlePVUpdate_VolumeAttributesChange(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
					VolumeAttributes: map[string]string{
						"Protocol": "iSCSI",
					},
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Update with VolumeAttributes change
	newPV := pv.DeepCopy()
	newPV.Spec.CSI.VolumeAttributes = map[string]string{
		"Protocol": "FC",
	}
	checker.handlePVUpdate(pv, newPV)

	// Verify protocol was updated
	checker.cacheMu.RLock()
	protocol := checker.protocolCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.Equal(t, "FC", protocol)
}

func TestK8sMetadataChecker_handlePVAdd_WithVolumeAttributes(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with VolumeAttributes
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
					VolumeAttributes: map[string]string{
						"Protocol": "iSCSI",
					},
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Verify protocol was cached
	checker.cacheMu.RLock()
	protocol := checker.protocolCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.Equal(t, "iSCSI", protocol)
}

func TestK8sMetadataChecker_handlePVAdd_WithoutVolumeAttributes(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV without VolumeAttributes
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
				},
			},
		},
	}

	checker.handlePVAdd(pv)

	// Verify protocol was not cached (unknown)
	checker.cacheMu.RLock()
	protocol := checker.protocolCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.Equal(t, "", protocol)
}

func TestK8sMetadataChecker_handlePVAdd_NilCSI(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with nil CSI
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: nil,
			},
		},
	}

	// Add with nil CSI - should not panic
	checker.handlePVAdd(pv)

	// Verify cache is empty
	checker.cacheMu.RLock()
	require.Len(t, checker.volumeIDCache, 0)
	checker.cacheMu.RUnlock()
}

func TestK8sMetadataChecker_handlePVDelete_WithoutVolumeHandle(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV without CSI
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: nil,
			},
		},
	}

	// Delete without volumeHandle - should not panic
	checker.handlePVDelete(pv)

	// Verify pending deletion is empty
	checker.pendingMutex.RLock()
	require.Len(t, checker.pendingDeletion, 0)
	checker.pendingMutex.RUnlock()
}

func TestK8sMetadataChecker_MarkDeleteCompleteByName_WithVolumeName(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a volume name to cache
	checker.volumeNameCache["test-volume"] = true

	// Mark as delete complete by name
	checker.MarkDeleteCompleteByName("test-volume")

	// Verify volume name was removed
	checker.cacheMu.RLock()
	_, exists := checker.volumeNameCache["test-volume"]
	checker.cacheMu.RUnlock()
	require.False(t, exists)
}

func TestK8sMetadataChecker_IsDriverManagedByName_NotInCache(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Check volume name not in cache
	managed, err := checker.IsDriverManagedByName(context.Background(), "nonexistent-volume")
	require.NoError(t, err)
	require.False(t, managed)
}

func TestK8sMetadataChecker_IsDriverManagedByName_InCache(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a volume name to cache
	checker.volumeNameCache["test-volume"] = true

	// Check volume name in cache
	managed, err := checker.IsDriverManagedByName(context.Background(), "test-volume")
	require.NoError(t, err)
	require.True(t, managed)
}

func TestK8sMetadataChecker_Start_NilClient(t *testing.T) {
	checker := NewK8sMetadataChecker(nil, "csi-powerstore")

	err := checker.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "kubernetes client not initialized")
}

func TestK8sMetadataChecker_Start_WithClient(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Start the informer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := checker.Start(ctx)
	require.NoError(t, err)

	// Stop to clean up
	checker.Stop()
}

func TestK8sMetadataChecker_InformerHandlers_WithStandaloneInformer(t *testing.T) {
	// Create a standalone informer using NewSharedIndexInformer with nil ListWatch
	// This gives us a real informer without background threads or network calls
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	pvInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{}, // nil ListWatch - no network calls
		&corev1.PersistentVolume{},
		0, // resync period
		indexers,
	)

	// Create checker with standalone informers
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Replace the informer factory's informers with our standalone ones
	checker.informerFactory = informers.NewSharedInformerFactory(client, 0)

	// Add test PV directly to the informer's indexer
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pv",
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
					VolumeAttributes: map[string]string{
						"protocol": "iSCSI",
					},
				},
			},
		},
	}
	err := pvInformer.GetIndexer().Add(pv)
	require.NoError(t, err)

	// Manually call the PV add handler to test the logic
	checker.handlePVAdd(pv)

	// Verify the volume was added to cache
	checker.cacheMu.RLock()
	_, exists := checker.volumeIDCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.True(t, exists, "Volume should be in cache after PV add")
}

func TestK8sMetadataChecker_startCleanupRoutine_WithStandaloneInformer(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Set a short grace period for testing
	checker.gracePeriod = 100 * time.Millisecond

	// Add a volume to pending deletion
	checker.pendingMutex.Lock()
	checker.pendingDeletion["vol-1"] = time.Now().Add(-200 * time.Millisecond) // Already expired
	checker.pendingMutex.Unlock()

	// Add to volume cache
	checker.cacheMu.Lock()
	checker.volumeIDCache["vol-1"] = true
	checker.protocolCache["vol-1"] = "iSCSI"
	checker.cacheMu.Unlock()

	// Run cleanup routine
	checker.cleanupStaleEntries()

	// Verify volume was removed from caches
	checker.cacheMu.RLock()
	_, inVolumeCache := checker.volumeIDCache["vol-1"]
	_, inProtocolCache := checker.protocolCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.False(t, inVolumeCache, "Volume should be removed from volume cache")
	require.False(t, inProtocolCache, "Volume should be removed from protocol cache")
}

func TestK8sMetadataChecker_fetchAndCachePVs_WithStandaloneInformer(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add test PVs to the fake client
	pv1 := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pv-1",
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array-1",
					VolumeAttributes: map[string]string{
						"protocol": "iSCSI",
					},
				},
			},
		},
	}
	_, err := client.CoreV1().PersistentVolumes().Create(context.Background(), pv1, metav1.CreateOptions{})
	require.NoError(t, err)

	// Fetch and cache PVs
	err = checker.fetchAndCachePVs(context.Background())
	require.NoError(t, err)

	// Verify volume was cached
	checker.cacheMu.RLock()
	_, exists := checker.volumeIDCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.True(t, exists, "Volume should be in cache")
}

func TestK8sMetadataChecker_onPVAdd_InvalidType(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Call onPVAdd with invalid type (string instead of PV)
	// This should log a warning but not panic
	assert.NotPanics(t, func() {
		checker.onPVAdd("invalid object")
	})
}

func TestK8sMetadataChecker_onPVUpdate_InvalidOldType(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Call onPVUpdate with invalid old type
	assert.NotPanics(t, func() {
		checker.onPVUpdate("invalid old", &corev1.PersistentVolume{})
	})
}

func TestK8sMetadataChecker_onPVUpdate_InvalidNewType(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Call onPVUpdate with invalid new type
	assert.NotPanics(t, func() {
		checker.onPVUpdate(&corev1.PersistentVolume{}, "invalid new")
	})
}

func TestK8sMetadataChecker_onPVDelete_InvalidType(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Call onPVDelete with invalid type
	assert.NotPanics(t, func() {
		checker.onPVDelete("invalid object")
	})
}

func TestK8sMetadataChecker_onVAAdd_InvalidType(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Call onVAAdd with invalid type
	assert.NotPanics(t, func() {
		checker.onVAAdd("invalid object")
	})
}

func TestK8sMetadataChecker_onVAUpdate_InvalidOldType(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Call onVAUpdate with invalid old type
	assert.NotPanics(t, func() {
		checker.onVAUpdate("invalid old", &storagev1.VolumeAttachment{})
	})
}

func TestK8sMetadataChecker_onVAUpdate_InvalidNewType(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Call onVAUpdate with invalid new type
	assert.NotPanics(t, func() {
		checker.onVAUpdate(&storagev1.VolumeAttachment{}, "invalid new")
	})
}

func TestK8sMetadataChecker_onVADelete_InvalidType(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Call onVADelete with invalid type
	assert.NotPanics(t, func() {
		checker.onVADelete("invalid object")
	})
}

func TestK8sMetadataChecker_Start_WaitForCacheSyncFailure(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Close the stop channel immediately to force WaitForCacheSync to fail
	close(checker.stopCh)

	// Start should return error due to cache sync failure
	err := checker.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to sync informer cache")
}

func TestK8sMetadataChecker_handlePVUpdate_OldPVNilCSI(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a new PV with CSI
	newPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "vol-1/array1/scsi",
				},
			},
		},
	}

	// Update with old PV having nil CSI
	oldPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: nil,
			},
		},
	}

	// Update with old PV nil CSI - should re-process
	checker.handlePVUpdate(oldPV, newPV)

	// Verify volume is in cache
	checker.cacheMu.RLock()
	_, exists := checker.volumeIDCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.True(t, exists)
}

func TestK8sMetadataChecker_handlePVUpdate_BothNilCSI(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Both PVs have nil CSI
	oldPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: nil,
			},
		},
	}

	newPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: nil,
			},
		},
	}

	// Update with both nil CSI - should not panic
	checker.handlePVUpdate(oldPV, newPV)

	// Verify cache is empty
	checker.cacheMu.RLock()
	require.Len(t, checker.volumeIDCache, 0)
	checker.cacheMu.RUnlock()
}

func TestK8sMetadataChecker_handlePVUpdate_VolumeHandleFromEmpty(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	// Add a PV with empty volumeHandle
	oldPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "csi-powerstore",
					VolumeHandle: "",
				},
			},
		},
	}

	checker.handlePVAdd(oldPV)

	// Update with non-empty volumeHandle
	newPV := oldPV.DeepCopy()
	newPV.Spec.CSI.VolumeHandle = "vol-1/array1/scsi"
	checker.handlePVUpdate(oldPV, newPV)

	// Verify volume is in cache
	checker.cacheMu.RLock()
	_, exists := checker.volumeIDCache["vol-1"]
	checker.cacheMu.RUnlock()
	require.True(t, exists)
}
