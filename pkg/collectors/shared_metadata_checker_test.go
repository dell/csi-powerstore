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

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSharedMetadataChecker_SetAndGet(t *testing.T) {
	shared := &SharedMetadataChecker{}
	checker := &K8sMetadataChecker{}

	shared.Set(checker)
	require.Equal(t, checker, shared.current())
}

func TestSharedMetadataChecker_Clear(t *testing.T) {
	shared := &SharedMetadataChecker{}
	checker := &K8sMetadataChecker{}

	shared.Set(checker)
	require.Equal(t, checker, shared.current())

	shared.Clear(checker)
	require.Nil(t, shared.current())
}

func TestSharedMetadataChecker_Clear_DifferentChecker(t *testing.T) {
	shared := &SharedMetadataChecker{}
	checker1 := &K8sMetadataChecker{}
	checker2 := &K8sMetadataChecker{}

	shared.Set(checker1)
	shared.Clear(checker2)
	require.Equal(t, checker1, shared.current())
}

func TestSharedMetadataChecker_Available(t *testing.T) {
	shared := &SharedMetadataChecker{}
	require.False(t, shared.Available())

	checker := &K8sMetadataChecker{}
	shared.Set(checker)
	require.True(t, shared.Available())

	shared.Clear(checker)
	require.False(t, shared.Available())
}

func TestSharedMetadataChecker_GetProtocol_WithChecker(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pv",
			},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					CSI: &corev1.CSIPersistentVolumeSource{
						Driver:       "csi-powerstore",
						VolumeHandle: "vol1/array1",
					},
				},
			},
		},
	)

	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	shared := &SharedMetadataChecker{}
	shared.Set(checker)

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	protocol := shared.GetProtocol(context.Background(), "vol1")
	require.Equal(t, "unknown", protocol)
}

func TestSharedMetadataChecker_GetProtocol_WithoutChecker(t *testing.T) {
	shared := &SharedMetadataChecker{}
	protocol := shared.GetProtocol(context.Background(), "vol1")
	require.Equal(t, "unknown", protocol)
}

func TestSharedMetadataChecker_RefreshCache_WithChecker(t *testing.T) {
	client := fake.NewSimpleClientset()
	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	shared := &SharedMetadataChecker{}
	shared.Set(checker)

	err := shared.RefreshCache(context.Background())
	require.NoError(t, err)
}

func TestSharedMetadataChecker_RefreshCache_WithoutChecker(t *testing.T) {
	shared := &SharedMetadataChecker{}
	err := shared.RefreshCache(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "metadata checker unavailable")
}

func TestSharedMetadataChecker_IsDriverManaged_WithChecker(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pv",
			},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					CSI: &corev1.CSIPersistentVolumeSource{
						Driver:       "csi-powerstore",
						VolumeHandle: "vol1/array1",
					},
				},
			},
		},
	)

	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	shared := &SharedMetadataChecker{}
	shared.Set(checker)

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	managed, err := shared.IsDriverManaged(context.Background(), "vol1")
	require.NoError(t, err)
	require.True(t, managed)
}

func TestSharedMetadataChecker_IsDriverManaged_WithoutChecker(t *testing.T) {
	shared := &SharedMetadataChecker{}
	managed, err := shared.IsDriverManaged(context.Background(), "vol1")
	require.Error(t, err)
	require.False(t, managed)
	require.Contains(t, err.Error(), "metadata checker unavailable")
}

func TestSharedMetadataChecker_IsDriverManagedByName_WithChecker(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pv",
			},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					CSI: &corev1.CSIPersistentVolumeSource{
						Driver:       "csi-powerstore",
						VolumeHandle: "vol1/array1",
					},
				},
			},
		},
	)

	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	shared := &SharedMetadataChecker{}
	shared.Set(checker)

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	managed, err := shared.IsDriverManagedByName(context.Background(), "test-pv")
	require.NoError(t, err)
	require.True(t, managed)
}

func TestSharedMetadataChecker_IsDriverManagedByName_WithoutChecker(t *testing.T) {
	shared := &SharedMetadataChecker{}
	managed, err := shared.IsDriverManagedByName(context.Background(), "test-pv")
	require.Error(t, err)
	require.False(t, managed)
	require.Contains(t, err.Error(), "metadata checker unavailable")
}

func TestSharedMetadataChecker_MarkDeleteComplete_WithChecker(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pv",
			},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					CSI: &corev1.CSIPersistentVolumeSource{
						Driver:       "csi-powerstore",
						VolumeHandle: "vol1/array1",
					},
				},
			},
		},
	)

	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	shared := &SharedMetadataChecker{}
	shared.Set(checker)

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	shared.MarkDeleteComplete("vol1")
}

func TestSharedMetadataChecker_MarkDeleteComplete_WithoutChecker(_ *testing.T) {
	shared := &SharedMetadataChecker{}
	shared.MarkDeleteComplete("vol1")
}

func TestSharedMetadataChecker_MarkDeleteCompleteByName_WithChecker(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pv",
			},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					CSI: &corev1.CSIPersistentVolumeSource{
						Driver:       "csi-powerstore",
						VolumeHandle: "vol1/array1",
					},
				},
			},
		},
	)

	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	shared := &SharedMetadataChecker{}
	shared.Set(checker)

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	shared.MarkDeleteCompleteByName("test-pv")
}

func TestSharedMetadataChecker_MarkDeleteCompleteByName_WithoutChecker(_ *testing.T) {
	shared := &SharedMetadataChecker{}
	shared.MarkDeleteCompleteByName("vol-1")
}

func TestSharedMetadataChecker_GetAttachmentStateForVolumeID_WithChecker(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pv",
			},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					CSI: &corev1.CSIPersistentVolumeSource{
						Driver:       "csi-powerstore",
						VolumeHandle: "vol1/array1",
					},
				},
			},
		},
	)

	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	shared := &SharedMetadataChecker{}
	shared.Set(checker)

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	attached, err := shared.GetAttachmentStateForVolumeID(context.Background(), "vol1", "array1")
	require.NoError(t, err)
	require.False(t, attached)
}

func TestSharedMetadataChecker_GetAttachmentStateForVolumeID_WithoutChecker(t *testing.T) {
	shared := &SharedMetadataChecker{}
	attached, err := shared.GetAttachmentStateForVolumeID(context.Background(), "vol1", "array1")
	require.Error(t, err)
	require.False(t, attached)
	require.Contains(t, err.Error(), "metadata checker unavailable")
}

func TestSharedMetadataChecker_GetAttachmentStateForPVName_WithChecker(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pv",
			},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					CSI: &corev1.CSIPersistentVolumeSource{
						Driver:       "csi-powerstore",
						VolumeHandle: "vol1/array1",
					},
				},
			},
		},
	)

	checker := NewK8sMetadataChecker(client, "csi-powerstore")

	shared := &SharedMetadataChecker{}
	shared.Set(checker)

	err := checker.RefreshCache(context.Background())
	require.NoError(t, err)

	attached, err := shared.GetAttachmentStateForPVName(context.Background(), "test-pv")
	require.NoError(t, err)
	require.False(t, attached)
}

func TestSharedMetadataChecker_GetAttachmentStateForPVName_WithoutChecker(t *testing.T) {
	shared := &SharedMetadataChecker{}
	attached, err := shared.GetAttachmentStateForPVName(context.Background(), "test-pv")
	require.Error(t, err)
	require.False(t, attached)
	require.Contains(t, err.Error(), "metadata checker unavailable")
}
