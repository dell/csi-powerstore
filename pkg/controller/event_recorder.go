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

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	log "github.com/dell/csmlog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	typedv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

// newControllerEventRecorder creates a Kubernetes event recorder and broadcaster for the controller service.
// The caller must call broadcaster.Shutdown() during service shutdown to stop background goroutines.
func newControllerEventRecorder(kubeConfigPath string) (record.EventRecorder, record.EventBroadcaster, error) {
	kubeclient, err := k8sutils.CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Kubernetes client for event recorder: %w", err)
	}
	return createEventRecorder(kubeclient.Clientset)
}

// createEventRecorder creates a record.EventRecorder and EventBroadcaster from a Kubernetes clientset.
func createEventRecorder(clientset kubernetes.Interface) (record.EventRecorder, record.EventBroadcaster, error) {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&typedv1core.EventSinkImpl{Interface: clientset.CoreV1().Events("")})

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, nil, fmt.Errorf("failed to add corev1 to scheme: %w", err)
	}

	eventRecorder := eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: identifiers.Name})
	return eventRecorder, eventBroadcaster, nil
}

// Metro restore event reasons
const (
	EventReasonMetroRestoreStarted    = "MetroRestoreStarted"
	EventReasonMetroConfigInitiated   = "MetroConfigurationInitiated"
	EventReasonMetroConfigSucceeded   = "MetroConfigurationSucceeded"
	EventReasonMetroConfigFailed      = "MetroConfigurationFailed"
	EventReasonMetroRestoreRolledBack = "MetroRestoreRolledBack"
	EventReasonMetroRestoreComplete   = "MetroRestoreComplete"
	EventReasonMetroArrayMismatch     = "MetroArrayMismatch"
	EventReasonMetroFractureBlocked   = "MetroFractureBlocked"
)

// NAA placement event reasons for multi-appliance MTV migration
const (
	EventReasonNAAResolutionSuccess        = "NAAResolutionSuccess"
	EventReasonNAAResolutionFailed         = "NAAResolutionFailed"
	EventReasonXCOPYSuccess                = "XCOPYSuccess"
	EventReasonHostCopyFallback            = "HostCopyFallback"
	EventReasonPlacementVerificationFailed = "PlacementVerificationFailed"
)

// emitMetroRestoreEvent emits a Kubernetes event for metro restore milestones.
// If the event recorder is nil, this is a no-op.
// The namespace parameter should be the PVC namespace from req.Parameters[KeyCSIPVCNamespace].
// If empty, the event is emitted in "default" as a fallback.
func (s *Service) emitMetroRestoreEvent(eventType, reason, message, volumeName, namespace string) {
	if s.EventRecorder == nil {
		return
	}
	if namespace == "" {
		namespace = "default"
	}
	objRef := &corev1.ObjectReference{
		Kind:      "PersistentVolumeClaim",
		Name:      volumeName,
		Namespace: namespace,
	}
	s.EventRecorder.Event(objRef, eventType, reason, message)
}

// emitNAAPlacementEvent emits a Kubernetes event for NAA placement outcomes.
// If the event recorder is nil, this is a no-op.
// The namespace parameter should be the PVC namespace from req.Parameters[KeyCSIPVCNamespace].
// If empty, the event is emitted in "default" as a fallback.
// This function fetches the PVC to get its UID for proper event association in kubectl describe.
func (s *Service) emitNAAPlacementEvent(ctx context.Context, eventType, reason, message, volumeName, namespace string) {
	if s.EventRecorder == nil {
		return
	}
	if namespace == "" {
		namespace = "default"
	}

	objRef := &corev1.ObjectReference{
		APIVersion: "v1",
		Kind:       "PersistentVolumeClaim",
		Name:       volumeName,
		Namespace:  namespace,
	}

	// Fetch PVC to get its UID for proper event association
	if k8sutils.Kubeclient != nil && k8sutils.Kubeclient.Clientset != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, pvcLookupTimeout)
		defer cancel()
		pvc, err := k8sutils.Kubeclient.Clientset.CoreV1().PersistentVolumeClaims(namespace).Get(lookupCtx, volumeName, metav1.GetOptions{})
		if err == nil {
			objRef.UID = pvc.UID
			objRef.ResourceVersion = pvc.ResourceVersion
		} else {
			log.Warnf("Failed to fetch PVC %s/%s for event UID: %v", namespace, volumeName, err)
		}
	}

	s.EventRecorder.Event(objRef, eventType, reason, message)
}

// pvcLookupTimeout is the timeout for fetching PVC details for event emission
const pvcLookupTimeout = 5 * time.Second
