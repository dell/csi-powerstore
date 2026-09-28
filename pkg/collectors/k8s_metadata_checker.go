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

package collectors

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	metricsprotocol "github.com/dell/csi-powerstore/v2/pkg/metrics/protocol"
	"github.com/dell/csmlog"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// K8sMetadataChecker checks if a volume is managed by the CSI driver
// by querying Kubernetes PVs and PVCs. It also implements ProtocolResolver
// to provide volume protocol information from PV VolumeAttributes.
type K8sMetadataChecker struct {
	k8sClient       kubernetes.Interface
	driverName      string
	volumeIDCache   map[string]bool   // PowerStore volume ID -> is driver managed
	volumeNameCache map[string]bool   // Volume name -> is driver managed (for file system matching)
	protocolCache   map[string]string // PowerStore volume ID -> protocol string (e.g., "iSCSI", "FC", "NVMeTCP", "NVMeFC", "nfs")
	pvNameCache     map[string]string // volumeID -> PV name
	arrayIDCache    map[string]string // volumeID -> arrayID (for validation)
	attachmentCache map[string]bool   // PV name -> attached status
	cacheMu         sync.RWMutex
	informerFactory informers.SharedInformerFactory
	stopCh          chan struct{}
	pendingDeletion map[string]time.Time // volumeID -> deletion timestamp (for event-based cleanup)
	pendingMutex    sync.RWMutex
	cleanupMu       sync.Mutex
	gracePeriod     time.Duration // cleanup grace period for stale entries
	cleanupTicker   *time.Ticker
	stopOnce        sync.Once
}

// NewK8sMetadataChecker creates a new K8sMetadataChecker
func NewK8sMetadataChecker(k8sClient kubernetes.Interface, driverName string) *K8sMetadataChecker {
	return &K8sMetadataChecker{
		k8sClient:       k8sClient,
		driverName:      driverName,
		volumeIDCache:   make(map[string]bool),
		volumeNameCache: make(map[string]bool),
		protocolCache:   make(map[string]string),
		pvNameCache:     make(map[string]string),
		arrayIDCache:    make(map[string]string),
		attachmentCache: make(map[string]bool),
		informerFactory: informers.NewSharedInformerFactory(k8sClient, 0),
		stopCh:          make(chan struct{}),
		pendingDeletion: make(map[string]time.Time),
		gracePeriod:     30 * time.Second, // default grace period
	}
}

// Start begins the informer-based cache updates
func (c *K8sMetadataChecker) Start(ctx context.Context) error {
	if c.k8sClient == nil {
		return fmt.Errorf("K8sMetadataChecker: kubernetes client not initialized")
	}

	csmlog.GetLogger().Infof("K8sMetadataChecker: starting informer-based cache updates")

	// Set up PV informer
	pvInformer := c.informerFactory.Core().V1().PersistentVolumes().Informer()

	// Add event handlers
	_, _ = pvInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onPVAdd,
		UpdateFunc: c.onPVUpdate,
		DeleteFunc: c.onPVDelete,
	})

	// Set up VolumeAttachment informer
	vaInformer := c.informerFactory.Storage().V1().VolumeAttachments().Informer()
	_, _ = vaInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onVAAdd,
		UpdateFunc: c.onVAUpdate,
		DeleteFunc: c.onVADelete,
	})

	// Start the informer factory
	c.informerFactory.Start(c.stopCh)

	// Wait for cache to sync (both PV and VolumeAttachment)
	if !cache.WaitForCacheSync(c.stopCh, pvInformer.HasSynced, vaInformer.HasSynced) {
		return fmt.Errorf("K8sMetadataChecker: failed to sync informer cache")
	}

	csmlog.GetLogger().Infof("K8sMetadataChecker: informer cache synced successfully")

	// Start cleanup routine for pending deletions
	c.startCleanupRoutine()

	// Perform initial refresh to populate cache with existing PVs
	if err := c.RefreshCache(ctx); err != nil {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to perform initial cache refresh: %v", err)
	}

	return nil
}

// onPVAdd handles PV add events
func (c *K8sMetadataChecker) onPVAdd(obj interface{}) {
	pv, ok := obj.(*corev1.PersistentVolume)
	if !ok {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to cast to PersistentVolume")
		return
	}
	c.handlePVAdd(pv)
}

// onPVUpdate handles PV update events
func (c *K8sMetadataChecker) onPVUpdate(oldObj, newObj interface{}) {
	oldPV, ok := oldObj.(*corev1.PersistentVolume)
	if !ok {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to cast old object to PersistentVolume")
		return
	}
	newPV, ok := newObj.(*corev1.PersistentVolume)
	if !ok {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to cast new object to PersistentVolume")
		return
	}
	c.handlePVUpdate(oldPV, newPV)
}

// onPVDelete handles PV delete events
func (c *K8sMetadataChecker) onPVDelete(obj interface{}) {
	pv, ok := pvFromDelete(obj)
	if !ok {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to extract PV from delete event")
		return
	}
	c.handlePVDelete(pv)
}

// onVAAdd handles VolumeAttachment add events
func (c *K8sMetadataChecker) onVAAdd(obj interface{}) {
	va, ok := obj.(*storagev1.VolumeAttachment)
	if !ok {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to cast to VolumeAttachment")
		return
	}
	c.handleVolumeAttachmentAdd(va)
}

// onVAUpdate handles VolumeAttachment update events
func (c *K8sMetadataChecker) onVAUpdate(oldObj, newObj interface{}) {
	oldVA, ok := oldObj.(*storagev1.VolumeAttachment)
	if !ok {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to cast old object to VolumeAttachment")
		return
	}
	newVA, ok := newObj.(*storagev1.VolumeAttachment)
	if !ok {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to cast new object to VolumeAttachment")
		return
	}
	c.handleVolumeAttachmentUpdate(oldVA, newVA)
}

// onVADelete handles VolumeAttachment delete events
func (c *K8sMetadataChecker) onVADelete(obj interface{}) {
	va, ok := volumeAttachmentFromDelete(obj)
	if !ok {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to extract VolumeAttachment from delete event")
		return
	}
	c.handleVolumeAttachmentDelete(va)
}

// Stop stops the informer and cleans up resources
func (c *K8sMetadataChecker) Stop() {
	csmlog.GetLogger().Infof("K8sMetadataChecker: stopping informer and cleanup routine")

	c.stopOnce.Do(func() {
		close(c.stopCh)

		c.cleanupMu.Lock()
		if c.cleanupTicker != nil {
			c.cleanupTicker.Stop()
			c.cleanupTicker = nil
		}
		c.cleanupMu.Unlock()

		c.informerFactory.Shutdown() // Gracefully stop all informer goroutines
	})
}

// handlePVAdd handles PV add events
func (c *K8sMetadataChecker) handlePVAdd(pv *corev1.PersistentVolume) {
	csmlog.GetLogger().Infof("K8sMetadataChecker: handlePVAdd called for PV %s", pv.Name)

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	volumeID := extractVolumeIDFromPV(pv)
	if volumeID == "" {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to extract volume ID from PV %s", pv.Name)
		return
	}

	// Check if it's a driver-managed PV
	if pv.Spec.CSI == nil || pv.Spec.CSI.Driver != c.driverName {
		csmlog.GetLogger().Debugf("K8sMetadataChecker: PV %s is not managed by driver %s", pv.Name, c.driverName)
		return
	}

	// Add to volume ID cache
	c.volumeIDCache[volumeID] = true

	// Add to volume name cache (for file system matching)
	c.volumeNameCache[pv.Name] = true

	// Add to PV name cache (for VolumeAttachment lookup)
	c.pvNameCache[volumeID] = pv.Name

	// Add to array ID cache (for validation)
	arrayID := extractArrayID(pv.Spec.CSI.VolumeHandle)
	if arrayID != "" {
		c.arrayIDCache[volumeID] = arrayID
	}

	// Extract and cache protocol
	var protocol string
	if pv.Spec.CSI.VolumeAttributes != nil {
		if p, ok := pv.Spec.CSI.VolumeAttributes["Protocol"]; ok {
			protocol = p
		}
	}

	// If protocol is generic block ("scsi"), try to determine
	// the real transport from nodeAffinity instead of caching the generic value.
	protocol = resolvePVProtocol(protocol, pv.Spec.NodeAffinity)

	if protocol != "" {
		c.protocolCache[volumeID] = protocol
		csmlog.GetLogger().Infof("K8sMetadataChecker: added volume %s with protocol %s from PV %s (cache size: %d volumes, %d protocols)", volumeID, protocol, pv.Name, len(c.volumeIDCache), len(c.protocolCache))
	} else {
		csmlog.GetLogger().Warnf("K8sMetadataChecker: no protocol found for volume %s from PV %s", volumeID, pv.Name)
	}
}

// handlePVUpdate handles PV update events
// Only processes updates if relevant fields changed (VolumeHandle, VolumeAttributes, NodeAffinity)
func (c *K8sMetadataChecker) handlePVUpdate(oldPV, newPV *corev1.PersistentVolume) {
	csmlog.GetLogger().Infof("K8sMetadataChecker: handlePVUpdate called for PV %s", newPV.Name)

	// Check if relevant fields changed
	volumeHandleChanged := false
	if oldPV.Spec.CSI == nil || newPV.Spec.CSI == nil {
		volumeHandleChanged = true
	} else {
		volumeHandleChanged = oldPV.Spec.CSI.VolumeHandle != newPV.Spec.CSI.VolumeHandle
	}

	volumeAttributesChanged := false
	if oldPV.Spec.CSI == nil || newPV.Spec.CSI == nil {
		volumeAttributesChanged = true
	} else {
		volumeAttributesChanged = !reflect.DeepEqual(oldPV.Spec.CSI.VolumeAttributes, newPV.Spec.CSI.VolumeAttributes)
	}

	nodeAffinityChanged := !reflect.DeepEqual(oldPV.Spec.NodeAffinity, newPV.Spec.NodeAffinity)

	// Only process if relevant fields changed
	if !volumeHandleChanged && !volumeAttributesChanged && !nodeAffinityChanged {
		csmlog.GetLogger().Debugf("K8sMetadataChecker: PV %s update skipped - no relevant changes", newPV.Name)
		return
	}

	csmlog.GetLogger().Debugf("K8sMetadataChecker: PV %s update processed - relevant fields changed", newPV.Name)
	c.handlePVAdd(newPV) // Re-process with new state
}

// handlePVDelete handles PV delete events
func (c *K8sMetadataChecker) handlePVDelete(pv *corev1.PersistentVolume) {
	csmlog.GetLogger().Infof("K8sMetadataChecker: handlePVDelete called for PV %s", pv.Name)

	volumeID := extractVolumeIDFromPV(pv)
	if volumeID == "" {
		return
	}

	// Check if volume is already in pending deletion (handle re-add edge case)
	c.pendingMutex.Lock()
	if _, exists := c.pendingDeletion[volumeID]; exists {
		c.pendingMutex.Unlock()
		csmlog.GetLogger().Debugf("K8sMetadataChecker: volume %s already in pending deletion, skipping", volumeID)
		return
	}

	// Mark as pending deletion instead of deleting immediately
	// This ensures protocol is available for DeleteVolume metrics
	c.pendingDeletion[volumeID] = time.Now()
	c.pendingMutex.Unlock()

	csmlog.GetLogger().Infof("K8sMetadataChecker: marked volume %s as pending deletion (PV %s deleted, pending deletions: %d)", volumeID, pv.Name, len(c.pendingDeletion))
}

// MarkDeleteComplete marks volume deletion as complete but preserves protocol in cache
// This is called by the metrics interceptor after a successful DeleteVolume
// Protocol is preserved to allow metrics interceptor to query it after operation completes
// Actual cache cleanup happens via cleanup routine after grace period
func (c *K8sMetadataChecker) MarkDeleteComplete(volumeID string) {
	normalizedVolumeID := extractVolumeID(volumeID)
	if normalizedVolumeID == "" {
		normalizedVolumeID = volumeID
	}

	c.pendingMutex.Lock()
	defer c.pendingMutex.Unlock()

	// Remove from pending deletion (cleanup routine will handle actual cache removal)
	delete(c.pendingDeletion, volumeID)
	delete(c.pendingDeletion, normalizedVolumeID)

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// Remove from ID and name caches, but preserve protocol for metrics
	delete(c.volumeIDCache, volumeID)
	delete(c.volumeIDCache, normalizedVolumeID)
	delete(c.volumeNameCache, volumeID)
	delete(c.volumeNameCache, normalizedVolumeID)
	delete(c.pvNameCache, volumeID)
	delete(c.pvNameCache, normalizedVolumeID)
	delete(c.arrayIDCache, volumeID)
	delete(c.arrayIDCache, normalizedVolumeID)

	// NOTE: protocolCache is NOT deleted here to allow metrics interceptor to query protocol
	// after DeleteVolume completes. The protocol will be cleaned up by the cleanup routine.

	csmlog.GetLogger().Infof("K8sMetadataChecker: marked volume %s deletion complete, protocol preserved (cache size: %d volumes, %d volume names, %d protocols, %d PV names, %d array IDs)", normalizedVolumeID, len(c.volumeIDCache), len(c.volumeNameCache), len(c.protocolCache), len(c.pvNameCache), len(c.arrayIDCache))
}

// MarkDeleteCompleteByName removes volume from cache by name after DeleteVolume completes
// This is used for file system deletion where file system names match PV names
func (c *K8sMetadataChecker) MarkDeleteCompleteByName(volumeName string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	delete(c.volumeNameCache, volumeName)

	csmlog.GetLogger().Infof("K8sMetadataChecker: removed volume name %s from cache (cache size: %d volume names)", volumeName, len(c.volumeNameCache))
}

// startCleanupRoutine starts the background goroutine that cleans up stale entries
func (c *K8sMetadataChecker) startCleanupRoutine() {
	c.cleanupMu.Lock()
	c.cleanupTicker = time.NewTicker(1 * time.Minute)
	ticker := c.cleanupTicker
	c.cleanupMu.Unlock()

	go func() {
		for {
			select {
			case <-ticker.C:
				c.cleanupStaleEntries()
			case <-c.stopCh:
				return
			}
		}
	}()
}

// cleanupStaleEntries removes entries that have been in pending deletion for longer than grace period
// Also cleans up orphaned protocol entries (protocols for volumes no longer in ID/name caches)
func (c *K8sMetadataChecker) cleanupStaleEntries() {
	c.pendingMutex.Lock()
	defer c.pendingMutex.Unlock()

	now := time.Now()
	staleCount := 0

	// Clean up entries in pending deletion that exceeded grace period
	for volumeID, deleteTime := range c.pendingDeletion {
		if now.Sub(deleteTime) > c.gracePeriod {
			delete(c.pendingDeletion, volumeID)

			c.cacheMu.Lock()
			delete(c.volumeIDCache, volumeID)
			delete(c.protocolCache, volumeID)
			c.cacheMu.Unlock()

			staleCount++
			csmlog.GetLogger().Infof("K8sMetadataChecker: cleaned up stale volume %s (grace period exceeded, pending deletions: %d)", volumeID, len(c.pendingDeletion))
		}
	}

	// Clean up orphaned protocol entries (protocols for volumes no longer in caches)
	c.cacheMu.Lock()
	for volumeID := range c.protocolCache {
		// If volume is not in volumeIDCache or volumeNameCache, it's orphaned
		if _, inIDCache := c.volumeIDCache[volumeID]; !inIDCache {
			if _, inNameCache := c.volumeNameCache[volumeID]; !inNameCache {
				// Volume is not in any cache, remove protocol
				delete(c.protocolCache, volumeID)
				staleCount++
				csmlog.GetLogger().Debugf("K8sMetadataChecker: cleaned up orphaned protocol for volume %s", volumeID)
			}
		}
	}
	c.cacheMu.Unlock()

	if staleCount > 0 {
		csmlog.GetLogger().Infof("K8sMetadataChecker: cleanup routine processed %d stale entries", staleCount)
	}
}

// IsDriverManaged checks if a volume is managed by the CSI driver (implements VolumeValidator interface)
// by looking up the corresponding PV in Kubernetes
func (c *K8sMetadataChecker) IsDriverManaged(_ context.Context, volumeID string) (bool, error) {
	if c.k8sClient == nil {
		return false, fmt.Errorf("K8sMetadataChecker: kubernetes client not initialized")
	}

	if volumeID == "" {
		return false, nil
	}

	// Check cache (should be populated by RefreshCache call before volume processing)
	c.cacheMu.RLock()
	cached, exists := c.volumeIDCache[volumeID]
	c.cacheMu.RUnlock()

	if exists {
		return cached, nil
	}

	// If not in cache, it's not managed by our driver
	return false, nil
}

// IsDriverManagedByName checks if a volume name is managed by the CSI driver
// This is used for file system matching where file system names match PV names
func (c *K8sMetadataChecker) IsDriverManagedByName(_ context.Context, volumeName string) (bool, error) {
	if c.k8sClient == nil {
		return false, fmt.Errorf("K8sMetadataChecker: kubernetes client not initialized")
	}

	if volumeName == "" {
		return false, nil
	}

	// Check cache (should be populated by RefreshCache call before volume processing)
	c.cacheMu.RLock()
	cached, exists := c.volumeNameCache[volumeName]
	c.cacheMu.RUnlock()

	if exists {
		return cached, nil
	}

	// If not in cache, it's not managed by our driver
	return false, nil
}

// fetchAndCachePVs fetches all PVs and populates the cache with driver-managed volumes
func (c *K8sMetadataChecker) fetchAndCachePVs(ctx context.Context) error {
	// Fetch all PVs (field selector for spec.csi.driver is not supported in Kubernetes)
	pvList, err := c.k8sClient.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("K8sMetadataChecker: failed to list PVs: %w", err)
	}

	csmlog.GetLogger().Infof("K8sMetadataChecker: fetched %d PVs from Kubernetes, driverName=%s", len(pvList.Items), c.driverName)

	// Build new cache with only driver-managed volume IDs and protocols
	newCache := make(map[string]bool)
	newNameCache := make(map[string]bool)
	newProtocolCache := make(map[string]string)
	newPVNameCache := make(map[string]string)
	newArrayIDCache := make(map[string]string)
	driverManagedCount := 0
	for _, pv := range pvList.Items {
		if pv.Spec.CSI != nil && pv.Spec.CSI.Driver == c.driverName {
			// Extract PowerStore volume ID from volumeHandle
			// volumeHandle format is typically: "volumeID/arrayID" or just "volumeID"
			volumeHandle := pv.Spec.CSI.VolumeHandle
			if volumeHandle == "" {
				csmlog.GetLogger().Warnf("K8sMetadataChecker: PV %s has empty volumeHandle, skipping", pv.Name)
				continue
			}

			// Extract volume ID by splitting on "/" and taking the first part
			volumeID := extractVolumeID(volumeHandle)
			if volumeID == "" {
				csmlog.GetLogger().Warnf("K8sMetadataChecker: failed to extract volume ID from volumeHandle %s for PV %s", volumeHandle, pv.Name)
				continue
			}

			newCache[volumeID] = true
			newNameCache[pv.Name] = true
			newPVNameCache[volumeID] = pv.Name

			// Extract and cache arrayID for validation
			arrayID := extractArrayID(volumeHandle)
			if arrayID != "" {
				newArrayIDCache[volumeID] = arrayID
			}

			// Extract protocol from VolumeAttributes if available
			var protocol string
			if pv.Spec.CSI.VolumeAttributes != nil {
				if p, ok := pv.Spec.CSI.VolumeAttributes["Protocol"]; ok {
					protocol = p
				}
			}

			// If protocol is generic block ("scsi"), try to determine
			// the real transport from nodeAffinity instead of caching the generic value.
			protocol = resolvePVProtocol(protocol, pv.Spec.NodeAffinity)

			if protocol != "" {
				newProtocolCache[volumeID] = protocol
				newProtocolCache[pv.Name] = protocol // Also cache by volume name for file system matching
				csmlog.GetLogger().Debugf("K8sMetadataChecker: cached protocol %s for volume ID %s from PV %s", protocol, volumeID, pv.Name)
			}

			driverManagedCount++
			csmlog.GetLogger().Debugf("K8sMetadataChecker: cached volume ID %s from PV %s (volumeHandle=%s)", volumeID, pv.Name, volumeHandle)
		}
	}

	csmlog.GetLogger().Infof("K8sMetadataChecker: cached %d driver-managed volume IDs from %d driver-managed PVs", len(newCache), driverManagedCount)
	csmlog.GetLogger().Debugf("K8sMetadataChecker: cached %d volume names from %d driver-managed PVs", len(newNameCache), driverManagedCount)
	csmlog.GetLogger().Debugf("K8sMetadataChecker: cached %d volume protocols", len(newProtocolCache))
	csmlog.GetLogger().Debugf("K8sMetadataChecker: cached %d PV name mappings", len(newPVNameCache))
	csmlog.GetLogger().Debugf("K8sMetadataChecker: cached %d array ID mappings", len(newArrayIDCache))

	// Update cache atomically
	c.cacheMu.Lock()
	c.volumeIDCache = newCache
	c.volumeNameCache = newNameCache
	c.protocolCache = newProtocolCache
	c.pvNameCache = newPVNameCache
	c.arrayIDCache = newArrayIDCache
	c.cacheMu.Unlock()

	return nil
}

// extractVolumeID extracts the PowerStore volume ID from the volumeHandle
// volumeHandle format is typically: "volumeID/arrayID" or just "volumeID"
func extractVolumeID(volumeHandle string) string {
	if volumeHandle == "" {
		return ""
	}

	// Split on "/" and take the first part as the volume ID
	// This handles both formats: "volumeID/arrayID" and "volumeID"
	parts := strings.Split(volumeHandle, "/")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}

	return ""
}

// pvFromDelete extracts a PersistentVolume from a delete event object.
// It handles both direct PV objects and DeletedFinalStateUnknown tombstones.
func pvFromDelete(obj interface{}) (*corev1.PersistentVolume, bool) {
	switch deleted := obj.(type) {
	case *corev1.PersistentVolume:
		return deleted, true
	case cache.DeletedFinalStateUnknown:
		pv, ok := deleted.Obj.(*corev1.PersistentVolume)
		return pv, ok
	default:
		return nil, false
	}
}

// volumeAttachmentFromDelete extracts a VolumeAttachment from a delete event object.
// It handles both direct VolumeAttachment objects and DeletedFinalStateUnknown tombstones.
func volumeAttachmentFromDelete(obj interface{}) (*storagev1.VolumeAttachment, bool) {
	switch deleted := obj.(type) {
	case *storagev1.VolumeAttachment:
		return deleted, true
	case cache.DeletedFinalStateUnknown:
		va, ok := deleted.Obj.(*storagev1.VolumeAttachment)
		return va, ok
	default:
		return nil, false
	}
}

// extractArrayID extracts the PowerStore array ID from the volumeHandle
// volumeHandle format is typically: "volumeID/arrayID" or "volumeID/arrayID/protocol"
// Returns empty string if arrayID is not present
func extractArrayID(volumeHandle string) string {
	if volumeHandle == "" {
		return ""
	}

	// Split on "/" and take the second part as the array ID
	// This handles both formats: "volumeID/arrayID" and "volumeID/arrayID/protocol"
	parts := strings.Split(volumeHandle, "/")
	if len(parts) > 1 && parts[1] != "" {
		return parts[1]
	}

	return ""
}

// extractVolumeIDFromPV extracts the volume ID from a PersistentVolume object
func extractVolumeIDFromPV(pv *corev1.PersistentVolume) string {
	if pv == nil || pv.Spec.CSI == nil {
		return ""
	}
	return extractVolumeID(pv.Spec.CSI.VolumeHandle)
}

// RefreshCache fetches and caches all PVs with field selector (implements VolumeValidator interface)
func (c *K8sMetadataChecker) RefreshCache(ctx context.Context) error {
	return c.fetchAndCachePVs(ctx)
}

// GetProtocol returns the actual protocol string for a volume (implements ProtocolResolver interface)
// Returns the cached protocol string from PV VolumeAttributes, or "unknown" if not found
// Supports both volume ID and volume name lookups (for file system name matching)
// Handles pending deletion case where PV is deleted but DeleteVolume operation is in progress
func (c *K8sMetadataChecker) GetProtocol(_ context.Context, volumeID string) string {
	if c.k8sClient == nil {
		return "unknown"
	}

	if volumeID == "" {
		return "unknown"
	}

	// Extract volume ID from full volume handle (format: "volumeID/arrayID" or "volumeID/arrayID/protocol")
	volumeID = extractVolumeID(volumeID)
	if volumeID == "" {
		return "unknown"
	}

	// Check cache for protocol by volume ID
	c.cacheMu.RLock()
	protocol, exists := c.protocolCache[volumeID]
	c.cacheMu.RUnlock()

	if exists {
		return protocol
	}

	// Check if volume is in pending deletion (PV deleted but DeleteVolume in progress)
	// In this case, the protocol should still be in cache for metrics
	c.pendingMutex.RLock()
	_, inPendingDeletion := c.pendingDeletion[volumeID]
	c.pendingMutex.RUnlock()

	if inPendingDeletion {
		// Protocol should still be in cache, try again with cache lock
		c.cacheMu.RLock()
		protocol, exists = c.protocolCache[volumeID]
		c.cacheMu.RUnlock()

		if exists {
			csmlog.GetLogger().Debugf("K8sMetadataChecker: returning protocol from cache for pending deletion volume %s: %s", volumeID, protocol)
			return protocol
		}
		csmlog.GetLogger().Debugf("K8sMetadataChecker: volume %s in pending deletion but protocol not found in cache", volumeID)
	}

	// If not found by ID, try looking up by name (for file system matching)
	c.cacheMu.RLock()
	nameProtocol, nameExists := c.protocolCache[volumeID] // Note: volumeID here might be a file system name
	c.cacheMu.RUnlock()

	if nameExists {
		return nameProtocol
	}

	// If not in cache, return unknown
	return "unknown"
}

// handleVolumeAttachmentAdd handles VolumeAttachment add events
func (c *K8sMetadataChecker) handleVolumeAttachmentAdd(va *storagev1.VolumeAttachment) {
	csmlog.GetLogger().Infof("K8sMetadataChecker: handleVolumeAttachmentAdd called for %s", va.Name)

	if va.Spec.Attacher != c.driverName {
		return
	}

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	pvName := va.Spec.Source.PersistentVolumeName
	if pvName != nil {
		c.attachmentCache[*pvName] = va.Status.Attached
		csmlog.GetLogger().Debugf("K8sMetadataChecker: cached attachment state for PV %s: %v", *pvName, va.Status.Attached)
	}
}

// handleVolumeAttachmentUpdate handles VolumeAttachment update events
func (c *K8sMetadataChecker) handleVolumeAttachmentUpdate(oldVA, newVA *storagev1.VolumeAttachment) {
	if newVA.Spec.Attacher != c.driverName {
		return
	}

	// Only process if attachment status changed
	if oldVA.Status.Attached == newVA.Status.Attached {
		return
	}

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	pvName := newVA.Spec.Source.PersistentVolumeName
	if pvName != nil {
		c.attachmentCache[*pvName] = newVA.Status.Attached
		csmlog.GetLogger().Debugf("K8sMetadataChecker: updated attachment state for PV %s: %v", *pvName, newVA.Status.Attached)
	}
}

// handleVolumeAttachmentDelete handles VolumeAttachment delete events
func (c *K8sMetadataChecker) handleVolumeAttachmentDelete(va *storagev1.VolumeAttachment) {
	csmlog.GetLogger().Infof("K8sMetadataChecker: handleVolumeAttachmentDelete called for %s", va.Name)

	if va.Spec.Attacher != c.driverName {
		return
	}

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	pvName := va.Spec.Source.PersistentVolumeName
	if pvName != nil {
		delete(c.attachmentCache, *pvName)
		csmlog.GetLogger().Debugf("K8sMetadataChecker: removed attachment state for PV %s", *pvName)
	}
}

// GetAttachmentStateForVolumeID returns the attachment state for a given volume ID
// The globalID is used to validate that the volume belongs to the correct array (multi-array safety)
func (c *K8sMetadataChecker) GetAttachmentStateForVolumeID(_ context.Context, volumeID string, globalID string) (bool, error) {
	if c.k8sClient == nil {
		return false, fmt.Errorf("K8sMetadataChecker: kubernetes client not initialized")
	}

	if volumeID == "" {
		return false, nil
	}

	// Extract volume ID from full volume handle
	volumeID = extractVolumeID(volumeID)
	if volumeID == "" {
		return false, nil
	}

	// Get PV name from cache
	c.cacheMu.RLock()
	pvName, pvExists := c.pvNameCache[volumeID]
	arrayID, arrayExists := c.arrayIDCache[volumeID]
	c.cacheMu.RUnlock()

	if !pvExists {
		return false, fmt.Errorf("volumeID %s not found in PV name cache", volumeID)
	}

	// Validate arrayID matches globalID for multi-array safety
	// Only validate if arrayID is present (some volumeHandles may not include arrayID)
	if arrayExists && arrayID != "" && globalID != "" {
		// Convert globalID format if needed (e.g., "PSc26835c9a0ba" to "c26835c9a0ba")
		// The arrayID in volumeHandle is typically without the "PS" prefix
		// For now, do a simple check - this may need adjustment based on actual format
		if !strings.Contains(arrayID, globalID) && !strings.Contains(globalID, arrayID) {
			csmlog.GetLogger().Debugf("K8sMetadataChecker: volumeID %s arrayID %s does not match globalID %s, skipping", volumeID, arrayID, globalID)
			return false, nil
		}
	}

	// Get attachment state from cache
	c.cacheMu.RLock()
	attached, exists := c.attachmentCache[pvName]
	c.cacheMu.RUnlock()

	if !exists {
		// Assume detached if no VolumeAttachment in cache
		return false, nil
	}

	return attached, nil
}

// GetAttachmentStateForPVName returns the attachment state for a given PV name
func (c *K8sMetadataChecker) GetAttachmentStateForPVName(_ context.Context, pvName string) (bool, error) {
	if c.k8sClient == nil {
		return false, fmt.Errorf("K8sMetadataChecker: kubernetes client not initialized")
	}

	if pvName == "" {
		return false, nil
	}

	// Get attachment state from cache
	c.cacheMu.RLock()
	attached, exists := c.attachmentCache[pvName]
	c.cacheMu.RUnlock()

	if !exists {
		// Assume detached if no VolumeAttachment in cache
		return false, nil
	}

	return attached, nil
}

func isGenericBlockProtocol(protocol string) bool {
	return metricsprotocol.IsGenericBlock(protocol)
}

func resolvePVProtocol(protocol string, nodeAffinity *corev1.VolumeNodeAffinity) string {
	if isGenericBlockProtocol(protocol) {
		return extractProtocolFromNodeAffinity(nodeAffinity)
	}
	normalized := metricsprotocol.Normalize(protocol)
	if normalized == metricsprotocol.Unknown {
		return ""
	}
	return normalized
}

// extractProtocolFromNodeAffinity determines the protocol from nodeAffinity labels
// This is used as a fallback when VolumeAttributes.Protocol is invalid or missing
// Labels follow the pattern: csi-powerstore.dellemc.com/<array-ip>-<protocol>
func extractProtocolFromNodeAffinity(nodeAffinity *corev1.VolumeNodeAffinity) string {
	protocol := metricsprotocol.FromNodeAffinity(nodeAffinity)
	if protocol == metricsprotocol.Unknown {
		return ""
	}
	return protocol
}
