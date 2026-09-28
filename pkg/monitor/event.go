/*
 *
 * Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package monitor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	log "github.com/dell/csmlog"
	"github.com/dell/gopowerstore"
	"github.com/prometheus/client_golang/prometheus"

	csictx "github.com/dell/gocsi/context"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	typedv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

type IMonitorService interface {
	// Reads the array secret from the filepath and populates array.Locker
	// with array info and API clients.
	UpdateArrays(arrayConfigFilepath string, fs fs.Interface, metricsRegistry ...prometheus.Registerer) error
	// Sets the arrays to monitor
	SetArrays(arrays map[string]*array.PowerStoreArray)
	// Sets the default array
	SetDefaultArray(defaultArray *array.PowerStoreArray)
	// Starts the service, polling for PowerStore Alerts and Events
	// every pollPeriod.
	Start(ctx context.Context, pollPeriod time.Duration)
}

// Service represents the volume event monitoring service
type Service struct {
	EventRecorder    record.EventRecorderLogger
	EventBroadcaster record.EventBroadcaster

	array.Locker

	kubeclient *k8sutils.K8sClient

	// Event-based fields
	pvInformer      cache.SharedIndexInformer
	eventInformer   cache.SharedIndexInformer
	informerFactory informers.SharedInformerFactory
	stopCh          chan struct{}
	stopOnce        sync.Once
	handlersOnce    sync.Once

	// Local cache (replaces polling)
	volumeCache      map[string]PersistentVolumeEvent
	cacheInitialized bool
	cacheMu          sync.RWMutex

	// apiTimeout is the context timeout for PowerStore API calls, parsed once at Start.
	apiTimeout time.Duration
}

type EventContent struct {
	// LastRecord is a reference to the most recent Kubernetes
	// event for a specific resource
	LatestRecord *corev1.Event
}

// PersistentVolumeEvent relates a Persistent Volume struct to its
// most recent Kubernetes event.
type PersistentVolumeEvent struct {
	EventContent

	Volume corev1.PersistentVolume
}

const (
	timeFormat         = "2006-01-02T15:04:05Z"
	VolumeResourceType = "volume"
)

// NewMonitorService creates a new monitor service.
// The Kubernetes client is created using the environment var, identifiers.EnvKubeConfigPath,
// or in-cluster config, and used to create the EventRecorder and EventBroadcaster.
func NewMonitorService(ctx context.Context) (IMonitorService, error) {
	kubeConfigPath, _ := csictx.LookupEnv(ctx, identifiers.EnvKubeConfigPath)
	kubeclient, err := k8sutils.CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes API client for the monitor service: %s", err.Error())
	}

	eventRecorder, eventBroadcaster, err := newEventRecorder(kubeclient)
	if err != nil {
		return nil, err
	}

	// Create informer factory for event-based monitoring
	informerFactory := informers.NewSharedInformerFactory(kubeclient.Clientset, 0)

	return &Service{
		EventRecorder:    eventRecorder,
		EventBroadcaster: eventBroadcaster,
		kubeclient:       kubeclient,

		// Initialize informers and cache
		informerFactory: informerFactory,
		pvInformer:      informerFactory.Core().V1().PersistentVolumes().Informer(),
		eventInformer:   informerFactory.Core().V1().Events().Informer(),
		stopCh:          make(chan struct{}),
		volumeCache:     make(map[string]PersistentVolumeEvent),
	}, nil
}

func (s *Service) ensureInformerSetup() bool {
	if s.volumeCache == nil {
		s.volumeCache = make(map[string]PersistentVolumeEvent)
	}
	if s.stopCh == nil {
		s.stopCh = make(chan struct{})
	}
	if s.kubeclient == nil || s.kubeclient.Clientset == nil {
		return false
	}
	if s.informerFactory == nil {
		s.informerFactory = informers.NewSharedInformerFactory(s.kubeclient.Clientset, 0)
	}
	if s.pvInformer == nil {
		s.pvInformer = s.informerFactory.Core().V1().PersistentVolumes().Informer()
	}
	if s.eventInformer == nil {
		s.eventInformer = s.informerFactory.Core().V1().Events().Informer()
	}
	return true
}

func newEventRecorder(kubeclient *k8sutils.K8sClient) (record.EventRecorderLogger, record.EventBroadcaster, error) {
	eventBroadcaster := record.NewBroadcaster()

	eventBroadcaster.StartRecordingToSink(&typedv1core.EventSinkImpl{Interface: kubeclient.Clientset.CoreV1().Events("")})

	scheme := runtime.NewScheme()
	err := corev1.AddToScheme(scheme)
	if err != nil {
		return nil, nil, err
	}

	eventRecorder := eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: identifiers.Name})

	return eventRecorder, eventBroadcaster, nil
}

// updateVolumeCache updates the local cache when a PV changes.
// Only PVs provisioned by this CSI driver are cached.
func (s *Service) updateVolumeCache(pv *corev1.PersistentVolume) {
	// Filter: only include PVs provisioned by this CSI driver
	if pv.Spec.CSI == nil || pv.Spec.CSI.Driver != identifiers.Name {
		return
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	existing, exists := s.volumeCache[pv.Name]
	if !exists {
		// New PV - get its latest event
		latestEvent := s.getLatestEventFromCache(pv.Name, pv.Namespace, "PersistentVolume")
		s.volumeCache[pv.Name] = PersistentVolumeEvent{
			Volume: *pv,
			EventContent: EventContent{
				LatestRecord: latestEvent,
			},
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
			log.FieldOperation: "VolumeCache",
			"pv_name":          pv.Name,
			"cache_size":       len(s.volumeCache),
		}).Info("PV added to cache via informer")
	} else {
		// Existing PV - update volume data, preserve event
		s.volumeCache[pv.Name] = PersistentVolumeEvent{
			Volume:       *pv,
			EventContent: existing.EventContent,
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
			log.FieldOperation: "VolumeCache",
			"pv_name":          pv.Name,
		}).Debug("PV updated in cache via informer")
	}
}

// removeVolumeCache removes a PV from the local cache
func (s *Service) removeVolumeCache(pvName string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	delete(s.volumeCache, pvName)
	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "VolumeCache",
		"pv_name":          pvName,
		"cache_size":       len(s.volumeCache),
	}).Info("PV removed from cache via informer")
}

// updateEventCache updates the event cache when a K8s event changes
func (s *Service) updateEventCache(event *corev1.Event) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	// Only process PersistentVolume events
	if event.InvolvedObject.Kind != "PersistentVolume" {
		return
	}

	pvName := event.InvolvedObject.Name
	if existing, exists := s.volumeCache[pvName]; exists {
		// Update if this event is newer
		if existing.LatestRecord == nil || event.LastTimestamp.After(existing.LatestRecord.LastTimestamp.Time) {
			s.volumeCache[pvName] = PersistentVolumeEvent{
				Volume: existing.Volume,
				EventContent: EventContent{
					LatestRecord: event,
				},
			}
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "EventCache",
				"pv_name":          pvName,
				"event_reason":     event.Reason,
			}).Debug("Event updated in cache via informer")
		}
	}
}

// removeEventCache handles event deletion
func (s *Service) removeEventCache(event *corev1.Event) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	if event.InvolvedObject.Kind != "PersistentVolume" {
		return
	}

	pvName := event.InvolvedObject.Name
	if existing, exists := s.volumeCache[pvName]; exists {
		// If this was the latest event, we need to fetch the new latest
		if existing.LatestRecord != nil && existing.LatestRecord.UID == event.UID {
			// Fetch latest event from cache or API
			latestEvent := s.getLatestEventFromCache(pvName, existing.Volume.Namespace, "PersistentVolume")
			s.volumeCache[pvName] = PersistentVolumeEvent{
				Volume: existing.Volume,
				EventContent: EventContent{
					LatestRecord: latestEvent,
				},
			}
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "EventCache",
				"pv_name":          pvName,
			}).Debug("Event removed from cache, fetched new latest event")
		}
	}
}

// getLatestEventFromCache gets the latest event from the event informer cache
func (s *Service) getLatestEventFromCache(name, namespace, kind string) *corev1.Event {
	if s.eventInformer == nil {
		return nil
	}

	// List all events from the informer cache
	eventList := s.eventInformer.GetIndexer().List()

	var latestEvent *corev1.Event
	for _, obj := range eventList {
		event, ok := obj.(*corev1.Event)
		if !ok {
			continue
		}

		// Filter by involved object
		if event.InvolvedObject.Kind != kind || event.InvolvedObject.Name != name {
			continue
		}
		if namespace != "" && event.InvolvedObject.Namespace != namespace {
			continue
		}

		if latestEvent == nil || event.LastTimestamp.After(latestEvent.LastTimestamp.Time) {
			latestEvent = event
		}
	}

	return latestEvent
}

// populateInitialCache populates the cache with existing PVs and events
func (s *Service) populateInitialCache(_ context.Context) {
	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "CacheInit",
	}).Info("populating initial cache from informers")

	// Get all PVs from informer cache
	pvList := s.pvInformer.GetIndexer().List()

	for _, obj := range pvList {
		pv, ok := obj.(*corev1.PersistentVolume)
		if !ok {
			continue
		}
		s.updateVolumeCache(pv)
	}

	s.cacheMu.Lock()
	s.cacheInitialized = true
	cacheSize := len(s.volumeCache)
	s.cacheMu.Unlock()

	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "CacheInit",
		"cache_size":       cacheSize,
	}).Info("initial cache populated from informers")
}

// Stop stops the monitor service and cleans up resources
func (s *Service) Stop() {
	s.stopOnce.Do(func() {
		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
		}).Info("stopping event-based monitor")
		if s.stopCh != nil {
			close(s.stopCh)
		}
		if s.informerFactory != nil {
			s.informerFactory.Shutdown()
		}
		if s.EventBroadcaster != nil {
			s.EventBroadcaster.Shutdown()
		}
	})
}

func persistentVolumeFromDelete(obj interface{}) (*corev1.PersistentVolume, bool) {
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

func eventFromDelete(obj interface{}) (*corev1.Event, bool) {
	switch deleted := obj.(type) {
	case *corev1.Event:
		return deleted, true
	case cache.DeletedFinalStateUnknown:
		event, ok := deleted.Obj.(*corev1.Event)
		return event, ok
	default:
		return nil, false
	}
}

// setupPVInformer sets up event handlers for PV changes
func (s *Service) setupPVInformer() {
	_, _ = s.pvInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pv, ok := obj.(*corev1.PersistentVolume)
			if !ok {
				return
			}
			s.updateVolumeCache(pv)
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "PVInformer",
				"pv_name":          pv.Name,
			}).Info("PV added via informer")
		},
		UpdateFunc: func(_, newObj interface{}) {
			newPV, ok := newObj.(*corev1.PersistentVolume)
			if !ok {
				return
			}
			s.updateVolumeCache(newPV)
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "PVInformer",
				"pv_name":          newPV.Name,
			}).Debug("PV updated via informer")
		},
		DeleteFunc: func(obj interface{}) {
			pv, ok := persistentVolumeFromDelete(obj)
			if !ok {
				return
			}
			s.removeVolumeCache(pv.Name)
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "PVInformer",
				"pv_name":          pv.Name,
			}).Info("PV deleted via informer")
		},
	})
}

// setupEventInformer sets up event handlers for K8s events
func (s *Service) setupEventInformer() {
	_, _ = s.eventInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			event, ok := obj.(*corev1.Event)
			if !ok {
				return
			}
			s.updateEventCache(event)
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "EventInformer",
				"event_reason":     event.Reason,
				"resource_name":    event.InvolvedObject.Name,
			}).Debug("K8s event added via informer")
		},
		UpdateFunc: func(_, newObj interface{}) {
			newEvent, ok := newObj.(*corev1.Event)
			if !ok {
				return
			}
			s.updateEventCache(newEvent)
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "EventInformer",
				"event_reason":     newEvent.Reason,
				"resource_name":    newEvent.InvolvedObject.Name,
			}).Debug("K8s event updated via informer")
		},
		DeleteFunc: func(obj interface{}) {
			event, ok := eventFromDelete(obj)
			if !ok {
				return
			}
			s.removeEventCache(event)
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "EventInformer",
				"event_reason":     event.Reason,
				"resource_name":    event.InvolvedObject.Name,
			}).Debug("K8s event deleted via informer")
		},
	})
}

// Start starts monitoring volumes and logging kubernetes events for alerts
// associated with Persistent Volumes backed by the PowerStore array(s).
func (s *Service) Start(ctx context.Context, pollPeriod time.Duration) {
	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "Start",
		"poll_period":      pollPeriod,
	}).Info("starting event-based monitor")

	// Parse API timeout once (default: 120 seconds)
	s.apiTimeout = 120 * time.Second
	if timeoutStr, ok := csictx.LookupEnv(ctx, identifiers.EnvPowerstoreAPITimeout); ok {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil && timeout > 0 {
			s.apiTimeout = timeout
		} else if err != nil {
			log.Warnf("invalid %s value %q, using default %s", identifiers.EnvPowerstoreAPITimeout, timeoutStr, s.apiTimeout)
		} else {
			log.Warnf("%s value %q is not positive, using default %s", identifiers.EnvPowerstoreAPITimeout, timeoutStr, s.apiTimeout)
		}
	}

	if !s.ensureInformerSetup() {
		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
			log.FieldOperation: "Start",
		}).Error("failed to initialize informers: kubernetes client is unavailable")
		return
	}

	// Set up informers for event-based monitoring
	s.handlersOnce.Do(func() {
		s.setupPVInformer()
		s.setupEventInformer()
	})

	// Start informers
	defer s.Stop()
	go func() {
		<-ctx.Done()
		s.Stop()
	}()
	s.informerFactory.Start(s.stopCh)

	// Wait for cache sync
	if !cache.WaitForCacheSync(s.stopCh, s.pvInformer.HasSynced, s.eventInformer.HasSynced) {
		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
			log.FieldOperation: "Start",
		}).Error("failed to sync informer caches")
		return
	}

	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "Start",
	}).Info("informer caches synced successfully")

	// Perform initial cache population
	s.populateInitialCache(ctx)

	// Keep the same polling logic for PowerStore alerts, but use cache instead of polling Kubernetes
	lastCheck := time.Now()
	ticker := time.NewTicker(pollPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.WithFields(log.Fields{
				log.FieldComponent: "monitor",
				log.FieldOperation: "Start",
				"error":            ctx.Err(),
			}).Debug("context expired for volume event monitor")
			return
		case now := <-ticker.C:
			s.monitorSince(lastCheck)
			lastCheck = now
		}
	}
}

// monitorSince queries all PowerStore arrays for alerts that
// have occurred between now and the lastTime the function was run, and processes
// any new alerts, creating kubernetes events, as needed.
func (s *Service) monitorSince(lastTime time.Time) {
	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "MonitorSince",
		"last_check":       lastTime,
	}).Debug("Getting alerts and events since last check")

	ctx, cancel := context.WithTimeout(context.Background(), s.apiTimeout)
	defer cancel()

	for _, arr := range s.Arrays() {
		alerts := []gopowerstore.Alert{}

		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
			log.FieldOperation: "MonitorSince",
			"array_id":         arr.GlobalID,
		}).Debug("Getting latest alerts for array")

		pageIndex := 0
		for {
			// get alerts since the last time they were read,
			// reading until there are no more pages of alerts available
			alertsResp, err := arr.GetClient().GetAlerts(ctx, gopowerstore.GetAlertsOpts{
				Queries: map[string]string{
					"generated_timestamp": fmt.Sprintf("gte.%s", lastTime.Format(timeFormat)),
					"order":               "generated_timestamp.asc",
				},
				RequestPagination: gopowerstore.RequestPagination{
					PageSize:   1000,
					StartIndex: pageIndex,
				},
			})
			if err != nil {
				log.WithFields(log.Fields{
					log.FieldComponent: "monitor",
					log.FieldOperation: "MonitorSince",
					"array_id":         arr.GlobalID,
					"error":            err,
				}).Error("failed to get alerts for array")
				return
			}
			alerts = append(alerts, alertsResp.Alerts...)
			if alertsResp.Pagination.Next == 0 {
				break
			}
			pageIndex = alertsResp.Pagination.Next
		}

		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
			log.FieldOperation: "MonitorSince",
			"array_id":         arr.GlobalID,
			"alert_count":      len(alerts),
		}).Debug("got alerts from array")
		s.processVolumeObjectEvents(ctx, alerts)
	}
}

// processVolumeObjectEvents steps through the provided PowerStore alerts,
// looking for alerts associated with Persistent Volumes (PVs) in the cluster.
// If alerts are found for a given PV, an event is logged with the event recorder.
// Alerts passed in should be sorted in ascending order to ensure they are recorded
// in the order they occurred on the PowerStore array.
func (s *Service) processVolumeObjectEvents(ctx context.Context, alerts gopowerstore.Alerts) {
	persistentVolumes := s.createVolumeMap(ctx)

	// Cache latest event lookups per volume within a single poll cycle
	// to avoid redundant API/cache calls when multiple alerts reference the same volume.
	latestEventCache := make(map[string]*corev1.Event)

	for _, alert := range alerts {
		// currently only monitoring alerts for "volume" type
		if alert.ResourceType != VolumeResourceType {
			continue
		}

		event, found := persistentVolumes[alert.ResourceName]
		if !found {
			// skip recording if the PowerStore alert does not belong to any of the Persistent Volumes
			continue
		}

		// Only fetch the latest K8s event for volumes that have an associated alert,
		// rather than for every volume in the cluster, to avoid excessive API calls.
		// Cache results so each volume is queried at most once per poll cycle.
		latestEvent, cached := latestEventCache[event.Volume.Name]
		if !cached {
			latestEvent = s.getLatestK8sEvent(ctx, event.Volume.Name, event.Volume.Namespace, "PersistentVolume")
			latestEventCache[event.Volume.Name] = latestEvent
		}

		// Do not record the same event twice.
		if latestEvent != nil && latestEvent.Message == alert.Description {
			continue
		}

		eventType := corev1.EventTypeWarning
		if strings.EqualFold(alert.Severity, "info") {
			eventType = corev1.EventTypeNormal
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
			log.FieldOperation: "ProcessEvent",
			"volume_name":      event.Volume.Name,
			"alert_severity":   alert.Severity,
			"alert_message":    alert.Description,
		}).Info("Alert is active for volume, recording Kubernetes event")
		s.EventRecorder.Event(&event.Volume, eventType, alert.Severity, alert.Description)

		// Update the cache so subsequent alerts for the same volume in this
		// poll cycle can dedup against the event we just recorded.
		latestEventCache[event.Volume.Name] = &corev1.Event{
			Message: alert.Description,
		}
	}
}

// createVolumeMap returns a map of Persistent Volume names to their PersistentVolumeEvents,
// where a PersistentVolumeEvent contains a reference to the PersistentVolume and the most
// recently recorded event for that volume (if one exists).
// Now uses local cache instead of polling Kubernetes API.
func (s *Service) createVolumeMap(ctx context.Context) map[string]PersistentVolumeEvent {
	s.cacheMu.RLock()
	cacheInitialized := s.cacheInitialized
	if cacheInitialized {
		result := make(map[string]PersistentVolumeEvent, len(s.volumeCache))
		for k, v := range s.volumeCache {
			result[k] = v
		}
		s.cacheMu.RUnlock()

		log.WithFields(log.Fields{
			log.FieldComponent: "monitor",
			log.FieldOperation: "VolumeDiscovery",
			"pv_count":         len(result),
			"source":           "cache",
		}).Info("enumerated persistent volumes from cache")

		return result
	}
	s.cacheMu.RUnlock()

	volumes, err := s.kubeclient.ListPersistentVolumes(ctx)
	if err != nil {
		log.Errorf("[Monitor] failed to get persistent volumes: %s", err.Error())
		return nil
	}

	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "VolumeDiscovery",
		"pv_count":         len(volumes.Items),
		"source":           "api",
	}).Info("enumerated persistent volumes from Kubernetes")

	volumesMap := make(map[string]PersistentVolumeEvent)
	for _, volume := range volumes.Items {
		// Filter: only include PVs provisioned by this CSI driver
		if volume.Spec.CSI == nil || volume.Spec.CSI.Driver != identifiers.Name {
			continue
		}
		volumesMap[volume.Name] = PersistentVolumeEvent{
			Volume: volume,
		}
	}

	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "VolumeDiscovery",
		"filtered_count":   len(volumesMap),
	}).Debug("filtered to PowerStore volumes")

	return volumesMap
}

func (s *Service) getLatestK8sEvent(ctx context.Context, name, namespace, kind string) *corev1.Event {
	s.cacheMu.RLock()
	cacheInitialized := s.cacheInitialized
	s.cacheMu.RUnlock()
	if cacheInitialized {
		return s.getLatestEventFromCache(name, namespace, kind)
	}

	events, err := s.kubeclient.GetEvents(ctx, kind, name, namespace)
	if err != nil {
		log.Errorf("[Monitor] failed to get kubernetes events for %s %q: %s", kind, name, err.Error())
		return nil
	}

	if len(events.Items) == 0 {
		return nil
	}

	latestEvent := events.Items[0]
	for _, event := range events.Items {
		if event.LastTimestamp.After(latestEvent.LastTimestamp.Time) {
			latestEvent = event
		}
	}

	log.WithFields(log.Fields{
		log.FieldComponent: "monitor",
		log.FieldOperation: "EventDiscovery",
		"resource_name":    name,
		"resource_kind":    kind,
		"source":           "api",
	}).Debug("retrieved latest Kubernetes event from API")

	return &latestEvent
}
