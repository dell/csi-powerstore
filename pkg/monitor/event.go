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
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csmlog"
	"github.com/dell/gopowerstore"

	csictx "github.com/dell/gocsi/context"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	typedv1core "k8s.io/client-go/kubernetes/typed/core/v1"

	"k8s.io/client-go/tools/record"
)

type IMonitorService interface {
	// Reads the array secret from the filepath and populates array.Locker
	// with array info and API clients.
	UpdateArrays(arrayConfigFilepath string, fs fs.Interface) error
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

// Instantiate csmlog on a package level
var log = csmlog.GetLogger()

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

	return &Service{
		EventRecorder:    eventRecorder,
		EventBroadcaster: eventBroadcaster,

		kubeclient: kubeclient,
	}, nil
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

// Start starts monitoring volumes and logging kubernetes events for alerts
// associated with Persistent Volumes backed by the PowerStore array(s).
func (s *Service) Start(ctx context.Context, pollPeriod time.Duration) {
	log.Infof("[Monitor] starting event monitor with poll period %s", pollPeriod)
	ticker := time.NewTicker(pollPeriod).C

	defer s.EventBroadcaster.Shutdown()
	// assumes events have already been recorded for pre-existing volumes
	// in order to avoid recording very old events.
	lastCheck := time.Now()
	for {
		select {
		case <-ctx.Done():
			log.Debugf("[Monitor] context expired for volume event monitor: %s", ctx.Err())
			return
		case now := <-ticker:
			s.monitorSince(lastCheck)
			lastCheck = now
		}
	}
}

// monitorSince queries all PowerStore arrays for alerts that
// have occurred between now and the lastTime the function was run, and processes
// any new alerts, creating kubernetes events, as needed.
func (s *Service) monitorSince(lastTime time.Time) {
	log.Debugf("[Monitor] Getting alerts and events since %s", lastTime)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, arr := range s.Locker.Arrays() {
		alerts := []gopowerstore.Alert{}

		log.Debugf("[Monitor] Getting latest alerts for array %q", arr.GlobalID)
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
				log.Errorf("[Monitor] failed to get alerts for array %q: %s", arr.GlobalID, err)
				return
			}
			alerts = append(alerts, alertsResp.Alerts...)
			if alertsResp.Pagination.Next == 0 {
				break
			}
			pageIndex = alertsResp.Pagination.Next
		}

		log.Debugf("[Monitor] got alerts: %v", alerts)
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

		// Do not record the same event twice.
		if event.LatestRecord != nil && event.LatestRecord.Message == alert.Description {
			continue
		}

		eventType := corev1.EventTypeWarning
		if strings.EqualFold(alert.Severity, "info") {
			eventType = corev1.EventTypeNormal
		}
		log.Infof("[Monitor] Alert is active for volume %q. recording event: %s", event.Volume.Name, alert.Description)
		s.EventRecorder.Event(&event.Volume, eventType, alert.Severity, alert.Description)
	}
}

// createVolumeMap returns a map of Persistent Volume names to their PersistentVolumeEvents,
// where a PersistentVolumeEvent contains a reference to the PersistentVolume and the most
// recently recorded event for that volume (if one exists).
func (s *Service) createVolumeMap(ctx context.Context) map[string]PersistentVolumeEvent {
	volumes, err := s.kubeclient.ListPersistentVolumes(ctx)
	if err != nil {
		log.Errorf("[Monitor] failed to get persistent volumes: %s", err.Error())
		return nil
	}

	log.Debugf("[Monitor] got persistent volumes: %v", volumes.Items)

	// Create map to easily navigate through volumes.
	volumesMap := make(map[string]PersistentVolumeEvent)
	for _, volume := range volumes.Items {
		latestObjectEvent := s.getLatestK8sEvent(ctx, volume.Name, volume.Namespace, "PersistentVolume")
		log.Debugf("[Monitor] got latest event for volume %q: %v", volume.Name, latestObjectEvent)
		volumesMap[volume.Name] = PersistentVolumeEvent{
			Volume: volume,
			EventContent: EventContent{
				LatestRecord: latestObjectEvent,
			},
		}
	}

	return volumesMap
}

// getLatestK8sEvent queries the cluster for all events related to the resource, "kind", of the given
// name, in the namespace provided, and returns the latest event.
func (s *Service) getLatestK8sEvent(ctx context.Context, name, namespace, kind string) *corev1.Event {
	events, err := s.kubeclient.GetEvents(ctx, kind, name, namespace)
	if err != nil {
		log.Errorf("[Monitor] failed to get kubernetes events for %s %q: %s", kind, name, err.Error())
		return nil
	}
	log.Debugf("[Monitor] got kubernetes events for %s %q: %v", kind, name, events.Items)

	if len(events.Items) == 0 {
		return nil
	}

	// Retrieval of Events from a k8sObject is not guaranteed to be sorted.
	latestEvent := events.Items[0]
	for _, event := range events.Items {
		if event.LastTimestamp.After(latestEvent.LastTimestamp.Time) {
			latestEvent = event
		}
	}

	log.Debugf("[Monitor] latest k8s event for %s %q: description: %s", kind, name, latestEvent.Message)

	return &latestEvent
}
