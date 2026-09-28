/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

	metricsprotocol "github.com/dell/csi-powerstore/v2/pkg/metrics/protocol"
	"github.com/dell/csm-metrics-common/pkg/naming"
	"github.com/dell/csmlog"
	"github.com/dell/gopowerstore"
	"github.com/prometheus/client_golang/prometheus"
)

// VolumeCollector collects PowerStore volume count, size, attachment, and health metrics.
// Note: Volume performance metrics (IOPS, bandwidth, latency) are handled by csm-metrics-powerstore.
type VolumeCollector struct {
	client           VolumeClient
	globalID         string
	metadata         VolumeMetadataProvider
	volumeTotal      *prometheus.GaugeVec
	volumeSizeDist   *prometheus.GaugeVec
	nvmeVolumeTotal  *prometheus.GaugeVec
	attachmentStatus *prometheus.GaugeVec
	unhealthyTotal   *prometheus.GaugeVec
	lastAttached     map[string]float64 // protocol -> last successful attached count (for best-effort semantics)
	lastDetached     map[string]float64 // protocol -> last successful detached count (for best-effort semantics)
	metadataSuccess  bool               // whether the last metadata refresh succeeded
}

func normalizeVolumeProtocol(protocol string) string {
	return metricsprotocol.Normalize(protocol)
}

// NewVolumeCollector creates a new VolumeCollector.
func NewVolumeCollector(client VolumeClient, reg prometheus.Registerer, globalID string, metadata VolumeMetadataProvider) (*VolumeCollector, error) {
	volumeTotal, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: naming.MetricCSIVolumeTotal,
		Help: "Total number of CSI-managed volumes per protocol.",
	}, []string{"global_id", "protocol"}), naming.MetricCSIVolumeTotal)
	if err != nil {
		return nil, err
	}
	volumeSizeDist, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_volume_size_distribution_bytes",
		Help: "Distribution of CSI volume sizes in bytes represented as cumulative bucket gauges.",
	}, []string{"global_id", "protocol", "bucket"}), "dell_powerstore_volume_size_distribution_bytes")
	if err != nil {
		return nil, err
	}
	nvmeVolumeTotal, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_nvme_volume_total",
		Help: "Total number of NVMe volumes per transport.",
	}, []string{"global_id", "transport"}), "dell_powerstore_nvme_volume_total")
	if err != nil {
		return nil, err
	}
	attachmentStatus, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_volume_attachment_status_total",
		Help: "Total number of CSI volumes by attachment status and protocol.",
	}, []string{"global_id", "protocol", "status"}), "dell_powerstore_volume_attachment_status_total")
	if err != nil {
		return nil, err
	}
	unhealthyTotal, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_volume_unhealthy_total",
		Help: "Total number of unhealthy CSI volumes per protocol.",
	}, []string{"global_id", "protocol"}), "dell_powerstore_volume_unhealthy_total")
	if err != nil {
		return nil, err
	}

	return &VolumeCollector{
		client:           client,
		globalID:         globalID,
		metadata:         metadata,
		volumeTotal:      volumeTotal,
		volumeSizeDist:   volumeSizeDist,
		nvmeVolumeTotal:  nvmeVolumeTotal,
		attachmentStatus: attachmentStatus,
		unhealthyTotal:   unhealthyTotal,
		lastAttached:     make(map[string]float64),
		lastDetached:     make(map[string]float64),
		metadataSuccess:  true,
	}, nil
}

// NewVolumeCollectorWithClient creates a new VolumeCollector with a gopowerstore.Client
// This is a convenience function that wraps the gopowerstore.Client in an adapter
func NewVolumeCollectorWithClient(client gopowerstore.Client, reg prometheus.Registerer, globalID string, metadata VolumeMetadataProvider) (*VolumeCollector, error) {
	adapter := &gopowerstoreVolumeAdapter{client: client}
	return NewVolumeCollector(adapter, reg, globalID, metadata)
}

// Collect fetches volume metrics.
func (c *VolumeCollector) Collect(ctx context.Context) error {
	// Refresh metadata cache (in production, this is K8sMetadataChecker which also implements ProtocolResolver
	// and refreshes the protocol cache as part of RefreshCache)
	metadataRefreshFailed := false
	if c.metadata != nil {
		if err := c.metadata.RefreshCache(ctx); err != nil {
			metadataRefreshFailed = true
			csmlog.GetLogger().Warnf("VolumeCollector: failed to refresh metadata cache: %v, using last known values for attachment metrics", err)
		}
	}

	volumes, err := c.client.GetVolumes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get volumes: %w", err)
	}
	fileSystems, err := c.client.ListFS(ctx)
	if err != nil {
		return fmt.Errorf("failed to get file systems: %w", err)
	}

	protocolCounts := make(map[string]int)
	nvmeTransportCounts := make(map[string]int)
	attachedCounts := make(map[string]int)
	unhealthyCounts := make(map[string]int)
	sizeBucketCounts := make(map[string]map[string]int)
	knownProtocols := []string{"iSCSI", "FC", "NVMeTCP", "NVMeFC", "NFS", "unknown"}
	knownBuckets := []struct {
		label string
		upper int64
	}{
		{label: "<=1GiB", upper: 1 << 30},
		{label: "<=5GiB", upper: 5 << 30},
		{label: "<=10GiB", upper: 10 << 30},
		{label: "<=50GiB", upper: 50 << 30},
		{label: "<=100GiB", upper: 100 << 30},
		{label: "<=500GiB", upper: 500 << 30},
		{label: "<=1TiB", upper: 1 << 40},
		{label: ">1TiB", upper: -1},
	}

	for _, vol := range volumes {
		if c.metadata != nil {
			isManaged, err := c.metadata.IsDriverManaged(ctx, vol.ID)
			if err != nil {
				csmlog.GetLogger().Warnf("VolumeCollector: failed to check if volume %s is driver managed: %v, skipping", vol.ID, err)
				continue
			}
			if !isManaged {
				continue
			}
		}

		// Get protocol from metadata
		protocol := "unknown"
		if c.metadata != nil {
			protocol = c.metadata.GetProtocol(ctx, vol.ID)
		}
		protocol = normalizeVolumeProtocol(protocol)

		// Derive NVMe transport from resolved protocol
		if protocol == "NVMeTCP" || protocol == "NVMeFC" {
			nvmeTransportCounts[protocol]++
		}

		protocolCounts[protocol]++

		if _, ok := sizeBucketCounts[protocol]; !ok {
			sizeBucketCounts[protocol] = make(map[string]int, len(knownBuckets))
		}
		for _, bucket := range knownBuckets {
			if bucket.upper < 0 || vol.Size <= bucket.upper {
				sizeBucketCounts[protocol][bucket.label]++
			}
		}

		// Use VolumeAttachment for attachment state
		isAttached := false
		attachmentLookupFailed := false
		if c.metadata != nil {
			attached, err := c.metadata.GetAttachmentStateForVolumeID(ctx, vol.ID, c.globalID)
			if err == nil {
				isAttached = attached
			} else {
				attachmentLookupFailed = true
				csmlog.GetLogger().Debugf("VolumeCollector: failed to get attachment state for volume %s: %v, using last known state", vol.ID, err)
			}
		}

		if isAttached {
			attachedCounts[protocol]++
		}

		// If any attachment lookup failed, mark metadata as failed for this scrape
		if attachmentLookupFailed {
			metadataRefreshFailed = true
		}

		if vol.State != gopowerstore.VolumeStateEnumReady {
			unhealthyCounts[protocol]++
		}
	}

	for _, fs := range fileSystems {
		// For file systems, match by name instead of ID since file system names match PV names
		if c.metadata != nil {
			isManaged, err := c.metadata.IsDriverManagedByName(ctx, fs.Name)
			if err != nil {
				csmlog.GetLogger().Warnf("VolumeCollector: failed to check if file system %s is driver managed: %v, skipping", fs.Name, err)
				continue
			}
			if !isManaged {
				continue
			}
		}

		protocol := "NFS"
		if c.metadata != nil {
			// For file systems, use volume name for protocol resolution since names match PV names
			if resolved := normalizeVolumeProtocol(c.metadata.GetProtocol(ctx, fs.Name)); resolved != "unknown" {
				protocol = resolved
			}
		}

		protocolCounts[protocol]++

		if _, ok := sizeBucketCounts[protocol]; !ok {
			sizeBucketCounts[protocol] = make(map[string]int, len(knownBuckets))
		}
		for _, bucket := range knownBuckets {
			if bucket.upper < 0 || fs.SizeTotal <= bucket.upper {
				sizeBucketCounts[protocol][bucket.label]++
			}
		}

		// Use VolumeAttachment for file systems too
		isAttached := false
		if c.metadata != nil {
			attached, err := c.metadata.GetAttachmentStateForPVName(ctx, fs.Name)
			if err == nil {
				isAttached = attached
			} else {
				metadataRefreshFailed = true
				csmlog.GetLogger().Debugf("VolumeCollector: failed to get attachment state for file system %s: %v, using last known state", fs.Name, err)
			}
		}

		if isAttached {
			attachedCounts[protocol]++
		}
	}

	for _, protocol := range knownProtocols {
		c.volumeTotal.DeleteLabelValues(c.globalID, protocol)
		c.unhealthyTotal.DeleteLabelValues(c.globalID, protocol)
		for _, bucket := range knownBuckets {
			c.volumeSizeDist.DeleteLabelValues(c.globalID, protocol, bucket.label)
		}
	}
	for _, transport := range []string{"NVMeTCP", "NVMeFC"} {
		c.nvmeVolumeTotal.DeleteLabelValues(c.globalID, transport)
	}

	for protocol, count := range protocolCounts {
		if count == 0 {
			continue
		}
		c.volumeTotal.WithLabelValues(c.globalID, protocol).Set(float64(count))
		c.unhealthyTotal.WithLabelValues(c.globalID, protocol).Set(float64(unhealthyCounts[protocol]))
		for _, bucket := range knownBuckets {
			c.volumeSizeDist.WithLabelValues(c.globalID, protocol, bucket.label).Set(float64(sizeBucketCounts[protocol][bucket.label]))
		}
	}

	// Update attachment status metrics only if metadata lookup succeeded
	// Otherwise, preserve last known good values (best-effort semantics)
	if !metadataRefreshFailed {
		for _, protocol := range knownProtocols {
			c.attachmentStatus.DeleteLabelValues(c.globalID, protocol, "attached")
			c.attachmentStatus.DeleteLabelValues(c.globalID, protocol, "detached")
		}

		for protocol, count := range protocolCounts {
			if count == 0 {
				continue
			}
			attachedCount := attachedCounts[protocol]
			detachedCount := count - attachedCount
			if detachedCount < 0 {
				detachedCount = 0
			}
			c.attachmentStatus.WithLabelValues(c.globalID, protocol, "attached").Set(float64(attachedCount))
			c.attachmentStatus.WithLabelValues(c.globalID, protocol, "detached").Set(float64(detachedCount))

			// Save last successful values (actual counts)
			c.lastAttached[protocol] = float64(attachedCount)
			c.lastDetached[protocol] = float64(detachedCount)
		}

		c.metadataSuccess = true
	} else {
		// Metadata lookup failed - preserve last successful attachment status
		csmlog.GetLogger().Warnf("VolumeCollector: metadata refresh failed, preserving last successful attachment status")
		for protocol, attachedCount := range c.lastAttached {
			if attachedCount > 0 {
				c.attachmentStatus.WithLabelValues(c.globalID, protocol, "attached").Set(attachedCount)
			}
		}
		for protocol, detachedCount := range c.lastDetached {
			if detachedCount > 0 {
				c.attachmentStatus.WithLabelValues(c.globalID, protocol, "detached").Set(detachedCount)
			}
		}
		c.metadataSuccess = false
	}

	for transport, count := range nvmeTransportCounts {
		if count == 0 {
			continue
		}
		c.nvmeVolumeTotal.WithLabelValues(c.globalID, transport).Set(float64(count))
	}

	for protocol, bucketCounts := range sizeBucketCounts {
		for bucket, count := range bucketCounts {
			if count == 0 {
				continue
			}
			c.volumeSizeDist.WithLabelValues(c.globalID, protocol, bucket).Set(float64(count))
		}
	}

	return nil
}

// Name returns the collector name.
func (c *VolumeCollector) Name() string { return "VolumeCollector" }
