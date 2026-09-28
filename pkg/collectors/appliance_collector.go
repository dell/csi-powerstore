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

	"github.com/dell/gopowerstore"
	"github.com/prometheus/client_golang/prometheus"
)

// ApplianceCollector collects PowerStore appliance capacity metrics.
type ApplianceCollector struct {
	client                ApplianceClient
	globalID              string
	physicalCapacity      *prometheus.GaugeVec
	utilizationRatio      *prometheus.GaugeVec
	dataReductionRatio    *prometheus.GaugeVec
	compressionRatio      *prometheus.GaugeVec
	thinProvisioningRatio *prometheus.GaugeVec
}

// NewApplianceCollector creates a new ApplianceCollector.
func NewApplianceCollector(client ApplianceClient, reg prometheus.Registerer, globalID string) (*ApplianceCollector, error) {
	physicalCapacity, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_appliance_physical_capacity_bytes",
		Help: "PowerStore appliance physical capacity in bytes.",
	}, []string{"global_id", "appliance_id", "appliance_name", "capacity_type"}), "dell_powerstore_appliance_physical_capacity_bytes")
	if err != nil {
		return nil, err
	}
	utilizationRatio, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_appliance_utilization_ratio",
		Help: "PowerStore appliance utilization ratio.",
	}, []string{"global_id", "appliance_id", "appliance_name"}), "dell_powerstore_appliance_utilization_ratio")
	if err != nil {
		return nil, err
	}
	dataReductionRatio, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_appliance_data_reduction_ratio",
		Help: "PowerStore data reduction ratio (deduplication + compression).",
	}, []string{"global_id", "appliance_id", "appliance_name"}), "dell_powerstore_appliance_data_reduction_ratio")
	if err != nil {
		return nil, err
	}
	compressionRatio, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_appliance_compression_ratio",
		Help: "PowerStore appliance compression effectiveness; sourced from overall efficiency_ratio (logical_provisioned / physical_used).",
	}, []string{"global_id", "appliance_id", "appliance_name"}), "dell_powerstore_appliance_compression_ratio")
	if err != nil {
		return nil, err
	}
	thinProvisioningRatio, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_appliance_thin_provisioning_ratio",
		Help: "PowerStore appliance thin provisioning ratio (logical_provisioned to logical_used).",
	}, []string{"global_id", "appliance_id", "appliance_name"}), "dell_powerstore_appliance_thin_provisioning_ratio")
	if err != nil {
		return nil, err
	}

	return &ApplianceCollector{
		client:                client,
		globalID:              globalID,
		physicalCapacity:      physicalCapacity,
		utilizationRatio:      utilizationRatio,
		dataReductionRatio:    dataReductionRatio,
		compressionRatio:      compressionRatio,
		thinProvisioningRatio: thinProvisioningRatio,
	}, nil
}

// NewApplianceCollectorWithClient creates a new ApplianceCollector with a gopowerstore.Client
// This is a convenience function that wraps the gopowerstore.Client in an adapter
func NewApplianceCollectorWithClient(client gopowerstore.Client, reg prometheus.Registerer, globalID string) (*ApplianceCollector, error) {
	adapter := &gopowerstoreApplianceAdapter{client: client}
	return NewApplianceCollector(adapter, reg, globalID)
}

// Collect fetches appliance capacity metrics.
func (c *ApplianceCollector) Collect(ctx context.Context) error {
	// Get cluster info to obtain cluster ID for space metrics
	cluster, err := c.client.GetCluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster info: %w", err)
	}

	// Get cluster-level space metrics
	spaceMetrics, err := c.client.SpaceMetricsByCluster(ctx, cluster.ID, gopowerstore.FiveMins)
	if err != nil {
		return fmt.Errorf("failed to get cluster space metrics: %w", err)
	}

	// Process space metrics - use the latest entry
	if len(spaceMetrics) > 0 {
		latest := spaceMetrics[len(spaceMetrics)-1]

		// Physical capacity metrics
		if latest.PhysicalTotal != nil {
			c.physicalCapacity.WithLabelValues(c.globalID, cluster.ID, cluster.Name, "total").Set(float64(*latest.PhysicalTotal))
		}
		if latest.PhysicalUsed != nil {
			c.physicalCapacity.WithLabelValues(c.globalID, cluster.ID, cluster.Name, "used").Set(float64(*latest.PhysicalUsed))
		}
		if latest.PhysicalTotal != nil && latest.PhysicalUsed != nil {
			free := float64(*latest.PhysicalTotal - *latest.PhysicalUsed)
			if free < 0 {
				free = 0
			}
			c.physicalCapacity.WithLabelValues(c.globalID, cluster.ID, cluster.Name, "free").Set(free)

			// Utilization ratio
			if *latest.PhysicalTotal > 0 {
				utilization := float64(*latest.PhysicalUsed) / float64(*latest.PhysicalTotal)
				c.utilizationRatio.WithLabelValues(c.globalID, cluster.ID, cluster.Name).Set(utilization)
			}
		}

		// Data reduction, compression and efficiency ratios
		c.dataReductionRatio.WithLabelValues(c.globalID, cluster.ID, cluster.Name).Set(float64(latest.DataReduction))
		c.compressionRatio.WithLabelValues(c.globalID, cluster.ID, cluster.Name).Set(float64(latest.EfficiencyRatio))
		c.thinProvisioningRatio.WithLabelValues(c.globalID, cluster.ID, cluster.Name).Set(float64(latest.ThinSavings))
	}

	// Get per-appliance metrics
	appliances, err := c.client.GetAppliances(ctx)
	if err != nil {
		return fmt.Errorf("failed to get appliances: %w", err)
	}

	// Collect metrics for each appliance
	for _, appliance := range appliances {
		// Get appliance-level space metrics
		appSpaceMetrics, err := c.client.SpaceMetricsByAppliance(ctx, appliance.ID, gopowerstore.FiveMins)
		if err != nil {
			// Log but continue with other appliances
			continue
		}

		// Process appliance space metrics - use the latest entry
		if len(appSpaceMetrics) > 0 {
			latest := appSpaceMetrics[len(appSpaceMetrics)-1]

			// Physical capacity metrics
			if latest.PhysicalTotal != nil {
				c.physicalCapacity.WithLabelValues(c.globalID, appliance.ID, appliance.Name, "total").Set(float64(*latest.PhysicalTotal))
			}
			if latest.PhysicalUsed != nil {
				c.physicalCapacity.WithLabelValues(c.globalID, appliance.ID, appliance.Name, "used").Set(float64(*latest.PhysicalUsed))
			}
			if latest.PhysicalTotal != nil && latest.PhysicalUsed != nil {
				free := float64(*latest.PhysicalTotal - *latest.PhysicalUsed)
				if free < 0 {
					free = 0
				}
				c.physicalCapacity.WithLabelValues(c.globalID, appliance.ID, appliance.Name, "free").Set(free)

				// Utilization ratio
				if *latest.PhysicalTotal > 0 {
					utilization := float64(*latest.PhysicalUsed) / float64(*latest.PhysicalTotal)
					c.utilizationRatio.WithLabelValues(c.globalID, appliance.ID, appliance.Name).Set(utilization)
				}
			}

			// Data reduction, compression and efficiency ratios
			c.dataReductionRatio.WithLabelValues(c.globalID, appliance.ID, appliance.Name).Set(float64(latest.DataReduction))
			c.compressionRatio.WithLabelValues(c.globalID, appliance.ID, appliance.Name).Set(float64(latest.EfficiencyRatio))
			c.thinProvisioningRatio.WithLabelValues(c.globalID, appliance.ID, appliance.Name).Set(float64(latest.ThinSavings))
		}
	}

	return nil
}

// Name returns the collector name.
func (c *ApplianceCollector) Name() string { return "ApplianceCollector" }
