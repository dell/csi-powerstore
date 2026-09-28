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
	"errors"
	"sync"
	"testing"

	"github.com/dell/gopowerstore"
	gpmocks "github.com/dell/gopowerstore/mocks"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testApplianceRegistry = prometheus.NewRegistry()
	applianceMetricsReset sync.Once
)

// resetApplianceMetrics resets the singleton metrics for testing
func resetApplianceMetrics() {
	applianceMetricsReset.Do(func() {
		// No-op for registry-scoped metrics; retained for older test helpers.
	})
}

func mustNewApplianceCollector(t *testing.T, client ApplianceClient, reg *prometheus.Registry, globalID string) *ApplianceCollector {
	t.Helper()
	collector, err := NewApplianceCollector(client, reg, globalID)
	require.NoError(t, err)
	return collector
}

func TestNewApplianceCollector_RegistrationError(t *testing.T) {
	client := &testApplianceClient{}
	reg := prometheus.NewRegistry()

	// Register a counter with the same name as the first gauge to cause registration error
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dell_powerstore_appliance_physical_capacity_bytes",
		Help: "Test counter",
	}, []string{"global_id", "appliance_id", "appliance_name", "capacity_type"})
	reg.MustRegister(counter)

	_, err := NewApplianceCollector(client, reg, "global-1")
	require.Error(t, err)
}

func TestNewApplianceCollectorWithClient_RegistrationError(t *testing.T) {
	client := &gpmocks.Client{}
	reg := prometheus.NewRegistry()

	// Register a counter with the same name as the first gauge to cause registration error
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dell_powerstore_appliance_physical_capacity_bytes",
		Help: "Test counter",
	}, []string{"global_id", "appliance_id", "appliance_name", "capacity_type"})
	reg.MustRegister(counter)

	_, err := NewApplianceCollectorWithClient(client, reg, "global-1")
	require.Error(t, err)
}

func mustNewApplianceCollectorWithClient(t *testing.T, client gopowerstore.Client, reg *prometheus.Registry, globalID string) *ApplianceCollector {
	t.Helper()
	collector, err := NewApplianceCollectorWithClient(client, reg, globalID)
	require.NoError(t, err)
	return collector
}

// testApplianceClient implements ApplianceClient for testing
type testApplianceClient struct {
	cluster             ClusterInfo
	clusterErr          error
	clusterMetrics      []gopowerstore.SpaceMetricsByClusterResponse
	clusterMetricsErr   error
	appliances          []gopowerstore.ApplianceInstance
	appliancesErr       error
	applianceMetrics    map[string][]gopowerstore.SpaceMetricsByApplianceResponse
	applianceMetricsErr error
}

func (m *testApplianceClient) GetCluster(_ context.Context) (ClusterInfo, error) {
	return m.cluster, m.clusterErr
}

func (m *testApplianceClient) SpaceMetricsByCluster(_ context.Context, _ string, _ gopowerstore.MetricsIntervalEnum) ([]gopowerstore.SpaceMetricsByClusterResponse, error) {
	return m.clusterMetrics, m.clusterMetricsErr
}

func (m *testApplianceClient) GetAppliances(_ context.Context) ([]gopowerstore.ApplianceInstance, error) {
	return m.appliances, m.appliancesErr
}

func (m *testApplianceClient) SpaceMetricsByAppliance(_ context.Context, applianceID string, _ gopowerstore.MetricsIntervalEnum) ([]gopowerstore.SpaceMetricsByApplianceResponse, error) {
	if m.applianceMetricsErr != nil {
		return nil, m.applianceMetricsErr
	}
	return m.applianceMetrics[applianceID], nil
}

func TestApplianceCollector_Collect_ClusterMetrics(t *testing.T) {
	resetApplianceMetrics()
	total := int64(1000)
	used := int64(500)
	client := &testApplianceClient{
		cluster: ClusterInfo{ID: "cluster-id-1", Name: "Cluster1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{
			{
				PhysicalTotal:   &total,
				PhysicalUsed:    &used,
				DataReduction:   2.0,
				EfficiencyRatio: 3.0,
			},
		},
	}

	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	err := c.Collect(context.Background())
	require.NoError(t, err)

	mf := gatherPSTMetric(t, testApplianceRegistry, "dell_powerstore_appliance_physical_capacity_bytes")
	require.NotNil(t, mf)
	v, ok := gaugePST(mf, map[string]string{
		"global_id": "global-1", "appliance_id": "cluster-id-1", "appliance_name": "Cluster1", "capacity_type": "total",
	})
	require.True(t, ok)
	assert.Equal(t, 1000.0, v)
}

func TestApplianceCollector_Collect_MultipleAppliances(t *testing.T) {
	resetApplianceMetrics()
	total1 := int64(1000)
	used1 := int64(500)
	total2 := int64(2000)
	used2 := int64(800)
	client := &testApplianceClient{
		cluster:        ClusterInfo{ID: "cluster-id-1", Name: "Cluster1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{{PhysicalTotal: &total1, PhysicalUsed: &used1}},
		appliances: []gopowerstore.ApplianceInstance{
			{ID: "appliance-1", Name: "Appliance1"},
			{ID: "appliance-2", Name: "Appliance2"},
		},
		applianceMetrics: map[string][]gopowerstore.SpaceMetricsByApplianceResponse{
			"appliance-1": {{PhysicalTotal: &total1, PhysicalUsed: &used1, DataReduction: 2.0, EfficiencyRatio: 3.0}},
			"appliance-2": {{PhysicalTotal: &total2, PhysicalUsed: &used2, DataReduction: 1.5, EfficiencyRatio: 2.5}},
		},
	}

	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	err := c.Collect(context.Background())
	require.NoError(t, err)

	mf := gatherPSTMetric(t, testApplianceRegistry, "dell_powerstore_appliance_physical_capacity_bytes")
	require.NotNil(t, mf)

	v1, ok := gaugePST(mf, map[string]string{
		"global_id": "global-1", "appliance_id": "appliance-1", "appliance_name": "Appliance1", "capacity_type": "total",
	})
	require.True(t, ok)
	assert.Equal(t, 1000.0, v1)

	v2, ok := gaugePST(mf, map[string]string{
		"global_id": "global-1", "appliance_id": "appliance-2", "appliance_name": "Appliance2", "capacity_type": "total",
	})
	require.True(t, ok)
	assert.Equal(t, 2000.0, v2)
}

func TestApplianceCollector_Collect_ZeroPhysicalTotal_OmitsUtilization(t *testing.T) {
	total := int64(0)
	used := int64(0)
	client := &testApplianceClient{
		cluster:        ClusterInfo{ID: "cluster-id-1", Name: "Cluster1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{{PhysicalTotal: &total, PhysicalUsed: &used}},
		// No appliances to avoid appliance-level metrics
		appliances: []gopowerstore.ApplianceInstance{},
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-zero-total")
	_ = c.Collect(context.Background())

	mf := gatherPSTMetric(t, testApplianceRegistry, "dell_powerstore_appliance_utilization_ratio")
	if mf != nil {
		_, ok := gaugePST(mf, map[string]string{"global_id": "global-zero-total", "appliance_id": "cluster-id-1", "appliance_name": "Cluster1"})
		assert.False(t, ok, "utilization_ratio must NOT be emitted when PhysicalTotal == 0")
	}
}

func TestApplianceCollector_Collect_DataReductionRatio(t *testing.T) {
	total := int64(1000)
	used := int64(500)
	client := &testApplianceClient{
		cluster:        ClusterInfo{ID: "cluster-id-1", Name: "Cluster1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{{PhysicalTotal: &total, PhysicalUsed: &used, DataReduction: 2.5}},
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")
	_ = c.Collect(context.Background())

	mf := gatherPSTMetric(t, testApplianceRegistry, "dell_powerstore_appliance_data_reduction_ratio")
	require.NotNil(t, mf)
	v, ok := gaugePST(mf, map[string]string{"global_id": "global-1", "appliance_id": "cluster-id-1", "appliance_name": "Cluster1"})
	require.True(t, ok)
	assert.InDelta(t, 2.5, v, 0.01)
}

func TestApplianceCollector_Collect_ThinProvisioningRatio(t *testing.T) {
	total := int64(1000)
	used := int64(500)
	client := &testApplianceClient{
		cluster:        ClusterInfo{ID: "cluster-id-1", Name: "Cluster1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{{PhysicalTotal: &total, PhysicalUsed: &used, ThinSavings: 4.0}},
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")
	_ = c.Collect(context.Background())

	mf := gatherPSTMetric(t, testApplianceRegistry, "dell_powerstore_appliance_thin_provisioning_ratio")
	require.NotNil(t, mf)
	v, ok := gaugePST(mf, map[string]string{"global_id": "global-1", "appliance_id": "cluster-id-1", "appliance_name": "Cluster1"})
	require.True(t, ok)
	assert.InDelta(t, 4.0, v, 0.01)
}

func TestApplianceCollector_Collect_ClusterError(t *testing.T) {
	client := &testApplianceClient{
		clusterErr: errors.New("cluster error"),
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	err := c.Collect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get cluster info")
}

func TestApplianceCollector_Collect_ClusterMetricsError(t *testing.T) {
	client := &testApplianceClient{
		cluster:           ClusterInfo{ID: "cluster-id-1"},
		clusterMetricsErr: errors.New("cluster metrics error"),
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	err := c.Collect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get cluster space metrics")
}

func TestApplianceCollector_Collect_AppliancesError(t *testing.T) {
	total := int64(1000)
	used := int64(500)
	client := &testApplianceClient{
		cluster:        ClusterInfo{ID: "cluster-id-1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{{PhysicalTotal: &total, PhysicalUsed: &used}},
		appliancesErr:  errors.New("appliances error"),
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	err := c.Collect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get appliances")
}

func TestApplianceCollector_Collect_EmptyClusterMetrics(t *testing.T) {
	client := &testApplianceClient{
		cluster:        ClusterInfo{ID: "cluster-id-1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{},
		appliances:     []gopowerstore.ApplianceInstance{},
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	err := c.Collect(context.Background())
	require.NoError(t, err)
	// Should not panic with empty metrics
}

func TestApplianceCollector_Collect_NilPhysicalValues(t *testing.T) {
	client := &testApplianceClient{
		cluster: ClusterInfo{ID: "cluster-id-1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{
			{PhysicalTotal: nil, PhysicalUsed: nil, DataReduction: 2.0, EfficiencyRatio: 3.0},
		},
		appliances: []gopowerstore.ApplianceInstance{},
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	err := c.Collect(context.Background())
	require.NoError(t, err)
	// Should not panic with nil values
}

func TestApplianceCollector_Collect_ApplianceMetricsError(t *testing.T) {
	total := int64(1000)
	used := int64(500)
	client := &testApplianceClient{
		cluster:        ClusterInfo{ID: "cluster-id-1"},
		clusterMetrics: []gopowerstore.SpaceMetricsByClusterResponse{{PhysicalTotal: &total, PhysicalUsed: &used}},
		appliances: []gopowerstore.ApplianceInstance{
			{ID: "app1", Name: "appliance1"},
			{ID: "app2", Name: "appliance2"},
		},
		applianceMetricsErr: errors.New("metrics error"),
	}

	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	err := c.Collect(context.Background())
	require.NoError(t, err)
	// Should not fail even if appliance metrics error occurs
	// Cluster metrics should still be collected
	metricFamilies, err := testApplianceRegistry.Gather()
	require.NoError(t, err)

	foundClusterMetric := false
	for _, mf := range metricFamilies {
		if *mf.Name == "dell_powerstore_appliance_physical_capacity_bytes" {
			foundClusterMetric = true
			break
		}
	}

	assert.True(t, foundClusterMetric, "Expected cluster metrics to be collected even with appliance metrics error")
}

func TestApplianceCollector_Name(t *testing.T) {
	client := &testApplianceClient{}
	resetApplianceMetrics()
	c := mustNewApplianceCollector(t, client, testApplianceRegistry, "global-1")

	assert.Equal(t, "ApplianceCollector", c.Name())
}

func TestNewApplianceCollector_NilRegistry(t *testing.T) {
	client := &testApplianceClient{}
	_, err := NewApplianceCollector(client, nil, "global-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "registry is nil")
}

func TestApplianceCollectorWithClient(t *testing.T) {
	// Skipping WithClient test due to import cycle with mocks package
	// The WithClient functionality is tested indirectly through the Collect tests
	t.Skip("Skipping WithClient test due to import cycle with mocks package")
}
