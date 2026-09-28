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

package metricsruntime

import (
	"context"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/collectors"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csi-powerstore/v2/pkg/metrics"
	gopowerstore "github.com/dell/gopowerstore"
	gpmocks "github.com/dell/gopowerstore/mocks"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLeaderElectionEnabled(t *testing.T) {
	// Test default (env var not set)
	assert.False(t, leaderElectionEnabled())

	// Test with true
	t.Setenv(identifiers.EnvMetricsLeaderElectionEnabled, "true")
	assert.True(t, leaderElectionEnabled())

	// Test with TRUE (case insensitive)
	t.Setenv(identifiers.EnvMetricsLeaderElectionEnabled, "TRUE")
	assert.True(t, leaderElectionEnabled())

	// Test with false
	t.Setenv(identifiers.EnvMetricsLeaderElectionEnabled, "false")
	assert.False(t, leaderElectionEnabled())

	// Test with other value
	t.Setenv(identifiers.EnvMetricsLeaderElectionEnabled, "random")
	assert.False(t, leaderElectionEnabled())
}

func TestDriverNamespace(t *testing.T) {
	// Test default
	assert.Equal(t, "default", driverNamespace())

	// Test with custom namespace
	t.Setenv(identifiers.EnvDriverNamespace, "custom-ns")
	assert.Equal(t, "custom-ns", driverNamespace())
}

func TestLeaderLeaseDuration(t *testing.T) {
	// Test default
	assert.Equal(t, 15*time.Second, leaderLeaseDuration())

	// Test with custom duration
	t.Setenv(identifiers.EnvMetricsLeaderElectionLeaseDuration, "30s")
	assert.Equal(t, 30*time.Second, leaderLeaseDuration())

	// Test with invalid duration (should use default)
	t.Setenv(identifiers.EnvMetricsLeaderElectionLeaseDuration, "invalid")
	assert.Equal(t, 15*time.Second, leaderLeaseDuration())

	// Test with zero duration (should use default)
	t.Setenv(identifiers.EnvMetricsLeaderElectionLeaseDuration, "0s")
	assert.Equal(t, 15*time.Second, leaderLeaseDuration())
}

func TestLeaderRenewDeadline(t *testing.T) {
	// Test default
	assert.Equal(t, 10*time.Second, leaderRenewDeadline())

	// Test with custom duration
	t.Setenv(identifiers.EnvMetricsLeaderElectionRenewDeadline, "20s")
	assert.Equal(t, 20*time.Second, leaderRenewDeadline())

	// Test with invalid duration (should use default)
	t.Setenv(identifiers.EnvMetricsLeaderElectionRenewDeadline, "invalid")
	assert.Equal(t, 10*time.Second, leaderRenewDeadline())
}

func TestLeaderRetryPeriod(t *testing.T) {
	// Test default
	assert.Equal(t, 5*time.Second, leaderRetryPeriod())

	// Test with custom duration
	t.Setenv(identifiers.EnvMetricsLeaderElectionRetryPeriod, "8s")
	assert.Equal(t, 8*time.Second, leaderRetryPeriod())

	// Test with invalid duration (should use default)
	t.Setenv(identifiers.EnvMetricsLeaderElectionRetryPeriod, "invalid")
	assert.Equal(t, 5*time.Second, leaderRetryPeriod())
}

func TestDurationFromEnv(t *testing.T) {
	// Test default (env var not set)
	assert.Equal(t, 30*time.Second, durationFromEnv("NONEXISTENT_VAR", 30*time.Second))

	// Test with valid duration
	t.Setenv("TEST_DURATION", "1m")
	assert.Equal(t, 1*time.Minute, durationFromEnv("TEST_DURATION", 30*time.Second))

	// Test with invalid duration (should use fallback)
	t.Setenv("TEST_DURATION", "invalid")
	assert.Equal(t, 30*time.Second, durationFromEnv("TEST_DURATION", 30*time.Second))

	// Test with zero duration (should use fallback)
	t.Setenv("TEST_DURATION", "0s")
	assert.Equal(t, 30*time.Second, durationFromEnv("TEST_DURATION", 30*time.Second))

	// Test with negative duration (should use fallback)
	t.Setenv("TEST_DURATION", "-1s")
	assert.Equal(t, 30*time.Second, durationFromEnv("TEST_DURATION", 30*time.Second))
}

func TestIntFromEnv(t *testing.T) {
	// Test default (env var not set)
	assert.Equal(t, 100, intFromEnv("NONEXISTENT_VAR", 100))

	// Test with valid int
	t.Setenv("TEST_INT", "200")
	assert.Equal(t, 200, intFromEnv("TEST_INT", 100))

	// Test with invalid int (should use fallback)
	t.Setenv("TEST_INT", "invalid")
	assert.Equal(t, 100, intFromEnv("TEST_INT", 100))

	// Test with zero (should use fallback)
	t.Setenv("TEST_INT", "0")
	assert.Equal(t, 100, intFromEnv("TEST_INT", 100))

	// Test with negative (should use fallback)
	t.Setenv("TEST_INT", "-1")
	assert.Equal(t, 100, intFromEnv("TEST_INT", 100))
}

func TestPollInterval(t *testing.T) {
	// Test default
	assert.Equal(t, time.Minute, pollInterval())

	// Test with custom interval
	t.Setenv(identifiers.EnvMetricsPollInterval, "2m")
	assert.Equal(t, 2*time.Minute, pollInterval())

	// Test with invalid interval (should use default)
	t.Setenv(identifiers.EnvMetricsPollInterval, "invalid")
	assert.Equal(t, time.Minute, pollInterval())

	// Test with zero interval (should use default)
	t.Setenv(identifiers.EnvMetricsPollInterval, "0s")
	assert.Equal(t, time.Minute, pollInterval())
}

func TestRuntimeConfig(t *testing.T) {
	// Test default config
	config := runtimeConfig()
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 60*time.Second, config.CacheTTL)
	assert.Equal(t, 100, config.RateLimit)
	assert.Equal(t, 3, config.CBThreshold)
	assert.Equal(t, 30*time.Second, config.CBResetTimeout)

	// Test with custom config
	t.Setenv(identifiers.EnvMetricsArrayTimeout, "60s")
	t.Setenv(identifiers.EnvMetricsCollectionCacheTTL, "120s")
	t.Setenv(identifiers.EnvMetricsArrayRateLimit, "200")
	t.Setenv(identifiers.EnvMetricsArrayCBThreshold, "5")
	t.Setenv(identifiers.EnvMetricsArrayCBResetTimeout, "60s")

	config = runtimeConfig()
	assert.Equal(t, 60*time.Second, config.Timeout)
	assert.Equal(t, 120*time.Second, config.CacheTTL)
	assert.Equal(t, 200, config.RateLimit)
	assert.Equal(t, 5, config.CBThreshold)
	assert.Equal(t, 60*time.Second, config.CBResetTimeout)
}

func TestRuntimeState_Stop(t *testing.T) {
	// Test nil state
	var state *RuntimeState
	assert.NotPanics(t, func() {
		state.Stop()
	})

	// Test state with nil fields
	state = &RuntimeState{}
	assert.NotPanics(t, func() {
		state.Stop()
	})

	// Test stop is idempotent
	_, cancel := context.WithCancel(context.Background())
	state = &RuntimeState{
		cancel:  cancel,
		checker: nil,
		manager: nil,
		shared:  nil,
	}
	assert.NotPanics(t, func() {
		state.Stop()
		state.Stop() // Should not panic
	})
}

func TestStartCollectors_NilRegistry(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Test with nil registry
	state := StartCollectors(context.Background(), nil, nil, "controller", nil, nil, nil)
	assert.Nil(t, state)
}

func TestStartCollectors_EmptyArrays(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Test with empty arrays
	registry := &prometheus.Registry{}
	state := StartCollectors(context.Background(), registry, nil, "controller", map[string]*array.PowerStoreArray{}, nil, nil)
	assert.Nil(t, state)
}

func TestStartCollectors_PreviousStateStop(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Test that previous state is stopped
	_, cancel := context.WithCancel(context.Background())
	previous := &RuntimeState{
		cancel: cancel,
	}

	registry := &prometheus.Registry{}
	state := StartCollectors(context.Background(), registry, nil, "controller", nil, previous, nil)
	assert.Nil(t, state)
}

func TestStartCollectors_NilArrays(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Test with nil arrays map
	registry := &prometheus.Registry{}
	state := StartCollectors(context.Background(), registry, nil, "controller", nil, nil, nil)
	assert.Nil(t, state)
}

func TestStartCollectors_WithoutKubeClient(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Create a simple array with nil client to avoid actual API calls
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
		},
	}

	registry := &prometheus.Registry{}
	shared := &collectors.SharedMetadataChecker{}

	state := StartCollectors(context.Background(), registry, nil, "controller", arrays, nil, shared)

	// State should be created but without checker
	assert.NotNil(t, state)
	assert.Nil(t, state.checker)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_NodeMode(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil for node mode
	k8sutils.Kubeclient = nil

	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
		},
	}

	registry := &prometheus.Registry{}
	shared := &collectors.SharedMetadataChecker{}

	state := StartCollectors(context.Background(), registry, nil, "node", arrays, nil, shared)

	// State should be created for node mode
	assert.NotNil(t, state)
	assert.Nil(t, state.checker)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_WithValidClient(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil to avoid informer timeout
	k8sutils.Kubeclient = nil

	// Create mock gopowerstore client with proper expectations
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)
	gpClient.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{{ID: "fs-1", Name: "fs-1"}}, nil)
	gpClient.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{ID: "export-1", FileSystemID: "fs-1"}, nil)
	gpClient.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-1"}}, nil)
	gpClient.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-1", VolumeID: "vol-1"}}, nil)
	gpClient.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{ID: "host-1"}, nil)

	// Create array with mock client
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)

	// State should be created
	assert.NotNil(t, state)
	assert.Nil(t, state.checker)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_WithoutSharedChecker(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Create mock gopowerstore client with proper expectations
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	// Create array with mock client
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, nil)

	// State should be created
	assert.NotNil(t, state)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_EarlyReturnNilRegistry(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	shared := &collectors.SharedMetadataChecker{}

	ctx := context.Background()

	// Test with nil registry - should return nil
	state := StartCollectors(ctx, nil, nil, "controller", nil, nil, shared)
	assert.Nil(t, state)
}

func TestStartCollectors_EarlyReturnEmptyArrays(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	registry := prometheus.NewRegistry()

	ctx := context.Background()

	// Test with empty arrays - should return nil
	state := StartCollectors(ctx, registry, nil, "controller", map[string]*array.PowerStoreArray{}, nil, nil)
	assert.Nil(t, state)
}

func TestStartCollectors_MultipleArrays(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Create mock gopowerstore clients with proper expectations
	gpClient1 := &gpmocks.Client{}
	gpClient1.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient1.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient1.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient1.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient1.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)
	gpClient1.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{{ID: "fs-1", Name: "fs-1"}}, nil)
	gpClient1.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{ID: "export-1", FileSystemID: "fs-1"}, nil)
	gpClient1.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-1"}}, nil)
	gpClient1.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-1", VolumeID: "vol-1"}}, nil)
	gpClient1.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{ID: "host-1"}, nil)

	gpClient2 := &gpmocks.Client{}
	gpClient2.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-2", Name: "cluster-b", State: "Configured"}, nil)
	gpClient2.On("SpaceMetricsByCluster", mock.Anything, "cluster-2", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient2.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-2", Name: "appliance-2"}}, nil)
	gpClient2.On("SpaceMetricsByAppliance", mock.Anything, "app-2", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient2.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-2", Size: 2}}, nil)
	gpClient2.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{{ID: "fs-2", Name: "fs-2"}}, nil)
	gpClient2.On("GetNFSExportByFileSystemID", mock.Anything, "fs-2").Return(gopowerstore.NFSExport{ID: "export-2", FileSystemID: "fs-2"}, nil)
	gpClient2.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-2"}}, nil)
	gpClient2.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-2").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-2", VolumeID: "vol-2"}}, nil)
	gpClient2.On("GetHost", mock.Anything, "host-2").Return(gopowerstore.Host{ID: "host-2"}, nil)

	// Create arrays with mock clients
	arrays := map[string]*array.PowerStoreArray{
		"test1": {
			GlobalID: "test-global-1",
			Client:   gpClient1,
		},
		"test2": {
			GlobalID: "test-global-2",
			Client:   gpClient2,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)

	// State should be created
	assert.NotNil(t, state)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_PreviousState(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Create mock gopowerstore client with proper expectations
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)
	gpClient.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{{ID: "fs-1", Name: "fs-1"}}, nil)
	gpClient.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{ID: "export-1", FileSystemID: "fs-1"}, nil)
	gpClient.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-1"}}, nil)
	gpClient.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-1", VolumeID: "vol-1"}}, nil)
	gpClient.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{ID: "host-1"}, nil)

	// Create array with mock client
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	// Create a previous state
	prevState := &RuntimeState{
		cancel: func() {},
		shared: shared,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, prevState, shared)

	// State should be created
	assert.NotNil(t, state)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_NodeModeWithValidClient(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Create mock gopowerstore client with proper expectations
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	// Create array with mock client
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "node", arrays, nil, nil)

	// State should be created for node mode
	assert.NotNil(t, state)
	assert.Nil(t, state.checker)

	// Wait for context to cancel to avoid race condition
	<-ctx.Done()
	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_WithKubeClientNoArrays(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set up mock kubeclient with fake clientset
	k8sutils.Kubeclient = &k8sutils.K8sClient{
		Clientset: fake.NewSimpleClientset(),
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Test with nil arrays - should return nil early
	state := StartCollectors(ctx, registry, nil, "controller", nil, nil, shared)
	assert.Nil(t, state)
}

func TestStartCollectors_WithKubeClientAndNilClientArray(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set up mock kubeclient with fake clientset
	k8sutils.Kubeclient = &k8sutils.K8sClient{
		Clientset: fake.NewSimpleClientset(),
	}

	// Create arrays with nil client (will skip collector creation)
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   nil,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)

	// State should be created with checker
	assert.NotNil(t, state)
	assert.NotNil(t, state.checker)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_WithProperServer(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Create mock gopowerstore client with proper expectations
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)
	gpClient.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{{ID: "fs-1", Name: "fs-1"}}, nil)
	gpClient.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{ID: "export-1", FileSystemID: "fs-1"}, nil)
	gpClient.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-1"}}, nil)
	gpClient.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-1", VolumeID: "vol-1"}}, nil)
	gpClient.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{ID: "host-1"}, nil)

	// Create array with mock client
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	// Create a properly initialized metrics server
	srv := metrics.NewServer("8443", registry)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, srv, "controller", arrays, nil, shared)

	// State should be created
	assert.NotNil(t, state)

	// Wait for context to cancel to avoid race condition
	<-ctx.Done()
	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_ControllerModeWithLeaderElection(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Enable leader election
	t.Setenv(identifiers.EnvMetricsLeaderElectionEnabled, "true")

	// Create mock gopowerstore client with proper expectations
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	// Create array with mock client
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)

	// State should be created
	assert.NotNil(t, state)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_WithSharedMetadataNotAvailable(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Create mock gopowerstore client with proper expectations
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	// Create array with mock client
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)

	// State should be created
	assert.NotNil(t, state)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_WithSharedClearOnCheckerError(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to a fake clientset (checker will start but may have issues)
	k8sutils.Kubeclient = &k8sutils.K8sClient{
		Clientset: fake.NewClientset(),
	}

	// Create array with nil client (should be skipped)
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   nil,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)

	// State should be created
	assert.NotNil(t, state)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_WithServerSetStale(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil
	k8sutils.Kubeclient = nil

	// Create mock gopowerstore client with proper expectations
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	// Create array with mock client
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}
	srv := metrics.NewServer("8443", registry)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, srv, "controller", arrays, nil, shared)

	// State should be created
	assert.NotNil(t, state)

	// Stop the state to clean up
	state.Stop()
}

func TestStartCollectors_LeaderElectionErrorFallback(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Set kubeclient to nil (leader election will fail and fallback to direct start)
	k8sutils.Kubeclient = nil

	// Enable leader election
	t.Setenv(identifiers.EnvMetricsLeaderElectionEnabled, "true")

	// Create mock gopowerstore client
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)
	assert.NotNil(t, state)
	state.Stop()
}

func TestStartCollectors_CollectorCreationErrors(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	k8sutils.Kubeclient = nil

	// Create mock client that will fail for some collectors
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)
	assert.NotNil(t, state)
	state.Stop()
}

func TestStartCollectors_SharedMetadataUnavailable(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	k8sutils.Kubeclient = nil

	// Create mock client
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}
	// Make shared unavailable by not setting it

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)
	assert.NotNil(t, state)
	state.Stop()
}

func TestStartCollectors_CollectorCreationFailure(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	k8sutils.Kubeclient = nil

	// Create array with invalid client that will cause collector creation to fail
	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   nil, // This will cause collector creation to be skipped
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)
	assert.NotNil(t, state)
	state.Stop()
}

func TestStartCollectors_SharedAvailableFalse(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	k8sutils.Kubeclient = nil

	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}
	// shared is initialized but not available (Available() returns false)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)
	assert.NotNil(t, state)
	state.Stop()
}

func TestStartCollectors_WithValidClientButCollectorErrors(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	k8sutils.Kubeclient = nil

	// Create mock client that will succeed for API calls
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)
	gpClient.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{{ID: "fs-1", Name: "fs-1"}}, nil)
	gpClient.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{ID: "export-1", FileSystemID: "fs-1"}, nil)
	gpClient.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-1"}}, nil)
	gpClient.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-1", VolumeID: "vol-1"}}, nil)
	gpClient.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{ID: "host-1"}, nil)

	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)
	assert.NotNil(t, state)
	state.Stop()
}

func TestStartCollectors_WithNilRegistry(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	k8sutils.Kubeclient = nil

	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, nil, nil, "controller", arrays, nil, shared)
	assert.Nil(t, state)
}

func TestStartCollectors_WithValidClientAndFullMocking(t *testing.T) {
	// Save original kubeclient
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	k8sutils.Kubeclient = &k8sutils.K8sClient{
		Clientset: fake.NewClientset(),
	}

	// Create array with valid client and full mocking
	gpClient := &gpmocks.Client{}
	gpClient.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	gpClient.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	gpClient.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	gpClient.On("SpaceMetricsByAppliance", mock.Anything, "app-1", mock.Anything).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)
	gpClient.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)
	gpClient.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{{ID: "fs-1", Name: "fs-1"}}, nil)
	gpClient.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{ID: "export-1", FileSystemID: "fs-1"}, nil)
	gpClient.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-1"}}, nil)
	gpClient.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-1", VolumeID: "vol-1"}}, nil)
	gpClient.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{ID: "host-1"}, nil)

	arrays := map[string]*array.PowerStoreArray{
		"test": {
			GlobalID: "test-global",
			Client:   gpClient,
		},
	}

	registry := prometheus.NewRegistry()
	shared := &collectors.SharedMetadataChecker{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	state := StartCollectors(ctx, registry, nil, "controller", arrays, nil, shared)
	assert.NotNil(t, state)
	state.Stop()
}
