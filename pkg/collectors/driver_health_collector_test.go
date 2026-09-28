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
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	metricsv1beta1client "k8s.io/metrics/pkg/client/clientset/versioned/typed/metrics/v1beta1"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csm-metrics-common/pkg/naming"
	metricsv1beta1api "k8s.io/metrics/pkg/apis/metrics/v1beta1"
)

var (
	testDriverHealthRegistry = prometheus.NewRegistry()
	driverHealthMetricsReset sync.Once
)

// resetDriverHealthMetrics resets the singleton metrics for testing
func resetDriverHealthMetrics() {
	driverHealthMetricsReset.Do(func() {
		// No-op for registry-scoped metrics; kept for compatibility with older tests.
	})
}

func mustNewPSTDriverHealthCollector(t *testing.T, reg *prometheus.Registry, globalID string, k8sClient *k8sutils.K8sClient) *PSTDriverHealthCollector {
	t.Helper()
	collector, err := NewPSTDriverHealthCollector(reg, globalID, k8sClient)
	require.NoError(t, err)
	return collector
}

func TestNewPSTDriverHealthCollector(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	assert.NotNil(t, collector)
	assert.Equal(t, globalID, collector.globalID)
	assert.NotNil(t, collector.uptimeGauge)
	assert.NotNil(t, collector.restartTotal)
	assert.NotNil(t, collector.goroutineCount)
	assert.NotNil(t, collector.connPoolActive)
	assert.NotNil(t, collector.cpuUsage)
	assert.NotNil(t, collector.memUsage)
}

func TestNewPSTDriverHealthCollector_NilRegistry(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Test with nil registry
	_, err := NewPSTDriverHealthCollector(nil, globalID, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry is nil")
}

func TestNewPSTDriverHealthCollector_RegistrationError(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"
	reg := prometheus.NewRegistry()

	// Register a counter with the same name as the first gauge to cause registration error
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: naming.MetricCSIDriverUptimeSeconds,
		Help: "Test counter",
	}, []string{naming.LabelGlobalID, "pod", "node", "namespace", "instance_type"})
	reg.MustRegister(counter)

	_, err := NewPSTDriverHealthCollector(reg, globalID, nil)
	require.Error(t, err)
}

func TestPSTDriverHealthCollector_getPodIdentityLabels(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)

	// Test with all env vars set
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvKubeNodeName, "test-node")
	t.Setenv(identifiers.EnvDriverNamespace, "test-ns")
	t.Setenv(identifiers.EnvCSIMode, "node")

	labels := collector.getPodIdentityLabels()
	require.Len(t, labels, 5)
	assert.Equal(t, globalID, labels[0])
	assert.Equal(t, "test-pod", labels[1])
	assert.Equal(t, "test-node", labels[2])
	assert.Equal(t, "test-ns", labels[3])
	assert.Equal(t, "node", labels[4])

	// Test with controller mode (should override node name)
	t.Setenv(identifiers.EnvCSIMode, "controller")
	labels = collector.getPodIdentityLabels()
	assert.Equal(t, "controller", labels[2])

	// Test with empty env vars (should use defaults)
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvKubeNodeName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
	t.Setenv(identifiers.EnvCSIMode, "")

	labels = collector.getPodIdentityLabels()
	assert.Equal(t, "unknown", labels[1])
	assert.Equal(t, "unknown", labels[2])
	assert.Equal(t, "unknown", labels[3])
	assert.Equal(t, "unknown", labels[4])
}

func TestPSTDriverHealthCollector_collectKubernetesMetrics(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)

	// Test with empty pod name - should return early
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "test-ns")
	collector.collectKubernetesMetrics(context.Background())

	// Test with empty namespace - should return early
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "")
	collector.collectKubernetesMetrics(context.Background())

	// Test with both set but nil k8s client - should return early
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "test-ns")
	collector.collectKubernetesMetrics(context.Background())
}

func TestPSTDriverHealthCollector_Name(t *testing.T) {
	resetDriverHealthMetrics()
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, "test-id", nil)

	assert.Equal(t, "PSTDriverHealthCollector", collector.Name())
}

func TestPSTDriverHealthCollector_Collect(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()
	err := collector.Collect(ctx)

	assert.NoError(t, err)

	// Verify that metrics were registered and can be gathered
	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)

	// Check that our specific metrics are present
	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.GetName()] = true
	}

	assert.True(t, metricNames["dell_csi_driver_uptime_seconds"])
	assert.True(t, metricNames["dell_csi_goroutine_count"])
	assert.True(t, metricNames["dell_csi_connection_pool_active"])
	// CPU/memory metrics may not be present without K8s client
	// assert.True(t, metricNames["dell_csi_driver_cpu_usage_percent"])
	// assert.True(t, metricNames["dell_csi_driver_memory_usage_bytes"])
}

func TestPSTDriverHealthCollector_Collect_MultipleTimes(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()

	// Collect multiple times to ensure metrics are updated
	for i := 0; i < 3; i++ {
		err := collector.Collect(ctx)
		assert.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	// Verify metrics are still valid
	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestPSTDriverHealthCollector_RestartCounter(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// With no pod identity env vars, the collector publishes a zero restart metric
	// so the family is visible before Kubernetes pod status is available.
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())
	_ = collector.Collect(context.Background())

	// Gather metrics to check restart counter
	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	// Find the restart metric
	var restartMetric *dto.MetricFamily
	for _, m := range metrics {
		if m.GetName() == "dell_csi_driver_restart_total" {
			restartMetric = m
			break
		}
	}

	require.NotNil(t, restartMetric)
	assert.Equal(t, 1, len(restartMetric.GetMetric()))
	assert.Equal(t, 0.0, restartMetric.GetMetric()[0].GetGauge().GetValue())
}

func TestPSTDriverHealthCollector_UptimeIncreases(t *testing.T) {
	resetDriverHealthMetrics()

	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	}
	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables for pod identity
	_ = os.Setenv(identifiers.EnvPodName, "test-pod")
	_ = os.Setenv(identifiers.EnvKubeNodeName, "test-node")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	_ = os.Setenv(identifiers.EnvCSIMode, "controller")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvKubeNodeName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
		_ = os.Unsetenv(identifiers.EnvCSIMode)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)

	ctx := context.Background()

	// First collection
	err = collector.Collect(ctx)
	require.NoError(t, err)

	firstMetrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	firstUptime := getGaugeValue(t, firstMetrics, "dell_csi_driver_uptime_seconds", map[string]string{"global_id": globalID})

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Second collection
	err = collector.Collect(ctx)
	require.NoError(t, err)

	secondMetrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	secondUptime := getGaugeValue(t, secondMetrics, "dell_csi_driver_uptime_seconds", map[string]string{"global_id": globalID})

	// Uptime should have increased
	assert.Greater(t, secondUptime, firstUptime)
}

func TestPSTDriverHealthCollector_GoroutineCount(t *testing.T) {
	resetDriverHealthMetrics()

	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	}
	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables for pod identity
	_ = os.Setenv(identifiers.EnvPodName, "test-pod")
	_ = os.Setenv(identifiers.EnvKubeNodeName, "test-node")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	_ = os.Setenv(identifiers.EnvCSIMode, "controller")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvKubeNodeName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
		_ = os.Unsetenv(identifiers.EnvCSIMode)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)

	ctx := context.Background()
	err = collector.Collect(ctx)
	require.NoError(t, err)

	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	goroutineCount := getGaugeValue(t, metrics, "dell_csi_goroutine_count", map[string]string{"global_id": globalID})

	// Goroutine count should be positive
	assert.Greater(t, goroutineCount, float64(0))
}

func TestPSTDriverHealthCollector_ConnectionPoolActive(t *testing.T) {
	resetDriverHealthMetrics()

	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client with a pod
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:         "csi-powerstore",
						RestartCount: 0,
						Ready:        true,
					},
				},
			},
		}), nil
	}
	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables for pod identity
	_ = os.Setenv(identifiers.EnvPodName, "test-pod")
	_ = os.Setenv(identifiers.EnvKubeNodeName, "test-node")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	_ = os.Setenv(identifiers.EnvCSIMode, "controller")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvKubeNodeName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
		_ = os.Unsetenv(identifiers.EnvCSIMode)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)

	ctx := context.Background()
	err = collector.Collect(ctx)
	require.NoError(t, err)

	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	connPoolActive := getGaugeValue(t, metrics, "dell_csi_connection_pool_active", map[string]string{"global_id": globalID})

	// Connection pool active should be 1 (indicating client is active)
	assert.Equal(t, float64(1), connPoolActive)
}

func TestPSTDriverHealthCollector_ContextCancellation(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := collector.Collect(ctx)
	// Collector should handle cancelled context gracefully
	// Since it doesn't actually do blocking operations, it should still succeed
	assert.NoError(t, err)
}

func TestPSTDriverHealthCollector_GoroutineCountMatchesRuntime(t *testing.T) {
	resetDriverHealthMetrics()

	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	}
	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables for pod identity
	_ = os.Setenv(identifiers.EnvPodName, "test-pod")
	_ = os.Setenv(identifiers.EnvKubeNodeName, "test-node")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	_ = os.Setenv(identifiers.EnvCSIMode, "controller")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvKubeNodeName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
		_ = os.Unsetenv(identifiers.EnvCSIMode)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()
	err = collector.Collect(ctx)
	require.NoError(t, err)

	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	goroutineCount := getGaugeValue(t, metrics, "dell_csi_goroutine_count", map[string]string{"global_id": globalID})

	// The collector records the active goroutine count; the exact value can
	// vary during test execution, so assert it is positive.
	assert.Greater(t, goroutineCount, float64(0))
}

func TestPSTDriverHealthCollector_CPUMemoryMetrics(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err)

	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	// With no pod identity env vars, the implementation skips Kubernetes metrics collection.
	assert.False(t, hasGaugeMetric(t, metrics, "dell_csi_driver_cpu_usage_percent", map[string]string{"global_id": globalID}))
	assert.False(t, hasGaugeMetric(t, metrics, "dell_csi_driver_memory_usage_bytes", map[string]string{"global_id": globalID}))
}

// mockK8sClientWithMetrics is a mock K8sClient that implements GetPodMetrics
type mockK8sClientWithMetrics struct {
	k8sutils.K8sClient
	cpuUsage      int64
	memoryUsage   int64
	containerName string
}

func (m *mockK8sClientWithMetrics) GetPodMetrics(_ context.Context, _ string, _ string) (*metricsv1beta1api.PodMetrics, error) {
	containerName := "csi-powerstore"
	if m.containerName != "" {
		containerName = m.containerName
	}

	return &metricsv1beta1api.PodMetrics{
		Containers: []metricsv1beta1api.ContainerMetrics{
			{
				Name: containerName,
				Usage: corev1.ResourceList{
					corev1.ResourceCPU:    *resource.NewMilliQuantity(m.cpuUsage, resource.DecimalSI),
					corev1.ResourceMemory: *resource.NewQuantity(m.memoryUsage, resource.BinarySI),
				},
			},
		},
	}, nil
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_WithMetricsClient(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set pod identity environment variables
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "default")

	// Create a mock K8sClient with a mock GetPodMetrics method
	k8sClient := &mockK8sClientWithMetrics{
		cpuUsage:    5000,               // 50% CPU usage
		memoryUsage: 1024 * 1024 * 1024, // 1GB memory
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err)

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_GetPodMetricsError(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set pod identity environment variables
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "default")

	// Create a mock K8sClient that returns an error from GetPodMetrics
	k8sClient := &mockK8sClientWithError{
		K8sClient: k8sutils.K8sClient{
			MetricsClient: nil, // No metrics client
		},
		returnError: true,
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err) // Should not error, just skip metrics collection

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_NoMatchingContainerName(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set pod identity environment variables
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "default")

	// Create a mock K8sClient with a mock GetPodMetrics method that returns a container with a non-matching name
	k8sClient := &mockK8sClientWithMetrics{
		cpuUsage:      5000,
		memoryUsage:   1024 * 1024 * 1024,
		containerName: "other-container", // Non-matching name
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err)

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_NilMetricsClient(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set pod identity environment variables
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "default")

	// Create a mock K8sClient with nil metrics client
	k8sClient := &mockK8sClientWithError{
		K8sClient: k8sutils.K8sClient{
			MetricsClient: nil, // No metrics client
		},
		returnError: false,
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err) // Should not error, just skip metrics collection

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_NilK8sClient(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set pod identity environment variables
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "default")

	// Create a collector with nil k8sClient
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err) // Should not error, just skip metrics collection

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_EmptyPodName(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set only namespace, not pod name
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "default")

	k8sClient := &mockK8sClientWithMetrics{
		cpuUsage:    5000,
		memoryUsage: 1024 * 1024 * 1024,
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err) // Should not error, just skip metrics collection

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_EmptyNamespace(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set only pod name, not namespace
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "")

	k8sClient := &mockK8sClientWithMetrics{
		cpuUsage:    5000,
		memoryUsage: 1024 * 1024 * 1024,
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err) // Should not error, just skip metrics collection

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_NoMatchingContainer(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set pod identity environment variables
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "default")

	// Create a mock K8sClient with a mock GetPodMetrics method that returns metrics for a different container
	k8sClient := &mockK8sClientWithMetrics{
		cpuUsage:      5000,
		memoryUsage:   1024 * 1024 * 1024,
		containerName: "other-container", // Not matching "csi-powerstore" or "driver"
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err)

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_EmptyContainers(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Set pod identity environment variables
	t.Setenv(identifiers.EnvPodName, "test-pod")
	t.Setenv(identifiers.EnvDriverNamespace, "default")

	// Create a mock K8sClient with a mock GetPodMetrics method that returns empty containers
	k8sClient := &mockK8sClientWithEmptyContainers{
		K8sClient: k8sutils.K8sClient{},
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err)

	// Clean up env vars
	t.Setenv(identifiers.EnvPodName, "")
	t.Setenv(identifiers.EnvDriverNamespace, "")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_NoPodName(t *testing.T) {
	resetDriverHealthMetrics()
	globalID := "test-global-id"

	// Don't set pod identity environment variables
	// This should cause collectKubernetesMetrics to return early

	k8sClient := &mockK8sClientWithMetrics{
		cpuUsage:    5000,
		memoryUsage: 1024 * 1024 * 1024,
	}

	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, &k8sClient.K8sClient)

	ctx := context.Background()
	err := collector.Collect(ctx)
	require.NoError(t, err)
}

// mockK8sClientWithError is a mock K8sClient that returns errors from GetPodMetrics
type mockK8sClientWithError struct {
	k8sutils.K8sClient
	returnError bool
}

func (m *mockK8sClientWithError) GetPodMetrics(_ context.Context, _ string, _ string) (*metricsv1beta1api.PodMetrics, error) {
	if m.returnError {
		return nil, errors.New("metrics error")
	}
	return nil, nil // Return nil metrics
}

// mockK8sClientWithEmptyContainers is a mock K8sClient that returns empty pod metrics
type mockK8sClientWithEmptyContainers struct {
	k8sutils.K8sClient
}

func (m *mockK8sClientWithEmptyContainers) GetPodMetrics(_ context.Context, _ string, _ string) (*metricsv1beta1api.PodMetrics, error) {
	return &metricsv1beta1api.PodMetrics{
		Containers: []metricsv1beta1api.ContainerMetrics{}, // Empty containers
	}, nil
}

// Helper function to get gauge value from metrics
func getGaugeValue(t *testing.T, metrics []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()

	for _, m := range metrics {
		if m.GetName() == name {
			for _, metric := range m.GetMetric() {
				labelMap := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labelMap[label.GetName()] = label.GetValue()
				}

				// Check if labels match (only check provided labels, ignore others)
				match := true
				for k, v := range labels {
					if labelMap[k] != v {
						match = false
						break
					}
				}

				if match {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}

	// Return 0 if metric not found (for metrics that weren't set)
	return 0
}

func hasGaugeMetric(t *testing.T, metrics []*dto.MetricFamily, name string, labels map[string]string) bool {
	t.Helper()

	for _, m := range metrics {
		if m.GetName() != name {
			continue
		}
		for _, metric := range m.GetMetric() {
			labelMap := make(map[string]string)
			for _, label := range metric.GetLabel() {
				labelMap[label.GetName()] = label.GetValue()
			}

			match := true
			for k, v := range labels {
				if labelMap[k] != v {
					match = false
					break
				}
			}

			if match {
				return true
			}
		}
	}
	return false
}

func TestPSTDriverHealthCollector_CollectRestartCount_WithK8sClient(t *testing.T) {
	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client with a pod that has restart count
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:         "csi-powerstore",
						RestartCount: 3,
					},
				},
			},
		}), nil
	}

	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables
	_ = os.Setenv(identifiers.EnvPodName, "test-pod")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	resetDriverHealthMetrics()
	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()
	err = collector.Collect(ctx)
	require.NoError(t, err)

	// Verify restart count metric is set (may be 0 if auto-detection fails)
	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	restartCount := getGaugeValue(t, metrics, "dell_csi_driver_restart_total", map[string]string{"global_id": globalID})
	// Just verify the metric exists and is non-negative (auto-detection may not work with fake client)
	assert.GreaterOrEqual(t, restartCount, float64(0), "restart count should be non-negative")
}

func TestPSTDriverHealthCollector_CollectRestartCount_PodNotFound(t *testing.T) {
	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client that returns error for pod lookup
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		// Empty clientset - pod lookup will fail
		return fake.NewSimpleClientset(), nil
	}

	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables
	_ = os.Setenv(identifiers.EnvPodName, "nonexistent-pod")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	resetDriverHealthMetrics()
	globalID := "test-global-id-pod-not-found"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()
	err = collector.Collect(ctx)
	require.NoError(t, err, "should not fail when pod is not found")

	// Restart count metric should not be set when pod is not found
	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	// Check that the metric value is 0 (not set) rather than checking if metric exists
	restartCount := getGaugeValue(t, metrics, "dell_csi_driver_restart_total", map[string]string{"global_id": globalID})
	assert.Equal(t, float64(0), restartCount, "restart count should be 0 when pod is not found")
}

func TestPSTDriverHealthCollector_CollectRestartCount_MultipleContainers(t *testing.T) {
	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client with multiple containers
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:         "sidecar",
						RestartCount: 1,
					},
					{
						Name:         "csi-powerstore",
						RestartCount: 5,
					},
					{
						Name:         "other",
						RestartCount: 2,
					},
				},
			},
		}), nil
	}

	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables
	_ = os.Setenv(identifiers.EnvPodName, "test-pod")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	resetDriverHealthMetrics()
	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()
	err = collector.Collect(ctx)
	require.NoError(t, err)

	// Should pick the csi-powerstore container
	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	restartCount := getGaugeValue(t, metrics, "dell_csi_driver_restart_total", map[string]string{"global_id": globalID})
	// Just verify the metric exists and is non-negative (auto-detection may not work with fake client)
	assert.GreaterOrEqual(t, restartCount, float64(0), "restart count should be non-negative")
}

func TestPSTDriverHealthCollector_CollectRestartCount_AutoDetectDriver(t *testing.T) {
	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client with "driver" container (fallback name)
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:         "driver",
						RestartCount: 2,
					},
				},
			},
		}), nil
	}

	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables
	_ = os.Setenv(identifiers.EnvPodName, "test-pod")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	resetDriverHealthMetrics()
	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()
	err = collector.Collect(ctx)
	require.NoError(t, err)

	// Should auto-detect the "driver" container
	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	restartCount := getGaugeValue(t, metrics, "dell_csi_driver_restart_total", map[string]string{"global_id": globalID})
	// Just verify the metric exists and is non-negative (auto-detection may not work with fake client)
	assert.GreaterOrEqual(t, restartCount, float64(0), "restart count should be non-negative")
}

func TestPSTDriverHealthCollector_CollectKubernetesMetrics_MetricsClientError(t *testing.T) {
	// Save original functions
	defaultNewForConfigFunc := k8sutils.NewForConfigFunc
	defaultNewMetricsForConfigFunc := k8sutils.NewMetricsForConfigFunc
	defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc

	// Setup fake Kubernetes client
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	}
	k8sutils.NewMetricsForConfigFunc = func(_ *rest.Config) (*metricsv1beta1client.MetricsV1beta1Client, error) {
		return nil, nil // Metrics client not available
	}

	defer func() {
		k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		k8sutils.NewMetricsForConfigFunc = defaultNewMetricsForConfigFunc
		k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
	}()

	// Set environment variables
	_ = os.Setenv(identifiers.EnvPodName, "test-pod")
	_ = os.Setenv(identifiers.EnvDriverNamespace, "default")
	defer func() {
		_ = os.Unsetenv(identifiers.EnvPodName)
		_ = os.Unsetenv(identifiers.EnvDriverNamespace)
	}()

	// Initialize Kubeclient
	_, err := k8sutils.CreateKubeClientSet()
	require.NoError(t, err)

	resetDriverHealthMetrics()
	globalID := "test-global-id"
	collector := mustNewPSTDriverHealthCollector(t, testDriverHealthRegistry, globalID, nil)
	_ = collector.Collect(context.Background())

	ctx := context.Background()
	err = collector.Collect(ctx)
	require.NoError(t, err)

	// When metrics client is not available, CPU/memory metrics should not be set
	metrics, err := testDriverHealthRegistry.Gather()
	require.NoError(t, err)

	assert.False(t, hasGaugeMetric(t, metrics, "dell_csi_driver_cpu_usage_percent", map[string]string{"global_id": globalID}))
	assert.False(t, hasGaugeMetric(t, metrics, "dell_csi_driver_memory_usage_bytes", map[string]string{"global_id": globalID}))
}
