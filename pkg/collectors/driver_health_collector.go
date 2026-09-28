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
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csm-metrics-common/pkg/naming"
	"github.com/dell/csmlog"
	"github.com/prometheus/client_golang/prometheus"
	k8score "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PSTDriverHealthCollector collects PowerStore driver health metrics.
type PSTDriverHealthCollector struct {
	globalID       string
	startTime      time.Time
	uptimeGauge    *prometheus.GaugeVec
	restartTotal   *prometheus.GaugeVec
	goroutineCount *prometheus.GaugeVec
	connPoolActive *prometheus.GaugeVec
	cpuUsage       *prometheus.GaugeVec
	memUsage       *prometheus.GaugeVec
	k8sClient      *k8sutils.K8sClient
}

// NewPSTDriverHealthCollector creates a new PSTDriverHealthCollector and registers its metrics.
func NewPSTDriverHealthCollector(reg prometheus.Registerer, globalID string, k8sClient *k8sutils.K8sClient) (*PSTDriverHealthCollector, error) {
	uptimeGauge, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: naming.MetricCSIDriverUptimeSeconds,
		Help: "Driver uptime in seconds since last restart.",
	}, []string{naming.LabelGlobalID, "pod", "node", "namespace", "instance_type"}), naming.MetricCSIDriverUptimeSeconds)
	if err != nil {
		return nil, err
	}
	restartTotal, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: naming.MetricCSIDriverRestartTotal,
		Help: "Total driver restarts from Kubernetes Pod API.",
	}, []string{naming.LabelGlobalID, "pod", "node", "namespace", "instance_type"}), naming.MetricCSIDriverRestartTotal)
	if err != nil {
		return nil, err
	}
	goroutineCount, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: naming.MetricCSIGoroutineCount,
		Help: "Number of active goroutines.",
	}, []string{naming.LabelGlobalID, "pod", "node", "namespace", "instance_type"}), naming.MetricCSIGoroutineCount)
	if err != nil {
		return nil, err
	}
	connPoolActive, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: naming.MetricCSIConnectionPoolActive,
		Help: "Proxy for PowerStore client activity based on ready containers in the driver pod.",
	}, []string{naming.LabelGlobalID, "pod", "node", "namespace", "instance_type"}), naming.MetricCSIConnectionPoolActive)
	if err != nil {
		return nil, err
	}
	cpuUsage, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: naming.MetricCSIDriverCPUUsagePercent,
		Help: "CSI driver CPU usage percentage from Kubernetes metrics API.",
	}, []string{naming.LabelGlobalID, "pod", "node", "namespace", "instance_type"}), naming.MetricCSIDriverCPUUsagePercent)
	if err != nil {
		return nil, err
	}
	memUsage, err := registerGaugeVec(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: naming.MetricCSIDriverMemoryUsageBytes,
		Help: "CSI driver memory usage in bytes from Kubernetes metrics API.",
	}, []string{naming.LabelGlobalID, "pod", "node", "namespace", "instance_type"}), naming.MetricCSIDriverMemoryUsageBytes)
	if err != nil {
		return nil, err
	}

	return &PSTDriverHealthCollector{
		globalID:       globalID,
		startTime:      time.Now().Add(-time.Millisecond),
		uptimeGauge:    uptimeGauge,
		restartTotal:   restartTotal,
		goroutineCount: goroutineCount,
		connPoolActive: connPoolActive,
		cpuUsage:       cpuUsage,
		memUsage:       memUsage,
		k8sClient:      k8sClient,
	}, nil
}

// getPodIdentityLabels returns the pod identity labels for metrics
func (c *PSTDriverHealthCollector) getPodIdentityLabels() []string {
	podName := os.Getenv(identifiers.EnvPodName)
	nodeName := os.Getenv(identifiers.EnvKubeNodeName)
	namespace := os.Getenv(identifiers.EnvDriverNamespace)
	mode := os.Getenv(identifiers.EnvCSIMode)

	// Provide default values if env vars are not set
	if podName == "" {
		podName = "unknown"
	}
	// For controller mode, always set node to "controller" regardless of environment variable
	// This handles cases where X_CSI_NODE_NAME is incorrectly set for controller pods
	if mode == "controller" {
		nodeName = "controller"
	} else if nodeName == "" {
		// For node mode, use environment variable or default to "unknown"
		nodeName = "unknown"
	}
	if namespace == "" {
		namespace = "unknown"
	}
	if mode == "" {
		mode = "unknown"
	}

	return []string{c.globalID, podName, nodeName, namespace, mode}
}

// Collect updates driver health metrics.
func (c *PSTDriverHealthCollector) Collect(ctx context.Context) error {
	labels := c.getPodIdentityLabels()
	c.uptimeGauge.WithLabelValues(labels...).Set(time.Since(c.startTime).Seconds())
	c.goroutineCount.WithLabelValues(labels...).Set(float64(runtime.NumGoroutine()))

	// Collect restart count from Kubernetes Pod API (skip if not available)
	c.collectRestartCount(ctx)

	// Use Kubernetes metrics API (skip if not available)
	c.collectKubernetesMetrics(ctx)

	// This is a proxy signal, not the array's internal connection pool depth.
	c.collectConnectionPoolMetrics(ctx)

	return nil
}

// collectRestartCount fetches the restart count from Kubernetes Pod API
func (c *PSTDriverHealthCollector) collectRestartCount(ctx context.Context) {
	labels := c.getPodIdentityLabels()
	c.restartTotal.WithLabelValues(labels...).Set(0)

	podName := os.Getenv(identifiers.EnvPodName)
	namespace := os.Getenv(identifiers.EnvDriverNamespace)

	if podName == "" || namespace == "" {
		return
	}

	// Use instance k8sClient if available, otherwise use global client
	var k8sClient *k8sutils.K8sClient
	if c.k8sClient != nil {
		k8sClient = c.k8sClient
	} else {
		k8sClient = k8sutils.Kubeclient
	}

	if k8sClient == nil || k8sClient.Clientset == nil {
		return
	}

	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	restartCount, err := k8sClient.GetPodRestartCountAuto(callCtx, namespace, podName)
	if err != nil {
		csmlog.GetLogger().Warnf("collectRestartCount: failed to get restart count for pod %s: %v", podName, err)
		return
	}

	c.restartTotal.WithLabelValues(labels...).Set(float64(restartCount))
}

// collectConnectionPoolMetrics sets a proxy metric derived from the number of ready
// containers in the current pod. This does not measure the PowerStore HTTP client's
// internal connection pool.
func (c *PSTDriverHealthCollector) collectConnectionPoolMetrics(ctx context.Context) {
	podName := os.Getenv(identifiers.EnvPodName)
	namespace := os.Getenv(identifiers.EnvDriverNamespace)

	if podName == "" || namespace == "" {
		c.connPoolActive.WithLabelValues(c.getPodIdentityLabels()...).Set(0)
		return
	}

	// Use instance k8sClient if available, otherwise use global client
	var k8sClient *k8sutils.K8sClient
	if c.k8sClient != nil {
		k8sClient = c.k8sClient
	} else {
		k8sClient = k8sutils.Kubeclient
	}

	if k8sClient == nil || k8sClient.Clientset == nil {
		c.connPoolActive.WithLabelValues(c.getPodIdentityLabels()...).Set(0)
		return
	}

	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	pod, err := k8sClient.Clientset.CoreV1().Pods(namespace).Get(callCtx, podName, metav1.GetOptions{})
	if err != nil {
		csmlog.GetLogger().Warnf("collectConnectionPoolMetrics: failed to get pod %s: %v", podName, err)
		c.connPoolActive.WithLabelValues(c.getPodIdentityLabels()...).Set(0)
		return
	}

	readyCount := 0
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Ready {
			readyCount++
		}
	}
	c.connPoolActive.WithLabelValues(c.getPodIdentityLabels()...).Set(float64(readyCount))
}

// collectKubernetesMetrics fetches CPU/memory metrics from Kubernetes Metrics API
func (c *PSTDriverHealthCollector) collectKubernetesMetrics(ctx context.Context) {
	// Get pod name and namespace from environment variables
	podName := os.Getenv(identifiers.EnvPodName)
	namespace := os.Getenv(identifiers.EnvDriverNamespace)

	if podName == "" || namespace == "" {
		return
	}

	// Use instance k8sClient if available, otherwise use global client
	var k8sClient *k8sutils.K8sClient
	if c.k8sClient != nil {
		k8sClient = c.k8sClient
	} else {
		k8sClient = k8sutils.Kubeclient
	}

	if k8sClient == nil || k8sClient.MetricsClient == nil {
		return
	}

	// Get pod metrics from Kubernetes
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	podMetrics, err := k8sClient.GetPodMetrics(callCtx, namespace, podName)
	if err != nil {
		return
	}

	// Find the CSI driver container metrics
	for _, container := range podMetrics.Containers {
		// Match container name (typically "csi-powerstore" or "driver")
		if strings.Contains(container.Name, "csi-powerstore") || strings.Contains(container.Name, "driver") {
			// Extract CPU usage (in cores, convert to percentage)
			cpuUsage := container.Usage[k8score.ResourceCPU]
			cpuPercent := float64(cpuUsage.MilliValue()) / 10.0 // Convert millicores to percentage

			// Extract memory usage (in bytes)
			memUsage := container.Usage[k8score.ResourceMemory]

			// Set metrics with pod identity labels
			labels := c.getPodIdentityLabels()
			c.cpuUsage.WithLabelValues(labels...).Set(cpuPercent)
			c.memUsage.WithLabelValues(labels...).Set(float64(memUsage.Value()))

			return
		}
	}
}

// Name returns the collector name.
func (c *PSTDriverHealthCollector) Name() string { return "PSTDriverHealthCollector" }
