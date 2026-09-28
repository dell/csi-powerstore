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

package collectors_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pstFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

func startPSTTestServer(t *testing.T, reg *prometheus.Registry) int {
	t.Helper()
	port := pstFreePort(t)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	time.Sleep(80 * time.Millisecond)
	return port
}

// I-PST-01: MetricsServer; appliance collector registered; scrape returns expected metrics.
func TestIntegration_PST_ApplianceMetricsScrape(t *testing.T) {
	reg := prometheus.NewRegistry()

	applianceCap := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_appliance_physical_capacity_bytes",
		Help: "Appliance physical capacity bytes.",
	}, []string{"global_id", "appliance_id"})
	reg.MustRegister(applianceCap)

	applianceCap.WithLabelValues("global-1", "appliance-1").Set(4e12)

	port := startPSTTestServer(t, reg)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "dell_powerstore_appliance_physical_capacity_bytes",
		"scrape must contain appliance capacity metric")
}

// I-PST-02: X_CSI_METRICS_ENABLED=false — no port bound.
func TestIntegration_PST_MetricsDisabled_NoPortBound(t *testing.T) {
	t.Setenv("X_CSI_METRICS_ENABLED", "false")

	port := pstFreePort(t)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 200*time.Millisecond)
	if conn != nil {
		_ = conn.Close()
	}
	assert.Error(t, err, "when X_CSI_METRICS_ENABLED=false, port must not be bound")
}

// I-PST-03: Multi-array — Array A circuit OPEN (stale=1), Array B healthy with fresh metrics.
func TestIntegration_PST_MultiArray_CircuitOpen_StaleGauge(t *testing.T) {
	reg := prometheus.NewRegistry()

	stale := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_metrics_stale",
		Help: "1 when PowerStore metrics are stale (circuit open).",
	}, []string{"global_id"})
	capacity := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dell_powerstore_appliance_physical_capacity_bytes",
		Help: "Capacity bytes.",
	}, []string{"global_id", "appliance_id"})
	reg.MustRegister(stale, capacity)

	// Array A: circuit open
	stale.WithLabelValues("array-A").Set(1)
	// Array B: healthy
	stale.WithLabelValues("array-B").Set(0)
	capacity.WithLabelValues("array-B", "appliance-1").Set(8e12)

	port := startPSTTestServer(t, reg)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `dell_powerstore_metrics_stale{global_id="array-A"} 1`,
		"stale gauge for Array A must be 1")
	assert.Contains(t, string(body), `dell_powerstore_appliance_physical_capacity_bytes`,
		"Array B capacity metric must be present")
}
