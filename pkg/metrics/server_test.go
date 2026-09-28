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

package metrics_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func freeMetricsPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

// U-PST-16: MetricsServer startup — /healthz returns 200.
func TestMetricsServer_Healthz_Returns200(t *testing.T) {
	reg := prometheus.NewRegistry()
	port := freeMetricsPort(t)
	srv := metrics.NewServer(fmt.Sprintf(":%d", port), reg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Start(ctx) }()
	time.Sleep(80 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/healthz", port))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode, "/healthz must return 200")
	assert.Equal(t, "ok", string(body))
}

// U-PST-17: dell_powerstore_metrics_stale = 0 on fresh collection; = 1 on stale.
func TestMetricsServer_StaleGauge_TogglesFreshAndStale(t *testing.T) {
	reg := prometheus.NewRegistry()
	port := freeMetricsPort(t)
	srv := metrics.NewServer(fmt.Sprintf(":%d", port), reg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Start(ctx) }()
	time.Sleep(80 * time.Millisecond)

	// Initially fresh
	srv.SetStale("global-1", false)
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Contains(t, string(body), `dell_powerstore_metrics_stale{global_id="global-1"} 0`,
		"fresh collection must report stale=0")

	// Now stale
	srv.SetStale("global-1", true)
	resp2, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	require.NoError(t, err)
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	assert.Contains(t, string(body2), `dell_powerstore_metrics_stale{global_id="global-1"} 1`,
		"stale collection must report stale=1")
}

func TestNewServer_WithRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := metrics.NewServer(":0", reg)

	assert.NotNil(t, srv)
	assert.NotNil(t, srv.MetricsServer)
}

func TestNewServer_WithRegisterer(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := metrics.NewServer(":0", reg)

	assert.NotNil(t, srv)
	assert.NotNil(t, srv.MetricsServer)
}

func TestNewServer_WithCustomRegisterer(t *testing.T) {
	// A registerer that does not implement Gatherer must cause a panic — it prevents
	// the server from silently serving an empty /metrics endpoint.
	customReg := &customRegisterer{}
	assert.Panics(t, func() {
		metrics.NewServer(":0", customReg)
	})
}

func TestNewServer_DifferentAddresses(t *testing.T) {
	reg1 := prometheus.NewRegistry()
	reg2 := prometheus.NewRegistry()
	srv1 := metrics.NewServer(":8080", reg1)
	srv2 := metrics.NewServer(":9090", reg2)

	assert.NotNil(t, srv1)
	assert.NotNil(t, srv2)
	assert.NotSame(t, srv1, srv2)
}

func TestNewServerWithTLS_Configuration(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := metrics.NewServerWithTLS(":8443", reg, "/path/to/cert.pem", "/path/to/key.pem")

	assert.NotNil(t, srv)
	assert.NotNil(t, srv.MetricsServer)
}

func TestNewServerWithTLS_WithCustomRegisterer(t *testing.T) {
	// A registerer that does not implement Gatherer must cause a panic — it prevents
	// the server from silently serving an empty /metrics endpoint.
	customReg := &customRegisterer{}
	assert.Panics(t, func() {
		metrics.NewServerWithTLS(":8443", customReg, "/path/to/cert.pem", "/path/to/key.pem")
	})
}

func TestNewServerWithTLS_DifferentAddresses(t *testing.T) {
	reg1 := prometheus.NewRegistry()
	reg2 := prometheus.NewRegistry()
	srv1 := metrics.NewServerWithTLS(":8443", reg1, "cert1.pem", "key1.pem")
	srv2 := metrics.NewServerWithTLS(":9443", reg2, "cert2.pem", "key2.pem")

	assert.NotNil(t, srv1)
	assert.NotNil(t, srv2)
	assert.NotSame(t, srv1, srv2)
}

func TestStartServerFromEnv(t *testing.T) {
	t.Setenv(identifiers.EnvMetricsPort, "0")
	t.Setenv(identifiers.EnvMetricsTLSCertFile, "")
	t.Setenv(identifiers.EnvMetricsTLSKeyFile, "")

	reg := prometheus.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv := metrics.StartServerFromEnv(ctx, reg)

	require.NotNil(t, srv)
	assert.NotNil(t, srv.MetricsServer)
}

func TestMetricsServer_StartTLS_ContextCancellation(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := metrics.NewServerWithTLS(":0", reg, "test-cert.pem", "test-key.pem")

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.StartTLS(ctx)
	}()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Should return error (context cancelled or TLS config error)
	select {
	case err := <-errChan:
		// We expect an error since we don't have valid cert files
		assert.Error(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("StartTLS did not return within timeout")
	}
}

func TestMetricsServer_StartTLS_InvalidConfig(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := metrics.NewServerWithTLS(":0", reg, "nonexistent-cert.pem", "nonexistent-key.pem")

	ctx := context.Background()
	err := srv.StartTLS(ctx)

	// Should fail due to missing cert files
	assert.Error(t, err)
}

// customRegisterer is a minimal implementation of prometheus.Registerer
// that doesn't implement prometheus.Gatherer to test fallback logic
type customRegisterer struct{}

func (c *customRegisterer) Register(_ prometheus.Collector) error {
	return nil
}

func (c *customRegisterer) MustRegister(_ ...prometheus.Collector) {
}

func (c *customRegisterer) Unregister(_ prometheus.Collector) bool {
	return true
}
