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

// Package metrics provides a lightweight Prometheus metrics HTTP server for csi-powerstore.
// This package now uses the csm-metrics-common shared library for standardized metrics infrastructure.
package metrics

import (
	"context"
	"crypto/tls"
	"strings"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csm-metrics-common/pkg/server"
	log "github.com/dell/csmlog"
	csictx "github.com/dell/gocsi/context"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// DefaultMetricsPort is the standardised metrics server port.
	DefaultMetricsPort = "8443"
)

// Server wraps the csm-metrics-common MetricsServer with PowerStore-specific functionality.
type Server struct {
	*server.MetricsServer
}

// NewServer creates a metrics Server using the provided registry.
// This uses the csm-metrics-common shared library with PowerStore-specific stale metric configuration.
func NewServer(addr string, reg prometheus.Registerer) *Server {
	// prometheus.Registry implements both Registerer and Gatherer; require callers to pass one.
	gatherer, ok := reg.(prometheus.Gatherer)
	if !ok {
		panic("metrics.NewServer: reg must implement prometheus.Gatherer (use *prometheus.Registry)")
	}

	cfg := server.Config{
		Port:            addr,
		Registry:        gatherer,
		MinTLSVersion:   tls.VersionTLS12,
		StaleMetricName: "dell_powerstore_metrics_stale",
		StaleLabels:     []string{"global_id"},
	}

	metricsServer := server.NewMetricsServer(cfg)
	return &Server{MetricsServer: metricsServer}
}

// NewServerWithTLS creates a metrics Server with TLS support.
// This uses the csm-metrics-common shared library with PowerStore-specific TLS and stale metric configuration.
func NewServerWithTLS(addr string, reg prometheus.Registerer, certFile, keyFile string) *Server {
	// prometheus.Registry implements both Registerer and Gatherer; require callers to pass one.
	gatherer, ok := reg.(prometheus.Gatherer)
	if !ok {
		panic("metrics.NewServerWithTLS: reg must implement prometheus.Gatherer (use *prometheus.Registry)")
	}

	cfg := server.Config{
		Port:            addr,
		CertFile:        certFile,
		KeyFile:         keyFile,
		Registry:        gatherer,
		MinTLSVersion:   tls.VersionTLS12,
		StaleMetricName: "dell_powerstore_metrics_stale",
		StaleLabels:     []string{"global_id"},
	}

	metricsServer := server.NewMetricsServer(cfg)
	return &Server{MetricsServer: metricsServer}
}

// StartServerFromEnv creates and starts a metrics server from PowerStore metrics env vars.
func StartServerFromEnv(ctx context.Context, registry prometheus.Registerer) *Server {
	metricsPort := DefaultMetricsPort
	if port, ok := csictx.LookupEnv(ctx, identifiers.EnvMetricsPort); ok && port != "" {
		metricsPort = port
	}
	if !strings.HasPrefix(metricsPort, ":") {
		metricsPort = ":" + metricsPort
	}

	certFile, hasCert := csictx.LookupEnv(ctx, identifiers.EnvMetricsTLSCertFile)
	keyFile, hasKey := csictx.LookupEnv(ctx, identifiers.EnvMetricsTLSKeyFile)

	var srv *Server
	if hasCert && hasKey && certFile != "" && keyFile != "" {
		srv = NewServerWithTLS(metricsPort, registry, certFile, keyFile)
	} else {
		srv = NewServer(metricsPort, registry)
	}

	go func() {
		if err := srv.Start(ctx); err != nil && ctx.Err() == nil {
			log.Errorf("metrics server stopped with error: %v", err)
		}
	}()
	return srv
}

// SetStale marks metrics for the given globalID as stale (1) or fresh (0).
// This delegates to the csm-metrics-common server's SetStale method.
func (s *Server) SetStale(globalID string, stale bool) {
	s.MetricsServer.SetStale([]string{globalID}, stale)
}

// Start begins serving metrics on the configured address until ctx is cancelled.
// This delegates to the csm-metrics-common server's Start method.
func (s *Server) Start(ctx context.Context) error {
	return s.MetricsServer.Start(ctx)
}

// StartTLS begins serving metrics with TLS on the configured address until ctx is cancelled.
// This delegates to the csm-metrics-common server's Start method (which handles TLS internally).
func (s *Server) StartTLS(ctx context.Context) error {
	return s.MetricsServer.Start(ctx)
}
