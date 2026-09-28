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

// Package collectors provides metrics collection lifecycle management for csi-powerstore.
// This package now uses the csm-metrics-common shared library for standardized collector management.
package collectors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csm-metrics-common/pkg/collector"
	"github.com/dell/csmlog"
	"github.com/prometheus/client_golang/prometheus"
)

// Collector defines the interface for metrics collectors.
// This is a simple two-method interface (Collect, Name) - Register is not required
// because constructors should register metrics atomically with construction.
type Collector interface {
	// Collect fetches and updates metrics for the collector.
	Collect(ctx context.Context) error

	// Name returns the collector name.
	Name() string
}

// StaleSetter is an optional interface that collectors can implement to set stale status.
type StaleSetter interface {
	// SetStale sets the stale status for metrics. Should be called with true on collection failure.
	SetStale(stale bool)
}

// collectorAdapter bridges a Collector to csmcollector.MetricsCollector.
// The Register method is a no-op because constructors register metrics directly.
type collectorAdapter struct {
	Collector
}

func (a *collectorAdapter) Register(_ prometheus.Registerer) error { return nil }

// Collect wraps the collector's Collect method.
func (a *collectorAdapter) Collect(ctx context.Context) error {
	return a.Collector.Collect(ctx)
}

// Manager wraps the csm-metrics-common Manager with PowerStore-specific functionality.
type Manager struct {
	collectors         []Collector
	collectorGlobalIDs map[Collector]string // collector instance -> globalID mapping
	csmMgr             *collector.Manager
	registry           prometheus.Registerer
	staleSetter        func(globalID string, stale bool) // Function to set stale status
	runtimeConfig      identifiers.RuntimeConfig         // Runtime configuration
	runtimes           map[string]*MetricsRuntime        // globalID -> runtime
	csmMu              sync.RWMutex
}

// NewManager creates a new Manager using the PowerStore pattern (simplified interface).
func NewManager(registry prometheus.Registerer) *Manager {
	return &Manager{
		collectors:         []Collector{},
		collectorGlobalIDs: make(map[Collector]string),
		registry:           registry,
		staleSetter: func(_ string, _ bool) {
			// Default no-op stale setter
		},
		runtimes: make(map[string]*MetricsRuntime),
	}
}

// SetStaleSetter sets the function to call when metrics should be marked as stale or fresh.
func (m *Manager) SetStaleSetter(staleSetter func(globalID string, stale bool)) {
	m.staleSetter = staleSetter
}

// SetRuntimeConfig sets the runtime configuration for resilience features.
func (m *Manager) SetRuntimeConfig(cfg identifiers.RuntimeConfig) {
	m.runtimeConfig = cfg
	// Wrap staleSetter in a closure to resolve at runtime, avoiding race conditions
	m.runtimeConfig.StaleReporter = func() func(globalID string, stale bool) {
		return m.staleSetter
	}
}

// GetRuntime returns the MetricsRuntime for a given globalID, creating it if needed.
func (m *Manager) GetRuntime(globalID string) *MetricsRuntime {
	if rt, exists := m.runtimes[globalID]; exists {
		return rt
	}
	rt := NewMetricsRuntime(globalID, m.runtimeConfig)
	m.runtimes[globalID] = rt
	return rt
}

// Register adds a collector to the manager.
func (m *Manager) Register(collector Collector) {
	m.collectors = append(m.collectors, collector)
}

// RegisterWithGlobalID adds a collector to the manager with its associated globalID.
func (m *Manager) RegisterWithGlobalID(collector Collector, globalID string) {
	m.collectors = append(m.collectors, collector)
	m.collectorGlobalIDs[collector] = globalID
}

// Unregister removes a collector from the manager by name.
func (m *Manager) Unregister(name string) {
	for i, c := range m.collectors {
		if c != nil && c.Name() == name {
			m.collectors = append(m.collectors[:i], m.collectors[i+1:]...)
			return
		}
	}
}

// Start begins periodic metrics collection for all registered collectors.
// This converts collectors to adapters and uses csm-metrics-common's per-goroutine runner.
func (m *Manager) Start(ctx context.Context, interval time.Duration) {
	csmlog.GetLogger().Infof("Starting metrics collection with csm-metrics-common manager")

	adapters := make([]collector.MetricsCollector, len(m.collectors))
	for i, c := range m.collectors {
		adapters[i] = &collectorAdapter{
			Collector: c,
		}
	}

	csmMgr := collector.NewManager(adapters, interval)
	m.csmMu.Lock()
	m.csmMgr = csmMgr
	m.csmMu.Unlock()

	csmMgr.Start(ctx)

	csmlog.GetLogger().Infof("Metrics collection started for %d collectors", len(m.collectors))
}

// Stop gracefully stops all collectors.
func (m *Manager) Stop() {
	csmlog.GetLogger().Info("Stopping metrics collectors")
	m.csmMu.RLock()
	csmMgr := m.csmMgr
	m.csmMu.RUnlock()
	if csmMgr != nil {
		csmMgr.Stop()
	}
	csmlog.GetLogger().Info("All metrics collectors stopped")
}

// CollectAll triggers an immediate collection from all registered collectors.
// This is used in unit tests; production code should call Start.
func (m *Manager) CollectAll(ctx context.Context) error {
	csmlog.GetLogger().Debug("Triggering immediate collection from all collectors")

	var errs []string
	for _, c := range m.collectors {
		if err := c.Collect(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", c.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Manager errors: %v", errs)
	}
	return nil
}

// GetCollectors returns a list of registered collector names.
func (m *Manager) GetCollectors() []string {
	names := make([]string, 0, len(m.collectors))
	for _, c := range m.collectors {
		if c != nil {
			names = append(names, c.Name())
		}
	}
	return names
}
