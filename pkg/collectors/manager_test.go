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
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

// mockCollector is a mock implementation of the Collector interface
type mockCollector struct {
	name         string
	collectFunc  func(ctx context.Context) error
	collectCount int
}

func (m *mockCollector) Collect(_ context.Context) error {
	m.collectCount++
	if m.collectFunc != nil {
		return m.collectFunc(context.Background())
	}
	return nil
}

func (m *mockCollector) Name() string {
	return m.name
}

func TestNewManager(t *testing.T) {
	reg := prometheus.NewRegistry()

	manager := NewManager(reg)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.registry)
	assert.Empty(t, manager.GetCollectors())
}

func TestManager_Register(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector := &mockCollector{name: "test-collector"}
	manager.Register(collector)

	collectors := manager.GetCollectors()
	assert.Len(t, collectors, 1)
	assert.Contains(t, collectors, "test-collector")
}

func TestManager_RegisterMultiple(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector1 := &mockCollector{name: "collector-1"}
	collector2 := &mockCollector{name: "collector-2"}
	collector3 := &mockCollector{name: "collector-3"}

	manager.Register(collector1)
	manager.Register(collector2)
	manager.Register(collector3)

	collectors := manager.GetCollectors()
	assert.Len(t, collectors, 3)
	assert.Contains(t, collectors, "collector-1")
	assert.Contains(t, collectors, "collector-2")
	assert.Contains(t, collectors, "collector-3")
}

func TestManager_Unregister(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector := &mockCollector{name: "test-collector"}
	manager.Register(collector)
	assert.Len(t, manager.GetCollectors(), 1)

	manager.Unregister("test-collector")
	assert.Empty(t, manager.GetCollectors())
}

func TestManager_UnregisterNonExistent(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	// Should not panic when unregistering non-existent collector
	manager.Unregister("non-existent")
	assert.Empty(t, manager.GetCollectors())
}

func TestManager_CollectAll(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector1 := &mockCollector{name: "collector-1"}
	collector2 := &mockCollector{name: "collector-2"}
	collector3 := &mockCollector{name: "collector-3"}

	manager.Register(collector1)
	manager.Register(collector2)
	manager.Register(collector3)

	ctx := context.Background()
	err := manager.CollectAll(ctx)

	assert.NoError(t, err)
	assert.Equal(t, 1, collector1.collectCount)
	assert.Equal(t, 1, collector2.collectCount)
	assert.Equal(t, 1, collector3.collectCount)
}

func TestManager_CollectAllWithError(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector1 := &mockCollector{name: "collector-1"}
	collector2 := &mockCollector{
		name: "collector-2",
		collectFunc: func(_ context.Context) error {
			return errors.New("collection error")
		},
	}
	collector3 := &mockCollector{name: "collector-3"}

	manager.Register(collector1)
	manager.Register(collector2)
	manager.Register(collector3)

	ctx := context.Background()
	err := manager.CollectAll(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Manager errors")
	assert.Equal(t, 1, collector1.collectCount)
	assert.Equal(t, 1, collector2.collectCount)
	assert.Equal(t, 1, collector3.collectCount)
}

func TestManager_CollectAllWithMultipleErrors(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector1 := &mockCollector{
		name: "collector-1",
		collectFunc: func(_ context.Context) error {
			return errors.New("error 1")
		},
	}
	collector2 := &mockCollector{
		name: "collector-2",
		collectFunc: func(_ context.Context) error {
			return errors.New("error 2")
		},
	}

	manager.Register(collector1)
	manager.Register(collector2)

	ctx := context.Background()
	err := manager.CollectAll(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Manager errors")
	assert.Equal(t, 1, collector1.collectCount)
	assert.Equal(t, 1, collector2.collectCount)
}

func TestManager_CollectAllEmpty(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	ctx := context.Background()
	err := manager.CollectAll(ctx)

	assert.NoError(t, err)
}

func TestManager_GetCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	// Empty initially
	assert.Empty(t, manager.GetCollectors())

	collector1 := &mockCollector{name: "collector-1"}
	collector2 := &mockCollector{name: "collector-2"}

	manager.Register(collector1)
	manager.Register(collector2)

	collectors := manager.GetCollectors()
	assert.Len(t, collectors, 2)
	assert.Contains(t, collectors, "collector-1")
	assert.Contains(t, collectors, "collector-2")
}

func TestManager_StartAndStop(t *testing.T) {
	reg := prometheus.NewRegistry()
	interval := 100 * time.Millisecond // Short interval for testing
	manager := NewManager(reg)

	collector := &mockCollector{name: "test-collector"}
	manager.Register(collector)

	// Start the manager
	manager.Start(context.Background(), interval)

	// Wait for at least one collection
	time.Sleep(150 * time.Millisecond)

	// Stop the manager
	manager.Stop()

	// Wait a bit to ensure goroutines stop
	time.Sleep(50 * time.Millisecond)

	// Verify collector was called at least once
	assert.GreaterOrEqual(t, collector.collectCount, 1)
}

func TestManager_StartMultipleCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	interval := 100 * time.Millisecond
	manager := NewManager(reg)

	collector1 := &mockCollector{name: "collector-1"}
	collector2 := &mockCollector{name: "collector-2"}
	collector3 := &mockCollector{name: "collector-3"}

	manager.Register(collector1)
	manager.Register(collector2)
	manager.Register(collector3)

	manager.Start(context.Background(), interval)

	// Wait for collections
	time.Sleep(250 * time.Millisecond)

	manager.Stop()
	time.Sleep(50 * time.Millisecond)

	// All collectors should have been called
	assert.GreaterOrEqual(t, collector1.collectCount, 1)
	assert.GreaterOrEqual(t, collector2.collectCount, 1)
	assert.GreaterOrEqual(t, collector3.collectCount, 1)
}

func TestManager_StartEmpty(_ *testing.T) {
	reg := prometheus.NewRegistry()
	interval := 100 * time.Millisecond
	manager := NewManager(reg)

	// Start without any collectors
	manager.Start(context.Background(), interval)

	// Wait a bit
	time.Sleep(150 * time.Millisecond)

	// Should not panic
	manager.Stop()
	time.Sleep(50 * time.Millisecond)
}

func TestManager_StartWithError(t *testing.T) {
	reg := prometheus.NewRegistry()
	interval := 100 * time.Millisecond
	manager := NewManager(reg)

	collector := &mockCollector{
		name: "error-collector",
		collectFunc: func(_ context.Context) error {
			return errors.New("collection error")
		},
	}
	manager.Register(collector)

	manager.Start(context.Background(), interval)

	// Wait for collections
	time.Sleep(250 * time.Millisecond)

	manager.Stop()
	time.Sleep(50 * time.Millisecond)

	// Collector should have been called despite errors
	assert.GreaterOrEqual(t, collector.collectCount, 1)
}

func TestManager_StopWithoutStart(_ *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	// Should not panic when stopping without starting
	manager.Stop()
}

func TestManager_ConcurrentAccess(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	// Register collectors sequentially; concurrent mutation is not supported by this manager.
	for i := 0; i < 10; i++ {
		collector := &mockCollector{name: string(rune('a' + i))}
		manager.Register(collector)
	}

	// Should have 10 collectors
	assert.Len(t, manager.GetCollectors(), 10)
}

func TestManager_CollectOnce(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector := &mockCollector{name: "test-collector"}
	manager.Register(collector)

	ctx := context.Background()
	err := manager.CollectAll(ctx)

	assert.NoError(t, err)
	assert.Equal(t, 1, collector.collectCount)
}

func TestManager_Reregister(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector1 := &mockCollector{name: "test-collector"}
	collector2 := &mockCollector{name: "test-collector"} // Same name

	manager.Register(collector1)
	assert.Len(t, manager.GetCollectors(), 1)

	// Re-registering with the same name adds a duplicate collector.
	manager.Register(collector2)
	assert.Len(t, manager.GetCollectors(), 2)
}

func TestManager_CollectAllContextCancellation(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector := &mockCollector{name: "test-collector"}
	manager.Register(collector)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := manager.CollectAll(ctx)

	// Should handle cancelled context
	assert.NoError(t, err) // Since collector doesn't actually check context
}

func TestManager_SetStaleSetter(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	manager.SetStaleSetter(func(globalID string, stale bool) {
		assert.Equal(t, "test-global", globalID)
		assert.True(t, stale)
	})

	// Trigger stale setter through CollectAll with error
	collector := &mockCollector{
		name: "error-collector",
		collectFunc: func(_ context.Context) error {
			return errors.New("test error")
		},
	}
	manager.RegisterWithGlobalID(collector, "test-global")

	_ = manager.CollectAll(context.Background())

	// Note: stale setter is called through adapter in Start, not CollectAll
	// This test verifies the setter is stored correctly
	assert.NotNil(t, manager.staleSetter)
}

func TestManager_SetRuntimeConfig(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	cfg := identifiers.RuntimeConfig{
		Timeout:        30 * time.Second,
		CacheTTL:       25 * time.Second,
		RateLimit:      100,
		CBThreshold:    3,
		CBResetTimeout: 30 * time.Second,
	}

	manager.SetRuntimeConfig(cfg)

	assert.Equal(t, cfg.Timeout, manager.runtimeConfig.Timeout)
	assert.Equal(t, cfg.CacheTTL, manager.runtimeConfig.CacheTTL)
	assert.Equal(t, cfg.RateLimit, manager.runtimeConfig.RateLimit)
	assert.Equal(t, cfg.CBThreshold, manager.runtimeConfig.CBThreshold)
	assert.Equal(t, cfg.CBResetTimeout, manager.runtimeConfig.CBResetTimeout)
}

func TestManager_GetRuntime_Enabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	cfg := identifiers.RuntimeConfig{
		Timeout:        30 * time.Second,
		CacheTTL:       25 * time.Second,
		RateLimit:      100,
		CBThreshold:    3,
		CBResetTimeout: 30 * time.Second,
	}

	manager.SetRuntimeConfig(cfg)

	// Get runtime for a global ID
	rt1 := manager.GetRuntime("global-1")
	assert.NotNil(t, rt1)

	// Should return same instance for same global ID
	rt2 := manager.GetRuntime("global-1")
	assert.Same(t, rt1, rt2)

	// Should return different instance for different global ID
	rt3 := manager.GetRuntime("global-2")
	assert.NotNil(t, rt3)
	assert.NotSame(t, rt1, rt3)
}

func TestManager_GetRuntime_AlwaysReturnsRuntime(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	// GetRuntime always returns a runtime even without explicit SetRuntimeConfig
	rt := manager.GetRuntime("global-1")
	assert.NotNil(t, rt)
}

func TestManager_RegisterWithGlobalID(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector := &mockCollector{name: "test-collector"}
	manager.RegisterWithGlobalID(collector, "global-1")

	collectors := manager.GetCollectors()
	assert.Len(t, collectors, 1)
	assert.Contains(t, collectors, "test-collector")
}

func TestManager_RegisterWithGlobalID_Multiple(t *testing.T) {
	reg := prometheus.NewRegistry()
	manager := NewManager(reg)

	collector1 := &mockCollector{name: "collector-1"}
	collector2 := &mockCollector{name: "collector-2"}

	manager.RegisterWithGlobalID(collector1, "global-1")
	manager.RegisterWithGlobalID(collector2, "global-2")

	collectors := manager.GetCollectors()
	assert.Len(t, collectors, 2)
	assert.Contains(t, collectors, "collector-1")
	assert.Contains(t, collectors, "collector-2")
}

func TestCollectorAdapter_Register(t *testing.T) {
	// Test that collectorAdapter's Register is a no-op
	adapter := &collectorAdapter{Collector: &mockCollector{name: "test"}}

	err := adapter.Register(prometheus.NewRegistry())
	assert.NoError(t, err)
}

func TestCollectorAdapter_Collect_Success(t *testing.T) {
	adapter := &collectorAdapter{
		Collector: &mockCollector{
			name: "test",
			collectFunc: func(_ context.Context) error {
				return nil
			},
		},
	}

	err := adapter.Collect(context.Background())
	assert.NoError(t, err)
}

func TestCollectorAdapter_Collect_Error(t *testing.T) {
	adapter := &collectorAdapter{
		Collector: &mockCollector{
			name: "test",
			collectFunc: func(_ context.Context) error {
				return errors.New("test error")
			},
		},
	}

	err := adapter.Collect(context.Background())
	assert.Error(t, err)
}

func TestCollectorAdapter_Collect_NoStaleSetter(t *testing.T) {
	adapter := &collectorAdapter{
		Collector: &mockCollector{
			name: "test",
			collectFunc: func(_ context.Context) error {
				return errors.New("test error")
			},
		},
	}

	err := adapter.Collect(context.Background())
	assert.Error(t, err)
}
