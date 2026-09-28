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

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()

	assert.NotNil(t, registry)
	assert.IsType(t, &prometheus.Registry{}, registry)
}

func TestNewRegistry_Empty(t *testing.T) {
	registry := NewRegistry()

	// Verify registry is empty (no default collectors)
	metrics, err := registry.Gather()
	assert.NoError(t, err)
	// Should be empty since we didn't register any collectors
	assert.Empty(t, metrics)
}

func TestNewRegistry_SeparateInstances(t *testing.T) {
	registry1 := NewRegistry()
	registry2 := NewRegistry()

	// Should be separate instances
	assert.NotSame(t, registry1, registry2)
}

func TestNewRegistry_CanRegisterMetrics(t *testing.T) {
	registry := NewRegistry()

	// Register a test metric
	testCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_counter",
		Help: "A test counter",
	})
	err := registry.Register(testCounter)
	assert.NoError(t, err)

	// Verify metric is registered
	metrics, err := registry.Gather()
	require.NoError(t, err)

	found := false
	for _, m := range metrics {
		if m.GetName() == "test_counter" {
			found = true
			break
		}
	}
	assert.True(t, found)
}
