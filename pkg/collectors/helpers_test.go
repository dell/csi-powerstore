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
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatherPSTMetric retrieves a metric family by name from a Prometheus registry.
func gatherPSTMetric(t *testing.T, reg prometheus.Gatherer, name string) *dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

// gaugePST returns the gauge value for a metric with matching labels.
func gaugePST(mf *dto.MetricFamily, labels map[string]string) (float64, bool) {
	if mf == nil {
		return 0, false
	}
	for _, m := range mf.GetMetric() {
		got := make(map[string]string)
		for _, lp := range m.GetLabel() {
			got[lp.GetName()] = lp.GetValue()
		}
		match := true
		for k, v := range labels {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func TestRegisterGaugeVec(t *testing.T) {
	// Test nil registry
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_metric",
		Help: "test help",
	}, []string{"label"})

	_, err := registerGaugeVec(nil, gauge, "test_metric")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "registry is nil")

	// Test successful registration
	reg := prometheus.NewRegistry()
	result, err := registerGaugeVec(reg, gauge, "test_metric")
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Test already registered (same metric)
	result2, err := registerGaugeVec(reg, gauge, "test_metric")
	assert.NoError(t, err)
	assert.NotNil(t, result2)

	// Test already registered with different type (should fail)
	// Register a CounterVec with the same name
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_metric2",
		Help: "test help",
	}, []string{"label"})

	reg2 := prometheus.NewRegistry()
	err = reg2.Register(counter)
	require.NoError(t, err)

	// Try to register a GaugeVec with the same name
	gauge2 := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_metric2",
		Help: "test help",
	}, []string{"label"})

	_, err = registerGaugeVec(reg2, gauge2, "test_metric2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected existing collector type")
}
