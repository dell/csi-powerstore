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

package collectors

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestRegisterGaugeVec_NilRegistry(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_metric",
		Help: "Test metric",
	}, []string{"label"})

	_, err := registerGaugeVec(nil, gauge, "test_metric")
	require.Error(t, err)
	require.Contains(t, err.Error(), "registry is nil")
}

func TestRegisterGaugeVec_AlreadyRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_metric",
		Help: "Test metric",
	}, []string{"label"})

	// Register once
	_, err := registerGaugeVec(reg, gauge, "test_metric")
	require.NoError(t, err)

	// Register again (should return the existing gauge)
	result, err := registerGaugeVec(reg, gauge, "test_metric")
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestRegisterGaugeVec_UnexpectedCollectorType(t *testing.T) {
	reg := prometheus.NewRegistry()
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_metric",
		Help: "Test metric",
	}, []string{"label"})

	// Register a counter with the same name and help string
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_metric",
		Help: "Test metric",
	}, []string{"label"})
	reg.MustRegister(counter)

	// Try to register gauge with same name (should fail with unexpected type error)
	_, err := registerGaugeVec(reg, gauge, "test_metric")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected existing collector type")
}
