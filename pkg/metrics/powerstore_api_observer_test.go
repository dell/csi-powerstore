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

package metrics

import (
	"errors"
	"testing"
	"time"

	"github.com/dell/gopowerstore/api"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getMetricFamily(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
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

func getCounterValue(mf *dto.MetricFamily, labels map[string]string) float64 {
	if mf == nil {
		return 0
	}
	for _, m := range mf.GetMetric() {
		got := map[string]string{}
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
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

func TestNewPowerStoreAPIObserver(t *testing.T) {
	reg := prometheus.NewRegistry()
	observer, err := NewPowerStoreAPIObserver(reg, "global-1")
	require.NoError(t, err)
	require.NotNil(t, observer)

	observer.ObservePowerStoreRequest(api.RequestObservation{
		Endpoint:   "volume",
		Method:     "GET",
		StatusCode: 200,
	})
	observer.ObservePowerStoreRequest(api.RequestObservation{
		Endpoint:   "volume",
		Action:     "create",
		Method:     "POST",
		StatusCode: 500,
		Err:        errors.New("boom"),
	})

	mf := getMetricFamily(t, reg, powerStoreAPIRequestsMetricName)
	require.NotNil(t, mf)

	assert.Equal(t, 1.0, getCounterValue(mf, map[string]string{
		"global_id": "global-1",
		"endpoint":  "volume",
		"method":    "GET",
		"status":    "success",
	}))
	assert.Equal(t, 1.0, getCounterValue(mf, map[string]string{
		"global_id": "global-1",
		"endpoint":  "volume/create",
		"method":    "POST",
		"status":    "failure",
	}))
}

func TestNewPowerStoreAPIObserver_IsolatedRegistries(t *testing.T) {
	regA := prometheus.NewRegistry()
	regB := prometheus.NewRegistry()

	observerA, err := NewPowerStoreAPIObserver(regA, "global-a")
	require.NoError(t, err)
	observerB, err := NewPowerStoreAPIObserver(regB, "global-b")
	require.NoError(t, err)

	observerA.ObservePowerStoreRequest(api.RequestObservation{Endpoint: "login_session", Method: "GET", StatusCode: 200})
	observerB.ObservePowerStoreRequest(api.RequestObservation{Endpoint: "login_session", Method: "GET", StatusCode: 200})

	mfA := getMetricFamily(t, regA, powerStoreAPIRequestsMetricName)
	mfB := getMetricFamily(t, regB, powerStoreAPIRequestsMetricName)
	require.NotNil(t, mfA)
	require.NotNil(t, mfB)

	assert.Equal(t, 1.0, getCounterValue(mfA, map[string]string{
		"global_id": "global-a",
		"endpoint":  "login_session",
		"method":    "GET",
		"status":    "success",
	}))
	assert.Equal(t, 1.0, getCounterValue(mfB, map[string]string{
		"global_id": "global-b",
		"endpoint":  "login_session",
		"method":    "GET",
		"status":    "success",
	}))
}

func TestNewPowerStoreAPIObserver_NilRegistry(t *testing.T) {
	observer, err := NewPowerStoreAPIObserver(nil, "global-1")
	assert.Error(t, err)
	assert.Nil(t, observer)
}

func TestPowerStoreAPIObserver_StatusFallback(t *testing.T) {
	reg := prometheus.NewRegistry()
	observer, err := NewPowerStoreAPIObserver(reg, "global-1")
	require.NoError(t, err)

	observer.ObservePowerStoreRequest(api.RequestObservation{
		Endpoint: "cluster",
		Method:   "GET",
		Err:      errors.New("transport error"),
	})

	mf := getMetricFamily(t, reg, powerStoreAPIRequestsMetricName)
	require.NotNil(t, mf)
	assert.Equal(t, 1.0, getCounterValue(mf, map[string]string{
		"global_id": "global-1",
		"endpoint":  "cluster",
		"method":    "GET",
		"status":    "failure",
	}))
}

func TestPowerStoreAPIObserver_DurationIgnored(t *testing.T) {
	reg := prometheus.NewRegistry()
	observer, err := NewPowerStoreAPIObserver(reg, "global-1")
	require.NoError(t, err)

	observer.ObservePowerStoreRequest(api.RequestObservation{
		Endpoint:   "cluster",
		Method:     "GET",
		Duration:   25 * time.Millisecond,
		StatusCode: 204,
	})

	mf := getMetricFamily(t, reg, powerStoreAPIRequestsMetricName)
	require.NotNil(t, mf)
	assert.Equal(t, 1.0, getCounterValue(mf, map[string]string{
		"global_id": "global-1",
		"endpoint":  "cluster",
		"method":    "GET",
		"status":    "success",
	}))
}

func TestPowerStoreAPIObserver_AlreadyRegisteredCounter(t *testing.T) {
	reg := prometheus.NewRegistry()

	// Create a counter with the same name and help string to simulate AlreadyRegisteredError
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: powerStoreAPIRequestsMetricName,
		Help: "Total PowerStore REST API requests observed through gopowerstore.",
	}, []string{"global_id", "endpoint", "method", "status"})

	err := reg.Register(counter)
	require.NoError(t, err)

	// This should handle the AlreadyRegisteredError case
	observer, err := NewPowerStoreAPIObserver(reg, "global-1")
	require.NoError(t, err)
	require.NotNil(t, observer)

	// Verify the observer still works
	observer.ObservePowerStoreRequest(api.RequestObservation{
		Endpoint:   "volume",
		Method:     "GET",
		StatusCode: 200,
	})

	mf := getMetricFamily(t, reg, powerStoreAPIRequestsMetricName)
	require.NotNil(t, mf)
	assert.Equal(t, 1.0, getCounterValue(mf, map[string]string{
		"global_id": "global-1",
		"endpoint":  "volume",
		"method":    "GET",
		"status":    "success",
	}))
}
