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
	"fmt"
	"sync"

	"github.com/dell/csm-metrics-common/pkg/naming"
	"github.com/dell/gopowerstore/api"
	"github.com/prometheus/client_golang/prometheus"
)

// powerStoreAPIRequestsMetricName uses the standardized metric name from csm-metrics-common
const powerStoreAPIRequestsMetricName = naming.MetricCSIAPICallTotal

var (
	powerStoreAPIObserverMu       sync.Mutex
	powerStoreAPIObserverByRegKey = map[string]*prometheus.CounterVec{}
)

// PowerStoreAPIObserver records PowerStore REST request totals using a bounded label set.
type PowerStoreAPIObserver struct {
	globalID    string
	apiRequests *prometheus.CounterVec
}

// NewPowerStoreAPIObserver creates or reuses the API request counter for a registry.
func NewPowerStoreAPIObserver(reg prometheus.Registerer, globalID string) (*PowerStoreAPIObserver, error) {
	if reg == nil {
		return nil, fmt.Errorf("powerstore api observer: registry is nil")
	}

	counter, err := getOrCreatePowerStoreAPIRequestCounter(reg)
	if err != nil {
		return nil, err
	}

	return &PowerStoreAPIObserver{
		globalID:    globalID,
		apiRequests: counter,
	}, nil
}

func getOrCreatePowerStoreAPIRequestCounter(reg prometheus.Registerer) (*prometheus.CounterVec, error) {
	regKey := fmt.Sprintf("%p", reg)

	powerStoreAPIObserverMu.Lock()
	defer powerStoreAPIObserverMu.Unlock()

	if counter, ok := powerStoreAPIObserverByRegKey[regKey]; ok {
		return counter, nil
	}

	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: powerStoreAPIRequestsMetricName,
		Help: "Total PowerStore REST API requests observed through gopowerstore.",
	}, []string{"global_id", "endpoint", "method", "status"})

	if err := reg.Register(counter); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing, ok := are.ExistingCollector.(*prometheus.CounterVec)
			if !ok {
				return nil, fmt.Errorf("powerstore api observer: unexpected existing collector type %T", are.ExistingCollector)
			}
			powerStoreAPIObserverByRegKey[regKey] = existing
			return existing, nil
		}
		return nil, fmt.Errorf("powerstore api observer: register counter: %w", err)
	}

	powerStoreAPIObserverByRegKey[regKey] = counter
	return counter, nil
}

// ObservePowerStoreRequest implements api.RequestObserver.
func (o *PowerStoreAPIObserver) ObservePowerStoreRequest(obs api.RequestObservation) {
	if o == nil || o.apiRequests == nil {
		return
	}

	endpoint := obs.Endpoint
	if obs.Action != "" {
		endpoint = endpoint + "/" + obs.Action
	}

	status := "failure"
	if obs.Err == nil && obs.StatusCode < 400 {
		status = "success"
	}

	o.apiRequests.WithLabelValues(o.globalID, endpoint, obs.Method, status).Inc()
}
