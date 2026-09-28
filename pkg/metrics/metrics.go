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

// Package metrics provides registry initialization and configuration for csi-powerstore metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Exposer is an interface for services that expose a Prometheus metrics registry.
type Exposer interface {
	MetricsRegistry() *prometheus.Registry
}

// NewRegistry creates and returns a new Prometheus registry with default configuration.
// The registry is initialized with default collectors for Go runtime metrics.
func NewRegistry() *prometheus.Registry {
	registry := prometheus.NewRegistry()
	return registry
}
