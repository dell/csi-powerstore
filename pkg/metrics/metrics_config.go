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
	"os"
	"strconv"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
)

// ParseResilienceConfig parses environment variables for metrics resilience features
// and returns a RuntimeConfig struct for use with MetricsRuntime.
func ParseResilienceConfig() (identifiers.RuntimeConfig, error) {
	cfg := identifiers.RuntimeConfig{
		Timeout:        getDurationEnv(identifiers.EnvMetricsArrayTimeout, 30*time.Second),
		CacheTTL:       getDurationEnv(identifiers.EnvMetricsCollectionCacheTTL, 60*time.Second),
		RateLimit:      getIntEnv(identifiers.EnvMetricsArrayRateLimit, 100),
		CBThreshold:    getIntEnv(identifiers.EnvMetricsArrayCBThreshold, 3),
		CBResetTimeout: getDurationEnv(identifiers.EnvMetricsArrayCBResetTimeout, 30*time.Second),
	}

	return cfg, nil
}

// getDurationEnv parses a duration environment variable with a default value.
func getDurationEnv(envVar string, defaultValue time.Duration) time.Duration {
	val := os.Getenv(envVar)
	if val == "" {
		return defaultValue
	}
	duration, err := time.ParseDuration(val)
	if err != nil {
		return defaultValue
	}
	return duration
}

// getIntEnv parses an integer environment variable with a default value.
func getIntEnv(envVar string, defaultValue int) int {
	val := os.Getenv(envVar)
	if val == "" {
		return defaultValue
	}
	intVal, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue
	}
	return intVal
}
