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

package metrics

import (
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseResilienceConfig(t *testing.T) {
	t.Setenv(identifiers.EnvMetricsArrayTimeout, "")
	t.Setenv(identifiers.EnvMetricsCollectionCacheTTL, "")
	t.Setenv(identifiers.EnvMetricsArrayRateLimit, "")
	t.Setenv(identifiers.EnvMetricsArrayCBThreshold, "")
	t.Setenv(identifiers.EnvMetricsArrayCBResetTimeout, "")

	cfg, err := ParseResilienceConfig()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.Equal(t, 60*time.Second, cfg.CacheTTL)
	assert.Equal(t, 100, cfg.RateLimit)
	assert.Equal(t, 3, cfg.CBThreshold)
	assert.Equal(t, 30*time.Second, cfg.CBResetTimeout)

	t.Setenv(identifiers.EnvMetricsArrayTimeout, "15s")
	t.Setenv(identifiers.EnvMetricsCollectionCacheTTL, "45s")
	t.Setenv(identifiers.EnvMetricsArrayRateLimit, "12")
	t.Setenv(identifiers.EnvMetricsArrayCBThreshold, "7")
	t.Setenv(identifiers.EnvMetricsArrayCBResetTimeout, "1m")

	cfg, err = ParseResilienceConfig()
	require.NoError(t, err)
	assert.Equal(t, 15*time.Second, cfg.Timeout)
	assert.Equal(t, 45*time.Second, cfg.CacheTTL)
	assert.Equal(t, 12, cfg.RateLimit)
	assert.Equal(t, 7, cfg.CBThreshold)
	assert.Equal(t, 1*time.Minute, cfg.CBResetTimeout)

	t.Setenv(identifiers.EnvMetricsArrayTimeout, "bad")
	t.Setenv(identifiers.EnvMetricsArrayRateLimit, "bad")
	assert.Equal(t, 30*time.Second, getDurationEnv(identifiers.EnvMetricsArrayTimeout, 30*time.Second))
	assert.Equal(t, 100, getIntEnv(identifiers.EnvMetricsArrayRateLimit, 100))
}

func TestNewServerWithTLS(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := NewServerWithTLS(":0", reg, "test-cert.pem", "test-key.pem")

	require.NotNil(t, srv)
	assert.NotNil(t, srv.MetricsServer)
}

func TestGetDurationEnv(t *testing.T) {
	// Test with empty env var (should return default)
	t.Setenv("TEST_DURATION", "")
	result := getDurationEnv("TEST_DURATION", 30*time.Second)
	assert.Equal(t, 30*time.Second, result)

	// Test with valid duration
	t.Setenv("TEST_DURATION", "45s")
	result = getDurationEnv("TEST_DURATION", 30*time.Second)
	assert.Equal(t, 45*time.Second, result)

	// Test with invalid duration (should return default)
	t.Setenv("TEST_DURATION", "invalid")
	result = getDurationEnv("TEST_DURATION", 30*time.Second)
	assert.Equal(t, 30*time.Second, result)

	// Test with different duration formats
	t.Setenv("TEST_DURATION", "1m")
	result = getDurationEnv("TEST_DURATION", 30*time.Second)
	assert.Equal(t, 1*time.Minute, result)

	t.Setenv("TEST_DURATION", "2h")
	result = getDurationEnv("TEST_DURATION", 30*time.Second)
	assert.Equal(t, 2*time.Hour, result)
}

func TestGetIntEnv(t *testing.T) {
	// Test with empty env var (should return default)
	t.Setenv("TEST_INT", "")
	result := getIntEnv("TEST_INT", 100)
	assert.Equal(t, 100, result)

	// Test with valid integer
	t.Setenv("TEST_INT", "42")
	result = getIntEnv("TEST_INT", 100)
	assert.Equal(t, 42, result)

	// Test with invalid integer (should return default)
	t.Setenv("TEST_INT", "invalid")
	result = getIntEnv("TEST_INT", 100)
	assert.Equal(t, 100, result)

	// Test with zero
	t.Setenv("TEST_INT", "0")
	result = getIntEnv("TEST_INT", 100)
	assert.Equal(t, 0, result)

	// Test with negative number
	t.Setenv("TEST_INT", "-5")
	result = getIntEnv("TEST_INT", 100)
	assert.Equal(t, -5, result)
}
