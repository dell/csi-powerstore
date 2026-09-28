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
	"github.com/dell/csm-metrics-common/pkg/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── NewMetricsRuntime ───────────────────────────────────────────────────────

func TestNewMetricsRuntime_ZeroConfigUsesDefaults(t *testing.T) {
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{})
	assert.NotNil(t, rt)
	assert.Equal(t, 30*time.Second, rt.timeout)
	assert.NotNil(t, rt.cache)
	assert.NotNil(t, rt.rateLimiter)
	assert.NotNil(t, rt.circuitBreaker)
}

func TestNewMetricsRuntime_ValidConfigHonored(t *testing.T) {
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout:        5 * time.Second,
		CacheTTL:       10 * time.Second,
		RateLimit:      50,
		CBThreshold:    2,
		CBResetTimeout: 15 * time.Second,
	})
	assert.Equal(t, 5*time.Second, rt.timeout)
}

// ── Do: success path ─────────────────────────────────────────────────────────

func TestMetricsRuntime_Do_SuccessReturnsResult(t *testing.T) {
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout: time.Second, CacheTTL: time.Minute, RateLimit: 100, CBThreshold: 3, CBResetTimeout: time.Minute,
	})

	v, err := rt.Do(context.Background(), "ep", "k1", func(_ context.Context) (any, error) {
		return "hello", nil
	})
	require.NoError(t, err)
	assert.Equal(t, "hello", v)
}

func TestMetricsRuntime_Do_SuccessClearsStale(t *testing.T) {
	var lastStale *bool
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout: time.Second, CacheTTL: time.Minute, RateLimit: 100, CBThreshold: 10, CBResetTimeout: time.Minute,
		StaleReporter: func() func(string, bool) {
			return func(_ string, s bool) { lastStale = &s }
		},
	})

	_, _ = rt.Do(context.Background(), "ep", "k1", func(_ context.Context) (any, error) {
		return "v1", nil
	})

	require.NotNil(t, lastStale)
	assert.False(t, *lastStale, "stale must be false after a successful call")
}

// ── Do: failure with cached fallback ─────────────────────────────────────────

func TestMetricsRuntime_Do_ServesStaleOnDownstreamFailure(t *testing.T) {
	staleCalls := []bool{}
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout: time.Second, CacheTTL: time.Minute, RateLimit: 100, CBThreshold: 10, CBResetTimeout: time.Minute,
		StaleReporter: func() func(string, bool) {
			return func(_ string, s bool) { staleCalls = append(staleCalls, s) }
		},
	})

	// First call succeeds – warms the cache.
	v, err := rt.Do(context.Background(), "ep", "k1", func(_ context.Context) (any, error) {
		return "fresh", nil
	})
	require.NoError(t, err)
	assert.Equal(t, "fresh", v)

	// Second call fails – cache hit should be returned without error.
	v, err = rt.Do(context.Background(), "ep", "k1", func(_ context.Context) (any, error) {
		return nil, errors.New("backend down")
	})
	require.NoError(t, err, "cache hit must not return an error")
	assert.Equal(t, "fresh", v)

	// Reporter: false (success), true (stale fallback).
	assert.Equal(t, []bool{false, true}, staleCalls)
}

func TestMetricsRuntime_Do_StaleClearedAfterSuccessfulRefresh(t *testing.T) {
	staleCalls := []bool{}
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout: time.Second, CacheTTL: time.Minute, RateLimit: 100, CBThreshold: 10, CBResetTimeout: time.Minute,
		StaleReporter: func() func(string, bool) {
			return func(_ string, s bool) { staleCalls = append(staleCalls, s) }
		},
	})

	_, _ = rt.Do(context.Background(), "ep", "k1", func(_ context.Context) (any, error) { return "v1", nil })
	_, _ = rt.Do(context.Background(), "ep", "k1", func(_ context.Context) (any, error) { return nil, errors.New("err") })
	_, _ = rt.Do(context.Background(), "ep", "k1", func(_ context.Context) (any, error) { return "v2", nil })

	assert.Equal(t, []bool{false, true, false}, staleCalls)
}

// ── Do: failure without cache ─────────────────────────────────────────────────

func TestMetricsRuntime_Do_PropagatesErrorWhenCacheEmpty(t *testing.T) {
	staleCalls := []bool{}
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout: time.Second, CacheTTL: time.Minute, RateLimit: 100, CBThreshold: 10, CBResetTimeout: time.Minute,
		StaleReporter: func() func(string, bool) {
			return func(_ string, s bool) { staleCalls = append(staleCalls, s) }
		},
	})

	_, err := rt.Do(context.Background(), "ep", "k1", func(_ context.Context) (any, error) {
		return nil, errors.New("backend error")
	})
	assert.Error(t, err, "error must propagate when cache has no entry")
	assert.Equal(t, []bool{true}, staleCalls, "stale must be marked when the backend is unavailable")
}

// ── Do: circuit breaker ──────────────────────────────────────────────────────

func TestMetricsRuntime_Do_CircuitOpensAfterThreshold(t *testing.T) {
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout: time.Second, CacheTTL: time.Minute, RateLimit: 100, CBThreshold: 2, CBResetTimeout: time.Hour,
	})

	fail := func(_ context.Context) (any, error) { return nil, errors.New("fail") }

	_, _ = rt.Do(context.Background(), "ep", "k1", fail) // failure 1
	_, _ = rt.Do(context.Background(), "ep", "k1", fail) // failure 2 – circuit opens

	_, err := rt.Do(context.Background(), "ep", "k1", fail) // circuit is open
	require.Error(t, err)
	assert.True(t, errors.Is(err, middleware.ErrCircuitOpen), "error should wrap ErrCircuitOpen")
}

// ── Do: timeout ──────────────────────────────────────────────────────────────

func TestMetricsRuntime_Do_TimeoutCutsCallShort(t *testing.T) {
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout: 50 * time.Millisecond, CacheTTL: time.Minute, RateLimit: 100, CBThreshold: 3, CBResetTimeout: time.Minute,
	})

	start := time.Now()
	_, err := rt.Do(context.Background(), "ep", "k1", func(callCtx context.Context) (any, error) {
		select {
		case <-callCtx.Done():
			return nil, callCtx.Err()
		case <-time.After(time.Second):
			return "late", nil
		}
	})
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Less(t, elapsed, 250*time.Millisecond, "call must have been interrupted by the timeout context")
}

// ── Do: rate limiter ─────────────────────────────────────────────────────────

func TestMetricsRuntime_Do_CancelledContextFailsRateLimit(t *testing.T) {
	rt := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{
		Timeout: time.Second, CacheTTL: time.Minute,
		RateLimit:      1, // Very tight limit
		CBThreshold:    3,
		CBResetTimeout: time.Minute,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := rt.Do(ctx, "ep", "k1", func(_ context.Context) (any, error) { return "x", nil })
	assert.Error(t, err, "cancelled context must fail rate limiter Wait")
}
