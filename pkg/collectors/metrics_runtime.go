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
	"fmt"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	csmcache "github.com/dell/csm-metrics-common/pkg/cache"
	"github.com/dell/csm-metrics-common/pkg/middleware"
)

// MetricsRuntime wraps PowerStore metrics calls with timeout, rate limiting,
// circuit breaking, and response caching. It is scoped per globalID so that
// failures on one array do not affect others.
type MetricsRuntime struct {
	globalID       string
	timeout        time.Duration
	cache          *csmcache.ResponseCache
	rateLimiter    *middleware.RateLimiter
	circuitBreaker *middleware.CircuitBreaker
	staleReporter  func() func(globalID string, stale bool)
}

// NewMetricsRuntime creates a MetricsRuntime for the given globalID using
// the provided configuration. Zero or negative config values are replaced
// with safe defaults so callers never need to guard against invalid opts.
func NewMetricsRuntime(globalID string, cfg identifiers.RuntimeConfig) *MetricsRuntime {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 90 * time.Second // Increased to be longer than collection interval
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 100
	}
	if cfg.CBThreshold <= 0 {
		cfg.CBThreshold = 3
	}
	if cfg.CBResetTimeout <= 0 {
		cfg.CBResetTimeout = 30 * time.Second
	}
	return &MetricsRuntime{
		globalID:       globalID,
		timeout:        cfg.Timeout,
		cache:          csmcache.NewResponseCache(cfg.CacheTTL),
		rateLimiter:    middleware.NewRateLimiter(cfg.RateLimit),
		circuitBreaker: middleware.NewCircuitBreaker(globalID, cfg.CBThreshold, cfg.CBResetTimeout),
		staleReporter:  cfg.StaleReporter,
	}
}

// Do executes fn through rate limiting, timeout, and circuit breaking, then
// caches the result. On failure, a cached result is served when available and
// the stale indicator is set. On success the stale indicator is cleared.
//
// endpoint is a logical name used as the rate-limiter bucket (e.g. "volumes").
// cacheKey must be unique per endpoint+parameter combination within a globalID.
func (r *MetricsRuntime) Do(ctx context.Context, endpoint, cacheKey string, fn func(context.Context) (any, error)) (any, error) {
	// 1. Rate-limit before acquiring timeout budget.
	if err := r.rateLimiter.Wait(ctx, endpoint); err != nil {
		return r.serveStaleOrError(cacheKey, fmt.Errorf("rate limiter cancelled for %s/%s: %w", r.globalID, endpoint, err))
	}

	// 2. Derive a timeout-bound context for the actual PowerStore call.
	callCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// 3. Execute through the circuit breaker.
	var result any
	cbErr := r.circuitBreaker.Call(func() error {
		v, err := fn(callCtx)
		if err != nil {
			return err
		}
		result = v
		return nil
	})

	if cbErr != nil {
		return r.serveStaleOrError(cacheKey, fmt.Errorf("%s/%s: %w", r.globalID, endpoint, cbErr))
	}

	// 4. Success: cache result and clear stale flag.
	r.cache.Set(cacheKey, result)
	r.setStale(false)
	return result, nil
}

// serveStaleOrError returns a cached result (marking metrics stale) when one
// is available, or propagates err when the cache is empty.
// Sets stale flag immediately on error regardless of cache state.
func (r *MetricsRuntime) serveStaleOrError(cacheKey string, err error) (any, error) {
	r.setStale(true) // Set stale immediately on error, not dependent on cache state
	if cached, ok := r.cache.Get(cacheKey); ok {
		return cached, nil
	}
	return nil, err
}

func (r *MetricsRuntime) setStale(stale bool) {
	if r.staleReporter != nil {
		reporter := r.staleReporter() // Resolve reporter at runtime to avoid race conditions
		if reporter != nil {
			reporter(r.globalID, stale)
		}
	}
}
