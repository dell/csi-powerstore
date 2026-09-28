/*
 *
 * Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package metricsruntime

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/collectors"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csi-powerstore/v2/pkg/metrics"
	log "github.com/dell/csmlog"
	csictx "github.com/dell/gocsi/context"
	"github.com/prometheus/client_golang/prometheus"
)

// RuntimeState owns the metrics collectors and metadata checker lifecycle.
type RuntimeState struct {
	cancel   context.CancelFunc
	checker  *collectors.K8sMetadataChecker
	manager  *collectors.Manager
	shared   *collectors.SharedMetadataChecker
	stopOnce sync.Once
}

// Stop shuts down the metrics runtime.
func (s *RuntimeState) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.checker != nil {
			s.checker.Stop()
		}
		if s.shared != nil {
			s.shared.Clear(s.checker)
		}
		if s.manager != nil {
			s.manager.Stop()
		}
	})
}

// StartCollectors starts pod-level and, for controller mode, array-level metrics collectors.
func StartCollectors(parent context.Context, registry *prometheus.Registry, srv *metrics.Server, mode string, arrays map[string]*array.PowerStoreArray, previous *RuntimeState, shared *collectors.SharedMetadataChecker) *RuntimeState {
	if previous != nil {
		previous.Stop()
	}
	if registry == nil || len(arrays) == 0 {
		if shared != nil {
			shared.Set(nil)
		}
		return nil
	}

	ctx, cancel := context.WithCancel(parent)
	state := &RuntimeState{cancel: cancel, shared: shared}

	var checker *collectors.K8sMetadataChecker
	if k8sutils.Kubeclient != nil && k8sutils.Kubeclient.Clientset != nil {
		checker = collectors.NewK8sMetadataChecker(k8sutils.Kubeclient.Clientset, identifiers.Name)
		state.checker = checker
		if shared != nil {
			shared.Set(checker)
		}
		if err := checker.Start(ctx); err != nil && ctx.Err() == nil {
			log.Errorf("metrics metadata checker stopped with error: %v", err)
			if shared != nil {
				shared.Clear(checker)
			}
		}
	} else {
		log.Warn("metrics collectors started without a Kubernetes client; volume validation will be best effort")
		if shared != nil {
			shared.Set(nil)
		}
	}

	manager := collectors.NewManager(registry)
	state.manager = manager
	if srv != nil {
		manager.SetStaleSetter(func(globalID string, stale bool) {
			srv.SetStale(globalID, stale)
		})
	}
	manager.SetRuntimeConfig(runtimeConfig())

	for _, arr := range arrays {
		if arr == nil || arr.GetClient() == nil {
			continue
		}
		if srv != nil {
			srv.SetStale(arr.GetGlobalID(), false)
		}

		if collector, err := collectors.NewPSTDriverHealthCollector(registry, arr.GetGlobalID(), k8sutils.Kubeclient); err != nil {
			log.Errorf("failed to create driver health collector for array %s: %v", arr.GetGlobalID(), err)
		} else {
			manager.Register(collector)
		}
	}

	startArrayCollectors := func(arrayCtx context.Context) {
		arrayManager := collectors.NewManager(registry)
		if srv != nil {
			arrayManager.SetStaleSetter(func(globalID string, stale bool) {
				srv.SetStale(globalID, stale)
			})
		}
		arrayManager.SetRuntimeConfig(runtimeConfig())

		for _, arr := range arrays {
			if arr == nil || arr.GetClient() == nil {
				continue
			}

			runtime := arrayManager.GetRuntime(arr.GetGlobalID())
			applianceClient := collectors.NewApplianceAdapterWithRuntime(arr.GetClient(), runtime)
			if collector, err := collectors.NewApplianceCollector(applianceClient, registry, arr.GetGlobalID()); err != nil {
				log.Errorf("failed to create appliance collector for array %s: %v", arr.GetGlobalID(), err)
			} else {
				arrayManager.Register(collector)
			}

			var metadata collectors.VolumeMetadataProvider
			if shared != nil {
				metadata = shared
			} else {
				metadata = &collectors.NoopVolumeMetadataProvider{}
			}
			// Skip volume collection if Kubernetes metadata is not available.
			// Without PV metadata, we cannot accurately determine which volumes are driver-managed.
			if shared == nil || !shared.Available() {
				log.Warnf("shared metadata checker not available for array %s, skipping volume collection to prevent inaccurate metrics", arr.GetGlobalID())
			} else {
				volumeClient := collectors.NewVolumeAdapterWithRuntime(arr.GetClient(), runtime)
				if collector, err := collectors.NewVolumeCollector(volumeClient, registry, arr.GetGlobalID(), metadata); err != nil {
					log.Errorf("failed to create volume collector for array %s: %v", arr.GetGlobalID(), err)
				} else {
					arrayManager.Register(collector)
				}
			}
		}

		interval := pollInterval()
		arrayManager.Start(arrayCtx, interval)
		_ = arrayManager.CollectAll(context.Background())
	}

	if strings.EqualFold(mode, "controller") {
		if leaderElectionEnabled() && k8sutils.Kubeclient != nil && k8sutils.Kubeclient.Clientset != nil {
			go func() {
				if err := k8sutils.LeaderElectionForMetrics(ctx, k8sutils.Kubeclient.Clientset, "powerstore-metrics", driverNamespace(), leaderRenewDeadline(), leaderLeaseDuration(), leaderRetryPeriod(), startArrayCollectors); err != nil && ctx.Err() == nil {
					log.Errorf("metrics leader election failed, falling back to local array metrics collection: %v", err)
					startArrayCollectors(ctx)
				}
			}()
		} else {
			startArrayCollectors(ctx)
		}
	}

	interval := pollInterval()
	manager.Start(ctx, interval)
	_ = manager.CollectAll(context.Background())
	return state
}

func leaderElectionEnabled() bool {
	if raw, ok := csictx.LookupEnv(context.Background(), identifiers.EnvMetricsLeaderElectionEnabled); ok {
		return strings.EqualFold(raw, "true")
	}
	return false
}

func driverNamespace() string {
	if ns := os.Getenv(identifiers.EnvDriverNamespace); ns != "" {
		return ns
	}
	return "default"
}

func leaderLeaseDuration() time.Duration {
	return durationFromEnv(identifiers.EnvMetricsLeaderElectionLeaseDuration, 15*time.Second)
}

func leaderRenewDeadline() time.Duration {
	return durationFromEnv(identifiers.EnvMetricsLeaderElectionRenewDeadline, 10*time.Second)
}

func leaderRetryPeriod() time.Duration {
	return durationFromEnv(identifiers.EnvMetricsLeaderElectionRetryPeriod, 5*time.Second)
}

func runtimeConfig() identifiers.RuntimeConfig {
	return identifiers.RuntimeConfig{
		Timeout:        durationFromEnv(identifiers.EnvMetricsArrayTimeout, 30*time.Second),
		CacheTTL:       durationFromEnv(identifiers.EnvMetricsCollectionCacheTTL, 60*time.Second),
		RateLimit:      intFromEnv(identifiers.EnvMetricsArrayRateLimit, 100),
		CBThreshold:    intFromEnv(identifiers.EnvMetricsArrayCBThreshold, 3),
		CBResetTimeout: durationFromEnv(identifiers.EnvMetricsArrayCBResetTimeout, 30*time.Second),
	}
}

func durationFromEnv(env string, fallback time.Duration) time.Duration {
	if raw, ok := csictx.LookupEnv(context.Background(), env); ok && raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
		log.Warnf("invalid %s value %q, using default %s", env, raw, fallback)
	}
	return fallback
}

func intFromEnv(env string, fallback int) int {
	if raw, ok := csictx.LookupEnv(context.Background(), env); ok && raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			return parsed
		}
		log.Warnf("invalid %s value %q, using default %d", env, raw, fallback)
	}
	return fallback
}

func pollInterval() time.Duration {
	interval := time.Minute
	if raw, ok := csictx.LookupEnv(context.Background(), identifiers.EnvMetricsPollInterval); ok && raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			interval = parsed
		} else if err != nil {
			log.Warnf("invalid %s value %q, using default %s", identifiers.EnvMetricsPollInterval, raw, interval)
		}
	}
	return interval
}
