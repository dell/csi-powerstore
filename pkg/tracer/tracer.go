/*
 *
 * Copyright © 2021 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package tracer provides OpenTracing tracer implementation
package tracer

import (
	"io"

	"github.com/opentracing/opentracing-go"

	"github.com/uber/jaeger-client-go/config"
	jprom "github.com/uber/jaeger-lib/metrics/prometheus"
)

// TracerConfigurator represents tracer configurator
type TracerConfigurator interface {
	FromEnv() (*config.Configuration, error)
}

// NewTracer returns a new tracer object
func NewTracer(configurator TracerConfigurator) (opentracing.Tracer, io.Closer, error) {
	// load config from environment variables
	cfg, err := configurator.FromEnv()

	if err != nil {
		return nil, nil, err
	}

	// create tracer from config
	return cfg.NewTracer(
		config.Metrics(jprom.New()),
	)
}
