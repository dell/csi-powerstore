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

package tracer

import (
	"errors"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/uber/jaeger-client-go/config"
	"testing"
)

func TestNewTracer(t *testing.T) {
	t.Run("success test", func(t *testing.T) {
		tracerMock := new(mocks.TracerConfigurator)
		tracerMock.On("FromEnv").Return(&config.Configuration{
			ServiceName: "SomeServiceName",
		}, nil)
		tracer, _, err := NewTracer(tracerMock)
		assert.Nil(t, err)
		assert.NotNil(t, tracer)
	})
	t.Run("failed scenario", func(t *testing.T) {
		tracerMock := new(mocks.TracerConfigurator)
		tracerMock.On("FromEnv").Return(nil, errors.New("error"))
		tracer, _, err := NewTracer(tracerMock)
		assert.Nil(t, tracer)
		assert.NotNil(t, err)
	})
}
