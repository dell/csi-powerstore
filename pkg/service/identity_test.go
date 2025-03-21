// Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPluginInfo(t *testing.T) {
	svc := service{}
	resp, err := svc.GetPluginInfo(context.Background(), nil)
	assert.Empty(t, resp)
	assert.Equal(t, err.Error(), "should not reach here")
}

func TestGetPluginCapabilities(t *testing.T) {
	svc := service{}
	resp, err := svc.GetPluginCapabilities(context.Background(), nil)
	assert.Empty(t, resp)
	assert.Equal(t, err.Error(), "should not reach here")
}

func TestProbe(t *testing.T) {
	svc := service{}
	resp, err := svc.Probe(context.Background(), nil)
	assert.Empty(t, resp)
	assert.Equal(t, err.Error(), "should not reach here")
}
