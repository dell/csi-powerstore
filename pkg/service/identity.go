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

// Package identity provides CSI specification compatible identity service.
package service

import (
	"context"
	"fmt"

	"github.com/container-storage-interface/spec/lib/go/csi"
)

// GetPluginInfo returns general information about plugin (driver) such as name, version and manifest
func (s *service) GetPluginInfo(_ context.Context, _ *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{}, fmt.Errorf("should not reach here")
}

// GetPluginCapabilities returns capabilities that are supported by the driver
func (s *service) GetPluginCapabilities(_ context.Context, _ *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	return &csi.GetPluginCapabilitiesResponse{}, fmt.Errorf("should not reach here")
}

// Probe returns current state of the driver and if it is ready to receive requests
func (s *service) Probe(_ context.Context, _ *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{}, fmt.Errorf("should not reach here")
}
