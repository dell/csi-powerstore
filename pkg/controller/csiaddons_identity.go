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

package controller

import (
	"context"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	log "github.com/dell/csmlog"
	csiaddonsidentity "github.com/csi-addons/spec/lib/go/identity"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// CSIAddonsIdentityServer implements the CSI-Addons Identity service
// This is required by the CSI-Addons sidecar for probing the driver
type CSIAddonsIdentityServer struct {
	csiaddonsidentity.UnimplementedIdentityServer
	service *Service
}

// NewCSIAddonsIdentityServer creates a new CSI-Addons identity server
func NewCSIAddonsIdentityServer(service *Service) *CSIAddonsIdentityServer {
	return &CSIAddonsIdentityServer{
		service: service,
	}
}

// RegisterCSIAddonsIdentityServer registers the CSI-Addons identity server with gRPC
func RegisterCSIAddonsIdentityServer(server *grpc.Server, srv *CSIAddonsIdentityServer) {
	csiaddonsidentity.RegisterIdentityServer(server, srv)
}

// GetIdentity returns the identity of the CSI-Addons driver
func (s *CSIAddonsIdentityServer) GetIdentity(
	ctx context.Context,
	_ *csiaddonsidentity.GetIdentityRequest,
) (*csiaddonsidentity.GetIdentityResponse, error) {
	log := log.WithContext(ctx)
	log.Info("CSI-Addons GetIdentity called")

	return &csiaddonsidentity.GetIdentityResponse{
		Name:          identifiers.Name,
		VendorVersion: identifiers.ManifestSemver,
		Manifest: map[string]string{
			"vendor": "Dell Inc.",
		},
	}, nil
}

// GetCapabilities returns the capabilities of the CSI-Addons driver
func (s *CSIAddonsIdentityServer) GetCapabilities(
	ctx context.Context,
	_ *csiaddonsidentity.GetCapabilitiesRequest,
) (*csiaddonsidentity.GetCapabilitiesResponse, error) {
	log := log.WithContext(ctx)
	log.Info("CSI-Addons GetCapabilities called")

	return &csiaddonsidentity.GetCapabilitiesResponse{
		Capabilities: []*csiaddonsidentity.Capability{
			{
				Type: &csiaddonsidentity.Capability_Service_{
					Service: &csiaddonsidentity.Capability_Service{
						Type: csiaddonsidentity.Capability_Service_CONTROLLER_SERVICE,
					},
				},
			},
			{
				Type: &csiaddonsidentity.Capability_VolumeReplication_{
					VolumeReplication: &csiaddonsidentity.Capability_VolumeReplication{
						Type: csiaddonsidentity.Capability_VolumeReplication_VOLUME_REPLICATION,
					},
				},
			},
			{
				Type: &csiaddonsidentity.Capability_VolumeGroup_{
					VolumeGroup: &csiaddonsidentity.Capability_VolumeGroup{
						Type: csiaddonsidentity.Capability_VolumeGroup_VOLUME_GROUP,
					},
				},
			},
			{
				Type: &csiaddonsidentity.Capability_VolumeGroup_{
					VolumeGroup: &csiaddonsidentity.Capability_VolumeGroup{
						Type: csiaddonsidentity.Capability_VolumeGroup_MODIFY_VOLUME_GROUP,
					},
				},
			},
			{
				Type: &csiaddonsidentity.Capability_VolumeGroup_{
					VolumeGroup: &csiaddonsidentity.Capability_VolumeGroup{
						Type: csiaddonsidentity.Capability_VolumeGroup_GET_VOLUME_GROUP,
					},
				},
			},
			{
				Type: &csiaddonsidentity.Capability_VolumeGroup_{
					VolumeGroup: &csiaddonsidentity.Capability_VolumeGroup{
						Type: csiaddonsidentity.Capability_VolumeGroup_LIST_VOLUME_GROUPS,
					},
				},
			},
			{
				Type: &csiaddonsidentity.Capability_VolumeReplication_{
					VolumeReplication: &csiaddonsidentity.Capability_VolumeReplication{
						Type: csiaddonsidentity.Capability_VolumeReplication_GET_REPLICATION_DESTINATION_INFO,
					},
				},
			},
		},
	}, nil
}

// Probe checks if the CSI-Addons driver is ready
func (s *CSIAddonsIdentityServer) Probe(
	ctx context.Context,
	_ *csiaddonsidentity.ProbeRequest,
) (*csiaddonsidentity.ProbeResponse, error) {
	log := log.WithContext(ctx)
	log.Info("CSI-Addons Probe called")

	// Basic health check: verify service is initialized
	if s.service == nil {
		log.Warn("CSI-Addons Probe: service is nil")
		return &csiaddonsidentity.ProbeResponse{
			Ready: wrapperspb.Bool(false),
		}, nil
	}

	return &csiaddonsidentity.ProbeResponse{
		Ready: wrapperspb.Bool(true),
	}, nil
}
