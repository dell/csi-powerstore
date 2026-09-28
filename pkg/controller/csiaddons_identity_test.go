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
	csiaddonsidentity "github.com/csi-addons/spec/lib/go/identity"
	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	"google.golang.org/grpc"
)

var _ = ginkgo.Describe("CSI-Addons Identity", func() {
	var identityServer *CSIAddonsIdentityServer

	ginkgo.BeforeEach(func() {
		setVariables()
		identityServer = NewCSIAddonsIdentityServer(ctrlSvc)
	})

	ginkgo.Describe("NewCSIAddonsIdentityServer", func() {
		ginkgo.It("should create a new identity server", func() {
			server := NewCSIAddonsIdentityServer(ctrlSvc)
			gomega.Expect(server).ToNot(gomega.BeNil())
			gomega.Expect(server.service).To(gomega.Equal(ctrlSvc))
		})
	})

	ginkgo.Describe("RegisterCSIAddonsIdentityServer", func() {
		ginkgo.It("should register the identity server with gRPC", func() {
			grpcServer := grpc.NewServer()
			gomega.Expect(func() {
				RegisterCSIAddonsIdentityServer(grpcServer, identityServer)
			}).ToNot(gomega.Panic())
		})
	})

	ginkgo.Describe("GetIdentity", func() {
		ginkgo.It("should return driver identity information", func() {
			req := &csiaddonsidentity.GetIdentityRequest{}
			resp, err := identityServer.GetIdentity(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.Name).To(gomega.Equal(identifiers.Name))
			gomega.Expect(resp.VendorVersion).To(gomega.Equal(identifiers.ManifestSemver))
			gomega.Expect(resp.Manifest).To(gomega.HaveKeyWithValue("vendor", "Dell Inc."))
		})
	})

	ginkgo.Describe("GetCapabilities", func() {
		ginkgo.It("should return all supported capabilities", func() {
			req := &csiaddonsidentity.GetCapabilitiesRequest{}
			resp, err := identityServer.GetCapabilities(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.Capabilities).ToNot(gomega.BeEmpty())

			// Verify specific capabilities are present
			hasControllerService := false
			hasVolumeReplication := false
			hasVolumeGroup := false
			hasModifyVolumeGroup := false
			hasGetVolumeGroup := false
			hasListVolumeGroups := false
			hasGetReplicationDestinationInfo := false

			for _, capability := range resp.Capabilities {
				if svc := capability.GetService(); svc != nil {
					if svc.Type == csiaddonsidentity.Capability_Service_CONTROLLER_SERVICE {
						hasControllerService = true
					}
				}
				if volRep := capability.GetVolumeReplication(); volRep != nil {
					if volRep.Type == csiaddonsidentity.Capability_VolumeReplication_VOLUME_REPLICATION {
						hasVolumeReplication = true
					}
					if volRep.Type == csiaddonsidentity.Capability_VolumeReplication_GET_REPLICATION_DESTINATION_INFO {
						hasGetReplicationDestinationInfo = true
					}
				}
				if volGrp := capability.GetVolumeGroup(); volGrp != nil {
					if volGrp.Type == csiaddonsidentity.Capability_VolumeGroup_VOLUME_GROUP {
						hasVolumeGroup = true
					}
					if volGrp.Type == csiaddonsidentity.Capability_VolumeGroup_MODIFY_VOLUME_GROUP {
						hasModifyVolumeGroup = true
					}
					if volGrp.Type == csiaddonsidentity.Capability_VolumeGroup_GET_VOLUME_GROUP {
						hasGetVolumeGroup = true
					}
					if volGrp.Type == csiaddonsidentity.Capability_VolumeGroup_LIST_VOLUME_GROUPS {
						hasListVolumeGroups = true
					}
				}
			}

			gomega.Expect(hasControllerService).To(gomega.BeTrue(), "should have CONTROLLER_SERVICE capability")
			gomega.Expect(hasVolumeReplication).To(gomega.BeTrue(), "should have VOLUME_REPLICATION capability")
			gomega.Expect(hasVolumeGroup).To(gomega.BeTrue(), "should have VOLUME_GROUP capability")
			gomega.Expect(hasModifyVolumeGroup).To(gomega.BeTrue(), "should have MODIFY_VOLUME_GROUP capability")
			gomega.Expect(hasGetVolumeGroup).To(gomega.BeTrue(), "should have GET_VOLUME_GROUP capability")
			gomega.Expect(hasListVolumeGroups).To(gomega.BeTrue(), "should have LIST_VOLUME_GROUPS capability")
			gomega.Expect(hasGetReplicationDestinationInfo).To(gomega.BeTrue(), "should have GET_REPLICATION_DESTINATION_INFO capability")
		})
	})

	ginkgo.Describe("Probe", func() {
		ginkgo.It("should return ready status", func() {
			req := &csiaddonsidentity.ProbeRequest{}
			resp, err := identityServer.Probe(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.Ready).ToNot(gomega.BeNil())
			gomega.Expect(resp.Ready.GetValue()).To(gomega.BeTrue())
		})

		ginkgo.It("should return not ready when service is nil", func() {
			nilServer := &CSIAddonsIdentityServer{service: nil}
			req := &csiaddonsidentity.ProbeRequest{}
			resp, err := nilServer.Probe(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.Ready).ToNot(gomega.BeNil())
			gomega.Expect(resp.Ready.GetValue()).To(gomega.BeFalse())
		})
	})
})
