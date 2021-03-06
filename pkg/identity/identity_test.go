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

package identity

import (
	"context"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/pkg/common"
	"github.com/golang/protobuf/ptypes/wrappers"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
	"testing"
)

var idntySvc *Service

func TestCSIIdentityService(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("idnty-svc.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "CSIIdentityService testing suite", []Reporter{junitReporter})
}

func setVariables() {
	idntySvc = NewIdentityService(common.Name, "v1.3.0", common.Manifest)
}

var _ = Describe("CSIIdentityService", func() {
	BeforeEach(func() {
		setVariables()
	})

	Describe("calling GetPluginInfo()", func() {
		It("should return correct info", func() {
			res, err := idntySvc.GetPluginInfo(context.Background(), &csi.GetPluginInfoRequest{})
			Expect(err).To(BeNil())
			Expect(res).To(Equal(&csi.GetPluginInfoResponse{
				Name:          idntySvc.name,
				VendorVersion: idntySvc.version,
				Manifest:      idntySvc.manifest,
			}))
		})
	})

	Describe("calling GetPluginCapabilities()", func() {
		It("should return correct capabilities", func() {
			res, err := idntySvc.GetPluginCapabilities(context.Background(), &csi.GetPluginCapabilitiesRequest{})
			Expect(err).To(BeNil())
			Expect(res).To(Equal(&csi.GetPluginCapabilitiesResponse{
				Capabilities: []*csi.PluginCapability{
					{
						Type: &csi.PluginCapability_Service_{
							Service: &csi.PluginCapability_Service{
								Type: csi.PluginCapability_Service_CONTROLLER_SERVICE,
							},
						},
					},
					{
						Type: &csi.PluginCapability_VolumeExpansion_{
							VolumeExpansion: &csi.PluginCapability_VolumeExpansion{
								Type: csi.PluginCapability_VolumeExpansion_ONLINE,
							},
						},
					},
					{
						Type: &csi.PluginCapability_VolumeExpansion_{
							VolumeExpansion: &csi.PluginCapability_VolumeExpansion{
								Type: csi.PluginCapability_VolumeExpansion_OFFLINE,
							},
						},
					},
					{
						Type: &csi.PluginCapability_Service_{
							Service: &csi.PluginCapability_Service{
								Type: csi.PluginCapability_Service_VOLUME_ACCESSIBILITY_CONSTRAINTS,
							},
						},
					},
				},
			},
			))
		})
	})

	Describe("calling Probe()", func() {
		It("should return current status'", func() {
			res, err := idntySvc.Probe(context.Background(), &csi.ProbeRequest{})
			Expect(err).To(BeNil())
			Expect(res).To(Equal(&csi.ProbeResponse{Ready: &wrappers.BoolValue{Value: idntySvc.ready}}))
		})
	})
})
