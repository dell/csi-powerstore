/*
 *
 * Copyright © 2021-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/pkg/powerstorecommon"
	ginkgo "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	gomega "github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var idntySvc *Service

func TestCSIIdentityService(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	junitReporter := reporters.NewJUnitReporter("idnty-svc.xml")
	ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "CSIIdentityService testing suite", []ginkgo.Reporter{junitReporter})
}

func setVariables() {
	idntySvc = NewIdentityService(powerstorecommon.Name, "v1.3.0", powerstorecommon.Manifest)
}

var _ = ginkgo.Describe("CSIIdentityService", func() {
	ginkgo.BeforeEach(func() {
		setVariables()
	})

	ginkgo.Describe("calling GetPluginInfo()", func() {
		ginkgo.It("should return correct info", func() {
			res, err := idntySvc.GetPluginInfo(context.Background(), &csi.GetPluginInfoRequest{})
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.GetPluginInfoResponse{
				Name:          idntySvc.name,
				VendorVersion: idntySvc.version,
				Manifest:      idntySvc.manifest,
			}))
		})
	})

	ginkgo.Describe("calling GetPluginCapabilities()", func() {
		ginkgo.It("should return correct capabilities", func() {
			res, err := idntySvc.GetPluginCapabilities(context.Background(), &csi.GetPluginCapabilitiesRequest{})
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.GetPluginCapabilitiesResponse{
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

	ginkgo.Describe("calling Probe()", func() {
		ginkgo.It("should return current status'", func() {
			res, err := idntySvc.Probe(context.Background(), &csi.ProbeRequest{})
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.ProbeResponse{Ready: &wrapperspb.BoolValue{Value: idntySvc.ready}}))
		})
	})
})
