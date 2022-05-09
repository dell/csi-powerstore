/*
 *
 * Copyright © 2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package controller_test

import (
	"context"
	vgsext "github.com/dell/dell-csi-extensions/volumeGroupSnapshot"
	"github.com/dell/gopowerstore"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("csi-extension-server", func() {
	BeforeEach(func() {
		setVariables()
	})
	Describe("calling CreateVolumeGroupSnapshot()", func() {
		When("valid member volumes are present", func() {
			It("should create volume group snapshot successfully", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/arr/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				Expect(err).To(BeNil())
				Expect(res.SnapshotGroupID).To(Equal(validGroupID))
			})
		})
	})
})
