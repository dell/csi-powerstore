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

const stateReady = "Ready"

var _ = Describe("csi-extension-server", func() {
	BeforeEach(func() {
		setVariables()
	})
	Describe("calling CreateVolumeGroupSnapshot()", func() {
		When("valid member volumes are present", func() {
			It("should create volume group snapshot successfully", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).
					Return(gopowerstore.VolumeGroup{
						ID:                 validGroupID,
						ProtectionPolicyID: validPolicyID,
						Volumes:            []gopowerstore.Volume{{ID: validBaseVolID, State: stateReady}},
					}, nil)

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				Expect(err).To(BeNil())
				Expect(res.SnapshotGroupID).To(Equal(validGroupID))
			})
		})
		When("there is no existing volume group created", func() {
			It("should create volume group and snapshot successfully", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).
					Return(gopowerstore.VolumeGroup{
						ID:                 validGroupID,
						ProtectionPolicyID: validPolicyID,
						Volumes:            []gopowerstore.Volume{{ID: validBaseVolID, State: stateReady}},
					}, nil)

				createGroupRequest := &gopowerstore.VolumeGroupCreate{
					Name:      validGroupName,
					VolumeIds: []string{validBaseVolID},
				}
				clientMock.On("CreateVolumeGroup", mock.Anything, createGroupRequest).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				Expect(err).To(BeNil())
				Expect(res.SnapshotGroupID).To(Equal(validGroupID))
			})
		})
		When("member volumes are not present", func() {
			It("should not create volume group snapshot successfully", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).
					Return(gopowerstore.VolumeGroup{
						ID:                 validGroupID,
						ProtectionPolicyID: validPolicyID,
						Volumes:            []gopowerstore.Volume{{ID: validBaseVolID, State: stateReady}},
					}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name: validGroupName,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				Expect(err).Error()
				Expect(res).To(BeNil())
			})
		})
		When("volume group name is empty", func() {
			It("should not create volume group snapshot successfully", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).
					Return(gopowerstore.VolumeGroup{
						ID:                 validGroupID,
						ProtectionPolicyID: validPolicyID,
						Volumes:            []gopowerstore.Volume{{ID: validBaseVolID, State: stateReady}},
					}, nil)

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &vgsext.CreateVolumeGroupSnapshotRequest{})

				Expect(err).Error()
				Expect(res).To(BeNil())
			})
		})
		When("volume group name length is greater than 27", func() {
			It("should not create volume group snapshot successfully", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).
					Return(gopowerstore.VolumeGroup{
						ID:                 validGroupID,
						ProtectionPolicyID: validPolicyID,
						Volumes:            []gopowerstore.Volume{{ID: validBaseVolID, State: stateReady}},
					}, nil)

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &vgsext.CreateVolumeGroupSnapshotRequest{
					Name: "1234561111111111111111111112",
				})

				Expect(err).Error()
				Expect(res).To(BeNil())
			})
		})
		When("get volume group fails", func() {
			It("should not create volume group snapshot successfully", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).
					Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				Expect(err).Error()
				Expect(res).To(BeNil())
			})
		})
	})
})
