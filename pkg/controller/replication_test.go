/*
 *
 * Copyright © 2021-2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package controller_test

import (
	"context"
	"github.com/dell/csi-powerstore/pkg/array"
	"github.com/dell/csi-powerstore/pkg/controller"
	csiext "github.com/dell/dell-csi-extensions/replication"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
)

var _ = Describe("Replication", func() {
	BeforeEach(func() {
		setVariables()
	})

	Describe("calling GetStorageProtectionGroupStatus()", func() {
		When("getting storage protection group status and state is ok", func() {
			It("should return synchronized status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_OK}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNCHRONIZED,
				))
			})
		})

		When("getting storage protection group status and state is failed over", func() {
			It("should return failed over status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_FAILED_OVER}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_FAILEDOVER,
				))
			})
		})

		When("getting storage protection group status and state is paused (for several reasons)", func() {
			It("should return suspended status (if paused)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_PAUSED}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			It("should return suspended status (if paused for migration)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_PAUSED_FOR_MIGRATION}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			It("should return suspended status (if paused for NDU)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_PAUSED_FOR_NDU}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			It("should return suspended status (if system paused)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_SYSTEM_PAUSED}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
		})

		When("getting storage protection group status and state is updating (in progress)", func() {
			It("should return 'sync in progress' status (if failing over)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_FAILING_OVER}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if failing over for DR)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_FAILING_OVER_FOR_DR}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if resuming)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_RESUMING}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if reprotecting)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_REPROTECTING}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if cutover for migration)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_PARTIAL_CUTOVER_FOR_MIGRATION}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if synchronizing)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_SYNCHRONIZING}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if initializing)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_INITIALIZING}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
		})

		When("getting storage protection group status and state is error", func() {
			It("should return invalid status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_ERROR}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_INVALID,
				))
			})
		})

		When("getting storage protection group status and state does not match with known protection group states", func() {
			It("should return unknown status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_UNKNOWN,
				))
			})
		})

		When("GlobalID is missing", func() {
			It("should fail", func() {

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(
					ContainSubstring("missing globalID in protection group attributes"),
				)
			})
		})

		When("Array with specified globalID couldn't be found", func() {
			It("should fail", func() {

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "SOMETHING WRONG"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(
					ContainSubstring("can't find array with global id"),
				)
			})
		})

		When("Invalid client response", func() {
			It("should fail", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, status.Errorf(codes.InvalidArgument, "Invalid client response"))

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(
					ContainSubstring("Invalid client response"),
				)
			})
		})
	})
	Describe("calling ExecuteAction()", func() {
		When("action is RS_ACTION_RESUME and state is OK", func() {
			It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "OK"}
				action := gopowerstore.RS_ACTION_RESUME
				failoverParams := gopowerstore.FailoverParams{}
				err := controller.ExecuteAction(&session, clientMock, action, &failoverParams)

				Expect(err).To(BeNil())
			})
		})

		When("action is RS_ACTION_REPROTECT and state is not OK", func() {
			It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "OK"}
				action := gopowerstore.RS_ACTION_REPROTECT
				failoverParams := gopowerstore.FailoverParams{}
				err := controller.ExecuteAction(&session, clientMock, action, &failoverParams)

				Expect(err).To(BeNil())

			})
		})

		When("action is RS_ACTION_PAUSE and state is Paused", func() {
			It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "Paused"}
				action := gopowerstore.RS_ACTION_PAUSE
				failoverParams := gopowerstore.FailoverParams{}
				err := controller.ExecuteAction(&session, clientMock, action, &failoverParams)

				Expect(err).To(BeNil())
			})
		})

		When("action is RS_ACTION_FAILOVER and state is Failing_Over", func() {
			It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "Failing_Over"}
				action := gopowerstore.RS_ACTION_FAILOVER
				failoverParams := gopowerstore.FailoverParams{}
				err := controller.ExecuteAction(&session, clientMock, action, &failoverParams)

				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(
					ContainSubstring("Execute action: RS (test) is still executing previous action"))

			})
		})

		When("action is RS_ACTION_FAILOVER and state is Failed_Over", func() {
			It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "Failed_Over"}
				action := gopowerstore.RS_ACTION_FAILOVER
				failoverParams := gopowerstore.FailoverParams{}
				err := controller.ExecuteAction(&session, clientMock, action, &failoverParams)

				Expect(err).To(BeNil())

			})

		})
		Describe("calling DeleteStorageProtectionGroup()", func() {
			When("GlobalID is missing", func() {
				It("should fail", func() {
					req := new(csiext.DeleteStorageProtectionGroupRequest)
					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("missing globalID in protection group attributes"))
				})
			})
			When("Array with specified globalID couldn't be found", func() {
				It("should fail", func() {

					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)
					params["globalID"] = "SOMETHING WRONG"
					req.ProtectionGroupAttributes = params
					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("can't find array with global id"))
				})
			})
			When("can't get volume group", func() {
				It("should fail", func() {
					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(

						gopowerstore.VolumeGroup{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})
					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID

					req.ProtectionGroupAttributes = params

					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Error: Unable to get Volume Group"))
				})
			})
			When("can't get volume group name", func() {
				It("should fail", func() {
					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(
						gopowerstore.VolumeGroup{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID

					req.ProtectionGroupAttributes = params

					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Error: Unable to get volume group name"))
				})
			})
			When("Can't unassign the protection policy from volume group", func() {
				It("should fail", func() {
					vg := gopowerstore.VolumeGroup{}
					vg.ProtectionPolicyID = validPolicyID
					vg.ID = validGroupID
					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(
						vg, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("ModifyVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID

					req.ProtectionGroupAttributes = params

					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Error: Unable to un-assign PP from Volume Group"))
				})
			})
			When("Can't delete volume group", func() {
				It("should fail", func() {
					vg := gopowerstore.VolumeGroup{}
					vg.ProtectionPolicyID = ""
					vg.ID = validGroupID
					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(
						vg, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("DeleteVolumeGroup", mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID

					req.ProtectionGroupAttributes = params
					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Error: : Unable to delete Volume Group"))
				})
			})
			When("Can't get the protection policy", func() {
				It("should fail", func() {
					vg := gopowerstore.VolumeGroup{}
					vg.ProtectionPolicyID = validPolicyID
					vg.ID = validGroupID
					vg.Name = validGroupName
					pp := gopowerstore.ProtectionPolicy{}
					pp.Name = validPolicyName

					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(
						vg, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("GetProtectionPolicyByName", mock.Anything, mock.Anything).Return(
						gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})
					clientMock.On("ModifyVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("DeleteVolumeGroup", mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
						gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID
					params["VolumeGroupName"] = validGroupName

					req.ProtectionGroupAttributes = params
					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Error: Unable to get the PP"))
				})
			})

			When("The replication rule couldn't be found", func() {
				It("should fail", func() {
					vg := gopowerstore.VolumeGroup{}
					vg.ProtectionPolicyID = validPolicyID
					vg.ID = validGroupID
					vg.Name = validGroupName
					pp := gopowerstore.ProtectionPolicy{}
					pp.Name = validPolicyName
					rr := gopowerstore.ReplicationRule{}
					rr.Name = validRuleName

					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(
						vg, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("GetProtectionPolicyByName", mock.Anything, mock.Anything).Return(
						gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("ModifyVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("DeleteVolumeGroup", mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
						rr, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID
					params["VolumeGroupName"] = validGroupName

					req.ProtectionGroupAttributes = params
					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Error: RR not found"))
				})
			})
			When("The replication rule can't be deleted", func() {
				It("should fail", func() {
					vg := gopowerstore.VolumeGroup{}
					vg.ProtectionPolicyID = validPolicyID
					vg.ID = validGroupID
					vg.Name = validGroupName
					pp := gopowerstore.ProtectionPolicy{}
					pp.Name = validPolicyName
					rr := gopowerstore.ReplicationRule{}
					rr.Name = validRuleName
					rr.ID = validRuleID

					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(
						vg, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("GetProtectionPolicyByName", mock.Anything, mock.Anything).Return(
						gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("ModifyVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("DeleteVolumeGroup", mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
						rr, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("DeleteReplicationRule", mock.Anything, mock.Anything).Return(
						gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID
					params["VolumeGroupName"] = validGroupName

					req.ProtectionGroupAttributes = params

					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Error: Unable to delete replication rule"))
				})
			})
		})
		Describe("calling GetReplicationCapabilities()", func() {
			When("basic parameters are declared", func() {
				It("should pass", func() {
					context := context.Background()
					req := new(csiext.GetReplicationCapabilityRequest)
					var rep = new(csiext.GetReplicationCapabilityResponse)
					rep.Capabilities = []*csiext.ReplicationCapability{
						{
							Type: &csiext.ReplicationCapability_Rpc{
								Rpc: &csiext.ReplicationCapability_RPC{
									Type: csiext.ReplicationCapability_RPC_CREATE_REMOTE_VOLUME,
								},
							},
						},
						{
							Type: &csiext.ReplicationCapability_Rpc{
								Rpc: &csiext.ReplicationCapability_RPC{
									Type: csiext.ReplicationCapability_RPC_CREATE_PROTECTION_GROUP,
								},
							},
						},
						{
							Type: &csiext.ReplicationCapability_Rpc{
								Rpc: &csiext.ReplicationCapability_RPC{
									Type: csiext.ReplicationCapability_RPC_DELETE_PROTECTION_GROUP,
								},
							},
						},
						{
							Type: &csiext.ReplicationCapability_Rpc{
								Rpc: &csiext.ReplicationCapability_RPC{
									Type: csiext.ReplicationCapability_RPC_REPLICATION_ACTION_EXECUTION,
								},
							},
						},
						{
							Type: &csiext.ReplicationCapability_Rpc{
								Rpc: &csiext.ReplicationCapability_RPC{
									Type: csiext.ReplicationCapability_RPC_MONITOR_PROTECTION_GROUP,
								},
							},
						},
					}
					rep.Actions = []*csiext.SupportedActions{
						{
							Actions: &csiext.SupportedActions_Type{
								Type: csiext.ActionTypes_FAILOVER_REMOTE,
							},
						},
						{
							Actions: &csiext.SupportedActions_Type{
								Type: csiext.ActionTypes_UNPLANNED_FAILOVER_LOCAL,
							},
						},
						{
							Actions: &csiext.SupportedActions_Type{
								Type: csiext.ActionTypes_REPROTECT_LOCAL,
							},
						},
						{
							Actions: &csiext.SupportedActions_Type{
								Type: csiext.ActionTypes_SUSPEND,
							},
						},
						{
							Actions: &csiext.SupportedActions_Type{
								Type: csiext.ActionTypes_RESUME,
							},
						},
						{
							Actions: &csiext.SupportedActions_Type{
								Type: csiext.ActionTypes_SYNC,
							},
						},
					}
					res, err := ctrlSvc.GetReplicationCapabilities(context, req)
					Expect(err).To(BeNil())
					Expect(res).To(Equal(rep))

				})
			})
		})

		Describe("calling ExecuteAction()", func() {
			When("action is unknown", func() {
				It("should fail", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_UNKNOWN_ACTION,
					}
					params := make(map[string]string)
					params["globalID"] = "globalvolid1"
					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       nil,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)
					Expect(err).NotTo(BeNil())

				})
			})
			When("Array can't be found", func() {
				It("should fail", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_FAILOVER_REMOTE,
					}
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
					clientMock.On("ExecuteAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(status.Errorf(codes.Internal, "Execute action: Failed to modify RS (%s) - Error (%s)", "123", "12"))
					ctrlSvc.SetArrays(map[string]*array.PowerStoreArray{})
					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)

					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("can't find array with global id "))

				})
			})
			When("the action is not supported", func() {
				It("should fail", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_UNKNOWN_ACTION,
					}
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationSession{}, status.Errorf(codes.Unknown, "The requested action does not match with supported actions"))

					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)
					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("The requested action does not match with supported actions"))

				})
			})

			When("the replication session is executing previous action. the action type is unplanned failover local", func() {
				It("should fail", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_UNPLANNED_FAILOVER_LOCAL,
					}
					session := gopowerstore.ReplicationSession{ID: "test", State: "Failing_Over"}

					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(session, nil)

					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)

					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Execute action: RS (test) is still executing previous action"))

				})
			})
			When("the action type is suspend", func() {
				It("pass", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_SUSPEND,
					}
					session := gopowerstore.ReplicationSession{ID: "test", State: "Failing_Over"}

					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(session, nil)

					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)

					Expect(err).To(BeNil())

				})
			})
			When("the replication session is executing previous action. the action type is failover remote.", func() {
				It("should fail", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_FAILOVER_REMOTE,
					}
					session := gopowerstore.ReplicationSession{ID: "test", State: "Failing_Over"}

					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(session, nil)

					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)

					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Execute action: RS (test) is still executing previous action"))

				})
			})
			When("the replication session can't be modified due to sync action type.", func() {
				It("should fail", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_SYNC,
					}
					session := gopowerstore.ReplicationSession{ID: "test", State: "Failed_Over"}

					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(session, nil)

					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)

					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("Execute action: Failed to modify RS (test) - Error ()"))

				})
			})
			When("the action type is resume", func() {
				It("should pass", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_RESUME,
					}
					session := gopowerstore.ReplicationSession{ID: "test", State: "Failing_Over"}

					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(session, nil)

					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)

					Expect(err).To(BeNil())

				})
			})
			When("the action type is sync", func() {
				It("should pass", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_SYNC,
					}
					session := gopowerstore.ReplicationSession{ID: "test", State: "Failing_Over"}

					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(session, nil)

					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)

					Expect(err).To(BeNil())

				})
			})
			When("the action type is reprotect local", func() {
				It("should pass", func() {

					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_REPROTECT_LOCAL,
					}
					session := gopowerstore.ReplicationSession{ID: "test", State: "Failing_Over"}

					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(session, nil)

					params := make(map[string]string)
					params["globalID"] = "globalvolid1"

					req := &csiext.ExecuteActionRequest{
						ActionId:                        "",
						ProtectionGroupId:               "",
						ActionTypes:                     &csiext.ExecuteActionRequest_Action{Action: action},
						ProtectionGroupAttributes:       params,
						RemoteProtectionGroupId:         "",
						RemoteProtectionGroupAttributes: nil,
					}
					_, err := ctrlSvc.ExecuteAction(context.Background(), req)

					Expect(err).To(BeNil())

				})
			})

		})

	})
})
