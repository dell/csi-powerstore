/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,  either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package controller

import (
	"context"
	"net/http"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	csiext "github.com/dell/dell-csi-extensions/replication"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = ginkgo.Describe("Replication", func() {
	ginkgo.BeforeEach(func() {
		setVariables()
	})

	ginkgo.Describe("calling GetStorageProtectionGroupStatus()", func() {
		ginkgo.When("getting storage protection group status and state is ok", func() {
			ginkgo.It("should return synchronized status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateOk}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SYNCHRONIZED,
				))
			})
		})

		ginkgo.When("getting storage protection group status and state is failed over", func() {
			ginkgo.It("should return failed over status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateFailedOver}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_FAILEDOVER,
				))
			})
		})

		ginkgo.When("getting storage protection group status and state is paused (for several reasons)", func() {
			ginkgo.It("should return suspended status (if paused)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStatePaused}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			ginkgo.It("should return suspended status (if paused for migration)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStatePausedForMigration}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			ginkgo.It("should return suspended status (if paused for NDU)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStatePausedForNdu}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			ginkgo.It("should return suspended status (if system paused)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateSystemPaused}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
		})

		ginkgo.When("getting storage protection group status and state is updating (in progress)", func() {
			ginkgo.It("should return 'sync in progress' status (if failing over)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateFailingOver}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			ginkgo.It("should return 'sync in progress' status (if failing over for DR)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateFailingOverForDR}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			ginkgo.It("should return 'sync in progress' status (if resuming)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateResuming}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			ginkgo.It("should return 'sync in progress' status (if reprotecting)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateReprotecting}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			ginkgo.It("should return 'sync in progress' status (if cutover for migration)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStatePartialCutoverForMigration}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			ginkgo.It("should return 'sync in progress' status (if synchronizing)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateSynchronizing}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			ginkgo.It("should return 'sync in progress' status (if initializing)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateInitializing}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
		})

		ginkgo.When("getting storage protection group status and state is error", func() {
			ginkgo.It("should return invalid status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RsStateError}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_INVALID,
				))
			})
		})

		ginkgo.When("getting storage protection group status and state does not match with known protection group states", func() {
			ginkgo.It("should return unknown status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Status.State).To(gomega.Equal(
					csiext.StorageProtectionGroupStatus_UNKNOWN,
				))
			})
		})

		ginkgo.When("GlobalID is missing", func() {
			ginkgo.It("should fail", func() {
				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(
					gomega.ContainSubstring("missing globalID in protection group attributes"),
				)
			})
		})

		ginkgo.When("Array with specified globalID couldn't be found", func() {
			ginkgo.It("should fail", func() {
				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "SOMETHING WRONG"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(
					gomega.ContainSubstring("can't find array with global id"),
				)
			})
		})

		ginkgo.When("Invalid client response", func() {
			ginkgo.It("should fail", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, status.Errorf(codes.InvalidArgument, "Invalid client response"))

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(
					gomega.ContainSubstring("Invalid client response"),
				)
			})
		})
	})
	ginkgo.Describe("calling ExecuteAction()", func() {
		ginkgo.When("action is RsActionResume and state is OK", func() {
			ginkgo.It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "OK"}
				action := gopowerstore.RsActionResume
				failoverParams := gopowerstore.FailoverParams{}
				err := ExecuteAction(&session, clientMock, action, &failoverParams)

				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("action is RsActionReprotect and state is not OK", func() {
			ginkgo.It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "OK"}
				action := gopowerstore.RsActionReprotect
				failoverParams := gopowerstore.FailoverParams{}
				err := ExecuteAction(&session, clientMock, action, &failoverParams)

				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("action is RsActionPause and state is Paused", func() {
			ginkgo.It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "Paused"}
				action := gopowerstore.RsActionPause
				failoverParams := gopowerstore.FailoverParams{}
				err := ExecuteAction(&session, clientMock, action, &failoverParams)

				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("action is RsActionFailover and state is Failing_Over", func() {
			ginkgo.It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "Failing_Over"}
				action := gopowerstore.RsActionFailover
				failoverParams := gopowerstore.FailoverParams{}
				err := ExecuteAction(&session, clientMock, action, &failoverParams)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(
					gomega.ContainSubstring("Execute action: RS (test) is still executing previous action"))
			})
		})

		ginkgo.When("action is RsActionFailover and state is Failed_Over", func() {
			ginkgo.It("return nil", func() {
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				session := gopowerstore.ReplicationSession{ID: "test", State: "Failed_Over"}
				action := gopowerstore.RsActionFailover
				failoverParams := gopowerstore.FailoverParams{}
				err := ExecuteAction(&session, clientMock, action, &failoverParams)

				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.Describe("calling DeleteLocalVolume()", func() {
			ginkgo.When("Volume ID is missing", func() {
				ginkgo.It("should fail", func() {
					req := new(csiext.DeleteLocalVolumeRequest)
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("can't delete volume of improper handle format"))
				})
			})
			ginkgo.When("Array with specified globalID couldn't be found", func() {
				ginkgo.It("should fail", func() {
					req := new(csiext.DeleteLocalVolumeRequest)
					handle := "valid-id/SOMETHING-WRONG/iscsi"
					req.VolumeHandle = handle
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("can't find array with global ID"))
				})
			})
			ginkgo.When("the volume cannot be found on the powerstore array", func() {
				ginkgo.It("should fail with 'not found'", func() {
					// GetVolume should return a NotFound error.
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
						gopowerstore.Volume{}, gopowerstore.WrapErr(gopowerstore.NewNotFoundError()),
					)

					req := &csiext.DeleteLocalVolumeRequest{
						VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
					}
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.Equal(
						&csiext.DeleteLocalVolumeResponse{},
					))
					gomega.Expect(err).To(gomega.BeNil())
				})
				ginkgo.It("should fail to get the volume", func() {
					// GetVolume should return a non-nil error, and not be a NotFoundError
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
						gopowerstore.Volume{}, gopowerstore.WrapErr(gopowerstore.NewAPIError()),
					)

					req := &csiext.DeleteLocalVolumeRequest{
						VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
					}
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(
						"Unable to get volume for deletion",
					))
				})
			})
			ginkgo.When("the volume group cannot be found", func() {
				ginkgo.It("should fail to get the volume group", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
					clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
						Return(gopowerstore.VolumeGroups{}, gopowerstore.WrapErr(gopowerstore.NewAPIError()))

					req := &csiext.DeleteLocalVolumeRequest{
						VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
					}
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
				})
			})
			ginkgo.When("the volume is part of volume group", func() {
				ginkgo.It("should fail to delete the volume", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
					clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
						Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID}}}, nil)

					req := &csiext.DeleteLocalVolumeRequest{
						VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
					}
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(
						"Unable to delete volume",
					))
				})
			})
			ginkgo.When("the volume is still protected", func() {
				ginkgo.It("should fail to delete the volume", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: validPolicyID}, nil)
					clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
						Return(gopowerstore.VolumeGroups{}, nil)

					req := &csiext.DeleteLocalVolumeRequest{
						VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
					}
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(
						"Unable to delete volume",
					))
				})
			})
			ginkgo.When("the delete volume call failed", func() {
				ginkgo.It("should fail to delete the volume", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
					clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
						Return(gopowerstore.VolumeGroups{}, nil)
					clientMock.On("DeleteVolume",
						mock.Anything,
						mock.AnythingOfType("*gopowerstore.VolumeDelete"),
						validBaseVolID).
						Return(gopowerstore.EmptyResponse(""), gopowerstore.NewAPIError())

					req := &csiext.DeleteLocalVolumeRequest{
						VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
					}
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(
						"Unable to delete volume",
					))
				})
			})
			ginkgo.When("the delete local volume is requested", func() {
				ginkgo.It("should succeed to delete the local volume", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
					clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
						Return(gopowerstore.VolumeGroups{}, nil)
					clientMock.On("DeleteVolume",
						mock.Anything,
						mock.AnythingOfType("*gopowerstore.VolumeDelete"),
						validBaseVolID).
						Return(gopowerstore.EmptyResponse(""), nil)

					req := &csiext.DeleteLocalVolumeRequest{
						VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
					}
					res, err := ctrlSvc.DeleteLocalVolume(context.Background(), req)

					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).ToNot(gomega.BeNil())
				})
			})
		})

		ginkgo.Describe("calling DeleteStorageProtectionGroup()", func() {
			ginkgo.When("GlobalID is missing", func() {
				ginkgo.It("should fail", func() {
					req := new(csiext.DeleteStorageProtectionGroupRequest)
					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("missing globalID in protection group attributes"))
				})
			})
			ginkgo.When("Array with specified globalID couldn't be found", func() {
				ginkgo.It("should fail", func() {
					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)
					params["globalID"] = "SOMETHING WRONG"
					req.ProtectionGroupAttributes = params
					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("can't find array with global id"))
				})
			})
			ginkgo.When("can't get volume group", func() {
				ginkgo.It("should fail", func() {
					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(

						gopowerstore.VolumeGroup{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})
					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID

					req.ProtectionGroupAttributes = params

					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Error: Unable to get Volume Group"))
				})
			})
			ginkgo.When("can't get volume group name", func() {
				ginkgo.It("should fail", func() {
					clientMock.On("GetVolumeGroup", mock.Anything, mock.Anything).Return(
						gopowerstore.VolumeGroup{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)

					params["globalID"] = firstValidID

					req.ProtectionGroupAttributes = params

					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Error: Unable to get volume group name"))
				})
			})
			ginkgo.When("Can't unassign the protection policy from volume group", func() {
				ginkgo.It("should fail", func() {
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

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Error: Unable to un-assign PP from Volume Group"))
				})
			})
			ginkgo.When("Can't delete volume group", func() {
				ginkgo.It("should fail", func() {
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

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Error: Unable to delete Volume Group"))
				})
			})
			ginkgo.When("Can't get the protection policy", func() {
				ginkgo.It("should fail", func() {
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

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Error: Unable to get protection policy"))
				})
			})

			ginkgo.When("The replication rule couldn't be found", func() {
				ginkgo.It("should fail", func() {
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

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Error: Unable to get replication rule"))
				})
			})
			ginkgo.When("The replication rule can't be deleted", func() {
				ginkgo.It("should fail", func() {
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

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Error: Unable to delete replication rule"))
				})
			})
			ginkgo.When("NFS context is detected via NasServerID", func() {
				ginkgo.It("should skip deletion logic and return success", func() {
					req := new(csiext.DeleteStorageProtectionGroupRequest)
					params := make(map[string]string)
					params["globalID"] = firstValidID
					params["NasServerID"] = "nas-server-id"
					req.ProtectionGroupAttributes = params
					res, err := ctrlSvc.DeleteStorageProtectionGroup(context.Background(), req)
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).ToNot(gomega.BeNil())
				})
			})
		})
		ginkgo.Describe("calling GetReplicationCapabilities()", func() {
			ginkgo.When("basic parameters are declared", func() {
				ginkgo.It("should pass", func() {
					context := context.Background()
					req := new(csiext.GetReplicationCapabilityRequest)
					rep := new(csiext.GetReplicationCapabilityResponse)
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
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(rep))
				})
			})
		})

		ginkgo.Describe("calling ExecuteAction()", func() {
			ginkgo.When("action is unknown", func() {
				ginkgo.It("should fail", func() {
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
					gomega.Expect(err).NotTo(gomega.BeNil())
				})
			})
			ginkgo.When("Array can't be found", func() {
				ginkgo.It("should fail", func() {
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

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("can't find array with global id "))
				})
			})
			ginkgo.When("the action is not supported", func() {
				ginkgo.It("should fail", func() {
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
					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("The requested action does not match with supported actions"))
				})
			})

			ginkgo.When("the replication session is executing previous action. the action type is unplanned failover local", func() {
				ginkgo.It("should fail", func() {
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

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Execute action: RS (test) is still executing previous action"))
				})
			})
			ginkgo.When("the action type is suspend", func() {
				ginkgo.It("pass", func() {
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

					gomega.Expect(err).To(gomega.BeNil())
				})
			})
			ginkgo.When("the replication session is executing previous action. the action type is failover remote.", func() {
				ginkgo.It("should fail", func() {
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

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Execute action: RS (test) is still executing previous action"))
				})
			})
			ginkgo.When("the replication session can't be modified due to sync action type.", func() {
				ginkgo.It("should fail", func() {
					action := &csiext.Action{
						ActionTypes: csiext.ActionTypes_SYNC,
					}
					session := gopowerstore.ReplicationSession{ID: "test", State: "Failed_Over"}

					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})
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

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("Execute action: Failed to modify RS (test) - Error ()"))
				})
			})
			ginkgo.When("the action type is resume", func() {
				ginkgo.It("should pass", func() {
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

					gomega.Expect(err).To(gomega.BeNil())
				})
			})
			ginkgo.When("the action type is sync", func() {
				ginkgo.It("should pass", func() {
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

					gomega.Expect(err).To(gomega.BeNil())
				})
			})
			ginkgo.When("the action type is reprotect local", func() {
				ginkgo.It("should pass", func() {
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

					gomega.Expect(err).To(gomega.BeNil())
				})
			})
		})
	})
})
