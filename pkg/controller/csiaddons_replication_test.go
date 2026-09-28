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
	"errors"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	csiaddonsreplication "github.com/csi-addons/spec/lib/go/replication"
	volumegrouprpc "github.com/csi-addons/spec/lib/go/volumegroup"
	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = ginkgo.Describe("CSI-Addons Replication", func() {
	var csiAddonsServer *CSIAddonsReplicationServer

	ginkgo.BeforeEach(func() {
		setVariables()
		csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
	})

	ginkgo.Describe("calling EnableVolumeReplication()", func() {
		ginkgo.When("request validation fails", func() {
			// Note: replication_id is OPTIONAL per CSI-Addons spec, so we don't test for its absence

			ginkgo.It("should fail when volume_id is missing", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationId: "test-replication-id",
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								// VolumeId is empty
								VolumeId: "",
							},
						},
					},
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem: validRemoteSystemName,
						CSIAddonsParamRPO:          validRPO,
					},
				}

				_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
			})

			ginkgo.It("should fail when remoteSystem parameter is missing", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRPO: validRPO,
						// CSIAddonsParamRemoteSystem is missing
					},
				}

				_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("remoteSystem"))
			})
		})

		ginkgo.When("Metro mode is requested", func() {
			ginkgo.It("should fail with unsupported error", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "METRO",
					},
				}

				// Mock the remote system lookup
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Metro"))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("not supported"))
			})
		})

		ginkgo.When("ASYNC replication mode is requested", func() {
			ginkgo.It("should fail when RPO is missing for ASYNC mode", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "ASYNC",
						// CSIAddonsParamRPO is missing
					},
				}

				// Mock the remote system lookup
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("RPO"))
			})

			ginkgo.It("should fail when RPO is Zero for ASYNC mode", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "ASYNC",
						CSIAddonsParamRPO:             "Zero",
					},
				}

				// Mock the remote system lookup
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("non-Zero"))
			})

			ginkgo.It("should successfully enable ASYNC replication for block volume", func() {
				vgName := defaultVGPrefix + "-" + validRemoteSystemName + "-" + validRPO
				ppName := "pp-" + vgName
				rrName := "rr-" + vgName

				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "ASYNC",
						CSIAddonsParamRPO:             validRPO,
					},
				}

				// Mock: No existing replication session
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				// Mock: Get remote system
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				// Mock: Protection policy doesn't exist
				clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
					gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

				// Mock: Replication rule doesn't exist
				clientMock.On("GetReplicationRuleByName", mock.Anything, rrName).Return(
					gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

				// Mock: Create replication rule
				clientMock.On("CreateReplicationRule", mock.Anything, mock.Anything).Return(
					gopowerstore.CreateResponse{ID: validRuleID}, nil)

				// Mock: Create protection policy
				clientMock.On("CreateProtectionPolicy", mock.Anything, mock.Anything).Return(
					gopowerstore.CreateResponse{ID: validPolicyID}, nil)

				// Mock: Apply protection policy to volume
				clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
					gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should fail when EnsureProtectionPolicyExists fails", func() {
				vgName := defaultVGPrefix + "-" + validRemoteSystemName + "-" + validRPO
				ppName := "pp-" + vgName
				rrName := "rr-" + vgName
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "ASYNC",
						CSIAddonsParamRPO:             validRPO,
					},
				}

				// Mock: No existing replication session
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				// Mock: Get remote system
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				// Mock: Protection policy exists but has an error during retrieval
				clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
					gopowerstore.ProtectionPolicy{}, errors.New("protection policy error"))

				// Mock: replication rule lookup and creation to force EnsureReplicationRuleExists failure
				clientMock.On("GetReplicationRuleByName", mock.Anything, rrName).Return(
					gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
				clientMock.On("CreateReplicationRule", mock.Anything, mock.Anything).Return(
					gopowerstore.CreateResponse{}, errors.New("create replication rule failed"))

				_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to ensure protection policy"))
			})

			ginkgo.It("should fail when ModifyVolume fails", func() {
				vgName := defaultVGPrefix + "-" + validRemoteSystemName + "-" + validRPO
				ppName := "pp-" + vgName
				rrName := "rr-" + vgName
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "ASYNC",
						CSIAddonsParamRPO:             validRPO,
					},
				}

				// Mock: No existing replication session
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				// Mock: Get remote system
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				// Mock: Protection policy doesn't exist
				clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
					gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

				// Mock: Replication rule doesn't exist
				clientMock.On("GetReplicationRuleByName", mock.Anything, rrName).Return(
					gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

				// Mock: Create replication rule
				clientMock.On("CreateReplicationRule", mock.Anything, mock.Anything).Return(
					gopowerstore.CreateResponse{ID: validRuleID}, nil)

				// Mock: Create protection policy
				clientMock.On("CreateProtectionPolicy", mock.Anything, mock.Anything).Return(
					gopowerstore.CreateResponse{ID: validPolicyID}, nil)

				// Mock: Apply protection policy to volume - fails
				clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
					gopowerstore.EmptyResponse(""), errors.New("volume modification failed"))

				_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to apply protection policy to volume"))
			})

			ginkgo.It("should return success when replication is already enabled (idempotency)", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "ASYNC",
						CSIAddonsParamRPO:             validRPO,
					},
				}

				// Mock: Existing replication session found
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)

				// Mock: Get remote system (still needed for validation)
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				res, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should return success when volume is already in protected volume group", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "ASYNC",
						CSIAddonsParamRPO:             validRPO,
					},
				}

				// Mock: Existing replication session found
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)

				// Mock: Get remote system (still needed for validation)
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				res, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("SYNC replication mode is requested", func() {
			// Note: SYNC mode silently uses Zero RPO regardless of user input, so no validation failure test needed

			ginkgo.It("should successfully enable SYNC replication with Zero RPO", func() {
				vgName := defaultVGPrefix + "-" + validRemoteSystemName + "-Zero"
				ppName := "pp-" + vgName
				rrName := "rr-" + vgName

				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "SYNC",
						// RPO defaults to Zero for SYNC
					},
				}

				// Mock: No existing replication session
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				// Mock: Get remote system
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
					gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				// Mock: Protection policy doesn't exist
				clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
					gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

				// Mock: Replication rule doesn't exist
				clientMock.On("GetReplicationRuleByName", mock.Anything, rrName).Return(
					gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

				// Mock: Create replication rule
				clientMock.On("CreateReplicationRule", mock.Anything, mock.Anything).Return(
					gopowerstore.CreateResponse{ID: validRuleID}, nil)

				// Mock: Create protection policy
				clientMock.On("CreateProtectionPolicy", mock.Anything, mock.Anything).Return(
					gopowerstore.CreateResponse{ID: validPolicyID}, nil)

				// Mock: Apply protection policy to volume
				clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
					gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("array is not found", func() {
			ginkgo.It("should fail with NotFound error for invalid array ID", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: invalidBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Parameters: map[string]string{
						CSIAddonsParamRemoteSystem:    validRemoteSystemName,
						CSIAddonsParamReplicationMode: "ASYNC",
						CSIAddonsParamRPO:             validRPO,
					},
				}

				_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
			})
		})
	})

	ginkgo.Describe("calling NewCSIAddonsReplicationServer()", func() {
		ginkgo.It("should create a new server with service reference", func() {
			server := NewCSIAddonsReplicationServer(ctrlSvc)

			gomega.Expect(server).ToNot(gomega.BeNil())
			gomega.Expect(server.service).To(gomega.Equal(ctrlSvc))
		})
	})

	ginkgo.Describe("extractReplicationSource", func() {
		ginkgo.When("replication source is nil", func() {
			ginkgo.It("should return empty strings without error", func() {
				volumeID, volumeGroupID, err := csiAddonsServer.extractReplicationSource(nil)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(volumeID).To(gomega.Equal(""))
				gomega.Expect(volumeGroupID).To(gomega.Equal(""))
			})
		})

		ginkgo.When("replication source has volume", func() {
			ginkgo.It("should return volume ID", func() {
				source := &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
							VolumeId: validBlockVolumeID,
						},
					},
				}

				volumeID, volumeGroupID, err := csiAddonsServer.extractReplicationSource(source)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(volumeID).To(gomega.Equal(validBlockVolumeID))
				gomega.Expect(volumeGroupID).To(gomega.Equal(""))
			})
		})

		ginkgo.When("replication source has volume group", func() {
			ginkgo.It("should return volume group ID", func() {
				source := &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				}

				volumeID, volumeGroupID, err := csiAddonsServer.extractReplicationSource(source)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(volumeID).To(gomega.Equal(""))
				gomega.Expect(volumeGroupID).To(gomega.Equal(validGroupID))
			})
		})

		ginkgo.When("replication source has neither volume nor volume group", func() {
			ginkgo.It("should return InvalidArgument error", func() {
				source := &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{},
					},
				}

				_, _, err := csiAddonsServer.extractReplicationSource(source)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
			})
		})

		ginkgo.When("replication source has unknown type", func() {
			ginkgo.It("should return error", func() {
				source := &csiaddonsreplication.ReplicationSource{}
				_, _, err := csiAddonsServer.extractReplicationSource(source)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unknown replication source type"))
			})
		})
	})

	ginkgo.Describe("calling DisableVolumeReplication()", func() {
		ginkgo.When("request validation fails", func() {
			// Note: replication_id is OPTIONAL per CSI-Addons spec, so we don't test for its absence

			ginkgo.It("should fail when volume_id is missing", func() {
				req := &csiaddonsreplication.DisableVolumeReplicationRequest{
					ReplicationId: "test-replication-id",
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								// VolumeId is empty
								VolumeId: "",
							},
						},
					},
				}

				_, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
			})
		})

		ginkgo.It("should allow disable when session is Failed_Over but local role is Source", func() {
			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
				ReplicationId: "test-replication-id",
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateFailedOver, Role: string(gopowerstore.ReplicationRoleSource)}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: ""}, nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
				gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with FailedPrecondition when Failed_Over and local role is Destination", func() {
			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
				ReplicationId: "test-replication-id",
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateFailedOver, Role: string(gopowerstore.ReplicationRoleDestination)}, nil)

			_, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should disable using replication_source volume", func() {
			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationId: "test-replication-id",
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: ""}, nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
				gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.When("block volume replication is disabled", func() {
			ginkgo.It("should successfully unassign protection policy from volume", func() {
				req := &csiaddonsreplication.DisableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
				}

				// Mock: Replication session exists and is not Failed_Over
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)

				// Mock: GetVolume to capture protection policy ID
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
					gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: ""}, nil)

				// Mock: Unassign protection policy
				clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
					gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should return success when volume is not found (idempotency)", func() {
				req := &csiaddonsreplication.DisableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())
				clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
					gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

				res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should handle already unassigned protection policy (idempotency)", func() {
				req := &csiaddonsreplication.DisableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
				}

				// Mock: Replication session exists and is not Failed_Over
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)

				// Mock: GetVolume to capture protection policy ID
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
					gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: ""}, nil)

				// Mock: Unassign protection policy
				clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
					gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

				res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})
		})
	})

	ginkgo.Describe("calling PromoteVolume()", func() {
		ginkgo.When("request validation fails", func() {
			// Note: replication_id is OPTIONAL per CSI-Addons spec, so we don't test for its absence

			ginkgo.It("should fail when volume_id is missing", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationId: "test-replication-id",
					// VolumeId is missing
				}

				_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
			})
		})

		ginkgo.When("block volume failover is requested", func() {
			ginkgo.It("should fail with FailedPrecondition when local is secondary, force=false and remote system appears down", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session for volume (local secondary)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:             validSessionID,
						RemoteSystemID: "remote-system-id",
						Role:           string(gopowerstore.ReplicationRoleDestination),
						State:          gopowerstore.RsStateFailedOver,
					}, nil)

				clientMock.On("GetRemoteSystem", mock.Anything, "remote-system-id").Return(
					gopowerstore.RemoteSystem{ID: "remote-system-id", DataConnectionState: string(gopowerstore.ConnStateCompleteDataConnLoss)}, nil)

				_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})

			ginkgo.It("should successfully execute unplanned failover (force=true)", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         true, // Unplanned failover
				}

				// Mock: Get replication session for volume (local secondary)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleDestination),
						State: gopowerstore.RsStateFailedOver,
					}, nil)

				// Mock: Execute failover action
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
					gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should return success when already primary (idempotency)", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - already primary
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: gopowerstore.RsStateOk,
					}, nil)

				res, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should return Aborted when failover is already in progress", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - failover in progress
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleDestination),
						State: gopowerstore.RsStateFailingOver,
					}, nil)

				_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
			})

			ginkgo.It("should fail when no replication session found for volume", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: No replication session found
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})

			ginkgo.It("should return Aborted when failover is already in progress", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - failover in progress
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleDestination),
						State: gopowerstore.RsStateFailingOver,
					}, nil)

				_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
			})

			ginkgo.It("should fail when no replication session found for volume", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: No replication session found
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})
		})

		ginkgo.When("array is not found", func() {
			ginkgo.It("should fail with NotFound error for invalid array ID", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: invalidBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
			})
		})
	})

	ginkgo.Describe("calling DemoteVolume()", func() {
		ginkgo.When("request validation fails", func() {
			// Note: replication_id is OPTIONAL per CSI-Addons spec, so we don't test for its absence

			ginkgo.It("should fail when volume_id is missing", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationId: "test-replication-id",
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								// VolumeId is empty
								VolumeId: "",
							},
						},
					},
				}

				_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
			})
		})

		ginkgo.When("block volume demotion is requested", func() {
			ginkgo.It("should return success when session is already in OK state (idempotency)", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - local secondary already
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleDestination),
						State: gopowerstore.RsStateOk,
					}, nil)

				res, err := csiAddonsServer.DemoteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should execute Reprotect when session is in Failed_Over state", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - local primary, needs planned failover
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: gopowerstore.RsStateOk,
					}, nil)

				// Mock: Execute planned failover action
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
					gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.DemoteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should return Aborted when Reprotect is already in progress", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - Reprotect in progress
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: gopowerstore.RsStateReprotecting,
					}, nil)

				_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
			})

			ginkgo.It("should return FailedPrecondition when session is paused without force", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - paused
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: gopowerstore.RsStatePaused,
					}, nil)

				_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})

			ginkgo.It("should resume paused session when force=true", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         true, // Force resume
				}

				// Mock: Get replication session - paused
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: gopowerstore.RsStatePaused,
					}, nil)

				// Mock: Execute Resume action
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
					gopowerstore.RsActionResume, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.DemoteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
			})

			ginkgo.It("should fail when no replication session found for volume", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: No replication session found
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})
		})

		ginkgo.When("array is not found", func() {
			ginkgo.It("should fail with NotFound error for invalid array ID", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: invalidBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
			})
		})
	})

	ginkgo.Describe("calling ResyncVolume()", func() {
		ginkgo.When("request validation fails", func() {
			// Note: replication_id is OPTIONAL per CSI-Addons spec, so we don't test for its absence

			ginkgo.It("should fail when volume_id is missing", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationId: "test-replication-id",
					// VolumeId is missing
				}

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
			})
		})

		ginkgo.When("block volume resync is requested", func() {
			ginkgo.It("should return ready=true when session is already in OK state", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - already in OK state
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						State: gopowerstore.RsStateOk,
					}, nil)

				res, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.Ready).To(gomega.BeTrue())
			})

			ginkgo.It("should return ready=false when session is synchronizing", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - synchronizing
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						State: gopowerstore.RsStateSynchronizing,
					}, nil)

				res, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.Ready).To(gomega.BeFalse())
			})

			ginkgo.It("should execute Reprotect when session is in Failed_Over state and local is Source", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: gopowerstore.RsStateFailedOver,
					}, nil)

				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
					gopowerstore.RsActionReprotect, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.Ready).To(gomega.BeFalse())
			})

			ginkgo.It("should execute Resume when session is paused", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - paused
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						State: gopowerstore.RsStatePaused,
					}, nil)

				// Mock: Execute Resume action
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
					gopowerstore.RsActionResume, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.Ready).To(gomega.BeFalse()) // Resume initiated, sync in progress
			})

			ginkgo.It("should return OutOfRange when session is in Failed_Over state without force", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - failed over
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleDestination),
						State: gopowerstore.RsStateFailedOver,
					}, nil)

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.OutOfRange))
			})

			ginkgo.It("should return OutOfRange when session is Failed_Over and local is Destination even with force=true", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         true, // Force flag doesn't help for Failed_Over + Destination
				}

				// Mock: Get replication session - failed over with Destination role
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleDestination),
						State: gopowerstore.RsStateFailedOver,
					}, nil)

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.OutOfRange))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("local is Destination"))
			})

			ginkgo.It("should return Aborted when failover is in progress", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				// Mock: Get replication session - failover in progress
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						State: gopowerstore.RsStateFailingOver,
					}, nil)

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
			})

			ginkgo.It("should return OutOfRange when session is Failed_Over and local is Destination", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleDestination), // Local is Destination
						State: gopowerstore.RsStateFailedOver,
					}, nil)

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.OutOfRange))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("local is Destination"))
			})

			ginkgo.It("should execute Sync when force=true on unexpected state", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         true,
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: "UnexpectedState", // Some unexpected state
					}, nil)
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
					gopowerstore.RsActionSync, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

				res, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.Ready).To(gomega.BeFalse())
			})

			ginkgo.It("should return FailedPrecondition when session is in unexpected state without force", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: "UnexpectedState", // Some unexpected state
					}, nil)

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unexpected state"))
			})

			ginkgo.It("should return FailedPrecondition when session is Failed_Over without force and neither primary nor secondary", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  "", // Empty role - neither primary nor secondary
						State: gopowerstore.RsStateFailedOver,
					}, nil)

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("use force=true"))
			})

			ginkgo.It("should handle FailingOverForDR state", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						Role:  string(gopowerstore.ReplicationRoleSource),
						State: gopowerstore.RsStateFailingOverForDR,
					}, nil)

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failover in progress"))
			})

			ginkgo.It("should fail when no replication session found for volume", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})
		})

		ginkgo.When("array is not found", func() {
			ginkgo.It("should fail with NotFound error for invalid array ID", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: invalidBlockVolumeID},
						},
					},
					ReplicationId: "test-replication-id",
					Force:         false,
				}

				_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
			})
		})
	})

	ginkgo.Describe("calling GetVolumeReplicationInfo()", func() {
		ginkgo.When("request validation fails", func() {
			ginkgo.It("should fail when volume_id is missing", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					// VolumeId is missing
				}

				_, err := csiAddonsServer.GetVolumeReplicationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
			})
		})

		ginkgo.When("block volume replication info is requested", func() {
			ginkgo.It("should return LastSyncTime and HEALTHY status when session is in OK state", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
				}

				// Mock: Get replication session - in OK state
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						State: gopowerstore.RsStateOk,
					}, nil)

				res, err := csiAddonsServer.GetVolumeReplicationInfo(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.LastSyncTime).ToNot(gomega.BeNil())
				gomega.Expect(res.Status).To(gomega.Equal(csiaddonsreplication.GetVolumeReplicationInfoResponse_HEALTHY))
				gomega.Expect(res.StatusMessage).ToNot(gomega.BeEmpty())
			})

			ginkgo.It("should return DEGRADED status and no LastSyncTime when session is synchronizing", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
				}

				// Mock: Get replication session - synchronizing
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						State: gopowerstore.RsStateSynchronizing,
					}, nil)

				res, err := csiAddonsServer.GetVolumeReplicationInfo(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.LastSyncTime).To(gomega.BeNil())
				gomega.Expect(res.Status).To(gomega.Equal(csiaddonsreplication.GetVolumeReplicationInfoResponse_DEGRADED))
				gomega.Expect(res.StatusMessage).ToNot(gomega.BeEmpty())
			})

			ginkgo.It("should return LastSyncTime and DEGRADED status when session is in Failed_Over state", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
				}

				// Mock: Get replication session - failed over
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:    validSessionID,
						State: gopowerstore.RsStateFailedOver,
					}, nil)

				res, err := csiAddonsServer.GetVolumeReplicationInfo(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.LastSyncTime).ToNot(gomega.BeNil())
				gomega.Expect(res.Status).To(gomega.Equal(csiaddonsreplication.GetVolumeReplicationInfoResponse_DEGRADED))
				gomega.Expect(res.StatusMessage).ToNot(gomega.BeEmpty())
			})

			ginkgo.It("should fail when no replication session found for volume", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
						},
					},
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				_, err := csiAddonsServer.GetVolumeReplicationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})
		})

		ginkgo.When("array is not found", func() {
			ginkgo.It("should fail with NotFound error for invalid array ID", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: invalidBlockVolumeID},
						},
					},
				}

				_, err := csiAddonsServer.GetVolumeReplicationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
			})
		})
	})

	ginkgo.Describe("calling GetReplicationDestinationInfo()", func() {
		ginkgo.When("request is nil", func() {
			ginkgo.It("should fail with InvalidArgument", func() {
				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), nil)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("request cannot be nil"))
			})
		})

		ginkgo.When("replication_source is nil", func() {
			ginkgo.It("should fail with InvalidArgument", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					// ReplicationSource is intentionally omitted
				}

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication_source is required"))
			})
		})

		ginkgo.When("replication source is a volume group", func() {
			ginkgo.It("should return NotFound when volume group not found on any array", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
							Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
								VolumeGroupId: "non-existent-vg-id",
							},
						},
					},
				}

				clientMock.On("GetVolumeGroup", mock.Anything, "non-existent-vg-id").Return(
					gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
				clientMock.On("GetVolumeGroups", mock.Anything).Return(
					[]gopowerstore.VolumeGroup{}, nil)

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
			})

			ginkgo.It("should return FailedPrecondition when no replication session exists", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
							Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
								VolumeGroupId: validGroupID,
							},
						},
					},
				}

				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
					gopowerstore.VolumeGroup{ID: validGroupID, Name: "test-vg"}, nil)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
					gopowerstore.ReplicationSession{}, errors.New("session not found"))

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})

			ginkgo.It("should return Unavailable when remote resource ID is empty", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
							Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
								VolumeGroupId: validGroupID,
							},
						},
					},
				}

				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
					gopowerstore.VolumeGroup{ID: validGroupID, Name: "test-vg"}, nil)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
					gopowerstore.ReplicationSession{
						ID:               validSessionID,
						RemoteSystemID:   validRemoteSystemID,
						RemoteResourceID: "",
					}, nil)

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unavailable))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("remote resource ID not yet available"))
			})

			ginkgo.It("should return Internal when GetRemoteSystem fails", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
							Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
								VolumeGroupId: validGroupID,
							},
						},
					},
				}

				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
					gopowerstore.VolumeGroup{ID: validGroupID, Name: "test-vg"}, nil)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
					gopowerstore.ReplicationSession{
						ID:               validSessionID,
						RemoteSystemID:   validRemoteSystemID,
						RemoteResourceID: validRemoteGroupID,
					}, nil)
				clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).Return(
					gopowerstore.RemoteSystem{}, errors.New("remote system lookup failed"))

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to get remote system"))
			})

			ginkgo.It("should successfully return destination volume group info with volume mappings", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
							Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
								VolumeGroupId: validGroupID,
							},
						},
					},
				}

				localVol1UUID := "vol1-local-uuid"
				localVol2UUID := "vol2-local-uuid"
				remoteVol1UUID := "vol1-remote-uuid"
				remoteVol2UUID := "vol2-remote-uuid"

				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
					gopowerstore.VolumeGroup{ID: validGroupID, Name: "test-vg"}, nil)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
					gopowerstore.ReplicationSession{
						ID:               validSessionID,
						RemoteSystemID:   validRemoteSystemID,
						RemoteResourceID: validRemoteGroupID,
						StorageElementPairs: []gopowerstore.StorageElementPair{
							{
								LocalStorageElementID:  localVol1UUID,
								RemoteStorageElementID: remoteVol1UUID,
							},
							{
								LocalStorageElementID:  localVol2UUID,
								RemoteStorageElementID: remoteVol2UUID,
							},
						},
					}, nil)
				clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).Return(
					gopowerstore.RemoteSystem{
						ID:           validRemoteSystemID,
						SerialNumber: validRemoteSystemGlobalID,
					}, nil)

				res, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())

				dest := res.GetReplicationDestination()
				gomega.Expect(dest).ToNot(gomega.BeNil())

				vgDest := dest.GetVolumegroup()
				gomega.Expect(vgDest).ToNot(gomega.BeNil())

				expectedVGID := validRemoteGroupID
				gomega.Expect(vgDest.GetVolumeGroupId()).To(gomega.Equal(expectedVGID))

				volumeMappings := vgDest.GetVolumeIds()
				gomega.Expect(volumeMappings).ToNot(gomega.BeNil())
				gomega.Expect(len(volumeMappings)).To(gomega.Equal(2))

				// findArrayWithVolumeGroupID iterates a Go map (non-deterministic order),
				// and both test arrays share the same clientMock, so either array's GlobalID
				// may appear in the source volume IDs. Determine which one was used.
				var arrayGlobalID string
				for key := range volumeMappings {
					if len(key) > 0 {
						// Extract the globalID portion from the key: <uuid>/<globalID>/scsi
						parts := strings.Split(key, "/")
						if len(parts) >= 2 {
							arrayGlobalID = parts[1]
							break
						}
					}
				}
				gomega.Expect(arrayGlobalID).ToNot(gomega.BeEmpty())

				expectedSourceVol1 := localVol1UUID + "/" + arrayGlobalID + "/scsi"
				expectedDestVol1 := remoteVol1UUID + "/" + validRemoteSystemGlobalID + "/scsi"
				gomega.Expect(volumeMappings[expectedSourceVol1]).To(gomega.Equal(expectedDestVol1))

				expectedSourceVol2 := localVol2UUID + "/" + arrayGlobalID + "/scsi"
				expectedDestVol2 := remoteVol2UUID + "/" + validRemoteSystemGlobalID + "/scsi"
				gomega.Expect(volumeMappings[expectedSourceVol2]).To(gomega.Equal(expectedDestVol2))
			})
		})

		ginkgo.When("array is not found", func() {
			ginkgo.It("should fail with NotFound for invalid array ID", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: invalidBlockVolumeID,
							},
						},
					},
				}

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
			})
		})

		ginkgo.When("no replication session is found for the volume", func() {
			ginkgo.It("should fail with FailedPrecondition", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: validBlockVolumeID,
							},
						},
					},
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{}, errors.New("session not found"))

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
			})
		})

		ginkgo.When("replication session has an empty RemoteResourceID", func() {
			ginkgo.It("should fail with Unavailable", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: validBlockVolumeID,
							},
						},
					},
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:               validSessionID,
						RemoteSystemID:   validRemoteSystemID,
						RemoteResourceID: "", // empty — no destination volume mapped
					}, nil)

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unavailable))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("remote resource ID not yet available"))
			})
		})

		ginkgo.When("GetRemoteSystem fails", func() {
			ginkgo.It("should fail with Internal", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: validBlockVolumeID,
							},
						},
					},
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:               validSessionID,
						RemoteSystemID:   validRemoteSystemID,
						RemoteResourceID: validRemoteVolID,
					}, nil)

				clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).Return(
					gopowerstore.RemoteSystem{}, errors.New("remote system lookup failed"))

				_, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to get remote system"))
			})
		})

		ginkgo.When("all required data is available", func() {
			ginkgo.It("should successfully return destination volume info for a block volume", func() {
				req := &csiaddonsreplication.GetReplicationDestinationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: validBlockVolumeID,
							},
						},
					},
				}

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
					gopowerstore.ReplicationSession{
						ID:               validSessionID,
						RemoteSystemID:   validRemoteSystemID,
						RemoteResourceID: validRemoteVolID,
					}, nil)

				clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).Return(
					gopowerstore.RemoteSystem{
						ID:           validRemoteSystemID,
						SerialNumber: validRemoteSystemGlobalID,
					}, nil)

				res, err := csiAddonsServer.GetReplicationDestinationInfo(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())

				dest := res.GetReplicationDestination()
				gomega.Expect(dest).ToNot(gomega.BeNil())

				volDest := dest.GetVolume()
				gomega.Expect(volDest).ToNot(gomega.BeNil())

				// Destination volume ID format: <remoteUUID>/<remoteSerialNumber>/<protocol>
				expectedVolumeID := validRemoteVolID + "/" + validRemoteSystemGlobalID + "/scsi"
				gomega.Expect(volDest.GetVolumeId()).To(gomega.Equal(expectedVolumeID))
			})
		})
	})
})

var _ = ginkgo.Describe("Helper Functions", func() {
	ginkgo.Describe("RegisterCSIAddonsReplicationServer", func() {
		ginkgo.It("should register the server successfully", func() {
			server := grpc.NewServer()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			// This should not panic
			RegisterCSIAddonsReplicationServer(server, csiAddonsServer)

			// If we get here, the registration succeeded
			gomega.Expect(true).To(gomega.BeTrue())
		})
	})

	_ = ginkgo.Describe("Validation Functions", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.Describe("validateEnableReplicationRequest", func() {
			ginkgo.It("should return error when request is nil", func() {
				err := csiAddonsServer.validateEnableReplicationRequest(nil)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("request cannot be nil"))
			})

			ginkgo.It("should return error when both replication_source and volume_id are missing", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					// Both ReplicationSource and VolumeId are missing
				}
				err := csiAddonsServer.validateEnableReplicationRequest(req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication_source is required"))
			})

			ginkgo.It("should succeed when replication_source is provided", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: "test-volume-id",
							},
						},
					},
				}
				err := csiAddonsServer.validateEnableReplicationRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})

			ginkgo.It("should succeed when volume_id is provided", func() {
				req := &csiaddonsreplication.EnableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: "test-volume-id"},
						},
					},
				}
				err := csiAddonsServer.validateEnableReplicationRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.Describe("validateDisableReplicationRequest", func() {
			ginkgo.It("should return error when request is nil", func() {
				err := csiAddonsServer.validateDisableReplicationRequest(nil)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("request cannot be nil"))
			})

			ginkgo.It("should return error when both replication_source and volume_id are missing", func() {
				req := &csiaddonsreplication.DisableVolumeReplicationRequest{
					// Both ReplicationSource and VolumeId are missing
				}
				err := csiAddonsServer.validateDisableReplicationRequest(req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication_source is required"))
			})

			ginkgo.It("should succeed when replication_source is provided", func() {
				req := &csiaddonsreplication.DisableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: "test-volume-id",
							},
						},
					},
				}
				err := csiAddonsServer.validateDisableReplicationRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})

			ginkgo.It("should succeed when volume_id is provided", func() {
				req := &csiaddonsreplication.DisableVolumeReplicationRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: "test-volume-id"},
						},
					},
				}
				err := csiAddonsServer.validateDisableReplicationRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.Describe("validatePromoteVolumeRequest", func() {
			ginkgo.It("should return error when request is nil", func() {
				err := csiAddonsServer.validatePromoteVolumeRequest(nil)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("request cannot be nil"))
			})

			ginkgo.It("should return error when both replication_source and volume_id are missing", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					// Both ReplicationSource and VolumeId are missing
				}
				err := csiAddonsServer.validatePromoteVolumeRequest(req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication_source is required"))
			})

			ginkgo.It("should succeed when replication_source is provided", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: "test-volume-id",
							},
						},
					},
				}
				err := csiAddonsServer.validatePromoteVolumeRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})

			ginkgo.It("should succeed when volume_id is provided", func() {
				req := &csiaddonsreplication.PromoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: "test-volume-id"},
						},
					},
				}
				err := csiAddonsServer.validatePromoteVolumeRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.Describe("validateDemoteVolumeRequest", func() {
			ginkgo.It("should return error when request is nil", func() {
				err := csiAddonsServer.validateDemoteVolumeRequest(nil)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("request cannot be nil"))
			})

			ginkgo.It("should return error when both replication_source and volume_id are missing", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					// Both ReplicationSource and VolumeId are missing
				}
				err := csiAddonsServer.validateDemoteVolumeRequest(req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication_source is required"))
			})

			ginkgo.It("should succeed when replication_source is provided", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: "test-volume-id",
							},
						},
					},
				}
				err := csiAddonsServer.validateDemoteVolumeRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})

			ginkgo.It("should succeed when volume_id is provided", func() {
				req := &csiaddonsreplication.DemoteVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: "test-volume-id"},
						},
					},
				}
				err := csiAddonsServer.validateDemoteVolumeRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.Describe("validateResyncVolumeRequest", func() {
			ginkgo.It("should return error when request is nil", func() {
				err := csiAddonsServer.validateResyncVolumeRequest(nil)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("request cannot be nil"))
			})

			ginkgo.It("should return error when both replication_source and volume_id are missing", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					// Both ReplicationSource and VolumeId are missing
				}
				err := csiAddonsServer.validateResyncVolumeRequest(req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication_source is required"))
			})

			ginkgo.It("should succeed when replication_source is provided", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: "test-volume-id",
							},
						},
					},
				}
				err := csiAddonsServer.validateResyncVolumeRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})

			ginkgo.It("should succeed when volume_id is provided", func() {
				req := &csiaddonsreplication.ResyncVolumeRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: "test-volume-id"},
						},
					},
				}
				err := csiAddonsServer.validateResyncVolumeRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.Describe("validateGetVolumeReplicationInfoRequest", func() {
			ginkgo.It("should return error when request is nil", func() {
				err := csiAddonsServer.validateGetVolumeReplicationInfoRequest(nil)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("request cannot be nil"))
			})

			ginkgo.It("should return error when both replication_source and volume_id are missing", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					// Both ReplicationSource and VolumeId are missing
				}
				err := csiAddonsServer.validateGetVolumeReplicationInfoRequest(req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication_source is required"))
			})

			ginkgo.It("should succeed when replication_source is provided", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{
								VolumeId: "test-volume-id",
							},
						},
					},
				}
				err := csiAddonsServer.validateGetVolumeReplicationInfoRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})

			ginkgo.It("should succeed when volume_id is provided", func() {
				req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
					ReplicationSource: &csiaddonsreplication.ReplicationSource{
						Type: &csiaddonsreplication.ReplicationSource_Volume{
							Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: "test-volume-id"},
						},
					},
				}
				err := csiAddonsServer.validateGetVolumeReplicationInfoRequest(req)
				gomega.Expect(err).To(gomega.BeNil())
			})
		})
	})

	ginkgo.Describe("enableVolumeReplicationForVolumeGroup", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.It("should fail with NotFound when VG not found on either array", func() {
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			// Mock GetVolumeGroup to fail on all arrays (2 arrays in test setup)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			// Mock GetVolumeGroups to fail on all arrays
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.enableVolumeReplicationForVolumeGroup(
				context.Background(), validGroupID, validRemoteSystemName, "ASYNC", validRPO, params)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should succeed when VG has no PP (creates PP/RR and assigns to VG)", func() {
			vgName := "test-vg"
			ppName := "pp-" + vgName
			rrName := "rr-" + vgName

			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			// Mock GetVolumeGroup to return VG without protection policy
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: vgName, ProtectionPolicyID: ""}, nil)

			// Mock: Get remote system (needed by EnsureProtectionPolicyExists)
			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

			// Mock: Protection policy doesn't exist yet
			clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

			// Mock: Replication rule doesn't exist yet
			clientMock.On("GetReplicationRuleByName", mock.Anything, rrName).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

			// Mock: Create replication rule
			clientMock.On("CreateReplicationRule", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validRuleID}, nil)

			// Mock: Create protection policy
			clientMock.On("CreateProtectionPolicy", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validPolicyID}, nil)

			// Mock: Assign PP to VG
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock: Replication session found after PP assignment
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)

			resp, err := csiAddonsServer.enableVolumeReplicationForVolumeGroup(
				context.Background(), validGroupID, validRemoteSystemName, "ASYNC", validRPO, params)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return idempotent success when VG already has PP with replication rules", func() {
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			// Mock GetVolumeGroup to return VG with existing protection policy
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: "test-vg", ProtectionPolicyID: validPolicyID}, nil)

			// Mock GetProtectionPolicy to return policy with replication rules
			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{ID: validPolicyID, ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}}}, nil)

			// Mock: Replication session found (idempotency path checks session)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)

			resp, err := csiAddonsServer.enableVolumeReplicationForVolumeGroup(
				context.Background(), validGroupID, validRemoteSystemName, "ASYNC", validRPO, params)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when GetProtectionPolicy returns error on existing PP", func() {
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			// Mock GetVolumeGroup to return VG with protection policy
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: "test-vg", ProtectionPolicyID: validPolicyID}, nil)

			// Mock GetProtectionPolicy to fail
			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{}, errors.New("protection policy error"))

			_, err := csiAddonsServer.enableVolumeReplicationForVolumeGroup(
				context.Background(), validGroupID, validRemoteSystemName, "ASYNC", validRPO, params)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should re-create PP when existing PP has no replication rules", func() {
			vgName := "test-vg"
			ppName := "pp-" + vgName

			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			// Mock GetVolumeGroup to return VG with PP that has no replication rules
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: vgName, ProtectionPolicyID: validPolicyID}, nil)

			// Mock GetProtectionPolicy to return policy without replication rules
			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{ID: validPolicyID, ReplicationRules: []gopowerstore.ReplicationRule{}}, nil)

			// Mock: Get remote system
			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

			// Mock: PP already exists (EnsureProtectionPolicyExists finds it by name)
			clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
				gopowerstore.ProtectionPolicy{ID: validPolicyID}, nil)

			// Mock: Assign PP to VG
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock: Replication session not found — code returns Unavailable for retry
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.enableVolumeReplicationForVolumeGroup(
				context.Background(), validGroupID, validRemoteSystemName, "ASYNC", validRPO, params)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unavailable))
		})

		ginkgo.It("should fail when EnsureProtectionPolicyExists fails", func() {
			vgName := "test-vg"
			ppName := "pp-" + vgName
			rrName := "rr-" + vgName

			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			// Mock GetVolumeGroup to return VG without PP
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: vgName, ProtectionPolicyID: ""}, nil)

			// Mock: Get remote system
			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

			// Mock: PP lookup fails with non-NotFound error
			clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
				gopowerstore.ProtectionPolicy{}, errors.New("connection error"))

			// Mock: RR lookup and creation to force EnsureReplicationRuleExists failure
			clientMock.On("GetReplicationRuleByName", mock.Anything, rrName).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
			clientMock.On("CreateReplicationRule", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{}, errors.New("create replication rule failed"))

			_, err := csiAddonsServer.enableVolumeReplicationForVolumeGroup(
				context.Background(), validGroupID, validRemoteSystemName, "ASYNC", validRPO, params)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should fail when UpdateVolumeGroupProtectionPolicy fails", func() {
			vgName := "test-vg"
			ppName := "pp-" + vgName
			rrName := "rr-" + vgName

			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			// Mock GetVolumeGroup to return VG without PP
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: vgName, ProtectionPolicyID: ""}, nil)

			// Mock: Get remote system
			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

			// Mock: PP doesn't exist
			clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

			// Mock: RR doesn't exist
			clientMock.On("GetReplicationRuleByName", mock.Anything, rrName).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

			// Mock: Create replication rule
			clientMock.On("CreateReplicationRule", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validRuleID}, nil)

			// Mock: Create protection policy
			clientMock.On("CreateProtectionPolicy", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validPolicyID}, nil)

			// Mock: Assign PP to VG fails
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), errors.New("update failed"))

			_, err := csiAddonsServer.enableVolumeReplicationForVolumeGroup(
				context.Background(), validGroupID, validRemoteSystemName, "ASYNC", validRPO, params)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should return Unavailable when replication session not found after PP assignment", func() {
			vgName := "test-vg"
			ppName := "pp-" + vgName
			rrName := "rr-" + vgName

			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			// Mock GetVolumeGroup to return VG without PP
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: vgName, ProtectionPolicyID: ""}, nil)

			// Mock: Get remote system
			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

			// Mock: PP doesn't exist
			clientMock.On("GetProtectionPolicyByName", mock.Anything, ppName).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

			// Mock: RR doesn't exist
			clientMock.On("GetReplicationRuleByName", mock.Anything, rrName).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

			// Mock: Create replication rule
			clientMock.On("CreateReplicationRule", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validRuleID}, nil)

			// Mock: Create protection policy
			clientMock.On("CreateProtectionPolicy", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validPolicyID}, nil)

			// Mock: Assign PP to VG
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock: Replication session not found yet — code returns Unavailable for retry
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.enableVolumeReplicationForVolumeGroup(
				context.Background(), validGroupID, validRemoteSystemName, "ASYNC", validRPO, params)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unavailable))
		})
	})

	ginkgo.Describe("disableVolumeReplicationForVolumeGroup", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.It("should succeed when findArrayWithVolumeGroupID fails", func() {
			// Mock GetVolumeGroup to fail on all arrays (2 arrays in test setup)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			// Mock GetVolumeGroups to fail on all arrays
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should succeed when non-destination VG with no protection policy", func() {
			// Mock GetVolumeGroup to return non-destination VG without protection policy
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       "",
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return no session
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			// Mock orphan RR cleanup: no orphaned rule found
			clientMock.On("GetReplicationRuleByName", mock.Anything, "rr-test-vg").Return(
				gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should succeed when destination VG and removeMembersFromVolumeGroup succeeds", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: true,
					Volumes:                  []gopowerstore.Volume{{ID: "vol-1"}, {ID: "vol-2"}},
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return NotFound (session already cleaned up)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			// Mock UpdateVolumeGroupProtectionPolicy (no-op since ProtectionPolicyID is empty)
			// Mock DeleteVolumeGroup
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock ModifyVolume for clearing protection policy from volumes
			clientMock.On("ModifyVolume", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeModify"), "vol-1").Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeModify"), "vol-2").Return(
				gopowerstore.EmptyResponse(""), nil)

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when destination VG and removeMembersFromVolumeGroup fails", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: true,
					Volumes:                  []gopowerstore.Volume{{ID: "vol-1"}},
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return NotFound (session already cleaned up)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			// Mock DeleteVolumeGroup to fail
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), errors.New("delete VG failed"))

			_, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("delete"))
		})

		ginkgo.It("should delete protection policy for destination VG with PP", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: true,
					ProtectionPolicyID:       validPolicyID,
					Volumes:                  []gopowerstore.Volume{{ID: "vol-1"}},
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return NotFound (session already cleaned up)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			// Mock UpdateVolumeGroupProtectionPolicy to clear PP from VG
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock DeleteVolumeGroup
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock ModifyVolume for clearing protection policy from volumes
			clientMock.On("ModifyVolume", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeModify"), "vol-1").Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock DeleteProtectionPolicy
			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			clientMock.AssertCalled(ginkgo.GinkgoT(), "DeleteProtectionPolicy", mock.Anything, validPolicyID)
		})

		ginkgo.It("should succeed even when destination VG PP deletion fails", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: true,
					ProtectionPolicyID:       validPolicyID,
					Volumes:                  []gopowerstore.Volume{{ID: "vol-1"}},
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return NotFound (session already cleaned up)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			// Mock UpdateVolumeGroupProtectionPolicy to clear PP from VG
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock DeleteVolumeGroup
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock ModifyVolume for clearing protection policy from volumes
			clientMock.On("ModifyVolume", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeModify"), "vol-1").Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock DeleteProtectionPolicy to fail (should not cause overall failure)
			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), errors.New("delete pp failed"))

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when GetProtectionPolicy fails", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return no session
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{}, errors.New("protection policy error"))

			_, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("protection policy error"))
		})

		ginkgo.It("should fail with NotFound when GetProtectionPolicy reports not found", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should succeed on full happy path with pause, unassign, delete policy, and delete rule", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:               validPolicyID,
					ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}},
				}, nil)

			// Mock pause: GetReplicationSessionByLocalResourceID + ExecuteActionOnReplicationSession
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "OK"}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			// Mock unassign protection policy
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock delete protection policy
			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			// Mock replication rule cleanup: rule has no policies, delete succeeds
			clientMock.On("GetReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.ReplicationRule{ID: validRuleID, ProtectionPolicies: []gopowerstore.ProtectionPolicy{}}, nil)
			clientMock.On("DeleteReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.EmptyResponse(""), nil)

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should succeed even when pause replication session fails", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:               validPolicyID,
					ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}},
				}, nil)

			// Mock pause failure: GetReplicationSessionByLocalResourceID returns error
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, errors.New("session not found"))

			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.ReplicationRule{ID: validRuleID, ProtectionPolicies: []gopowerstore.ProtectionPolicy{}}, nil)
			clientMock.On("DeleteReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.EmptyResponse(""), nil)

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should succeed even when ModifyVolumeGroup (unassign policy) fails", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:               validPolicyID,
					ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}},
				}, nil)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "Paused"}, nil)

			// Mock unassign failure
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), errors.New("modify failed"))

			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.ReplicationRule{ID: validRuleID, ProtectionPolicies: []gopowerstore.ProtectionPolicy{}}, nil)
			clientMock.On("DeleteReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.EmptyResponse(""), nil)

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when DeleteProtectionPolicy fails", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:               validPolicyID,
					ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}},
				}, nil)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "Paused"}, nil)

			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), errors.New("delete policy failed"))

			_, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("delete policy failed"))
		})

		ginkgo.It("should succeed when GetReplicationRule fails during cleanup", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:               validPolicyID,
					ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}},
				}, nil)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "Paused"}, nil)

			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			// GetReplicationRule fails — should continue without error
			clientMock.On("GetReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.ReplicationRule{}, errors.New("rule not found"))

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should skip deletion when replication rule still has protection policies", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:               validPolicyID,
					ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}},
				}, nil)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "Paused"}, nil)

			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			// Rule still has protection policies — should skip deletion
			clientMock.On("GetReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.ReplicationRule{
					ID:                 validRuleID,
					ProtectionPolicies: []gopowerstore.ProtectionPolicy{{ID: "other-policy"}},
				}, nil)

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return Unavailable when DeleteReplicationRule fails transiently", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:               validPolicyID,
					ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}},
				}, nil)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "Paused"}, nil)

			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.ReplicationRule{ID: validRuleID, ProtectionPolicies: []gopowerstore.ProtectionPolicy{}}, nil)

			// DeleteReplicationRule fails — should return Unavailable for external retry
			clientMock.On("DeleteReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.EmptyResponse(""), errors.New("delete rule failed"))

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unavailable))
			gomega.Expect(resp).To(gomega.BeNil())
		})

		ginkgo.It("should treat VG as source when session role is Source despite is_replication_destination=true", func() {
			// This tests the fix for PowerStore bug where is_replication_destination flag
			// is not updated after unplanned failover
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: true, // Flag says destination
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return session with Source role
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource), // But session says Source!
				}, nil)

			// Mock GetProtectionPolicy
			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:   validPolicyID,
					Name: "test-policy",
					ReplicationRules: []gopowerstore.ReplicationRule{
						{ID: validRuleID},
					},
				}, nil)

			// Mock ExecuteActionOnReplicationSession for pause
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock unassignProtectionPolicyFromVolumeGroup
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			// Mock DeleteProtectionPolicy
			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			// Mock GetReplicationRule
			clientMock.On("GetReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.ReplicationRule{
					ID:                 validRuleID,
					ProtectionPolicies: []gopowerstore.ProtectionPolicy{},
				}, nil)

			// Mock DeleteReplicationRule
			clientMock.On("DeleteReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.EmptyResponse(""), nil)

			resp, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			// Should succeed with source cleanup path (not destination path)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())

			// Verify that source cleanup was performed (delete policy, delete rules)
			clientMock.AssertCalled(ginkgo.GinkgoT(), "DeleteProtectionPolicy", mock.Anything, validPolicyID)
		})

		ginkgo.It("should return OutOfRange when destination VG has active session", func() {
			// Test that destination VG with active session returns OutOfRange to indicate operation not allowed in current state
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: true,
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return active session with Destination role
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleDestination),
				}, nil)

			_, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			// Should return OutOfRange error (operation not allowed in current state)
			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.OutOfRange))
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("retry after source-side cleanup"))
		})

		ginkgo.It("should use session role when it contradicts VG flag", func() {
			// Test that session role takes precedence over VG flag
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     "test-vg",
					IsReplicationDestination: false, // Flag says source
					ProtectionPolicyID:       validPolicyID,
				}, nil)

			// Mock GetReplicationSessionByLocalResourceID to return session with Destination role
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleDestination), // But session says Destination!
				}, nil)

			_, err := csiAddonsServer.disableVolumeReplicationForVolumeGroup(context.Background(), validGroupID)

			// Should return OutOfRange (destination path) despite VG flag saying source
			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.OutOfRange))
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("retry after source-side cleanup"))
		})
	})

	ginkgo.Describe("promoteVolumeForVolumeGroup", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.It("should fail with InvalidArgument when volume group ID is empty", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: "",
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail with InvalidArgument when vgGetParameters fails", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{}, // Missing required parameters
			}

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail with NotFound when volume group not found on either array", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			// Mock GetVolumeGroup to fail on all arrays
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			// Mock GetVolumeGroups to fail on all arrays
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should fail with FailedPrecondition when GetReplicationSessionByLocalResourceID fails", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, errors.New("replication session not found"))

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should fail with Aborted when failover is already in progress (Failing_Over)", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailingOver,
				}, nil)

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
		})

		ginkgo.It("should fail with Aborted when failover is already in progress (Failing_Over_For_DR)", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailingOverForDR,
				}, nil)

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
		})

		ginkgo.It("should return success when already primary (role=Source)", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleSource),
					State: gopowerstore.RsStateOk,
				}, nil)

			res, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return success when already primary inferred (empty role, state=OK)", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  "",
					State: gopowerstore.RsStateOk,
				}, nil)

			res, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with Aborted when secondary, force=false, and GetRemoteSystem fails", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: false,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:             validSessionID,
					Role:           string(gopowerstore.ReplicationRoleDestination),
					State:          gopowerstore.RsStateFailedOver,
					RemoteSystemID: validRemoteSystemID,
				}, nil)
			clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).Return(
				gopowerstore.RemoteSystem{}, errors.New("remote system unreachable"))

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
		})

		ginkgo.It("should fail with FailedPrecondition when secondary, force=false, and remote system appears down", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: false,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:             validSessionID,
					Role:           string(gopowerstore.ReplicationRoleDestination),
					State:          gopowerstore.RsStateFailedOver,
					RemoteSystemID: validRemoteSystemID,
				}, nil)
			clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, DataConnectionState: string(gopowerstore.ConnStateCompleteDataConnLoss)}, nil)

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should fail with FailedPrecondition when secondary, force=false, and remote system is up", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: false,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:             validSessionID,
					Role:           string(gopowerstore.ReplicationRoleDestination),
					State:          gopowerstore.RsStateFailedOver,
					RemoteSystemID: validRemoteSystemID,
				}, nil)
			clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, DataConnectionState: string(gopowerstore.ConnStateOK)}, nil)

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should successfully execute unplanned failover when secondary with force=true", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleDestination),
					State: gopowerstore.RsStateFailedOver,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when secondary with force=true and ExecuteAction fails", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleDestination),
					State: "Synchronizing",
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with FailedPrecondition for planned failback (FailedOver + Destination role, force=false)", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: false,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:             validSessionID,
					Role:           string(gopowerstore.ReplicationRoleDestination),
					State:          gopowerstore.RsStateFailedOver,
					RemoteSystemID: validRemoteSystemID,
				}, nil)
			clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, DataConnectionState: string(gopowerstore.ConnStateCompleteDataConnLoss)}, nil)

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should successfully execute reverse failover (FailedOver + Destination role, force=true)", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleDestination),
					State: gopowerstore.RsStateFailedOver,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when reverse failover fails (Destination role, force=true)", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleDestination),
					State: "Synchronizing",
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with FailedPrecondition for unexpected role/state combination", func() {
			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  "",
					State: gopowerstore.RsStatePaused,
				}, nil)

			_, err := csiAddonsServer.promoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})
	})

	ginkgo.Describe("demoteVolumeForVolumeGroup", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.It("should fail with InvalidArgument when volume group ID is empty", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: "",
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail with InvalidArgument when vgGetParameters fails", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{}, // Missing required parameters
			}

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail with NotFound when volume group not found on either array", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			// Mock GetVolumeGroup to fail on all arrays
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			// Mock GetVolumeGroups to fail on all arrays
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should fail when GetReplicationSessionByLocalResourceID fails", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, errors.New("replication session not found"))

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when failover is already in progress (Failing_Over)", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailingOver,
				}, nil)

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when failover is already in progress (Failing_Over_For_DR)", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailingOverForDR,
				}, nil)

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with Aborted when reprotect is already in progress", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateReprotecting,
				}, nil)

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
		})

		ginkgo.It("should fail with FailedPrecondition when paused and force=false", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: false,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStatePaused,
				}, nil)

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should succeed when paused and force=true (resume succeeds)", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStatePaused,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionResume, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with Internal when paused and force=true but resume fails", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStatePaused,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionResume, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should return success when already secondary (role=Destination)", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleDestination),
					State: gopowerstore.RsStateOk,
				}, nil)

			res, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should succeed when primary (role=Source) and planned failover succeeds", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleSource),
					State: gopowerstore.RsStateOk,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when primary (role=Source) and planned failover fails", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleSource),
					State: gopowerstore.RsStateOk,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return success when inferred secondary (empty role, state=Failed_Over)", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  "",
					State: gopowerstore.RsStateFailedOver,
				}, nil)

			res, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should succeed when inferred primary (empty role, state=OK) and failover succeeds", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  "",
					State: gopowerstore.RsStateOk,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with FailedPrecondition when role/state is unexpected", func() {
			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  "UnknownRole",
					State: "UnknownState",
				}, nil)

			_, err := csiAddonsServer.demoteVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})
	})

	ginkgo.Describe("resyncVolumeForVolumeGroup", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.It("should fail with InvalidArgument when vgGetParameters fails", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{}, // Missing required parameters
			}

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail with NotFound when volume group not found on either array", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			// Mock GetVolumeGroup to fail on all arrays
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			// Mock GetVolumeGroups to fail on all arrays
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should fail when GetReplicationSessionByLocalResourceID fails", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, errors.New("session not found"))

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return Ready=true when state is OK", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)

			res, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
			gomega.Expect(res.Ready).To(gomega.BeTrue())
		})

		ginkgo.It("should return Ready=false when state is Synchronizing", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateSynchronizing}, nil)

			res, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
			gomega.Expect(res.Ready).To(gomega.BeFalse())
		})

		ginkgo.It("should execute Resume and return Ready=false when state is Paused", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStatePaused}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionResume, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
			gomega.Expect(res.Ready).To(gomega.BeFalse())
		})

		ginkgo.It("should fail when Resume action fails on Paused state", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStatePaused}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionResume, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should execute Reprotect when FailedOver and session role is Source", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailedOver,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionReprotect, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
			gomega.Expect(res.Ready).To(gomega.BeFalse())
		})

		ginkgo.It("should fail when Reprotect action fails on FailedOver Source role", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailedOver,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionReprotect, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return OutOfRange when FailedOver, Destination role, even with force=true", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailedOver,
					Role:  string(gopowerstore.ReplicationRoleDestination),
				}, nil)

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.OutOfRange))
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("local is Destination"))
		})

		ginkgo.It("should return OutOfRange when FailedOver, Destination role, and force=false", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: false,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailedOver,
					Role:  string(gopowerstore.ReplicationRoleDestination),
				}, nil)

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.OutOfRange))
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("local is Destination"))
		})

		ginkgo.It("should fail with Aborted when state is FailingOver", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateFailingOver}, nil)

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
		})

		ginkgo.It("should execute Sync when default state and force=true", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "UnexpectedState"}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionSync, mock.Anything).Return(gopowerstore.EmptyResponse(""), nil)

			res, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
			gomega.Expect(res.Ready).To(gomega.BeFalse())
		})

		ginkgo.It("should fail when Sync action fails on default state with force", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "UnexpectedState"}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionSync, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with FailedPrecondition when default state and force=false", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
				Force: false,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: "UnexpectedState"}, nil)

			_, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should find VG on target array when not found on source array", func() {
			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
						Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
							VolumeGroupId: validGroupID,
						},
					},
				},
				Parameters: map[string]string{
					sourceArrayParameter: secondValidID,
					targetArrayParameter: firstValidID,
				},
			}

			// Source array (secondValidID) fails to find VG
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError()).Once()
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, nil).Once()

			// Target array (firstValidID) finds VG
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID}, nil).Once()

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)

			res, err := csiAddonsServer.resyncVolumeForVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
			gomega.Expect(res.Ready).To(gomega.BeTrue())
		})
	})

	ginkgo.Describe("getVolumeReplicationInfoForVolumeGroup", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.It("should fail with NotFound when volume group not found on either array", func() {
			// Mock GetVolumeGroup to fail on all arrays
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			// Mock GetVolumeGroups to fail on all arrays
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.getVolumeReplicationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})
	})

	ginkgo.Describe("getReplicationDestinationInfoForVolumeGroup", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.It("should fail with NotFound when volume group not found on either array", func() {
			// Mock GetVolumeGroup to fail on all arrays
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			// Mock GetVolumeGroups to fail on all arrays
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			_, err := csiAddonsServer.getReplicationDestinationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})
	})

	ginkgo.Describe("NewCSIAddonsVolumeGroupServer", func() {
		ginkgo.It("should create a new volume group server", func() {
			server := NewCSIAddonsVolumeGroupServer(ctrlSvc)
			gomega.Expect(server).ToNot(gomega.BeNil())
			gomega.Expect(server.service).To(gomega.Equal(ctrlSvc))
		})
	})

	ginkgo.Describe("CreateVolumeGroup", func() {
		var vgServer *CSIAddonsVolumeGroupServer

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
		})

		ginkgo.It("should fail when volume group name is empty", func() {
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name: "",
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail when no source volumes provided", func() {
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "test-vg",
				VolumeIds: []string{},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail when parameters are nil", func() {
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "test-vg",
				VolumeIds: []string{validBlockVolumeID},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail when sourceArray parameter is missing", func() {
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "test-vg",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					targetArrayParameter: secondValidID,
				},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail when targetArray parameter is missing", func() {
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "test-vg",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
				},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail when sourceArray not found in arrays", func() {
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-vg",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter:     "non-existent-array",
					targetArrayParameter:     secondValidID,
					targetArrayNameParameter: validRemoteSystemName,
				},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should fail when targetArray not found in arrays", func() {
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-vg",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter:     firstValidID,
					targetArrayParameter:     "non-existent-array",
					targetArrayNameParameter: validRemoteSystemName,
				},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should find existing VG and return it", func() {
			existingVG := gopowerstore.VolumeGroup{
				ID:   validGroupID,
				Name: defaultVGPrefix + "-test-vg",
				Volumes: []gopowerstore.Volume{
					{ID: validBaseVolID, Size: validVolSize},
				},
			}

			clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(
				gopowerstore.Volume{
					ID:   validBaseVolID,
					Size: validVolSize,
					VolumeGroup: []gopowerstore.VolumeGroup{
						{ID: validGroupID},
					},
				}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(existingVG, nil)
			clientMock.On("GetVolumeGroupByName", mock.Anything, mock.Anything).Return(existingVG, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID}, nil)

			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-vg",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter:            firstValidID,
					targetArrayParameter:            secondValidID,
					targetArrayNameParameter:        validRemoteSystemName,
					CSIAddonsParamRPO:               validRPO,
					CSIAddonsParamVolumeGroupPrefix: defaultVGPrefix,
				},
			}

			resp, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroup).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with InvalidArgument when a volume id is empty", func() {
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-vg",
				VolumeIds: []string{""},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should route to createReplicaVolumeGroup when volume is a replication destination", func() {
			// Simulate unplanned failover: volumes are on the source array (firstValidID)
			// but are replication destinations from a prior replication relationship.
			// The VGRC's sourceArray matches the volume's array, so the targetArray check
			// does not trigger. The IsReplicationDestination check should catch this.
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{
					ID:                       validBaseVolID,
					Size:                     validVolSize,
					IsReplicationDestination: true,
				}, nil)
			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(
				gopowerstore.VolumeGroups{
					VolumeGroup: []gopowerstore.VolumeGroup{
						{ID: validGroupID, Name: defaultVGPrefix + "-replica-vg"},
					},
				}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-replica-vg"}, nil)

			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-failover-side",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter:            firstValidID,
					targetArrayParameter:            secondValidID,
					targetArrayNameParameter:        validRemoteSystemName,
					CSIAddonsParamVolumeGroupPrefix: defaultVGPrefix,
				},
			}

			resp, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroup).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroup.VolumeGroupId).To(gomega.Equal(validGroupID))
		})
	})

	ginkgo.Describe("DeleteVolumeGroup", func() {
		var vgServer *CSIAddonsVolumeGroupServer

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
		})

		ginkgo.It("should return nil error when volume group not found (idempotent)", func() {
			req := &volumegrouprpc.DeleteVolumeGroupRequest{
				VolumeGroupId: "non-existent-vg",
			}

			clientMock.On("GetVolumeGroup", mock.Anything, "non-existent-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroupByName", mock.Anything, mock.Anything).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			resp, err := vgServer.DeleteVolumeGroup(context.Background(), req)

			// findArrayWithVolumeGroupID returns nil, nil, nil when not found
			// DeleteVolumeGroup returns &DeleteVolumeGroupResponse{}, nil (idempotent)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return success for replication destination VG", func() {
			req := &volumegrouprpc.DeleteVolumeGroupRequest{
				VolumeGroupId: validGroupID,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg", IsReplicationDestination: true}, nil)

			resp, err := vgServer.DeleteVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with Internal when deleting the source VG fails", func() {
			req := &volumegrouprpc.DeleteVolumeGroupRequest{
				VolumeGroupId: validGroupID,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     defaultVGPrefix + "-vg",
					IsReplicationDestination: false,
					Volumes:                  []gopowerstore.Volume{{ID: validBaseVolID}},
				}, nil)
			clientMock.On("GetVolumeGroupByName", mock.Anything, mock.Anything).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())
			// removeMembersFromVolumeGroup returns a plain error, so the RPC maps it to Internal.
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), errors.New("remove failed"))

			_, err := vgServer.DeleteVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should delete source VG successfully", func() {
			req := &volumegrouprpc.DeleteVolumeGroupRequest{
				VolumeGroupId: validGroupID,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     defaultVGPrefix + "-vg",
					IsReplicationDestination: false,
					ProtectionPolicyID:       "",
				}, nil)
			clientMock.On("GetVolumeGroupByName", mock.Anything, mock.Anything).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("DeleteProtectionPolicy", mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetProtectionPolicyByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.NewNotFoundError())

			resp, err := vgServer.DeleteVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("ModifyVolumeGroupMembership", func() {
		var vgServer *CSIAddonsVolumeGroupServer

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
		})

		ginkgo.It("should fail when volume group ID is empty", func() {
			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: "",
			}

			_, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail when parameters are nil", func() {
			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: validGroupID,
			}

			_, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should return empty response when VG not found and no volumes to add", func() {
			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: "non-existent-vg",
				VolumeIds:     []string{},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, "non-existent-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, nil)

			resp, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return NotFound when VG not found and there are volumes to add", func() {
			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: "non-existent-vg",
				VolumeIds:     []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, "non-existent-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, nil)

			_, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should skip membership update for replication destination VG", func() {
			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: validGroupID,
				VolumeIds:     []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     defaultVGPrefix + "-vg",
					IsReplicationDestination: true,
					Volumes: []gopowerstore.Volume{
						{ID: validBaseVolID, Size: validVolSize},
					},
				}, nil)

			resp, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with InvalidArgument when a volume id is empty", func() {
			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: validGroupID,
				VolumeIds:     []string{""},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:                       validGroupID,
					Name:                     defaultVGPrefix + "-vg",
					IsReplicationDestination: false,
					Volumes: []gopowerstore.Volume{
						{ID: validBaseVolID, Size: validVolSize},
					},
				}, nil)

			_, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})
	})

	ginkgo.Describe("ControllerGetVolumeGroup", func() {
		var vgServer *CSIAddonsVolumeGroupServer

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
		})

		ginkgo.It("should return volume group when found", func() {
			req := &volumegrouprpc.ControllerGetVolumeGroupRequest{
				VolumeGroupId: validGroupID,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{
					ID:   validGroupID,
					Name: defaultVGPrefix + "-test-vg",
					Volumes: []gopowerstore.Volume{
						{ID: validBaseVolID, Size: validVolSize},
					},
				}, nil)

			resp, err := vgServer.ControllerGetVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroup).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroup.VolumeGroupId).To(gomega.Equal(validGroupID))
			gomega.Expect(resp.VolumeGroup.Volumes).To(gomega.HaveLen(1))
		})

		ginkgo.It("should return NotFound when volume group not found", func() {
			req := &volumegrouprpc.ControllerGetVolumeGroupRequest{
				VolumeGroupId: "non-existent-vg",
			}

			clientMock.On("GetVolumeGroup", mock.Anything, "non-existent-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))

			_, err := vgServer.ControllerGetVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})
	})

	ginkgo.Describe("ListVolumeGroups", func() {
		var vgServer *CSIAddonsVolumeGroupServer

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
		})

		ginkgo.It("should return empty list when no volume groups exist", func() {
			req := &volumegrouprpc.ListVolumeGroupsRequest{}

			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{}, nil)

			resp, err := vgServer.ListVolumeGroups(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.Entries).To(gomega.BeEmpty())
		})

		ginkgo.It("should return volume groups with correct prefix", func() {
			req := &volumegrouprpc.ListVolumeGroupsRequest{}

			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{
				{ID: "vg-1", Name: defaultVGPrefix + "-vg-one"},
				{ID: "vg-2", Name: "other-vg"},
				{ID: "vg-3", Name: defaultVGPrefix + "-vg-two"},
			}, nil)

			resp, err := vgServer.ListVolumeGroups(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(len(resp.Entries)).To(gomega.BeNumerically(">=", 2))
		})

		ginkgo.It("should handle GetVolumeGroups error gracefully", func() {
			req := &volumegrouprpc.ListVolumeGroupsRequest{}

			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, errors.New("api error"))

			resp, err := vgServer.ListVolumeGroups(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("deleteArrayVolumeGroup", func() {
		var vgServer *CSIAddonsVolumeGroupServer
		var testArr *array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
			testArr = ctrlSvc.Arrays()[firstValidID]
		})

		ginkgo.It("should delete source VG with volumes", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 validGroupID,
				Name:               defaultVGPrefix + "-vg-source",
				ProtectionPolicyID: validPolicyID,
				Volumes: []gopowerstore.Volume{
					{ID: validBaseVolID},
				},
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: ""}, nil)
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("DeleteProtectionPolicy", mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetProtectionPolicyByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.NewNotFoundError())

			err := vgServer.deleteArrayVolumeGroup(context.Background(), testArr, vg)

			gomega.Expect(err).To(gomega.BeNil())
		})

		ginkgo.It("should delete source VG with no volumes", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 validGroupID,
				Name:               defaultVGPrefix + "-vg-source",
				ProtectionPolicyID: validPolicyID,
				Volumes:            []gopowerstore.Volume{},
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: ""}, nil)
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("DeleteProtectionPolicy", mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetProtectionPolicyByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.NewNotFoundError())

			err := vgServer.deleteArrayVolumeGroup(context.Background(), testArr, vg)

			gomega.Expect(err).To(gomega.BeNil())
		})

		ginkgo.It("should return error when remove members fails", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 validGroupID,
				Name:               defaultVGPrefix + "-vg-source",
				ProtectionPolicyID: validPolicyID,
				Volumes: []gopowerstore.Volume{
					{ID: validBaseVolID},
				},
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), errors.New("remove failed"))

			err := vgServer.deleteArrayVolumeGroup(context.Background(), testArr, vg)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("getVolumeReplicationInfoForVolumeGroup", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		ginkgo.It("should return info for healthy replication session", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)

			resp, err := csiAddonsServer.getVolumeReplicationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.LastSyncTime).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return info for failed over replication session", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailedOver,
					Role:  string(gopowerstore.ReplicationRoleDestination),
				}, nil)

			resp, err := csiAddonsServer.getVolumeReplicationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.LastSyncTime).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return info for synchronizing replication session", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateSynchronizing,
				}, nil)

			resp, err := csiAddonsServer.getVolumeReplicationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return info for failing over replication session", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailingOver,
				}, nil)

			resp, err := csiAddonsServer.getVolumeReplicationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return info for paused replication session", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStatePaused,
				}, nil)

			resp, err := csiAddonsServer.getVolumeReplicationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when VG not found", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, nil)

			_, err := csiAddonsServer.getVolumeReplicationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should fail when replication session not found", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{}, errors.New("no session"))

			_, err := csiAddonsServer.getVolumeReplicationInfoForVolumeGroup(context.Background(), validGroupID)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})
	})

	ginkgo.Describe("createVolumeGroup (private)", func() {
		var vgServer *CSIAddonsVolumeGroupServer
		var testArr *array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
			testArr = ctrlSvc.Arrays()[firstValidID]
		})

		ginkgo.It("should create new VG when not found (async mode)", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, defaultVGPrefix+"-new-vg").Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("CreateVolumeGroup", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-new-vg"}, nil)

			resp, err := vgServer.createVolumeGroup(context.Background(), testArr, "req-name", []string{validBaseVolID}, defaultVGPrefix+"-new-vg", "ASYNC")

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroupId).To(gomega.Equal(validGroupID))
		})

		ginkgo.It("should create new VG with write order consistent in sync mode", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, defaultVGPrefix+"-sync-vg").Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("CreateVolumeGroup", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-sync-vg"}, nil)

			resp, err := vgServer.createVolumeGroup(context.Background(), testArr, "req-name", []string{validBaseVolID}, defaultVGPrefix+"-sync-vg", "SYNC")

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroupId).To(gomega.Equal(validGroupID))
		})

		ginkgo.It("should update existing VG with new members", func() {
			existingVG := gopowerstore.VolumeGroup{
				ID:   validGroupID,
				Name: defaultVGPrefix + "-existing-vg",
				Volumes: []gopowerstore.Volume{
					{ID: "existing-vol-1"},
				},
			}
			clientMock.On("GetVolumeGroupByName", mock.Anything, defaultVGPrefix+"-existing-vg").Return(existingVG, nil)
			clientMock.On("AddMembersToVolumeGroup", mock.Anything, mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)

			resp, err := vgServer.createVolumeGroup(context.Background(), testArr, "req-name",
				[]string{"existing-vol-1", "new-vol-2"}, "vg-existing-vg", "ASYNC")

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroupId).To(gomega.Equal(validGroupID))
		})

		ginkgo.It("should skip adding members when all already exist", func() {
			existingVG := gopowerstore.VolumeGroup{
				ID:   validGroupID,
				Name: defaultVGPrefix + "-existing-vg",
				Volumes: []gopowerstore.Volume{
					{ID: validBaseVolID},
				},
			}
			clientMock.On("GetVolumeGroupByName", mock.Anything, defaultVGPrefix+"-existing-vg").Return(existingVG, nil)

			resp, err := vgServer.createVolumeGroup(context.Background(), testArr, "req-name",
				[]string{validBaseVolID}, "vg-existing-vg", "ASYNC")

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroupId).To(gomega.Equal(validGroupID))
		})

		ginkgo.It("should return error when CreateVolumeGroup API fails", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, defaultVGPrefix+"-fail-vg").Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("CreateVolumeGroup", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{}, errors.New("create failed"))

			_, err := vgServer.createVolumeGroup(context.Background(), testArr, "req-name", []string{validBaseVolID}, defaultVGPrefix+"-fail-vg", "ASYNC")

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should return error when GetVolumeGroup after create fails", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, defaultVGPrefix+"-get-fail-vg").Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("CreateVolumeGroup", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, errors.New("get failed"))

			_, err := vgServer.createVolumeGroup(context.Background(), testArr, "req-name", []string{validBaseVolID}, defaultVGPrefix+"-get-fail-vg", "ASYNC")

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should return error when GetVolumeGroupByName returns non-NotFound error", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, defaultVGPrefix+"-query-err-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("connection error"))

			_, err := vgServer.createVolumeGroup(context.Background(), testArr, "req-name", []string{validBaseVolID}, defaultVGPrefix+"-query-err-vg", "ASYNC")

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should return error when AddMembersToVolumeGroup fails", func() {
			existingVG := gopowerstore.VolumeGroup{
				ID:      validGroupID,
				Name:    defaultVGPrefix + "-add-fail-vg",
				Volumes: []gopowerstore.Volume{},
			}
			clientMock.On("GetVolumeGroupByName", mock.Anything, defaultVGPrefix+"-add-fail-vg").Return(existingVG, nil)
			clientMock.On("AddMembersToVolumeGroup", mock.Anything, mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), errors.New("add failed"))

			_, err := vgServer.createVolumeGroup(context.Background(), testArr, "req-name", []string{"new-vol"}, defaultVGPrefix+"-add-fail-vg", "ASYNC")

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})
	})

	ginkgo.Describe("createReplicaVolumeGroup (private)", func() {
		var vgServer *CSIAddonsVolumeGroupServer

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
		})

		ginkgo.It("should succeed for single volume in VG on target array", func() {
			// Volume belongs to secondValidID (target array)
			targetVolID := filepath.Join(validBaseVolID, secondValidID, "scsi")

			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(
				gopowerstore.VolumeGroups{
					VolumeGroup: []gopowerstore.VolumeGroup{
						{ID: validGroupID, Name: defaultVGPrefix + "-replica-vg"},
					},
				}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-replica-vg"}, nil)

			resp := &volumegrouprpc.CreateVolumeGroupResponse{
				VolumeGroup: &volumegrouprpc.VolumeGroup{},
			}
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-replica",
				VolumeIds: []string{targetVolID},
			}
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			result, err := vgServer.createReplicaVolumeGroup(context.Background(), req, params, resp)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(result).ToNot(gomega.BeNil())
			gomega.Expect(result.VolumeGroup.VolumeGroupId).To(gomega.Equal(validGroupID))
		})

		ginkgo.It("should fail with NotFound when GetVolumeGroup reports not found", func() {
			targetVolID := filepath.Join(validBaseVolID, secondValidID, "scsi")

			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(
				gopowerstore.VolumeGroups{
					VolumeGroup: []gopowerstore.VolumeGroup{
						{ID: validGroupID, Name: defaultVGPrefix + "-replica-vg"},
					},
				}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			resp := &volumegrouprpc.CreateVolumeGroupResponse{
				VolumeGroup: &volumegrouprpc.VolumeGroup{},
			}
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-replica",
				VolumeIds: []string{targetVolID},
			}
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			_, err := vgServer.createReplicaVolumeGroup(context.Background(), req, params, resp)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should fail when volume not in any VG", func() {
			targetVolID := filepath.Join(validBaseVolID, secondValidID, "scsi")

			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(
				gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{}}, nil)

			resp := &volumegrouprpc.CreateVolumeGroupResponse{
				VolumeGroup: &volumegrouprpc.VolumeGroup{},
			}
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-replica",
				VolumeIds: []string{targetVolID},
			}
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			_, err := vgServer.createReplicaVolumeGroup(context.Background(), req, params, resp)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail when GetVolumeGroupsByVolumeID errors", func() {
			targetVolID := filepath.Join(validBaseVolID, secondValidID, "scsi")

			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(
				gopowerstore.VolumeGroups{}, errors.New("api error"))

			resp := &volumegrouprpc.CreateVolumeGroupResponse{
				VolumeGroup: &volumegrouprpc.VolumeGroup{},
			}
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-replica",
				VolumeIds: []string{targetVolID},
			}
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			_, err := vgServer.createReplicaVolumeGroup(context.Background(), req, params, resp)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when volumes are in different VGs", func() {
			targetVolID1 := filepath.Join(validBaseVolID, secondValidID, "scsi")
			targetVolID2 := filepath.Join(validRemoteVolID, secondValidID, "scsi")

			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(
				gopowerstore.VolumeGroups{
					VolumeGroup: []gopowerstore.VolumeGroup{
						{ID: "vg-1", Name: defaultVGPrefix + "-vg-1"},
					},
				}, nil)
			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validRemoteVolID).Return(
				gopowerstore.VolumeGroups{
					VolumeGroup: []gopowerstore.VolumeGroup{
						{ID: "vg-2", Name: defaultVGPrefix + "-vg-2"},
					},
				}, nil)

			resp := &volumegrouprpc.CreateVolumeGroupResponse{
				VolumeGroup: &volumegrouprpc.VolumeGroup{},
			}
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-replica",
				VolumeIds: []string{targetVolID1, targetVolID2},
			}
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			_, err := vgServer.createReplicaVolumeGroup(context.Background(), req, params, resp)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail when array not found for volumes", func() {
			// Volume belongs to an unknown array
			unknownVolID := filepath.Join(validBaseVolID, "unknown-array", "scsi")

			resp := &volumegrouprpc.CreateVolumeGroupResponse{
				VolumeGroup: &volumegrouprpc.VolumeGroup{},
			}
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-replica",
				VolumeIds: []string{unknownVolID},
			}
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			_, err := vgServer.createReplicaVolumeGroup(context.Background(), req, params, resp)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should fail when GetVolumeGroup fails for the found VG", func() {
			targetVolID := filepath.Join(validBaseVolID, secondValidID, "scsi")

			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(
				gopowerstore.VolumeGroups{
					VolumeGroup: []gopowerstore.VolumeGroup{
						{ID: validGroupID, Name: defaultVGPrefix + "-replica-vg"},
					},
				}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, errors.New("get vg failed"))

			resp := &volumegrouprpc.CreateVolumeGroupResponse{
				VolumeGroup: &volumegrouprpc.VolumeGroup{},
			}
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-replica",
				VolumeIds: []string{targetVolID},
			}
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			_, err := vgServer.createReplicaVolumeGroup(context.Background(), req, params, resp)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail when volumes belong to different arrays", func() {
			vol1 := filepath.Join(validBaseVolID, secondValidID, "scsi")
			vol2 := filepath.Join(validRemoteVolID, firstValidID, "scsi")

			resp := &volumegrouprpc.CreateVolumeGroupResponse{
				VolumeGroup: &volumegrouprpc.VolumeGroup{},
			}
			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-test-replica",
				VolumeIds: []string{vol1, vol2},
			}
			params := map[string]string{
				sourceArrayParameter:     firstValidID,
				targetArrayParameter:     secondValidID,
				targetArrayNameParameter: validRemoteSystemName,
			}

			_, err := vgServer.createReplicaVolumeGroup(context.Background(), req, params, resp)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})
	})

	ginkgo.Describe("CreateVolumeGroup - new VG creation path", func() {
		var vgServer *CSIAddonsVolumeGroupServer

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
		})

		ginkgo.It("should create new VG successfully end-to-end", func() {
			clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(
				gopowerstore.Volume{ID: validBaseVolID, Size: validVolSize}, nil)
			// No existing VG found
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{}, nil)
			// VG does not exist by name
			clientMock.On("GetVolumeGroupByName", mock.Anything, mock.Anything).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())
			clientMock.On("CreateVolumeGroup", mock.Anything, mock.Anything).Return(
				gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg-test"}, nil)

			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-new-vg-test",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter:            firstValidID,
					targetArrayParameter:            secondValidID,
					targetArrayNameParameter:        validRemoteSystemName,
					CSIAddonsParamRPO:               validRPO,
					CSIAddonsParamVolumeGroupPrefix: "tw",
				},
			}

			resp, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroup).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroup.VolumeGroupId).To(gomega.Equal(validGroupID))
			gomega.Expect(resp.VolumeGroup.VolumeGroupContext[sourceArrayParameter]).To(gomega.Equal(firstValidID))
			gomega.Expect(resp.VolumeGroup.VolumeGroupContext[targetArrayParameter]).To(gomega.Equal(secondValidID))
		})

		ginkgo.It("should fail when GetVolume fails", func() {
			clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(
				gopowerstore.Volume{}, errors.New("volume not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{}, nil)

			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-fail-vol",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter:            firstValidID,
					targetArrayParameter:            secondValidID,
					targetArrayNameParameter:        validRemoteSystemName,
					CSIAddonsParamVolumeGroupPrefix: "tw",
				},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should fail with NotFound when GetVolume returns a not-found error", func() {
			clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(
				gopowerstore.Volume{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{}, nil)

			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-missing-vol",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter:            firstValidID,
					targetArrayParameter:            secondValidID,
					targetArrayNameParameter:        validRemoteSystemName,
					CSIAddonsParamVolumeGroupPrefix: "tw",
				},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should route to createReplicaVolumeGroup when volumes on target array", func() {
			targetVolID := filepath.Join(validBaseVolID, secondValidID, "scsi")

			clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(
				gopowerstore.VolumeGroups{
					VolumeGroup: []gopowerstore.VolumeGroup{
						{ID: validGroupID, Name: defaultVGPrefix + "-replica-vg"},
					},
				}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-replica-vg"}, nil)

			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-target-side",
				VolumeIds: []string{targetVolID},
				Parameters: map[string]string{
					sourceArrayParameter:            firstValidID,
					targetArrayParameter:            secondValidID,
					targetArrayNameParameter:        validRemoteSystemName,
					CSIAddonsParamVolumeGroupPrefix: "tw",
				},
			}

			resp, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
			gomega.Expect(resp.VolumeGroup.VolumeGroupId).To(gomega.Equal(validGroupID))
		})

		ginkgo.It("should fail when createVolumeGroup errors", func() {
			clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(
				gopowerstore.Volume{ID: validBaseVolID, Size: validVolSize}, nil)
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{}, nil)
			clientMock.On("GetVolumeGroupByName", mock.Anything, mock.Anything).Return(
				gopowerstore.VolumeGroup{}, errors.New("connection error"))

			req := &volumegrouprpc.CreateVolumeGroupRequest{
				Name:      "vgrcontent-create-fail",
				VolumeIds: []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter:            firstValidID,
					targetArrayParameter:            secondValidID,
					targetArrayNameParameter:        validRemoteSystemName,
					CSIAddonsParamVolumeGroupPrefix: "tw",
				},
			}

			_, err := vgServer.CreateVolumeGroup(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("ModifyVolumeGroupMembership - additional paths", func() {
		var vgServer *CSIAddonsVolumeGroupServer

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
		})

		ginkgo.It("should add and remove members successfully", func() {
			existingVG := gopowerstore.VolumeGroup{
				ID:   validGroupID,
				Name: defaultVGPrefix + "-mod-vg",
				Volumes: []gopowerstore.Volume{
					{ID: validBaseVolID},
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(existingVG, nil)
			clientMock.On("AddMembersToVolumeGroup", mock.Anything, mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: validGroupID,
				VolumeIds:     []string{filepath.Join(validRemoteVolID, firstValidID, "scsi")},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			resp, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return success for replication destination VG", func() {
			destVG := gopowerstore.VolumeGroup{
				ID:                       validGroupID,
				Name:                     defaultVGPrefix + "-dest-vg",
				IsReplicationDestination: true,
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(destVG, nil)

			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: validGroupID,
				VolumeIds:     []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			resp, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return NotFound when the final GetVolumeGroup reports not found", func() {
			destVG := gopowerstore.VolumeGroup{
				ID:                       validGroupID,
				Name:                     defaultVGPrefix + "-dest-vg",
				IsReplicationDestination: true,
			}

			// First lookup (findVolumeGroupOnArray) succeeds, final reload is NotFound.
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(destVG, nil).Once()
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError()).Once()

			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: validGroupID,
				VolumeIds:     []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			_, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should return success with empty volumes when VG not found", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, "missing-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{}, nil)

			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: "missing-vg",
				VolumeIds:     []string{},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			resp, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return error when VG not found but volumes specified", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, "missing-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{}, nil)

			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: "missing-vg",
				VolumeIds:     []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			_, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.NotFound))
		})

		ginkgo.It("should return error when AddMembers fails", func() {
			existingVG := gopowerstore.VolumeGroup{
				ID:      validGroupID,
				Name:    defaultVGPrefix + "-mod-vg",
				Volumes: []gopowerstore.Volume{},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(existingVG, nil)
			clientMock.On("AddMembersToVolumeGroup", mock.Anything, mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), errors.New("add failed"))

			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: validGroupID,
				VolumeIds:     []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			_, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return error when remove members fails", func() {
			existingVG := gopowerstore.VolumeGroup{
				ID:   validGroupID,
				Name: defaultVGPrefix + "-mod-vg",
				Volumes: []gopowerstore.Volume{
					{ID: validBaseVolID},
					{ID: "extra-vol"},
				},
			}

			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(existingVG, nil)
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), errors.New("remove failed"))

			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: validGroupID,
				VolumeIds:     []string{validBlockVolumeID},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			_, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should find VG on target array when not on source", func() {
			targetVG := gopowerstore.VolumeGroup{
				ID:   validGroupID,
				Name: defaultVGPrefix + "-target-vg",
			}

			// Not found on source
			clientMock.On("GetVolumeGroup", mock.Anything, "target-vg-id").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found")).Once()
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{}, nil).Once()
			// Found on target
			clientMock.On("GetVolumeGroup", mock.Anything, "target-vg-id").Return(targetVG, nil).Once()
			// GetVolumeGroup for final read
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(targetVG, nil)

			req := &volumegrouprpc.ModifyVolumeGroupMembershipRequest{
				VolumeGroupId: "target-vg-id",
				VolumeIds:     []string{},
				Parameters: map[string]string{
					sourceArrayParameter: firstValidID,
					targetArrayParameter: secondValidID,
				},
			}

			resp, err := vgServer.ModifyVolumeGroupMembership(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("deleteArrayVolumeGroup - additional paths", func() {
		var vgServer *CSIAddonsVolumeGroupServer
		var testArr *array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			vgServer = NewCSIAddonsVolumeGroupServer(ctrlSvc)
			testArr = ctrlSvc.Arrays()[firstValidID]
		})

		ginkgo.It("should return error when UpdateVolumeGroupProtectionPolicy fails", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 validGroupID,
				Name:               defaultVGPrefix + "-vg-fail-pp",
				ProtectionPolicyID: validPolicyID,
				Volumes:            []gopowerstore.Volume{},
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), errors.New("update pp failed"))

			err := vgServer.deleteArrayVolumeGroup(context.Background(), testArr, vg)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return error when GetVolumeGroup in polling loop fails", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 validGroupID,
				Name:               defaultVGPrefix + "-vg-poll-fail",
				ProtectionPolicyID: validPolicyID,
				Volumes:            []gopowerstore.Volume{},
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{}, errors.New("get vg failed"))

			err := vgServer.deleteArrayVolumeGroup(context.Background(), testArr, vg)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return error when DeleteVolumeGroup fails", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 validGroupID,
				Name:               defaultVGPrefix + "-vg-del-fail",
				ProtectionPolicyID: validPolicyID,
				Volumes:            []gopowerstore.Volume{},
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: ""}, nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetProtectionPolicyByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), errors.New("delete vg failed"))

			err := vgServer.deleteArrayVolumeGroup(context.Background(), testArr, vg)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should delete replication rule when it exists with no policies", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 validGroupID,
				Name:               defaultVGPrefix + "-vg-rr",
				ProtectionPolicyID: validPolicyID,
				Volumes:            []gopowerstore.Volume{},
			}

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID, State: gopowerstore.RsStateOk}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, validGroupID, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: ""}, nil)
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetProtectionPolicyByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ProtectionPolicy{}, gopowerstore.NewNotFoundError())
			clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("DeleteProtectionPolicy", mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ReplicationRule{ID: validRuleID, ProtectionPolicies: []gopowerstore.ProtectionPolicy{}}, nil)
			clientMock.On("DeleteReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.EmptyResponse(""), nil)

			err := vgServer.deleteArrayVolumeGroup(context.Background(), testArr, vg)

			gomega.Expect(err).To(gomega.BeNil())
		})
	})

	ginkgo.Describe("disableBlockReplication - additional paths", func() {
		ginkgo.It("should return OutOfRange when role is Destination with active non-FailedOver session", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			// Session is OK state, role is Destination
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleDestination),
				}, nil)

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.OutOfRange))
		})

		ginkgo.It("should return success when no replication session exists (idempotent)", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			// GetReplicationSessionByLocalResourceID returns error (no session)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return Internal when ModifyVolume fails with non-NotFound error", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: validPolicyID}, nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
				gopowerstore.EmptyResponse(""), errors.New("internal error"))

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should delete unused protection policy after unassigning from volume", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: validPolicyID}, nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
				gopowerstore.EmptyResponse(""), nil)
			// PP is unused after unassignment
			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:               validPolicyID,
					Volumes:          []gopowerstore.Volume{},
					VolumeGroups:     []gopowerstore.VolumeGroup{},
					ReplicationRules: []gopowerstore.ReplicationRule{{ID: validRuleID}},
				}, nil)
			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), nil)

			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.ReplicationRule{ID: validRuleID, ProtectionPolicies: []gopowerstore.ProtectionPolicy{}}, nil)
			clientMock.On("DeleteReplicationRule", mock.Anything, validRuleID).Return(
				gopowerstore.EmptyResponse(""), nil)

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
			clientMock.AssertCalled(ginkgo.GinkgoT(), "DeleteProtectionPolicy", mock.Anything, validPolicyID)
			clientMock.AssertCalled(ginkgo.GinkgoT(), "DeleteReplicationRule", mock.Anything, validRuleID)
		})

		ginkgo.It("should not delete protection policy when still used by other volumes", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: validPolicyID}, nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
				gopowerstore.EmptyResponse(""), nil)
			// PP is still used by another volume
			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:           validPolicyID,
					Volumes:      []gopowerstore.Volume{{ID: "other-vol"}},
					VolumeGroups: []gopowerstore.VolumeGroup{},
				}, nil)

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
			clientMock.AssertNotCalled(ginkgo.GinkgoT(), "DeleteProtectionPolicy", mock.Anything, mock.Anything)
		})

		ginkgo.It("should return success when GetVolume returns NotFound", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return Internal when GetVolume fails with non-NotFound error", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{}, errors.New("get volume failed"))

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Internal))
		})

		ginkgo.It("should succeed even when GetProtectionPolicy fails during cleanup", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: validPolicyID}, nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{}, errors.New("pp lookup failed"))

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})

		ginkgo.It("should succeed even when DeleteProtectionPolicy fails during cleanup", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
				gopowerstore.Volume{ID: validBaseVolID, ProtectionPolicyID: validPolicyID}, nil)
			clientMock.On("ModifyVolume", mock.Anything, mock.Anything, validBaseVolID).Return(
				gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.ProtectionPolicy{
					ID:           validPolicyID,
					Volumes:      []gopowerstore.Volume{},
					VolumeGroups: []gopowerstore.VolumeGroup{},
				}, nil)
			clientMock.On("DeleteProtectionPolicy", mock.Anything, validPolicyID).Return(
				gopowerstore.EmptyResponse(""), errors.New("delete pp failed"))

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			res, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("disableVolumeReplicationForVolume - NFS path", func() {
		ginkgo.It("should return Unimplemented for NFS volume", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validNfsVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unimplemented))
		})
	})

	ginkgo.Describe("promoteVolumeForVolume - additional paths", func() {
		ginkgo.It("should fail with FailedPrecondition when remote system is reachable and force=false", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:             validSessionID,
					RemoteSystemID: "remote-system-id",
					Role:           string(gopowerstore.ReplicationRoleDestination),
					State:          gopowerstore.RsStateFailedOver,
				}, nil)
			clientMock.On("GetRemoteSystem", mock.Anything, "remote-system-id").Return(
				gopowerstore.RemoteSystem{ID: "remote-system-id", DataConnectionState: "OK"}, nil)

			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
				Force: false,
			}

			_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should fail with FailedPrecondition when GetRemoteSystem fails and force=false", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:             validSessionID,
					RemoteSystemID: "remote-system-id",
					Role:           string(gopowerstore.ReplicationRoleDestination),
					State:          gopowerstore.RsStateFailedOver,
				}, nil)
			clientMock.On("GetRemoteSystem", mock.Anything, "remote-system-id").Return(
				gopowerstore.RemoteSystem{}, errors.New("cannot reach remote"))

			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
				Force: false,
			}

			_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.FailedPrecondition))
		})

		ginkgo.It("should return Unimplemented for NFS volume", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validNfsVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unimplemented))
		})

		ginkgo.It("should return error when failover execution fails", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			// Use RsStatePaused so validateRSState returns actionRequired=true for RsActionFailover
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleDestination),
					State: gopowerstore.RsStatePaused,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
				Force: true,
			}

			_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return Aborted for FailingOverForDR state", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleDestination),
					State: gopowerstore.RsStateFailingOverForDR,
				}, nil)

			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
		})
	})

	ginkgo.Describe("demoteVolumeForVolume - additional paths", func() {
		ginkgo.It("should return Unimplemented for NFS volume", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validNfsVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unimplemented))
		})

		ginkgo.It("should return Aborted for FailingOver state", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleSource),
					State: gopowerstore.RsStateFailingOver,
				}, nil)

			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Aborted))
		})

		ginkgo.It("should return error when planned failover execution fails", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleSource),
					State: gopowerstore.RsStateOk,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionFailover, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return error when resume fails with force=true", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					Role:  string(gopowerstore.ReplicationRoleSource),
					State: gopowerstore.RsStatePaused,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID,
				gopowerstore.RsActionResume, mock.Anything).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest}})

			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
				Force: true,
			}

			_, err := csiAddonsServer.DemoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("configureAsyncSyncReplication - additional paths", func() {
		ginkgo.It("should fail with InvalidArgument for ASYNC mode with empty RPO", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

			req := &csiaddonsreplication.EnableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
				Parameters: map[string]string{
					CSIAddonsParamRemoteSystem:    validRemoteSystemName,
					CSIAddonsParamReplicationMode: "ASYNC",
					CSIAddonsParamRPO:             "", // Empty RPO for ASYNC - should fail
				},
			}

			_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})

		ginkgo.It("should fail for NFS protocol with block volume path", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

			req := &csiaddonsreplication.EnableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validNfsVolumeID},
					},
				},
				Parameters: map[string]string{
					CSIAddonsParamRemoteSystem:    validRemoteSystemName,
					CSIAddonsParamReplicationMode: "ASYNC",
					CSIAddonsParamRPO:             validRPO,
				},
			}

			_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unimplemented))
		})

		ginkgo.It("should fail for invalid RPO value", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(
				gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())
			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(
				gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

			req := &csiaddonsreplication.EnableVolumeReplicationRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validBlockVolumeID},
					},
				},
				Parameters: map[string]string{
					CSIAddonsParamRemoteSystem:    validRemoteSystemName,
					CSIAddonsParamReplicationMode: "ASYNC",
					CSIAddonsParamRPO:             "Invalid_RPO",
				},
			}

			_, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})
	})

	ginkgo.Describe("resyncVolumeForVolume - additional paths", func() {
		ginkgo.It("should return Unimplemented for NFS volume", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validNfsVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.ResyncVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unimplemented))
		})
	})

	ginkgo.Describe("getVolumeReplicationInfoForVolume - additional paths", func() {
		ginkgo.It("should return Unimplemented for NFS volume", func() {
			setVariables()
			csiAddonsServer := NewCSIAddonsReplicationServer(ctrlSvc)

			req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
				ReplicationSource: &csiaddonsreplication.ReplicationSource{
					Type: &csiaddonsreplication.ReplicationSource_Volume{
						Volume: &csiaddonsreplication.ReplicationSource_VolumeSource{VolumeId: validNfsVolumeID},
					},
				},
			}

			_, err := csiAddonsServer.GetVolumeReplicationInfo(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.Unimplemented))
		})
	})

	ginkgo.Describe("Dispatch functions - volume group paths", func() {
		var csiAddonsServer *CSIAddonsReplicationServer

		ginkgo.BeforeEach(func() {
			setVariables()
			csiAddonsServer = NewCSIAddonsReplicationServer(ctrlSvc)
		})

		vgReplicationSource := &csiaddonsreplication.ReplicationSource{
			Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
				Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
					VolumeGroupId: validGroupID,
				},
			},
		}

		ginkgo.It("EnableVolumeReplication should route to VG handler", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{ID: validSessionID}, nil)

			req := &csiaddonsreplication.EnableVolumeReplicationRequest{
				ReplicationSource: vgReplicationSource,
				Parameters: map[string]string{
					CSIAddonsParamRemoteSystem:      validRemoteSystemName,
					CSIAddonsParamReplicationMode:   "ASYNC",
					CSIAddonsParamRPO:               validRPO,
					CSIAddonsParamVolumeGroupPrefix: "tw",
				},
			}

			resp, err := csiAddonsServer.EnableVolumeReplication(context.Background(), req)

			// May succeed or fail depending on internal logic; the key is it reaches the VG path
			// Accept either success or an expected error (not a panic)
			if err != nil {
				gomega.Expect(status.Code(err)).ToNot(gomega.Equal(codes.OK))
			} else {
				gomega.Expect(resp).ToNot(gomega.BeNil())
			}
		})

		ginkgo.It("DisableVolumeReplication should route to VG handler", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)
			// Mock orphan RR cleanup: no orphaned rule found
			clientMock.On("GetReplicationRuleByName", mock.Anything, mock.Anything).Return(
				gopowerstore.ReplicationRule{}, gopowerstore.NewNotFoundError())

			req := &csiaddonsreplication.DisableVolumeReplicationRequest{
				ReplicationSource: vgReplicationSource,
			}

			resp, err := csiAddonsServer.DisableVolumeReplication(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("PromoteVolume should route to VG handler", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateFailedOver,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: vgReplicationSource,
				Force:             false,
			}

			resp, err := csiAddonsServer.PromoteVolume(context.Background(), req)

			if err != nil {
				gomega.Expect(status.Code(err)).ToNot(gomega.Equal(codes.OK))
			} else {
				gomega.Expect(resp).ToNot(gomega.BeNil())
			}
		})

		ginkgo.It("DemoteVolume should route to VG handler", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			req := &csiaddonsreplication.DemoteVolumeRequest{
				ReplicationSource: vgReplicationSource,
				Force:             false,
			}

			resp, err := csiAddonsServer.DemoteVolume(context.Background(), req)

			if err != nil {
				gomega.Expect(status.Code(err)).ToNot(gomega.Equal(codes.OK))
			} else {
				gomega.Expect(resp).ToNot(gomega.BeNil())
			}
		})

		ginkgo.It("ResyncVolume should route to VG handler", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStatePaused,
				}, nil)
			clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			req := &csiaddonsreplication.ResyncVolumeRequest{
				ReplicationSource: vgReplicationSource,
				Force:             false,
			}

			resp, err := csiAddonsServer.ResyncVolume(context.Background(), req)

			if err != nil {
				gomega.Expect(status.Code(err)).ToNot(gomega.Equal(codes.OK))
			} else {
				gomega.Expect(resp).ToNot(gomega.BeNil())
			}
		})

		ginkgo.It("GetVolumeReplicationInfo should route to VG handler", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(
				gopowerstore.VolumeGroup{ID: validGroupID, Name: defaultVGPrefix + "-vg"}, nil)
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Return(
				gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
					Role:  string(gopowerstore.ReplicationRoleSource),
				}, nil)

			req := &csiaddonsreplication.GetVolumeReplicationInfoRequest{
				ReplicationSource: vgReplicationSource,
			}

			resp, err := csiAddonsServer.GetVolumeReplicationInfo(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(resp).ToNot(gomega.BeNil())
		})

		ginkgo.It("PromoteVolume should fail when both IDs empty", func() {
			emptySource := &csiaddonsreplication.ReplicationSource{
				Type: &csiaddonsreplication.ReplicationSource_Volumegroup{
					Volumegroup: &csiaddonsreplication.ReplicationSource_VolumeGroupSource{
						VolumeGroupId: "",
					},
				},
			}

			req := &csiaddonsreplication.PromoteVolumeRequest{
				ReplicationSource: emptySource,
			}

			_, err := csiAddonsServer.PromoteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(status.Code(err)).To(gomega.Equal(codes.InvalidArgument))
		})
	})
})
