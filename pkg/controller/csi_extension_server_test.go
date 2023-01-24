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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dell/csi-powerstore/pkg/common"
	podmon "github.com/dell/dell-csi-extensions/podmon"
	vgsext "github.com/dell/dell-csi-extensions/volumeGroupSnapshot"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

const stateReady = "Ready"

var _ = Describe("csi-extension-server", func() {
	BeforeEach(func() {
		setVariables()
	})
	Describe("calling ValidateVolumeHostConnectivity()", func() {
		When("checking if ValidateVolumeHostConnectivity is implemented ", func() {
			It("should return a message that ValidateVolumeHostConnectivity is implemented", func() {
				req := &podmon.ValidateVolumeHostConnectivityRequest{}
				res, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res.Messages[0]).To(Equal("ValidateVolumeHostConnectivity is implemented"))
			})
		})

		When("nodeId is not provided ", func() {
			It("should return error", func() {
				volId := []string{validBaseVolID}
				req := &podmon.ValidateVolumeHostConnectivityRequest{
					ArrayId:   "default",
					VolumeIds: volId,
					NodeId:    "",
				}
				_, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				Expect(err).ToNot(BeNil())
			})
		})

		When("array status is not fetched so server will not respond ", func() {
			It("should return error", func() {
				volId := []string{validBaseVolID}
				req := &podmon.ValidateVolumeHostConnectivityRequest{
					ArrayId:   "default",
					VolumeIds: volId,
					NodeId:    "csi-node-003c684ccb0c4ca0a9c99423563dfd2c-127.0.0.1",
				}
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				_, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				Expect(err).ToNot(BeNil())
			})
		})

		When("not sending arrayId in request body ", func() {
			It("should not return error but IO in response should be false", func() {
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				var resp []gopowerstore.PerformanceMetricsByVolumeResponse
				clientMock.On("PerformanceMetricsByVolume", context.Background(), mock.Anything, mock.Anything).
					Return(resp, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					})
				volId := []string{validBaseVolID}
				req := &podmon.ValidateVolumeHostConnectivityRequest{
					VolumeIds: volId,
					NodeId:    "csi-node-003c684ccb0c4ca0a9c99423563dfd2c-127.0.0.1",
				}
				common.APIPort = ":9028"
				var status common.ArrayConnectivityStatus
				status.LastAttempt = time.Now().Unix()
				status.LastSuccess = time.Now().Unix()
				input, _ := json.Marshal(status)
				// responding with some dummy response that is for the case when array is connected and LastSuccess check was just finished
				http.HandleFunc("/array-status/globalvolid1", func(w http.ResponseWriter, r *http.Request) {
					w.Write(input)
				})

				fmt.Printf("Starting server at port 9028\n")
				go http.ListenAndServe(":9028", nil)

				response, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(response.IosInProgress).To(BeFalse())
			})
		})

		When("not sending arrayId in request body and default array is connected well and IO operation is also there ", func() {
			It("should not return error", func() {
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				resp2 := make([]gopowerstore.PerformanceMetricsByVolumeResponse, 6)
				resp2[0].TotalIops = 0.0
				resp2[0].WriteIops = 0.0
				resp2[0].ReadIops = 0.0
				resp2[1].TotalIops = 0.0
				resp2[1].WriteIops = 0.0
				resp2[1].ReadIops = 0.0
				resp2[2].TotalIops = 4.9
				resp2[2].WriteIops = 2.6
				resp2[2].ReadIops = 2.3
				resp2[3].TotalIops = 0.0
				resp2[4].TotalIops = 4.6
				resp2[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByVolume", context.Background(), mock.Anything, mock.Anything).
					Return(resp2, nil)
				volId2 := []string{validBaseVolID}
				req2 := &podmon.ValidateVolumeHostConnectivityRequest{
					VolumeIds: volId2,
					NodeId:    "csi-node-003c684ccb0c4ca0a9c99423563dfd2c-127.0.0.1",
				}

				response, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req2)
				Expect(err).To(BeNil())
				Expect(response.IosInProgress).To(BeTrue())
			})
		})
	})

	Describe("calling IsIOInProgress and QueryArrayStatus", func() {
		When("IOConnectivity for scsi type volume on array", func() {
			It("should not fail", func() {
				var resp []gopowerstore.PerformanceMetricsByVolumeResponse
				clientMock.On("PerformanceMetricsByVolume", context.Background(), mock.Anything, mock.Anything).
					Return(resp, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					})
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "scsi")
				Expect(err).ToNot(BeNil())
			})
		})

		When("IOConnectivity for nfs type volume on array", func() {
			It("should not fail", func() {
				var resp []gopowerstore.PerformanceMetricsByFileSystemResponse
				clientMock.On("PerformanceMetricsByFileSystem", context.Background(), mock.Anything, mock.Anything).
					Return(resp, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					})
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "nfs")
				Expect(err).ToNot(BeNil())
			})
		})

		When("IOConnectivity for scsi type volume on array when IO operation is not there", func() {
			It("should not fail", func() {
				resp := make([]gopowerstore.PerformanceMetricsByVolumeResponse, 6)
				resp[0].TotalIops = 0.0
				resp[1].TotalIops = 0.0
				resp[2].TotalIops = 0.0
				resp[3].TotalIops = 0.0
				resp[4].TotalIops = 0.0
				resp[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByVolume", context.Background(), mock.Anything, mock.Anything).
					Return(resp, nil)
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "scsi")
				Expect(err).ToNot(BeNil())
			})
		})

		When("IOConnectivity for scsi type volume on array when IO operation is there", func() {
			It("should not fail", func() {
				resp := make([]gopowerstore.PerformanceMetricsByVolumeResponse, 6)
				resp[0].TotalIops = 0.0
				resp[1].TotalIops = 0.0
				resp[2].TotalIops = 4.9
				resp[3].TotalIops = 0.0
				resp[4].TotalIops = 4.6
				resp[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByVolume", context.Background(), mock.Anything, mock.Anything).
					Return(resp, nil)
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "scsi")
				Expect(err).To(BeNil())
			})
		})

		When("IOConnectivity for nfs type volume on array when IO operation is not there", func() {
			It("should not fail", func() {
				resp := make([]gopowerstore.PerformanceMetricsByFileSystemResponse, 6)
				resp[0].TotalIops = 0.0
				resp[1].TotalIops = 0.0
				resp[2].TotalIops = 0.0
				resp[3].TotalIops = 0.0
				resp[4].TotalIops = 0.0
				resp[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByFileSystem", context.Background(), mock.Anything, mock.Anything).
					Return(resp, nil)
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "nfs")
				Expect(err).ToNot(BeNil())
			})
		})

		When("IOConnectivity for nfs type volume on array when IO operation is there", func() {
			It("should not fail", func() {
				resp := make([]gopowerstore.PerformanceMetricsByFileSystemResponse, 6)
				resp[0].TotalIops = 0.0
				resp[1].TotalIops = 0.0
				resp[2].TotalIops = 4.9
				resp[3].TotalIops = 0.0
				resp[4].TotalIops = 4.6
				resp[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByFileSystem", context.Background(), mock.Anything, mock.Anything).
					Return(resp, nil)
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "nfs")
				Expect(err).To(BeNil())
			})
		})

		When("API call to the specified url to retrieve connection status for the array that is connected", func() {
			It("should not fail", func() {
				common.SetAPIPort(context.Background())
				var status common.ArrayConnectivityStatus
				status.LastAttempt = time.Now().Unix()
				status.LastSuccess = time.Now().Unix()
				input, _ := json.Marshal(status)
				// responding with some dummy response that is for the case when array is connected and LastSuccess check was just finished
				http.HandleFunc("/array/id1", func(w http.ResponseWriter, r *http.Request) {
					w.Write(input)
				})

				fmt.Printf("Starting server at port 8089\n")
				go http.ListenAndServe(":8089", nil)
				// c, _ := context.WithTimeout(context.Background(), 10*time.Second)
				check, err := ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:8089/array/id1")
				Expect(err).To(BeNil())
				Expect(check).ToNot(BeFalse())
			})
		})

		When("API call to the specified url to retrieve connection status for the array that is not connected", func() {
			It("should not fail", func() {
				common.SetAPIPort(context.Background())
				var status common.ArrayConnectivityStatus
				status.LastAttempt = time.Now().Unix()
				status.LastSuccess = time.Now().Unix() - 100
				input, _ := json.Marshal(status)
				// responding with some dummy response that is for the case when array is connected and LastSuccess check was just finished
				http.HandleFunc("/array/id2", func(w http.ResponseWriter, r *http.Request) {
					w.Write(input)
				})

				fmt.Printf("Starting server at port 9098\n")
				go http.ListenAndServe(":9098", nil)
				// c, _ := context.WithTimeout(context.Background(), 10*time.Second)
				check, err := ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:9098/array/id2")
				Expect(err).To(BeNil())
				Expect(check).ToNot(BeTrue())
			})
		})

		When("API call to the specified url to retrieve connection status for the array with diff diff error conditions", func() {
			It("should not fail", func() {
				common.SetAPIPort(context.Background())
				var status common.ArrayConnectivityStatus
				status.LastAttempt = time.Now().Unix() - 200
				status.LastSuccess = time.Now().Unix() - 200
				input, _ := json.Marshal(status)
				// responding with some dummy response that is for the case when array check was just done quite back
				http.HandleFunc("/array/id3", func(w http.ResponseWriter, r *http.Request) {
					w.Write(input)
				})

				http.HandleFunc("/array/id4", func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("invalid type response"))
				})

				fmt.Printf("Starting server at port 9099\n")
				go http.ListenAndServe(":9099", nil)

				check, err := ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:9099/array/id3")
				Expect(err).To(BeNil())
				Expect(check).ToNot(BeTrue())

				check, err = ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:9099/array/id4")
				Expect(err).ToNot(BeNil())
				Expect(check).ToNot(BeTrue())

				check, err = ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:9099/array/id5")
				Expect(err).ToNot(BeNil())
				Expect(check).ToNot(BeTrue())
			})
		})
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
