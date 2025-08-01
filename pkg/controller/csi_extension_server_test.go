/*
 *
 * Copyright © 2022-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	podmon "github.com/dell/dell-csi-extensions/podmon"
	vgsext "github.com/dell/dell-csi-extensions/volumeGroupSnapshot"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	"github.com/go-openapi/strfmt"
	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

const (
	stateReady = "Ready"
)

var nodeConnectivityServer = struct {
	port       string
	statusPath string
}{
	port:       "9028",
	statusPath: "/array-status",
}

var arrayOneStatusEndpoint = filepath.Join(nodeConnectivityServer.statusPath, firstValidID)

func getActiveIOVolumeMetrics() []gopowerstore.PerformanceMetricsByVolumeResponse {
	volumeMetrics := make([]gopowerstore.PerformanceMetricsByVolumeResponse, 6)
	freshTime, _ := strfmt.ParseDateTime(fmt.Sprint(time.Now().UTC().Format("2006-01-02T15:04:05Z")))
	volumeMetrics[0].TotalIops = 0.0
	volumeMetrics[0].WriteIops = 0.0
	volumeMetrics[0].ReadIops = 0.0
	volumeMetrics[1].TotalIops = 0.0
	volumeMetrics[1].WriteIops = 0.0
	volumeMetrics[1].ReadIops = 0.0
	volumeMetrics[2].TotalIops = 4.9
	volumeMetrics[2].WriteIops = 2.6
	volumeMetrics[2].CommonMetricsFields.Timestamp = freshTime
	volumeMetrics[2].ReadIops = 2.3
	volumeMetrics[3].TotalIops = 0.0
	volumeMetrics[3].CommonMetricsFields.Timestamp = freshTime
	volumeMetrics[4].TotalIops = 4.6
	volumeMetrics[4].CommonMetricsFields.Timestamp = freshTime
	volumeMetrics[5].TotalIops = 0.0
	return volumeMetrics
}

func getInactiveIOVolumeMetrics() []gopowerstore.PerformanceMetricsByVolumeResponse {
	volumeMetrics := make([]gopowerstore.PerformanceMetricsByVolumeResponse, 6)
	freshTime, _ := strfmt.ParseDateTime(fmt.Sprint(time.Now().UTC().Format("2006-01-02T15:04:05Z")))
	volumeMetrics[0].TotalIops = 0.0
	volumeMetrics[0].WriteIops = 0.0
	volumeMetrics[0].ReadIops = 0.0
	volumeMetrics[1].TotalIops = 0.0
	volumeMetrics[1].WriteIops = 0.0
	volumeMetrics[1].ReadIops = 0.0
	volumeMetrics[2].TotalIops = 0.0
	volumeMetrics[2].WriteIops = 0.0
	volumeMetrics[2].CommonMetricsFields.Timestamp = freshTime
	volumeMetrics[2].ReadIops = 0.0
	volumeMetrics[3].TotalIops = 0.0
	volumeMetrics[3].CommonMetricsFields.Timestamp = freshTime
	volumeMetrics[4].TotalIops = 0.0
	volumeMetrics[4].CommonMetricsFields.Timestamp = freshTime
	volumeMetrics[5].TotalIops = 0.0
	return volumeMetrics
}

func startNodeConnectivityCheckerServer(port string, endpoints ...string) {
	identifiers.APIPort = ":" + port
	var status identifiers.ArrayConnectivityStatus
	status.LastAttempt = time.Now().Unix()
	status.LastSuccess = time.Now().Unix()
	input, _ := json.Marshal(status)
	// responding with some dummy response that is for the case when array is connected and LastSuccess check was just finished
	for _, endpoint := range endpoints {
		http.HandleFunc(endpoint, func(w http.ResponseWriter, _ *http.Request) {
			_, err := w.Write(input)
			if err != nil {
				fmt.Printf("error encountered when handling incoming request to mock node connectivity checker server: %s\n", err)
			}
		})
	}

	fmt.Printf("Starting server at port %s\n", port)

	go func() {
		err := http.ListenAndServe(identifiers.APIPort, nil) // #nosec G114
		if err != nil {
			fmt.Printf("error encountered serving mock node connectivity checker server: %s\n", err)
		}
	}()
}

var _ = ginkgo.Describe("csi-extension-server", func() {
	ginkgo.BeforeSuite(func() {
		startNodeConnectivityCheckerServer(nodeConnectivityServer.port, arrayOneStatusEndpoint)
	})

	ginkgo.BeforeEach(func() {
		setVariables()
	})

	ginkgo.Describe("calling ValidateVolumeHostConnectivity()", func() {
		ginkgo.When("checking if ValidateVolumeHostConnectivity is implemented ", func() {
			ginkgo.It("should return a message that ValidateVolumeHostConnectivity is implemented", func() {
				req := &podmon.ValidateVolumeHostConnectivityRequest{}
				res, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Messages[0]).To(gomega.Equal("ValidateVolumeHostConnectivity is implemented"))
			})
		})

		ginkgo.When("nodeId is not provided ", func() {
			ginkgo.It("should return error", func() {
				volID := []string{validLegacyVolID}
				req := &podmon.ValidateVolumeHostConnectivityRequest{
					ArrayId:   "default",
					VolumeIds: volID,
					NodeId:    "",
				}
				_, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("array ID provided in the request and arrayID in the volumeID do not match", func() {
			ginkgo.It("should return error", func() {
				volID := []string{validLegacyVolID}
				req := &podmon.ValidateVolumeHostConnectivityRequest{
					ArrayId:   "default",
					VolumeIds: volID,
					NodeId:    "csi-node-003c684ccb0c4ca0a9c99423563dfd2c-127.0.0.1",
				}
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				_, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("neither arrayId nor volId is present in the request body ", func() {
			ginkgo.It("should not return error", func() {
				req := &podmon.ValidateVolumeHostConnectivityRequest{
					NodeId: "csi-node-003c684ccb0c4ca0a9c99423563dfd2c-127.0.0.1",
				}
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				_, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("Invalid nodeID is sent in the request body ", func() {
			ginkgo.It("should return error", func() {
				req := &podmon.ValidateVolumeHostConnectivityRequest{
					NodeId: "csi-node-003c684ccb0c4ca0a9c99423563dfd2c-@@@",
				}
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				_, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("not sending arrayId in request body ", func() {
			ginkgo.It("should not return error but IO in response should be false", func() {
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				var resp []gopowerstore.PerformanceMetricsByVolumeResponse
				clientMock.On("PerformanceMetricsByVolume", mock.Anything, mock.Anything, mock.Anything).
					Return(resp, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					})
				volID := []string{validLegacyVolID}
				req := &podmon.ValidateVolumeHostConnectivityRequest{
					VolumeIds: volID,
					NodeId:    "csi-node-003c684ccb0c4ca0a9c99423563dfd2c-127.0.0.1",
				}

				response, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(response.IosInProgress).To(gomega.BeFalse())
			})
		})

		ginkgo.When("not sending arrayId in request body and default array is connected well and IO operation is also there ", func() {
			ginkgo.It("should not return error", func() {
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				resp2 := make([]gopowerstore.PerformanceMetricsByVolumeResponse, 6)
				freshTime, _ := strfmt.ParseDateTime(fmt.Sprint(time.Now().UTC().Format("2006-01-02T15:04:05Z")))
				resp2[0].TotalIops = 0.0
				resp2[0].WriteIops = 0.0
				resp2[0].ReadIops = 0.0
				resp2[1].TotalIops = 0.0
				resp2[1].WriteIops = 0.0
				resp2[1].ReadIops = 0.0
				resp2[2].TotalIops = 4.9
				resp2[2].WriteIops = 2.6
				resp2[2].CommonMetricsFields.Timestamp = freshTime
				resp2[2].ReadIops = 2.3
				resp2[3].TotalIops = 0.0
				resp2[3].CommonMetricsFields.Timestamp = freshTime
				resp2[4].TotalIops = 4.6
				resp2[4].CommonMetricsFields.Timestamp = freshTime
				resp2[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByVolume", mock.Anything, mock.Anything, mock.Anything).
					Return(resp2, nil)
				volID2 := []string{validLegacyVolID}
				req2 := &podmon.ValidateVolumeHostConnectivityRequest{
					VolumeIds: volID2,
					NodeId:    "csi-node-003c684ccb0c4ca0a9c99423563dfd2c-127.0.0.1",
				}

				response, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req2)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(response.IosInProgress).To(gomega.BeTrue())
			})
		})

		ginkgo.When("the preferred array of a metro volume is disconnected, but the non-preferred is connected", func() {
			ginkgo.It("should report IO is in-progress", func() {
				// preferred side will have no IO in-progress
				metroMetricsPreferred := getInactiveIOVolumeMetrics()
				metroMetricsNonPreferred := getActiveIOVolumeMetrics()

				clientMock.On("PerformanceMetricsByVolume", mock.Anything, validBaseVolID, mock.Anything).Times(1).
					Return(metroMetricsPreferred, nil)
				clientMock.On("PerformanceMetricsByVolume", mock.Anything, validRemoteVolID, mock.Anything).Times(1).
					Return(metroMetricsNonPreferred, nil)

				req := &podmon.ValidateVolumeHostConnectivityRequest{
					VolumeIds: []string{validMetroBlockVolumeID},
					NodeId:    validNodeID,
				}

				response, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(response.IosInProgress).To(gomega.BeTrue())
			})
		})

		ginkgo.When("the both arrays of a metro volume are disconnected", func() {
			ginkgo.It("should report IO is not in-progress", func() {
				// preferred side will have no IO in-progress
				metroMetricsPreferred := getInactiveIOVolumeMetrics()
				metroMetricsNonPreferred := getInactiveIOVolumeMetrics()

				clientMock.On("PerformanceMetricsByVolume", mock.Anything, validBaseVolID, mock.Anything).Times(1).
					Return(metroMetricsPreferred, nil)
				clientMock.On("PerformanceMetricsByVolume", mock.Anything, validRemoteVolID, mock.Anything).Times(1).
					Return(metroMetricsNonPreferred, nil)

				req := &podmon.ValidateVolumeHostConnectivityRequest{
					VolumeIds: []string{validMetroBlockVolumeID},
					NodeId:    validNodeID,
				}

				response, err := ctrlSvc.ValidateVolumeHostConnectivity(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(response.IosInProgress).To(gomega.BeFalse())
			})
		})
	})

	ginkgo.Describe("calling IsIOInProgress and QueryArrayStatus", func() {
		ginkgo.When("IOConnectivity for scsi type volume on array", func() {
			ginkgo.It("should not fail", func() {
				var resp []gopowerstore.PerformanceMetricsByVolumeResponse
				clientMock.On("PerformanceMetricsByVolume", context.Background(), mock.Anything, mock.Anything).
					Return(resp, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					})
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "scsi")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("IOConnectivity for nfs type volume on array", func() {
			ginkgo.It("should not fail", func() {
				var resp []gopowerstore.PerformanceMetricsByFileSystemResponse
				clientMock.On("PerformanceMetricsByFileSystem", context.Background(), mock.Anything, mock.Anything).
					Return(resp, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					})
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "nfs")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("IOConnectivity for scsi type volume on array when IO operation is not there", func() {
			ginkgo.It("should not fail", func() {
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
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("IOConnectivity for scsi type volume on array when IO operation is there", func() {
			ginkgo.It("should not fail", func() {
				resp := make([]gopowerstore.PerformanceMetricsByVolumeResponse, 6)
				freshTime, _ := strfmt.ParseDateTime(fmt.Sprint(time.Now().UTC().Format("2006-01-02T15:04:05Z")))
				resp[0].TotalIops = 0.0
				resp[1].TotalIops = 0.0
				resp[2].TotalIops = 4.9
				resp[2].CommonMetricsFields.Timestamp = freshTime
				resp[3].TotalIops = 0.0
				resp[4].CommonMetricsFields.Timestamp = freshTime
				resp[4].TotalIops = 4.6
				resp[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByVolume", context.Background(), mock.Anything, mock.Anything).
					Return(resp, nil)
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "scsi")
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("IOConnectivity for scsi type volume on array when IO operation is there but entry is not fresh", func() {
			ginkgo.It("should fail", func() {
				resp := make([]gopowerstore.PerformanceMetricsByVolumeResponse, 6)
				// stale time
				staleTime, _ := strfmt.ParseDateTime(fmt.Sprint(time.Now().Add(time.Duration(-600) * time.Minute).Format("2006-01-02T15:04:05Z")))
				resp[0].TotalIops = 0.0
				resp[1].TotalIops = 0.0
				resp[2].TotalIops = 4.9
				resp[2].CommonMetricsFields.Timestamp = staleTime
				resp[3].TotalIops = 0.0
				resp[4].CommonMetricsFields.Timestamp = staleTime
				resp[4].TotalIops = 4.6
				resp[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByVolume", context.Background(), mock.Anything, mock.Anything).
					Return(resp, nil)
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "scsi")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("IOConnectivity for nfs type volume on array when IO operation is not there", func() {
			ginkgo.It("should not fail", func() {
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
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})

		ginkgo.When("IOConnectivity for nfs type volume on array when IO operation is there", func() {
			ginkgo.It("should not fail", func() {
				resp := make([]gopowerstore.PerformanceMetricsByFileSystemResponse, 6)
				freshTime, _ := strfmt.ParseDateTime(fmt.Sprint(time.Now().UTC().Format("2006-01-02T15:04:05Z")))
				resp[0].TotalIops = 0.0
				resp[1].TotalIops = 0.0
				resp[2].CommonMetricsFields.Timestamp = freshTime
				resp[2].TotalIops = 4.9
				resp[3].TotalIops = 0.0
				resp[4].TotalIops = 4.6
				resp[4].CommonMetricsFields.Timestamp = freshTime
				resp[5].TotalIops = 0.0
				clientMock.On("PerformanceMetricsByFileSystem", context.Background(), mock.Anything, mock.Anything).
					Return(resp, nil)
				err := ctrlSvc.IsIOInProgress(context.Background(), validBlockVolumeID, ctrlSvc.DefaultArray(), "nfs")
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("API call to the specified url to retrieve connection status for the array that is connected", func() {
			ginkgo.It("should not fail", func() {
				identifiers.SetAPIPort(context.Background())
				var status identifiers.ArrayConnectivityStatus
				status.LastAttempt = time.Now().Unix()
				status.LastSuccess = time.Now().Unix()
				input, _ := json.Marshal(status)
				// responding with some dummy response that is for the case when array is connected and LastSuccess check was just finished
				http.HandleFunc("/array/id1", func(w http.ResponseWriter, _ *http.Request) {
					w.Write(input)
				})

				server := &http.Server{Addr: ":49154"} // #nosec G112
				fmt.Printf("Starting server at port 49154 \n")
				go func() {
					err := server.ListenAndServe()
					if err != nil {
						fmt.Println(err)
					}
				}()
				check, err := ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:49154/array/id1")
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(check).ToNot(gomega.BeFalse())
				server.Shutdown(context.Background())
			})
		})

		ginkgo.When("API call to the specified url to retrieve connection status for the array that is not connected", func() {
			ginkgo.It("should not fail", func() {
				identifiers.SetAPIPort(context.Background())
				var status identifiers.ArrayConnectivityStatus
				status.LastAttempt = time.Now().Unix()
				status.LastSuccess = time.Now().Unix() - 100
				input, _ := json.Marshal(status)
				// responding with some dummy response that is for the case when array is connected and LastSuccess check was just finished
				http.HandleFunc("/array/id2", func(w http.ResponseWriter, _ *http.Request) {
					w.Write(input)
				})

				server := &http.Server{Addr: ":49153"} // #nosec G112
				fmt.Printf("Starting server at port 49153 \n")
				go func() {
					err := server.ListenAndServe()
					if err != nil {
						fmt.Println(err)
					}
				}()
				check, err := ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:49153/array/id2")
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(check).ToNot(gomega.BeTrue())
				server.Shutdown(context.Background())
			})
		})

		ginkgo.When("API call to the specified url to retrieve connection status for the array with diff diff error conditions", func() {
			ginkgo.It("should not fail", func() {
				identifiers.SetAPIPort(context.Background())
				var status identifiers.ArrayConnectivityStatus
				status.LastAttempt = time.Now().Unix() - 200
				status.LastSuccess = time.Now().Unix() - 200
				input, _ := json.Marshal(status)
				// Responding with a dummy response for the case when the array check was done a while ago
				http.HandleFunc("/array/id3", func(w http.ResponseWriter, _ *http.Request) {
					w.Write(input)
				})

				http.HandleFunc("/array/id4", func(w http.ResponseWriter, _ *http.Request) {
					w.Write([]byte("invalid type response"))
				})
				server := &http.Server{Addr: ":49152"} // #nosec G112
				fmt.Printf("Starting server at port 49152 \n")
				go func() {
					err := server.ListenAndServe()
					if err != nil {
						fmt.Println(err)
					}
				}()
				check, err := ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:49152/array/id3")
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(check).ToNot(gomega.BeTrue())

				check, err = ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:49152/array/id4")
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(check).ToNot(gomega.BeTrue())

				check, err = ctrlSvc.QueryArrayStatus(context.Background(), "http://localhost:49152/array/id5")
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(check).ToNot(gomega.BeTrue())
				server.Shutdown(context.Background())
			})
		})
	})

	ginkgo.Describe("calling CreateVolumeGroupSnapshot()", func() {
		ginkgo.When("should create volume group snapshot successfully", func() {
			ginkgo.It("valid member volumes are present", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
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

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.SnapshotGroupID).To(gomega.Equal(validGroupID))
			})

			ginkgo.It("there is no existing volume group", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{}, nil)
				createGroupRequest := &gopowerstore.VolumeGroupCreate{
					Name:      validGroupName,
					VolumeIDs: []string{validBaseVolID},
				}
				clientMock.On("CreateVolumeGroup", mock.Anything, createGroupRequest).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
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

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.SnapshotGroupID).To(gomega.Equal(validGroupID))
			})
		})

		ginkgo.When("should not create volume group snapshot with invalid request", func() {
			ginkgo.It("volume group name is empty in the request", func() {
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &vgsext.CreateVolumeGroupSnapshotRequest{})

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Name to be set"))
				gomega.Expect(res).To(gomega.BeNil())
			})

			ginkgo.It("volume group name length is greater than 27 in the request", func() {
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &vgsext.CreateVolumeGroupSnapshotRequest{
					Name: "1234561111111111111111111112",
				})

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("longer than 27 character max"))
				gomega.Expect(res).To(gomega.BeNil())
			})

			ginkgo.It("source volumes are not present in the request", func() {
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &vgsext.CreateVolumeGroupSnapshotRequest{
					Name: validGroupName,
				})

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Source volumes are not present"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})

		ginkgo.When("should not create volume group snapshot", func() {
			ginkgo.It("get volume group by name fails", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{}, gopowerstore.NewAPIError())

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Error getting volume group by name"))
				gomega.Expect(res).To(gomega.BeNil())
			})

			ginkgo.It("add members to volume group fails", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{ID: validGroupID}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.NewNotFoundError())

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Error adding volume group members"))
				gomega.Expect(res).To(gomega.BeNil())
			})

			ginkgo.It("get volume group by ID fails", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{}, gopowerstore.NewAPIError())

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Error getting volume group by volume ID"))
				gomega.Expect(res).To(gomega.BeNil())
			})

			ginkgo.It("create volume group fails", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{}, nil)
				createGroupRequest := &gopowerstore.VolumeGroupCreate{
					Name:      validGroupName,
					VolumeIDs: []string{validBaseVolID},
				}
				clientMock.On("CreateVolumeGroup", mock.Anything, createGroupRequest).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, gopowerstore.NewNotFoundError())

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Error creating volume group"))
				gomega.Expect(res).To(gomega.BeNil())
			})

			ginkgo.It("create volume group snapshot fails", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{}, gopowerstore.NewNotFoundError())

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Error creating volume group snapshot"))
				gomega.Expect(res).To(gomega.BeNil())
			})

			ginkgo.It("get volume group fails", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
					Return(gopowerstore.VolumeGroup{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("AddMembersToVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("CreateVolumeGroupSnapshot", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).
					Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

				var sourceVols []string
				sourceVols = append(sourceVols, validBaseVolID+"/"+firstValidID+"/scsi")
				req := vgsext.CreateVolumeGroupSnapshotRequest{
					Name:            validGroupName,
					SourceVolumeIDs: sourceVols,
				}
				res, err := ctrlSvc.CreateVolumeGroupSnapshot(context.Background(), &req)

				gomega.Expect(err).Error()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Error getting volume group snapshot"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
	})
})
