/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	csiext "github.com/dell/dell-csi-extensions/replication"

	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	csictx "github.com/dell/gocsi/context"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	ginkgo "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	gomega "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

const (
	validBaseVolID               = "39bb1b5f-5624-490d-9ece-18f7b28a904e"
	validBlockVolumeID           = "39bb1b5f-5624-490d-9ece-18f7b28a904e/globalvolid1/scsi"
	validNfsVolumeID             = "39bb1b5f-5624-490d-9ece-18f7b28a904e/globalvolid2/nfs"
	validMetroVolumeID           = validBlockVolumeID + ":" + validRemoteVolID + "/" + secondValidID
	invalidBlockVolumeID         = "39bb1b5f-5624-490d-9ece-18f7b28a904e/globalvolid3/scsi"
	validNasID                   = "24aefac2-a796-47dc-886a-c73ff8c1a671"
	validVolSize                 = 16 * 1024 * 1024 * 1024
	firstValidID                 = "globalvolid1"
	secondValidID                = "globalvolid2"
	validNasName                 = "my-nas-name"
	validSnapName                = "my-snap"
	validNodeID                  = "csi-node-1a47a1b91c444a8a90193d8066669603-127.0.0.1"
	validHostName                = "csi-node-1a47a1b91c444a8a90193d8066669603"
	validHostID                  = "24aefac2-a796-47dc-886a-c73ff8c1a671"
	validClusterName             = "localSystemName"
	validRemoteVolID             = "9f840c56-96e6-4de9-b5a3-27e7c20eaa77"
	validRemoteSystemName        = "remoteName"
	validRemoteSystemID          = "df7f804c-6373-4659-b197-36654d17979c"
	validMetroNamespaceGroupName = "csi-" + validNamespaceName + "-" + validRemoteSystemName
	validMetroGroupName          = "csi-" + validRemoteSystemName
	validReplicationVGPrefix     = "csi"
	validSessionID               = "9abd0198-2733-4e46-b5fa-456e9c367184"
	validRPO                     = "Five_Minutes"
	zeroRPO                      = "Zero"
	replicationModeSync          = "SYNC"
	replicationModeAsync         = "ASYNC"
	validGroupID                 = "610adaef-4f0a-4dff-9812-29ffa5daf185"
	validRemoteGroupID           = "62ed932b-329b-4ba6-b0e0-3f51c34c4701"
	validNamespaceName           = "default"
	validGroupName               = "csi-" + validRemoteSystemName + "-" + validRPO
	validGroupNameSync           = "csi-" + validRemoteSystemName + "-" + zeroRPO
	validNamespacedGroupName     = "csi-" + validNamespaceName + "-" + validRemoteSystemName + "-" + validRPO
	validNamespacedGroupNameSync = "csi-" + validNamespaceName + "-" + validRemoteSystemName + "-" + zeroRPO
	validPolicyID                = "e74f6cfd-ae2a-4cde-ad6b-529b40edee5e"
	validPolicyName              = "pp-" + validGroupName
	validPolicyNameSync          = "pp-" + validGroupNameSync
	validRuleID                  = "c721f30b-0b37-4aaf-a3a2-ef99caba2100"
	validRuleName                = "rr-" + validGroupName
	validReplicationPrefix       = "/" + controller.KeyReplicationEnabled
	validVolumeGroupName         = "VGName"
	validRemoteSystemGlobalID    = "PS111111111111"
	validNfsAcls                 = "A::OWNER@:RWX"
	validNfsServerID             = "24aefac2-a796-47dc-886a-c73ff8c1a671"
	validApplianceID             = "my-appliance"
	validRemoteApplianceID       = "my-appliance2"
	validServiceTag              = "service-tag"
)

var (
	clientMock *gopowerstoremock.Client
	fsMock     *mocks.FsInterface
	ctrlSvc    *controller.Service
)

func TestCSIControllerService(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	junitReporter := reporters.NewJUnitReporter("ctrl-svc.xml")
	ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "CSIControllerService testing suite", []ginkgo.Reporter{junitReporter})
}

func setVariables() {
	clientMock = new(gopowerstoremock.Client)
	fsMock = new(mocks.FsInterface)

	arrays := make(map[string]*array.PowerStoreArray)
	first := &array.PowerStoreArray{
		Endpoint:      "https://192.168.0.1/api/rest",
		Username:      "admin",
		GlobalID:      firstValidID,
		Password:      "pass",
		BlockProtocol: common.ISCSITransport,
		Insecure:      true,
		IsDefault:     true,
		Client:        clientMock,
		IP:            "192.168.0.1",
	}
	second := &array.PowerStoreArray{
		Endpoint:      "https://192.168.0.2/api/rest",
		Username:      "admin",
		GlobalID:      secondValidID,
		Password:      "pass",
		NasName:       validNasName,
		BlockProtocol: common.NoneTransport,
		Insecure:      true,
		Client:        clientMock,
		IP:            "192.168.0.2",
	}

	arrays[firstValidID] = first
	arrays[secondValidID] = second

	csictx.Setenv(context.Background(), common.EnvReplicationPrefix, "replication.storage.dell.com")
	csictx.Setenv(context.Background(), common.EnvNfsAcls, "A::OWNER@:RWX")

	ctrlSvc = &controller.Service{Fs: fsMock}
	ctrlSvc.SetArrays(arrays)
	ctrlSvc.SetDefaultArray(first)
	ctrlSvc.Init()
}

func addMetaData(createParams interface{}) {
	if t, ok := createParams.(interface {
		MetaData() http.Header
	}); ok {
		t.MetaData().Set(controller.HeaderPersistentVolumeName, "")
		t.MetaData().Set(controller.HeaderPersistentVolumeClaimName, "")
		t.MetaData().Set(controller.HeaderPersistentVolumeClaimNamespace, "")
	} else {
		fmt.Printf("warning: %T: no MetaData method exists, consider updating gopowerstore library.", createParams)
	}
}

var _ = ginkgo.Describe("CSIControllerService", func() {
	ginkgo.BeforeEach(func() {
		setVariables()
	})

	ginkgo.Describe("calling CreateVolume()", func() {
		ginkgo.When("creating block volume", func() {
			ginkgo.It("should successfully create block volume", func() {
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = firstValidID
				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID:             firstValidID,
							common.KeyArrayVolumeName:     "my-vol",
							common.KeyProtocol:            "scsi",
							common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
							controller.KeyCSIPVCName:      req.Name,
							controller.KeyCSIPVCNamespace: validNamespaceName,
							common.KeyServiceTag:          validServiceTag,
						},
					},
				}))
			})
		})

		ginkgo.It("should successfully create block volume and vol attributes should be set", func() {
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = firstValidID
			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			req.Parameters[common.KeyVolumeDescription] = "Vol-description"
			req.Parameters[common.KeyAppType] = "Other"
			req.Parameters[common.KeyAppTypeOther] = "Android"
			req.Parameters[common.KeyApplianceID] = "12345"
			req.Parameters[common.KeyProtectionPolicyID] = "xyz"
			req.Parameters[common.KeyPerformancePolicyID] = "abc"
			res, err := ctrlSvc.CreateVolume(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayID:             firstValidID,
						common.KeyArrayVolumeName:     "my-vol",
						common.KeyProtocol:            "scsi",
						common.KeyVolumeDescription:   "Vol-description",
						common.KeyAppType:             "Other",
						common.KeyAppTypeOther:        "Android",
						common.KeyApplianceID:         "12345",
						common.KeyProtectionPolicyID:  "xyz",
						common.KeyPerformancePolicyID: "abc",
						controller.KeyCSIPVCName:      req.Name,
						controller.KeyCSIPVCNamespace: validNamespaceName,
						common.KeyServiceTag:          validServiceTag,
					},
				},
			}))
		})
	})
	ginkgo.When("creating a block volume with replication properties", func() {
		var req *csi.CreateVolumeRequest
		ginkgo.BeforeEach(func() {
			req = getTypicalCreateVolumeRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = firstValidID
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationEnabled)] = "true"
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = validRPO
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem)] = validRemoteSystemName
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces)] = "true"
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationVGPrefix)] = validReplicationVGPrefix
			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
		})

		ginkgo.It("should create volume and volumeGroup if policy exists - ASYNC", func() {
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			// all entities not exists
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
				Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			EnsureProtectionPolicyExistsMock()

			createGroupRequest := &gopowerstore.VolumeGroupCreate{Name: validGroupName, ProtectionPolicyID: validPolicyID}
			clientMock.On("CreateVolumeGroup", mock.Anything, createGroupRequest).Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)

			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationRPO):              validRPO,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         validReplicationVGPrefix,
					},
				},
			}))
		})

		ginkgo.It("should create volume and volumeGroup if policy exists - SYNC", func() {
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = zeroRPO

			// all entities not exists
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			EnsureProtectionPolicyExistsMockSync()

			createGroupRequest := &gopowerstore.VolumeGroupCreate{Name: validGroupNameSync, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: true}
			clientMock.On("CreateVolumeGroup", mock.Anything, createGroupRequest).Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)

			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationRPO):              zeroRPO,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should create vg with namespace if namespaces not ignored - ASYNC", func() {
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces)] = "false"
			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName

			defer func() {
				req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces)] = "true"
				req.Parameters[controller.KeyCSIPVCNamespace] = ""
			}()

			clientMock.On("GetVolumeGroupByName", mock.Anything, validNamespacedGroupName).
				Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(gopowerstore.RemoteSystem{
				Name: validRemoteSystemName,
				ID:   validRemoteSystemID,
			}, nil)

			clientMock.On("GetProtectionPolicyByName", mock.Anything, "pp-"+validNamespacedGroupName).
				Return(gopowerstore.ProtectionPolicy{ID: validPolicyID}, nil)

			createGroupRequest := &gopowerstore.VolumeGroupCreate{Name: validNamespacedGroupName, ProtectionPolicyID: validPolicyID}
			clientMock.On("CreateVolumeGroup", mock.Anything, createGroupRequest).Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationRPO):              validRPO,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "false",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         validReplicationVGPrefix,
					},
				},
			}))
		})

		ginkgo.It("should create vg with namespace if namespaces not ignored - SYNC", func() {
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces)] = "false"
			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = zeroRPO

			defer func() {
				req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces)] = "true"
				req.Parameters[controller.KeyCSIPVCNamespace] = ""
			}()

			clientMock.On("GetVolumeGroupByName", mock.Anything, validNamespacedGroupNameSync).
				Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(gopowerstore.RemoteSystem{
				Name: validRemoteSystemName,
				ID:   validRemoteSystemID,
			}, nil)

			clientMock.On("GetProtectionPolicyByName", mock.Anything, "pp-"+validNamespacedGroupNameSync).
				Return(gopowerstore.ProtectionPolicy{ID: validPolicyID}, nil)

			createGroupRequest := &gopowerstore.VolumeGroupCreate{Name: validNamespacedGroupNameSync, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: true}
			clientMock.On("CreateVolumeGroup", mock.Anything, createGroupRequest).Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationRPO):              zeroRPO,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "false",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should create new volume with existing volumeGroup with policy - ASYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)

			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationRPO):              validRPO,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         validReplicationVGPrefix,
					},
				},
			}))
		})

		ginkgo.It("should create new volume with existing volumeGroup with policy - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: true}, nil)
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = zeroRPO

			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(controller.KeyReplicationRPO):              zeroRPO,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should fail create new volume with existing volumeGroup with policy and when IsWriteOrderConsistent is false - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = zeroRPO

			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't apply protection policy with sync rule if volume group is not write-order consistent"))
		})

		ginkgo.It("should create volume and update volumeGroup without policy, but policy exists - ASYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)

			EnsureProtectionPolicyExistsMock()

			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationRPO):              validRPO,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         validReplicationVGPrefix,
					},
				},
			}))
		})

		ginkgo.It("should create volume and update volumeGroup without policy, but policy exists - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: true}, nil)

			EnsureProtectionPolicyExistsMockSync()

			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = zeroRPO
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(controller.KeyReplicationRPO):              zeroRPO,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should fail create volume and update volumeGroup without policy, but policy exists when IsWriteOrderConsistent is false - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)

			EnsureProtectionPolicyExistsMockSync()

			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = zeroRPO
			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't apply protection policy with sync rule if volume group is not write-order consistent"))
		})

		ginkgo.It("should fail create volume and update volumeGroup if we can't ensure that policy exists - ASYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
				Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).
				Return(gopowerstore.RemoteSystem{}, gopowerstore.NewHostIsNotExistError())

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't ensure protection policy exists"))
		})

		ginkgo.It("should fail create volume and update volumeGroup if we can't ensure that policy exists - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).
				Return(gopowerstore.RemoteSystem{}, gopowerstore.NewHostIsNotExistError())

			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = zeroRPO

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't ensure protection policy exists"))
		})

		ginkgo.It("should fail when rpo incorrect", func() {
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = "invalidRpo"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("invalid RPO value"))
		})

		ginkgo.It("should fail when rpo not declared in parameters -ASYNC", func() {
			delete(req.Parameters, ctrlSvc.WithRP(controller.KeyReplicationRPO))

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication mode is ASYNC but no RPO specified in storage class"))
		})

		ginkgo.It("should default RPO to Zero when mode is SYNC and RPO is not specified", func() {
			delete(req.Parameters, ctrlSvc.WithRP(controller.KeyReplicationRPO))
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: true}, nil)

			EnsureProtectionPolicyExistsMockSync()

			clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = "SYNC"
			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                                 "my-vol",
						common.KeyProtocol:                                        "scsi",
						common.KeyArrayID:                                         firstValidID,
						common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                                      validServiceTag,
						controller.KeyCSIPVCName:                                  req.Name,
						controller.KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(controller.KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should fail when remote system not declared in parameters", func() {
			delete(req.Parameters, ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem))

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication enabled but no remote system specified in storage class"))
		})

		ginkgo.It("should fail when mode is incorrect", func() {
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = "SYNCMETRO"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("invalid replication mode"))
		})

		ginkgo.It("should fail when mode is ASYNC and RPO is Zero", func() {
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = replicationModeAsync
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = zeroRPO
			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication mode ASYNC requires RPO value to be non Zero"))
		})

		ginkgo.It("should fail when mode is SYNC and RPO is not Zero", func() {
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = "SYNC"
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRPO)] = validRPO
			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication mode SYNC requires RPO value to be Zero"))
		})

		ginkgo.It("should fail when volume group prefix not declared in parameters", func() {
			delete(req.Parameters, ctrlSvc.WithRP(controller.KeyReplicationVGPrefix))

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication enabled but no volume group prefix specified in storage class"))
		})

		ginkgo.It("should fail when invalid remote system is specified in parameters for metro volume", func() {
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = "METRO"
			req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem)] = "invalid"

			clientMock.On("GetRemoteSystemByName", mock.Anything, "invalid").Return(gopowerstore.RemoteSystem{}, gopowerstore.NewNotFoundError())

			res, err := ctrlSvc.CreateVolume(context.Background(), req)

			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't query remote system by name"))
		})

		ginkgo.Context("replication type is metro volume", func() {
			var configureMetroRequest *gopowerstore.MetroConfig

			ginkgo.BeforeEach(func() {
				// Default mock function functionality for metro replication.
				// This base functionality can be overridden in the individual test implementation.
				configureMetroRequest = &gopowerstore.MetroConfig{RemoteSystemID: validRemoteSystemID}
				req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = "METRO"
				// not needed for testing metro
				delete(req.Parameters, ctrlSvc.WithRP(controller.KeyReplicationRPO))
				delete(req.Parameters, ctrlSvc.WithRP(controller.KeyReplicationVGPrefix))

				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(gopowerstore.RemoteSystem{
					Name:         validRemoteSystemName,
					ID:           validRemoteSystemID,
					SerialNumber: secondValidID,
				}, nil)
				clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			})

			ginkgo.It("should configure metro replication on volume", func() {
				delete(req.Parameters, ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces))

				clientMock.On("ConfigureMetroVolume", mock.Anything, validBaseVolID, configureMetroRequest).
					Return(gopowerstore.MetroSessionResponse{ID: validSessionID}, nil)
				clientMock.On("GetVolume", context.Background(), mock.Anything).
					Return(gopowerstore.Volume{ApplianceID: validApplianceID, MetroReplicationSessionID: validSessionID}, nil)
				clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(gopowerstore.ReplicationSession{
					LocalResourceID:  validBaseVolID,
					RemoteResourceID: validRemoteVolID,
					ResourceType:     "volume",
				}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      validMetroVolumeID,
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:                             "my-vol",
							common.KeyProtocol:                                    "scsi",
							common.KeyArrayID:                                     firstValidID,
							common.KeyVolumeDescription:                           req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:                                  validServiceTag,
							controller.KeyCSIPVCName:                              req.Name,
							controller.KeyCSIPVCNamespace:                         validNamespaceName,
							ctrlSvc.WithRP(controller.KeyReplicationEnabled):      "true",
							ctrlSvc.WithRP(controller.KeyReplicationMode):         "METRO",
							ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem): validRemoteSystemName,
						},
					},
				}))
			})

			ginkgo.It("should fail to configure metro replication on volume if the volume cannot be found", func() {
				// Return volume not found error when trying to configure a metro session for that volume
				clientMock.On("ConfigureMetroVolume", mock.Anything, validBaseVolID, configureMetroRequest).
					Return(gopowerstore.MetroSessionResponse{}, gopowerstore.NewNotFoundError())
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ID: validBaseVolID, MetroReplicationSessionID: validSessionID}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't configure metro on volume"))
			})

			ginkgo.It("should fail when invalid remote system is specified in parameters for metro volume", func() {
				req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem)] = "invalid"

				// return 404 Not Found error when querying for the remote system
				clientMock.On("GetRemoteSystemByName", mock.Anything, "invalid").Return(gopowerstore.RemoteSystem{}, gopowerstore.NewNotFoundError())

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't query remote system by name"))
			})

			ginkgo.It("should fail if it can't find the replication session", func() {
				clientMock.On("ConfigureMetroVolume", mock.Anything, validBaseVolID, configureMetroRequest).
					Return(gopowerstore.MetroSessionResponse{ID: validSessionID}, nil)
				clientMock.On("GetVolume", context.Background(), mock.Anything).
					Return(gopowerstore.Volume{ApplianceID: validApplianceID, MetroReplicationSessionID: validSessionID}, nil)
				clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				// Return 404 Not Found error when querying for the replication session
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).Return(gopowerstore.ReplicationSession{}, gopowerstore.NewNotFoundError())

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("could not get metro replication session"))
			})

			ginkgo.It("should fail if the replication session resource type is incorrect", func() {
				clientMock.On("ConfigureMetroVolume", mock.Anything, validBaseVolID, configureMetroRequest).
					Return(gopowerstore.MetroSessionResponse{ID: validSessionID}, nil)
				clientMock.On("GetVolume", context.Background(), mock.Anything).
					Return(gopowerstore.Volume{ApplianceID: validApplianceID, MetroReplicationSessionID: validSessionID}, nil)
				clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				// Return a bad resource type for the replication session; "file_system"
				resourceType := "file_system"
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validBaseVolID).
					Return(gopowerstore.ReplicationSession{ResourceType: resourceType, ID: validSessionID}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring((fmt.Sprintf("replication session %s has a resource type %s, wanted type 'volume' or 'volume_group'",
					validSessionID, resourceType))))
			})
		})

		ginkgo.Context("replication type is metro volume group", func() {
			var configureMetroRequest *gopowerstore.MetroConfig
			var validMetroVolumeGroup gopowerstore.VolumeGroup

			ginkgo.BeforeEach(func() {
				// Default mock function functionality for metro replication.
				// This base functionality can be overridden in the individual test implementation.
				configureMetroRequest = &gopowerstore.MetroConfig{RemoteSystemID: validRemoteSystemID}
				req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationMode)] = "METRO"
				req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces)] = "false"
				// not needed for testing metro
				delete(req.Parameters, ctrlSvc.WithRP(controller.KeyReplicationRPO))

				validMetroVolumeGroup = gopowerstore.VolumeGroup{
					ID:                        validGroupID,
					Name:                      validMetroNamespaceGroupName,
					MetroReplicationSessionID: validSessionID,
					ProtectionPolicyID:        "",
					IsWriteOrderConsistent:    true,
				}

				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(gopowerstore.RemoteSystem{
					Name:         validRemoteSystemName,
					ID:           validRemoteSystemID,
					SerialNumber: secondValidID,
				}, nil)
				clientMock.On("GetVolume", context.Background(), mock.Anything).
					Return(gopowerstore.Volume{ApplianceID: validApplianceID, MetroReplicationSessionID: validSessionID}, nil)
				clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			})

			ginkgo.It("should create a new metro volume group with the namespace in the group name", func() {
				// vg should not exist
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(gopowerstore.VolumeGroup{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
				clientMock.On("CreateVolumeGroup", mock.Anything, &gopowerstore.VolumeGroupCreate{
					Name:                   validMetroNamespaceGroupName,
					IsWriteOrderConsistent: true,
				}).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.VolumeGroup{
					ID:   validGroupID,
					Name: validMetroNamespaceGroupName,
				}, nil)
				clientMock.On("ConfigureMetroVolumeGroup", mock.Anything, validGroupID, configureMetroRequest).
					Return(gopowerstore.MetroSessionResponse{ID: validSessionID}, nil)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{
						ResourceType: "volume_group",
						StorageElementPairs: []gopowerstore.StorageElementPair{
							{
								LocalStorageElementID:  validBaseVolID,
								RemoteStorageElementID: validRemoteVolID,
							},
						},
					}, nil)

				// ignoreNamespace parameter to false.
				req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces)] = "false"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).NotTo(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      validMetroVolumeID,
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:                                 "my-vol",
							common.KeyProtocol:                                        "scsi",
							common.KeyArrayID:                                         firstValidID,
							common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:                                      validServiceTag,
							controller.KeyCSIPVCName:                                  req.Name,
							controller.KeyCSIPVCNamespace:                             validNamespaceName,
							ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
							ctrlSvc.WithRP(controller.KeyReplicationMode):             "METRO",
							ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
							ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "false",
							ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         validReplicationVGPrefix,
						},
					},
				}))
			})

			ginkgo.It("should create a new metro volume group without the namespace in the name", func() {
				// vg should not exist
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroGroupName).
					Return(gopowerstore.VolumeGroup{}, gopowerstore.APIError{ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound}})
				clientMock.On("CreateVolumeGroup", mock.Anything, &gopowerstore.VolumeGroupCreate{
					Name:                   validMetroGroupName,
					IsWriteOrderConsistent: true,
				}).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.VolumeGroup{
					ID:   validGroupID,
					Name: validMetroGroupName,
				}, nil)
				clientMock.On("ConfigureMetroVolumeGroup", mock.Anything, validGroupID, configureMetroRequest).
					Return(gopowerstore.MetroSessionResponse{ID: validSessionID}, nil)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{
						ResourceType: "volume_group",
						StorageElementPairs: []gopowerstore.StorageElementPair{
							{
								LocalStorageElementID:  validBaseVolID,
								RemoteStorageElementID: validRemoteVolID,
							},
						},
					}, nil)

				// add vg prefix parameters and set ignore namespace param to true/null/empty-string
				req.Parameters[ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces)] = "true"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).NotTo(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      validMetroVolumeID,
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:                                 "my-vol",
							common.KeyProtocol:                                        "scsi",
							common.KeyArrayID:                                         firstValidID,
							common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:                                      validServiceTag,
							controller.KeyCSIPVCName:                                  req.Name,
							controller.KeyCSIPVCNamespace:                             validNamespaceName,
							ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
							ctrlSvc.WithRP(controller.KeyReplicationMode):             "METRO",
							ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
							ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "true",
							ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         validReplicationVGPrefix,
						},
					},
				}))
			})

			ginkgo.It("should configure metro replication, re-using the existing, empty volume group with the same name", func() {
				// an empty vg already exists but is not metro replicated
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(gopowerstore.VolumeGroup{
						ID:                        validGroupID,
						Name:                      validMetroNamespaceGroupName,
						MetroReplicationSessionID: "",
						ProtectionPolicyID:        "",
						Volumes:                   []gopowerstore.Volume{},
						IsWriteOrderConsistent:    true,
					}, nil)

				clientMock.On("ConfigureMetroVolumeGroup", mock.Anything, validGroupID, configureMetroRequest).
					Return(gopowerstore.MetroSessionResponse{ID: validSessionID}, nil)
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{
						ResourceType: "volume_group",
						StorageElementPairs: []gopowerstore.StorageElementPair{
							{
								LocalStorageElementID:  validBaseVolID,
								RemoteStorageElementID: validRemoteVolID,
							},
						},
					}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).NotTo(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      validMetroVolumeID,
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:                                 "my-vol",
							common.KeyProtocol:                                        "scsi",
							common.KeyArrayID:                                         firstValidID,
							common.KeyVolumeDescription:                               req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:                                      validServiceTag,
							controller.KeyCSIPVCName:                                  req.Name,
							controller.KeyCSIPVCNamespace:                             validNamespaceName,
							ctrlSvc.WithRP(controller.KeyReplicationEnabled):          "true",
							ctrlSvc.WithRP(controller.KeyReplicationMode):             "METRO",
							ctrlSvc.WithRP(controller.KeyReplicationRemoteSystem):     validRemoteSystemName,
							ctrlSvc.WithRP(controller.KeyReplicationIgnoreNamespaces): "false",
							ctrlSvc.WithRP(controller.KeyReplicationVGPrefix):         validReplicationVGPrefix,
						},
					},
				}))
			})

			ginkgo.It("should fail to configure metro on an existing volume group if the volume group has attached volumes", func() {
				// a vg already exists and is not part of a metro session,
				// but it is disqualified from use because it has volumes attached
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(gopowerstore.VolumeGroup{
						ID:                        validGroupID,
						Name:                      validMetroNamespaceGroupName,
						MetroReplicationSessionID: "",
						ProtectionPolicyID:        "",
						Volumes: []gopowerstore.Volume{
							{
								ID: validBaseVolID,
							},
						},
					}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					fmt.Sprintf("volume group %s found with volumes attached, but not part of a metro replication session.", validMetroNamespaceGroupName)))
			})

			ginkgo.It("should fail to configure metro on an existing volume group if the group is not write-order consistent", func() {
				// Return a volume group that is not write-order consistent.
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(gopowerstore.VolumeGroup{
						ID:                        validGroupID,
						Name:                      validMetroNamespaceGroupName,
						MetroReplicationSessionID: "",
						ProtectionPolicyID:        "",
						Volumes:                   []gopowerstore.Volume{},
						IsWriteOrderConsistent:    false,
					}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					"volume group %s is not write-order consistent and cannot be used for metro replication.", validMetroNamespaceGroupName))
			})

			ginkgo.It("should fail to add the volume to the vg if the replication session is not in OK state", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(validMetroVolumeGroup, nil)

				// Replication session is in a 'error' state
				clientMock.On("GetReplicationSessionByID", mock.Anything, validSessionID).
					Return(gopowerstore.ReplicationSession{State: gopowerstore.RsStateError}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					fmt.Sprintf("cannot add volumes to volume group %s because the metro replication session is not in running state.", validMetroNamespaceGroupName)))
			})

			ginkgo.It("should fail if the remote volume ID cannot be found", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(validMetroVolumeGroup, nil)
				clientMock.On("GetReplicationSessionByID", mock.Anything, validSessionID).Return(gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
				}, nil)
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionPause, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionResume, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)

				// return a replication session that has a missing remote volume ID
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{
						ResourceType: "volume_group",
						StorageElementPairs: []gopowerstore.StorageElementPair{
							{
								LocalStorageElementID:  validBaseVolID,
								RemoteStorageElementID: "",
							},
						},
					}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					fmt.Sprintf("could not get remote volume pair for local volume %s", validBaseVolID)))
			})

			ginkgo.It("should fail if a new volume group cannot be created", func() {
				// report the vg as not existing
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(gopowerstore.VolumeGroup{}, gopowerstore.WrapErr(gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					}))

				// return an error when creating the volume group
				clientMock.On("CreateVolumeGroup", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{}, gopowerstore.WrapErr(gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					}))

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(fmt.Sprintf(
					"unable to create volume group %s on PowerStore array", validMetroNamespaceGroupName)))
			})

			ginkgo.It("should fail if metro replication cannot be configured on the new volume group", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(gopowerstore.VolumeGroup{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})
				clientMock.On("CreateVolumeGroup", mock.Anything, &gopowerstore.VolumeGroupCreate{
					Name:                   validMetroNamespaceGroupName,
					IsWriteOrderConsistent: true,
				}).
					Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
				clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.VolumeGroup{
					ID:   validGroupID,
					Name: validMetroNamespaceGroupName,
				}, nil)

				// return an error when trying to start a metro replication session.
				clientMock.On("ConfigureMetroVolumeGroup", mock.Anything, validGroupID, mock.Anything).
					Return(gopowerstore.MetroSessionResponse{}, gopowerstore.WrapErr(gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					}))

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					fmt.Sprintf("unable to configure metro replication on volume group %s", validMetroNamespaceGroupName)))
			})

			ginkgo.It("should fail to add a volume to an existing volume group with a protection policy", func() {
				// return a volume group with a protection policy, triggering an error
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(gopowerstore.VolumeGroup{
						Name:                      validMetroNamespaceGroupName,
						MetroReplicationSessionID: validSessionID,
						ProtectionPolicyID:        validPolicyID,
					}, nil)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(
					gomega.ContainSubstring(fmt.Sprintf("volume group %s has a protection policy assigned making it incompatible for usage with metro replication", validMetroNamespaceGroupName)))
			})

			ginkgo.It("should fail to add a volume to an existing volume group if the metro session cannot be paused", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(validMetroVolumeGroup, nil)
				clientMock.On("GetReplicationSessionByID", mock.Anything, validSessionID).Return(gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
				}, nil)

				// return an error when trying to pause the metro session
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionPause, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.WrapErr(gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
						},
					}))

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					fmt.Sprintf("unable to pause metro replication session on volume group %s", validMetroNamespaceGroupName)))
			})

			ginkgo.It("should fail if the metro replication session cannot be resumed", func() {
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(validMetroVolumeGroup, nil)
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionPause, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("GetReplicationSessionByID", mock.Anything, validSessionID).Return(gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
				}, nil)

				// return an error when trying to resume the replication session.
				clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionResume, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.WrapErr(gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
						},
					}))

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					fmt.Sprintf("unable to resume metro replication session on volume group %s", validMetroNamespaceGroupName)))
			})

			ginkgo.It("should fail if querying the volume group returns error other than NotFound", func() {
				// return an error other than 404
				clientMock.On("GetVolumeGroupByName", mock.Anything, validMetroNamespaceGroupName).
					Return(gopowerstore.VolumeGroup{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					})

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(fmt.Sprintf("unexpected error occurred while getting the volume group")))
			})
		})
	})

	ginkgo.When("creating nfs volume", func() {
		ginkgo.It("should successfully create nfs volume", func() {
			clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
			clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
			clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
			clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:     "my-vol",
						common.KeyProtocol:            "nfs",
						common.KeyArrayID:             secondValidID,
						common.KeyNfsACL:              "A::OWNER@:RWX",
						common.KeyNasName:             validNasName,
						common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:          validServiceTag,
						controller.KeyCSIPVCName:      req.Name,
						controller.KeyCSIPVCNamespace: validNamespaceName,
					},
					AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
				},
			}))
		})

		ginkgo.It("should successfully create nfs volume & all vol attribute should get set", func() {
			clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
			clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
			clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
			clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[controller.KeyCSIPVCName] = req.Name
			req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
			req.Parameters[common.KeyVolumeDescription] = "Vol-description"
			req.Parameters[common.KeyConfigType] = "ConfigType_A"
			req.Parameters[common.KeyAccessPolicy] = "AccessPolicy_A"
			req.Parameters[common.KeyLockingPolicy] = "KeyLockingPolicy_A"
			req.Parameters[common.KeyFolderRenamePolicy] = "KeyFolderRenamePolicy"
			req.Parameters[common.KeyIsAsyncMtimeEnabled] = "true"
			req.Parameters[common.KeyProtectionPolicyID] = "KeyProtectionPolicyID"
			req.Parameters[common.KeyFileEventsPublishingMode] = "KeyFileEventsPublishingMode"
			req.Parameters[common.KeyHostIoSize] = "VMware_16K"
			req.Parameters[common.KeyFlrCreateMode] = "KeyFlrCreateMode"
			req.Parameters[common.KeyFlrDefaultRetention] = "KeyFlrDefaultRetention"
			req.Parameters[common.KeyFlrMinRetention] = "KeyFlrMinRetention"
			req.Parameters[common.KeyFlrMaxRetention] = "KeyFlrMaxRetention"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:          "my-vol",
						common.KeyProtocol:                 "nfs",
						common.KeyArrayID:                  secondValidID,
						common.KeyNfsACL:                   "A::OWNER@:RWX",
						common.KeyNasName:                  validNasName,
						common.KeyVolumeDescription:        "Vol-description",
						common.KeyConfigType:               "ConfigType_A",
						common.KeyAccessPolicy:             "AccessPolicy_A",
						common.KeyLockingPolicy:            "KeyLockingPolicy_A",
						common.KeyFolderRenamePolicy:       "KeyFolderRenamePolicy",
						common.KeyIsAsyncMtimeEnabled:      "true",
						common.KeyProtectionPolicyID:       "KeyProtectionPolicyID",
						common.KeyFileEventsPublishingMode: "KeyFileEventsPublishingMode",
						common.KeyHostIoSize:               "VMware_16K",
						common.KeyFlrCreateMode:            "KeyFlrCreateMode",
						common.KeyFlrDefaultRetention:      "KeyFlrDefaultRetention",
						common.KeyFlrMinRetention:          "KeyFlrMinRetention",
						common.KeyFlrMaxRetention:          "KeyFlrMaxRetention",
						common.KeyServiceTag:               validServiceTag,
						controller.KeyCSIPVCName:           req.Name,
						controller.KeyCSIPVCNamespace:      validNamespaceName,
					},
					AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
				},
			}))
		})

		ginkgo.When("creating nfs volume with NFS acls in array config and storage class", func() {
			ginkgo.It("should successfully create nfs volume with storage class NFS acls in volume response", func() {
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
				clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
				clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{ID: validNfsServerID, IsNFSv4Enabled: true}, nil)
				clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
				clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
				clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				ctrlSvc.Arrays()[secondValidID].NfsAcls = "A::GROUP@:RWX"

				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.Parameters[common.KeyNfsACL] = "0777"
				req.Parameters[common.KeyArrayID] = secondValidID
				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:     "my-vol",
							common.KeyProtocol:            "nfs",
							common.KeyArrayID:             secondValidID,
							common.KeyNfsACL:              "0777",
							common.KeyNasName:             validNasName,
							common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:          validServiceTag,
							controller.KeyCSIPVCName:      req.Name,
							controller.KeyCSIPVCNamespace: validNamespaceName,
						},
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})
		})

		ginkgo.When("creating nfs volume with NFS acls in array config and not in storage class", func() {
			ginkgo.It("should successfully create nfs volume with array config NFS acls in volume response", func() {
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
				clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
				clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{ID: validNfsServerID, IsNFSv4Enabled: true}, nil)
				clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
				clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
				clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				ctrlSvc.Arrays()[secondValidID].NfsAcls = "A::GROUP@:RWX"

				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = secondValidID
				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:     "my-vol",
							common.KeyProtocol:            "nfs",
							common.KeyArrayID:             secondValidID,
							common.KeyNfsACL:              "A::GROUP@:RWX",
							common.KeyNasName:             validNasName,
							common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:          validServiceTag,
							controller.KeyCSIPVCName:      req.Name,
							controller.KeyCSIPVCNamespace: validNamespaceName,
						},
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})
		})

		ginkgo.When("creating nfs volume with NFS acls not in array config and not in storage class", func() {
			ginkgo.It("should successfully create nfs volume with default NFS acls in volume response", func() {
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
				clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
				clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{ID: validNfsServerID, IsNFSv4Enabled: true}, nil)
				clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
				clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
				clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = secondValidID
				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:     "my-vol",
							common.KeyProtocol:            "nfs",
							common.KeyArrayID:             secondValidID,
							common.KeyNfsACL:              "A::OWNER@:RWX",
							common.KeyNasName:             validNasName,
							common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:          validServiceTag,
							controller.KeyCSIPVCName:      req.Name,
							controller.KeyCSIPVCNamespace: validNamespaceName,
						},
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})
		})

		ginkgo.When("creating nfs volume with NFS acls in not in secrets & default", func() {
			ginkgo.It("should successfully create nfs volume with empty NFS acls in volume response", func() {
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
				clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
				clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{ID: validNfsServerID, IsNFSv4Enabled: true}, nil)
				clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
				clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
				clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = secondValidID
				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName

				ctrlSvc.Arrays()[secondValidID].NfsAcls = ""
				csictx.Setenv(context.Background(), common.EnvNfsAcls, "")

				_ = ctrlSvc.Init()

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:     "my-vol",
							common.KeyProtocol:            "nfs",
							common.KeyArrayID:             secondValidID,
							common.KeyNfsACL:              "",
							common.KeyNasName:             validNasName,
							common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:          validServiceTag,
							controller.KeyCSIPVCName:      req.Name,
							controller.KeyCSIPVCNamespace: validNamespaceName,
						},
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})
		})

		ginkgo.When("creating nfs volume without nfs topology in AccessibilityRequirements", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = secondValidID

				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName

				iscsiTopology := &csi.Topology{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-iscsi": "true"}}
				preferred := []*csi.Topology{iscsiTopology}
				accessibilityRequirements := &csi.TopologyRequirement{Preferred: preferred}
				req.AccessibilityRequirements = accessibilityRequirements

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("invalid topology requested for NFS Volume. Please validate your storage class has nfs topology."))
			})
		})

		ginkgo.When("creating nfs volume with more than one topology in AccessibilityRequirements", func() {
			ginkgo.It("should return only nfs topology", func() {
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
				clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
				clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
				clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
				clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = secondValidID

				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName

				iscsiTopology := &csi.Topology{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-iscis": "true"}}
				req.AccessibilityRequirements.Preferred = append(req.AccessibilityRequirements.Preferred, iscsiTopology)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:     "my-vol",
							common.KeyProtocol:            "nfs",
							common.KeyArrayID:             secondValidID,
							common.KeyNfsACL:              "A::OWNER@:RWX",
							common.KeyNasName:             validNasName,
							common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:          validServiceTag,
							controller.KeyCSIPVCName:      req.Name,
							controller.KeyCSIPVCNamespace: validNamespaceName,
						},
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})
		})

		ginkgo.When("volume name already in use", func() {
			ginkgo.It("should return existing volume [Block]", func() {
				volName := "my-vol"
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateVolume", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
						},
					})

				clientMock.On("GetVolumeByName", mock.Anything, volName).Return(gopowerstore.Volume{
					ID:   validBaseVolID,
					Name: volName,
					Size: validVolSize,
				}, nil)
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				req := getTypicalCreateVolumeRequest(volName, validVolSize)
				req.Parameters[common.KeyArrayID] = firstValidID
				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:     "my-vol",
							common.KeyProtocol:            "scsi",
							common.KeyArrayID:             firstValidID,
							common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:          validServiceTag,
							controller.KeyCSIPVCName:      req.Name,
							controller.KeyCSIPVCNamespace: validNamespaceName,
						},
					},
				}))
			})

			ginkgo.It("should return existing volume [NFS]", func() {
				volName := "my-vol"
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)

				clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusUnprocessableEntity,
					},
				})

				clientMock.On("GetFSByName", mock.Anything, volName).Return(gopowerstore.FileSystem{
					ID:        validBaseVolID,
					Name:      volName,
					SizeTotal: validVolSize,
				}, nil)
				clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
				clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
				clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				req := getTypicalCreateVolumeNFSRequest(volName, validVolSize)
				req.Parameters[common.KeyArrayID] = secondValidID
				req.Parameters[controller.KeyCSIPVCName] = req.Name
				req.Parameters[controller.KeyCSIPVCNamespace] = validNamespaceName
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:     "my-vol",
							common.KeyProtocol:            "nfs",
							common.KeyArrayID:             secondValidID,
							common.KeyNfsACL:              "A::OWNER@:RWX",
							common.KeyNasName:             validNasName,
							common.KeyVolumeDescription:   req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:          validServiceTag,
							controller.KeyCSIPVCName:      req.Name,
							controller.KeyCSIPVCNamespace: validNamespaceName,
						},
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})

			ginkgo.When("existing volume size is smaller", func() {
				ginkgo.It("should fail [Block]", func() {
					volName := "my-vol"
					clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
					clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
					clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
					clientMock.On("CreateVolume", mock.Anything, mock.Anything).
						Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusUnprocessableEntity,
							},
						})

					clientMock.On("GetVolumeByName", mock.Anything, volName).Return(gopowerstore.Volume{
						ID:   validBaseVolID,
						Name: volName,
						Size: validVolSize / 2,
					}, nil)

					req := getTypicalCreateVolumeRequest(volName, validVolSize)
					req.Parameters[common.KeyArrayID] = firstValidID
					res, err := ctrlSvc.CreateVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("volume '" + volName + "' already exists but is incompatible volume size"),
					)
				})

				ginkgo.It("should fail [NFS]", func() {
					volName := "my-vol"
					clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)

					clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
						},
					})

					clientMock.On("GetFSByName", mock.Anything, volName).Return(gopowerstore.FileSystem{
						ID:        validBaseVolID,
						Name:      volName,
						SizeTotal: validVolSize / 2,
					}, nil)

					req := getTypicalCreateVolumeNFSRequest(volName, validVolSize)
					req.Parameters[common.KeyArrayID] = secondValidID
					res, err := ctrlSvc.CreateVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(
						gomega.ContainSubstring("filesystem '" + volName + "' already exists but is incompatible volume size"),
					)
				})
			})
		})

		ginkgo.When("creating volume from snapshot", func() {
			ginkgo.It("should create volume using snapshot as a source [Block]", func() {
				snapID := validBlockVolumeID

				contentSource := &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
					Snapshot: &csi.VolumeContentSource_SnapshotSource{
						SnapshotId: snapID,
					},
				}}

				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					ID:   validBaseVolID,
					Size: validVolSize,
				}, nil)

				clientMock.On("CreateVolumeFromSnapshot", mock.Anything, mock.Anything, validBaseVolID).
					Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.VolumeContentSource = contentSource
				req.Parameters[common.KeyArrayID] = firstValidID

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID: firstValidID,
						},
						ContentSource: contentSource,
					},
				}))
			})

			ginkgo.It("should create volume using snapshot as a source [NFS]", func() {
				snapID := validNfsVolumeID
				volName := "my-vol"

				contentSource := &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
					Snapshot: &csi.VolumeContentSource_SnapshotSource{
						SnapshotId: snapID,
					},
				}}

				clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{
					ID:        validBaseVolID,
					SizeTotal: validVolSize + controller.ReservedSize,
				}, nil)

				fsClone := &gopowerstore.FsClone{
					Name:        &volName,
					Description: nil,
				}
				addMetaData(fsClone)
				clientMock.On("CreateFsFromSnapshot", mock.Anything, fsClone, validBaseVolID).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

				req := getTypicalCreateVolumeNFSRequest(volName, validVolSize)
				req.VolumeContentSource = contentSource
				req.Parameters[common.KeyArrayID] = secondValidID

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayID: secondValidID,
						},
						ContentSource:      contentSource,
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})
		})

		ginkgo.When("cloning volume", func() {
			ginkgo.It("should create volume using volume as a source [Block]", func() {
				srcID := validBlockVolumeID
				volName := "my-vol"

				contentSource := &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
					Volume: &csi.VolumeContentSource_VolumeSource{
						VolumeId: srcID,
					},
				}}

				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					ID:   validBaseVolID,
					Size: validVolSize,
				}, nil)

				volClone := &gopowerstore.VolumeClone{
					Name:        &volName,
					Description: nil,
				}
				addMetaData(volClone)
				clientMock.On("CloneVolume", mock.Anything, volClone, validBaseVolID).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

				req := getTypicalCreateVolumeRequest(volName, validVolSize)
				req.VolumeContentSource = contentSource
				req.Parameters[common.KeyArrayID] = firstValidID

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID: firstValidID,
						},
						ContentSource: contentSource,
					},
				}))
			})

			ginkgo.It("should create volume using volume as a source [NFS]", func() {
				srcID := validNfsVolumeID
				volName := "my-vol"

				contentSource := &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
					Volume: &csi.VolumeContentSource_VolumeSource{
						VolumeId: srcID,
					},
				}}

				clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{
					ID:        validBaseVolID,
					SizeTotal: validVolSize + controller.ReservedSize,
				}, nil)

				fsClone := &gopowerstore.FsClone{
					Name:        &volName,
					Description: nil,
				}
				addMetaData(fsClone)
				clientMock.On("CloneFS", mock.Anything, fsClone, validBaseVolID).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

				req := getTypicalCreateVolumeNFSRequest(volName, validVolSize)
				req.VolumeContentSource = contentSource
				req.Parameters[common.KeyArrayID] = secondValidID

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayID: secondValidID,
						},
						ContentSource:      contentSource,
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})
		})

		ginkgo.When("there is no array IP in storage class", func() {
			ginkgo.It("should use default array", func() {
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:   "my-vol",
							common.KeyProtocol:          "scsi",
							common.KeyArrayID:           firstValidID,
							common.KeyVolumeDescription: "-",
							common.KeyServiceTag:        validServiceTag,
						},
					},
				}))
			})
		})

		ginkgo.When("there array IP passed to storage class is not config", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = "127.0.0.1"
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find array with provided id"))
			})
		})

		ginkgo.When("requesting block access from nfs volume", func() {
			ginkgo.It("should fail [new key]", func() {
				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.VolumeCapabilities[0].AccessType = &csi.VolumeCapability_Block{
					Block: &csi.VolumeCapability_BlockVolume{},
				}
				req.Parameters[common.KeyArrayID] = secondValidID
				req.Parameters[controller.KeyFsType] = "nfs"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("raw block requested from NFS Volume"))
			})

			ginkgo.It("should fail [old key]", func() {
				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.VolumeCapabilities[0].AccessType = &csi.VolumeCapability_Block{
					Block: &csi.VolumeCapability_BlockVolume{},
				}
				req.Parameters[common.KeyArrayID] = secondValidID
				req.Parameters[controller.KeyFsTypeOld] = "nfs"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("raw block requested from NFS Volume"))
			})
		})

		ginkgo.When("volume name is empty", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalCreateVolumeRequest("", validVolSize)
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("name cannot be empty"))
			})
		})

		ginkgo.When("volume size is incorrect", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.CapacityRange.LimitBytes = -1000
				req.CapacityRange.RequiredBytes = -1000
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					fmt.Sprintf("bad capacity: volume size bytes %d and limit size bytes: %d must not be negative", req.CapacityRange.RequiredBytes, req.CapacityRange.RequiredBytes),
				))
			})
		})
	})

	ginkgo.Describe("calling DeleteVolume()", func() {
		ginkgo.When("deleting block volume", func() {
			ginkgo.It("should successfully delete block volume", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{ID: validBaseVolID, Size: validVolSize}, nil)
				clientMock.On("DeleteVolume",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})
		})
		ginkgo.When("deleting block volume with old volume handle naming", func() {
			ginkgo.It("should successfully delete block volume", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{ID: validBaseVolID, Size: validVolSize}, nil)
				clientMock.On("DeleteVolume",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)
				array.IPToArray = make(map[string]string)
				array.IPToArray["192.168.0.1"] = "globalvolid1"
				req := &csi.DeleteVolumeRequest{VolumeId: "39bb1b5f-5624-490d-9ece-18f7b28a904e/192.168.0.1/scsi"}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})
		})

		ginkgo.When("delete block volume with replication props", func() {
			ginkgo.It("should successful delete block volume and remove it from group and unassigned policy", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("RemoveMembersFromVolumeGroup",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"),
					validGroupID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("ModifyVolume",
					mock.Anything,
					&gopowerstore.VolumeModify{ProtectionPolicyID: ""},
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{ID: validBaseVolID, Size: validVolSize}, nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID}

				clientMock.On("DeleteVolume",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})
		})

		ginkgo.When("delete block metro volume with replication props", func() {
			ginkgo.Context("the volume is part of a volume group", func() {
				ginkgo.BeforeEach(func() {
					// Provide mocks that return data for a positive, non-error, happy path test case.
					// If testing an error path, alter the mock in the individual test scenario.
					clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
						Return(gopowerstore.VolumeGroups{
							VolumeGroup: []gopowerstore.VolumeGroup{
								{
									ID:                        validGroupID,
									Name:                      validMetroNamespaceGroupName,
									MetroReplicationSessionID: validSessionID,
								},
							},
						}, nil)
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
						Return(gopowerstore.ReplicationSession{
							ID:    validSessionID,
							State: gopowerstore.RsStateOk,
						}, nil)
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionPause, mock.Anything).
						Return(gopowerstore.EmptyResponse(""), nil)
					clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, &gopowerstore.VolumeGroupMembers{VolumeIDs: []string{validBaseVolID}}, validGroupID).
						Return(gopowerstore.EmptyResponse(""), nil)
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionResume, mock.Anything).
						Return(gopowerstore.EmptyResponse(""), nil)
					clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
					clientMock.On("DeleteVolume", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeDelete"), validBaseVolID).Return(gopowerstore.EmptyResponse(""), nil)
				})

				ginkgo.It("should successfully delete block metro volume", func() {
					// happy path
					req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
					res, err := ctrlSvc.DeleteVolume(context.Background(), req)

					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
				})

				ginkgo.It("should fail if the replication session cannot be retrieved", func() {
					// override the good mock
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Unset()
					// return an error when trying to get the replication session
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
						Return(gopowerstore.ReplicationSession{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
							},
						})

					req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
					res, err := ctrlSvc.DeleteVolume(context.Background(), req)

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to get metro session for volume group %s", validGroupID))
				})

				ginkgo.It("should fail if the replication session is not in 'OK' or 'Paused' state", func() {
					// override the good mock
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).Unset()
					// return an error a replication session with a bad state
					clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
						Return(gopowerstore.ReplicationSession{
							ID:    validSessionID,
							State: gopowerstore.RsStateError,
						}, nil)

					req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
					res, err := ctrlSvc.DeleteVolume(context.Background(), req)

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(
						"failed to delete volume %s because the metro replication session is in %s state", validBaseVolID, gopowerstore.RsStateError))
				})

				ginkgo.It("should fail if the replication session cannot be paused", func() {
					// override the good mock
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionPause, mock.Anything).Unset()
					// retun an error when trying to pause the session
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionPause, mock.Anything).
						Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusInternalServerError,
							},
						})

					req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
					res, err := ctrlSvc.DeleteVolume(context.Background(), req)

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(
						"failed to delete volume %s because the replication session could not be paused", validBaseVolID))
				})

				ginkgo.It("should fail if the replication session state cannot be restored", func() {
					// override the good mock
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionResume, mock.Anything).Unset()
					// return an error message when the replication session state cannot be restored
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionResume, mock.Anything).
						Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusInternalServerError,
							},
						})

					req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
					res, err := ctrlSvc.DeleteVolume(context.Background(), req)

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(
						"failed to delete volume %s because the replication session could not be resumed", validBaseVolID))
				})

				ginkgo.It("should fail and resume replication if the volume cannot be removed from the volume group", func() {
					// override the good mock
					clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, &gopowerstore.VolumeGroupMembers{VolumeIDs: []string{validBaseVolID}}, validGroupID).
						Unset()
					// return an http error code when the volume cannot be removed from the volume group
					clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, &gopowerstore.VolumeGroupMembers{VolumeIDs: []string{validBaseVolID}}, validGroupID).
						Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusInternalServerError,
							},
						})

					req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
					res, err := ctrlSvc.DeleteVolume(context.Background(), req)

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err.(gopowerstore.APIError).StatusCode).To(gomega.Equal(http.StatusInternalServerError))
				})

				ginkgo.It("should fail if the volume cannot be removed from the volume group and the replication session cannot be resumed", func() {
					// override the good mocks
					clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, &gopowerstore.VolumeGroupMembers{VolumeIDs: []string{validBaseVolID}}, validGroupID).
						Unset()
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionResume, mock.Anything).Unset()

					// return an http error code when the volume cannot be removed from the volume group
					clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, &gopowerstore.VolumeGroupMembers{VolumeIDs: []string{validBaseVolID}}, validGroupID).
						Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusInternalServerError,
							},
						})
					// Return an error when trying to restore the replication session after failing to remove the volume
					clientMock.On("ExecuteActionOnReplicationSession", mock.Anything, validSessionID, gopowerstore.RsActionResume, mock.Anything).
						Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusInternalServerError,
								Message:    "error",
							},
						})

					req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
					res, err := ctrlSvc.DeleteVolume(context.Background(), req)

					gomega.Expect(err).NotTo(gomega.BeNil())
					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err.(gopowerstore.APIError).StatusCode).To(gomega.Equal(http.StatusInternalServerError))
				})
			})

			ginkgo.It("should successfully delete block metro volume", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, MetroReplicationSessionID: validSessionID}, nil)
				endMetroRequest := &gopowerstore.EndMetroVolumeOptions{DeleteRemoteVolume: true}
				clientMock.On("EndMetroVolume", mock.Anything, validBaseVolID, endMetroRequest).Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("DeleteVolume", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeDelete"), validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})

			ginkgo.It("should report success even if the metro volume is not found", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				// report the volume as 404 Not Found.
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})

			ginkgo.It("should fail to delete block metro volume", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, MetroReplicationSessionID: validSessionID}, nil)
				clientMock.On("EndMetroVolume", mock.Anything, validBaseVolID, mock.AnythingOfType("*gopowerstore.EndMetroVolumeOptions")).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.NewNotFoundError())

				req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure ending metro session on volume"))
			})

			ginkgo.It("should fail to delete the block metro volume if the volume info cannot be retrieved", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)

				// Return an 500 error when getting the volume
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusInternalServerError,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validMetroVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure getting volume"))
			})
		})

		ginkgo.When("deleting nfs volume", func() {
			ginkgo.It("should successfully delete nfs volume", func() {
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.FileSystem{}, nil)
				clientMock.On("DeleteFS",
					mock.Anything,
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})
		})

		ginkgo.When("volume id is not specified", func() {
			ginkgo.It("should fail", func() {
				req := &csi.DeleteVolumeRequest{}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume ID is required"))
			})
		})

		ginkgo.When("there is no array ip in volume id", func() {
			ginkgo.It("should check storage using default array [no volume found]", func() {
				clientMock.On("GetVolume", context.Background(), validBaseVolID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})
				clientMock.On("GetFS", context.Background(), validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})

			ginkgo.It("should check storage using default array [unexpected api error]", func() {
				e := errors.New("api-error")
				clientMock.On("GetVolume", context.Background(), validBaseVolID).
					Return(gopowerstore.Volume{}, e)
				clientMock.On("GetFS", context.Background(), validBaseVolID).
					Return(gopowerstore.FileSystem{}, e)

				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure checking volume status"))
			})
		})

		ginkgo.When("when trying delete volume with existing snapshots", func() {
			ginkgo.It("should fail [NFS]", func() {
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.FileSystem{
						{
							ID:   "0",
							Name: "name",
						},
					}, nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("snapshots based on this volume still exist"))
			})
		})
		ginkgo.When("when trying delete volume with existing snapshots", func() {
			ginkgo.It("should fail [scsi]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
					gopowerstore.Volume{
						ID:   validBaseVolID,
						Name: "name",
						Size: validVolSize,
					}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{{ID: "snap-id-1"}, {ID: "snap-id-2"}}, nil)
				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("snapshots based on this volume still exist"))
			})
		})
		ginkgo.When("volume does not exist", func() {
			ginkgo.It("should succeed [Block]", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
				clientMock.On("DeleteVolume",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})

			ginkgo.It("should succeed [NFS]", func() {
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.FileSystem{}, nil)
				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, nil)
				clientMock.On("DeleteFS",
					mock.Anything,
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})
		})

		ginkgo.When("block volume still attached to host", func() {
			ginkgo.It("should fail", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
				clientMock.On("DeleteVolume",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume with ID '" + validBaseVolID + "' is still attached to host"))
			})
		})

		ginkgo.When("can not connect to API", func() {
			ginkgo.It("should fail [Block]", func() {
				e := errors.New("can't connect")
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, e)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.Volume{}, e)

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(e.Error()))
			})

			ginkgo.It("should fail [NFS]", func() {
				e := errors.New("can't connect")
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.FileSystem{}, e)

				req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure getting snapshot"))
			})
		})

		ginkgo.When("volume id contains unsupported protocol", func() {
			ginkgo.It("should fail", func() {
				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID + "/" + firstValidID + "/smb"}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't figure out protocol"))
			})
		})
	})

	ginkgo.Describe("calling CreateSnapshot()", func() {
		ginkgo.When("parameters are correct", func() {
			ginkgo.It("should successfully create new snapshot [Block]", func() {
				snapName := validSnapName
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
					gopowerstore.Volume{
						Name: "name",
						Size: validVolSize,
					}, nil)

				clientMock.On("GetVolumeByName", mock.Anything, validSnapName).Return(
					gopowerstore.Volume{}, errors.New("not nil"))

				clientMock.On("CreateSnapshot", mock.Anything, &gopowerstore.SnapshotCreate{
					Name:        &snapName,
					Description: nil,
				}, validBaseVolID).Return(gopowerstore.CreateResponse{ID: "new-snap-id"}, nil)

				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validBlockVolumeID,
					Name:           validSnapName,
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Snapshot.SnapshotId).To(gomega.Equal("new-snap-id/globalvolid1/scsi"))
				gomega.Expect(res.Snapshot.SizeBytes).To(gomega.Equal(int64(validVolSize)))
				gomega.Expect(res.Snapshot.SourceVolumeId).To(gomega.Equal(validBaseVolID))
			})

			ginkgo.It("should successfully create new snapshot [NFS]", func() {
				snapName := validSnapName
				clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(
					gopowerstore.FileSystem{
						Name:      "name",
						SizeTotal: validVolSize,
					}, nil)

				clientMock.On("GetFSByName", mock.Anything, validSnapName).Return(
					gopowerstore.FileSystem{}, errors.New("not nil"))

				clientMock.On("CreateFsSnapshot", mock.Anything, &gopowerstore.SnapshotFSCreate{
					Name:        snapName,
					Description: "",
				}, validBaseVolID).Return(gopowerstore.CreateResponse{ID: "new-snap-id"}, nil)

				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validNfsVolumeID,
					Name:           validSnapName,
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Snapshot.SnapshotId).To(gomega.Equal("new-snap-id/globalvolid2/nfs"))
				gomega.Expect(res.Snapshot.SizeBytes).To(gomega.Equal(int64(validVolSize - controller.ReservedSize)))
				gomega.Expect(res.Snapshot.SourceVolumeId).To(gomega.Equal(validBaseVolID))
			})
		})

		ginkgo.When("snapshot name already taken", func() {
			ginkgo.It("should fail [sourceVolumeId != snap.sourceVolumeId]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
					gopowerstore.Volume{
						Name: "name",
						Size: validVolSize,
					}, nil)

				clientMock.On("GetVolumeByName", mock.Anything, validSnapName).Return(
					gopowerstore.Volume{
						Name: validSnapName,
						ID:   "old-snap-id",
						Size: validVolSize,
						ProtectionData: gopowerstore.ProtectionData{
							SourceID: "some-random-id",
						},
					}, nil)

				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validBlockVolumeID,
					Name:           validSnapName,
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(fmt.Sprintf("snapshot with name '%s' exists, but SourceVolumeId %s doesn't match", "my-snap", validBaseVolID)))
			})

			ginkgo.It("should succeed [same sourceVolumeId]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
					gopowerstore.Volume{
						Name: "name",
						Size: validVolSize,
					}, nil)

				clientMock.On("GetVolumeByName", mock.Anything, validSnapName).Return(
					gopowerstore.Volume{
						Name: validSnapName,
						ID:   "old-snap-id",
						Size: validVolSize,
						ProtectionData: gopowerstore.ProtectionData{
							SourceID: validBaseVolID,
						},
					}, nil)

				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validBlockVolumeID,
					Name:           validSnapName,
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Snapshot.SnapshotId).To(gomega.Equal("old-snap-id/globalvolid1/scsi"))
				gomega.Expect(res.Snapshot.SizeBytes).To(gomega.Equal(int64(validVolSize)))
				gomega.Expect(res.Snapshot.SourceVolumeId).To(gomega.Equal(validBaseVolID))
			})
		})

		ginkgo.When("there is an API error when creating snapshot", func() {
			ginkgo.It("should return that error", func() {
				snapName := validSnapName
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
					gopowerstore.Volume{
						Name: "name",
						Size: validVolSize,
					}, nil)

				clientMock.On("GetVolumeByName", mock.Anything, validSnapName).Return(
					gopowerstore.Volume{}, errors.New("not nil"))

				clientMock.On("CreateSnapshot", mock.Anything, &gopowerstore.SnapshotCreate{
					Name:        &snapName,
					Description: nil,
				}, validBaseVolID).Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusGatewayTimeout,
						Message:    "something went wrong",
					},
				})

				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validBlockVolumeID,
					Name:           validSnapName,
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("something went wrong"))
			})
		})
	})

	ginkgo.Describe("calling DeleteSnapshot()", func() {
		ginkgo.When("parameters are correct", func() {
			ginkgo.It("should successfully delete snapshot [Block]", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, Name: validVolumeGroupName}}}, nil)
				clientMock.On("DeleteVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("DeleteSnapshot", mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"), validBaseVolID).Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validBlockVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteSnapshotResponse{}))
			})

			ginkgo.It("should successfully delete snapshot [NFS]", func() {
				clientMock.On("GetFsSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{}, nil)

				clientMock.On("DeleteFsSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validNfsVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteSnapshotResponse{}))
			})
		})

		ginkgo.When("there is no snapshot", func() {
			ginkgo.It("should return no error [Block]", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, "").
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{}}, nil)
				clientMock.On("DeleteVolumeGroup", mock.Anything, "").Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("DeleteSnapshot", mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"), validBaseVolID).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				})

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validBlockVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteSnapshotResponse{}))
			})

			ginkgo.It("should return no error [NFS]", func() {
				clientMock.On("GetFsSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{}, nil)

				clientMock.On("DeleteFsSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				})

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validNfsVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteSnapshotResponse{}))
			})
		})

		ginkgo.When("there is no such source volume", func() {
			ginkgo.It("should return no error", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				})
				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validBlockVolumeID,
				}

				_, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
			})
		})
	})

	ginkgo.Describe("calling ControllerExpandVolume()", func() {
		ginkgo.When("expanding scsi volume", func() {
			ginkgo.It("should successfully expand scsi volume", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					Size: validVolSize,
				}, nil)
				clientMock.On("ModifyVolume",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeModify"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := getTypicalControllerExpandRequest(validBlockVolumeID, validVolSize*2)

				res, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerExpandVolumeResponse{
					CapacityBytes:         validVolSize * 2,
					NodeExpansionRequired: true,
				}))
			})

			ginkgo.When("not able to get volume info", func() {
				ginkgo.It("should fail", func() {
					e := errors.New("some-api-error")
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, e)

					req := getTypicalControllerExpandRequest(validBlockVolumeID, validVolSize*2)
					_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring("detected SCSI protocol but wasn't able to fetch the volume info"))
				})
			})

			ginkgo.When("not able to modify volume", func() {
				ginkgo.It("should fail", func() {
					e := errors.New("some-api-error")
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
						Size: validVolSize,
					}, nil)
					clientMock.On("ModifyVolume",
						mock.Anything,
						mock.AnythingOfType("*gopowerstore.VolumeModify"),
						validBaseVolID).
						Return(gopowerstore.EmptyResponse(""), e)

					req := getTypicalControllerExpandRequest(validBlockVolumeID, validVolSize*2)

					_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(e.Error()))
				})
			})
		})

		ginkgo.When("expanding nfs volume", func() {
			ginkgo.It("should successfully expand nfs volume", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{
					SizeTotal: validVolSize,
				}, nil)
				clientMock.On("ModifyFS",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.FSModify"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := getTypicalControllerExpandRequest(validNfsVolumeID, validVolSize*2)

				res, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerExpandVolumeResponse{
					CapacityBytes:         validVolSize * 2,
					NodeExpansionRequired: false,
				}))
			})

			ginkgo.When("not able to modify filesystem", func() {
				ginkgo.It("should fail", func() {
					e := errors.New("some-api-error")
					clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{
						SizeTotal: validVolSize,
					}, nil)
					clientMock.On("ModifyFS",
						mock.Anything,
						mock.AnythingOfType("*gopowerstore.FSModify"),
						validBaseVolID).
						Return(gopowerstore.EmptyResponse(""), e)

					req := getTypicalControllerExpandRequest(validNfsVolumeID, validVolSize*2)

					_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(e.Error()))
				})
			})
		})

		ginkgo.When("volume id is incorrect", func() {
			ginkgo.It("should fail", func() {
				e := errors.New("api-error")
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, e)
				clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{}, e)

				req := getTypicalControllerExpandRequest(validBaseVolID, validVolSize*2)

				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to parse the volume id"))
			})
		})

		ginkgo.When("requested size exceeds limit", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalControllerExpandRequest(validBlockVolumeID, controller.MaxVolumeSizeBytes+1)

				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume exceeds allowed limit"))
			})
		})
	})

	ginkgo.Describe("calling ControllerPublishVolume()", func() {
		fsName := "testFS"
		nfsID := "1ae5edac1-a796-886a-47dc-c72a3j8clw031"
		nasID := "some-nas-id"
		interfaceID := "215as1223-d124-ss1h-njh4-c72a3j8clw031"

		ginkgo.When("parameters are correct", func() {
			ginkgo.It("should succeed [Block]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

				clientMock.On("GetHostByName", mock.Anything, validNodeID).Return(gopowerstore.Host{ID: validHostID}, nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{}, nil).Once()

				clientMock.On("AttachVolumeToHost", mock.Anything, validHostID, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil).Once()

				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
					}, nil)
				clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
					}, nil)
				clientMock.On("GetFCPorts", mock.Anything).
					Return([]gopowerstore.FcPort{
						{
							IsLinkUp: true,
							Wwn:      "58:cc:f0:93:48:a0:03:a3",
							WwnNVMe:  "58ccf091492b0c22",
							WwnNode:  "58ccf090c9200c22",
						},
					}, nil)

				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{Name: validClusterName, NVMeNQN: "nqn"}, nil)

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"PORTAL0":        "192.168.1.1:3260",
						"TARGET0":        "iqn",
						"NVMEFCPORTAL0":  "nn-0x58ccf090c9200c22:pn-0x58ccf091492b0c22",
						"NVMEFCTARGET0":  "nqn",
						"DEVICE_WWN":     "68ccf098003ceb5e4577a20be6d11bf9",
						"LUN_ADDRESS":    "1",
						"FCWWPN0":        "58ccf09348a003a3",
						"NVMETCPTARGET0": "nqn",
						"NVMETCPPORTAL0": "192.168.1.1:4420",
					},
				}))
			})

			ginkgo.It("should succeed [NFS]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID:          validBaseVolID,
						Name:        fsName,
						NasServerID: nasID,
					}, nil)

				apiError := gopowerstore.NewAPIError()
				apiError.StatusCode = http.StatusNotFound

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
					Return(gopowerstore.NFSExport{}, *apiError).Once()

				nfsExportCreate := &gopowerstore.NFSExportCreate{
					Name:         fsName,
					FileSystemID: validBaseVolID,
					Path:         "/" + fsName,
				}
				clientMock.On("CreateNFSExport", mock.Anything, nfsExportCreate).
					Return(gopowerstore.CreateResponse{ID: nfsID}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
					Return(gopowerstore.NFSExport{ID: nfsID}, nil).Once()

				clientMock.On("ModifyNFSExport", mock.Anything, &gopowerstore.NFSExportModify{
					AddRWRootHosts: []string{"127.0.0.1"},
				}, nfsID).Return(gopowerstore.CreateResponse{}, nil)

				clientMock.On("GetNAS", mock.Anything, nasID).
					Return(gopowerstore.NAS{
						Name:                            validNasName,
						CurrentPreferredIPv4InterfaceID: interfaceID,
					}, nil)

				clientMock.On("GetFileInterface", mock.Anything, interfaceID).
					Return(gopowerstore.FileInterface{IPAddress: secondValidID}, nil)

				req := getTypicalControllerPublishVolumeRequest("multiple-writer", validNodeID, validNfsVolumeID)
				req.VolumeCapability = getVolumeCapabilityNFS()
				req.VolumeContext = map[string]string{controller.KeyFsType: "nfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"nasName":       validNasName,
						"NfsExportPath": secondValidID + ":/",
						"ExportID":      nfsID,
						"allowRoot":     "",
						"HostIP":        "127.0.0.1",
						"nfsAcls":       "",
					},
				}))
			})
			ginkgo.It("should succeed [NFS] with externalAccess", func() {
				// setting externalAccess environment variable
				err := csictx.Setenv(context.Background(), common.EnvExternalAccess, "10.0.0.0/24")
				gomega.Expect(err).To(gomega.BeNil())
				_ = ctrlSvc.Init()

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID:          validBaseVolID,
						Name:        fsName,
						NasServerID: nasID,
					}, nil)

				apiError := gopowerstore.NewAPIError()
				apiError.StatusCode = http.StatusNotFound

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
					Return(gopowerstore.NFSExport{}, *apiError).Once()

				nfsExportCreate := &gopowerstore.NFSExportCreate{
					Name:         fsName,
					FileSystemID: validBaseVolID,
					Path:         "/" + fsName,
				}
				clientMock.On("CreateNFSExport", mock.Anything, nfsExportCreate).
					Return(gopowerstore.CreateResponse{ID: nfsID}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
					Return(gopowerstore.NFSExport{ID: nfsID}, nil).Once()

				clientMock.On("ModifyNFSExport", mock.Anything, &gopowerstore.NFSExportModify{
					AddRWRootHosts: []string{
						"127.0.0.1",
						"10.0.0.0/255.255.255.0",
					},
				}, nfsID).Return(gopowerstore.CreateResponse{}, nil)

				clientMock.On("GetNAS", mock.Anything, nasID).
					Return(gopowerstore.NAS{
						Name:                            validNasName,
						CurrentPreferredIPv4InterfaceID: interfaceID,
					}, nil)

				clientMock.On("GetFileInterface", mock.Anything, interfaceID).
					Return(gopowerstore.FileInterface{IPAddress: secondValidID}, nil)

				req := getTypicalControllerPublishVolumeRequest("multiple-writer", validNodeID, validNfsVolumeID)
				req.VolumeCapability = getVolumeCapabilityNFS()
				req.VolumeContext = map[string]string{controller.KeyFsType: "nfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						common.KeyNasName:       validNasName,
						common.KeyNfsExportPath: secondValidID + ":/",
						common.KeyExportID:      nfsID,
						common.KeyAllowRoot:     "",
						common.KeyHostIP:        "127.0.0.1",
						common.KeyNfsACL:        "",
						common.KeyNatIP:         "10.0.0.0/255.255.255.0",
					},
				}))
				// Removing externalAccess environment variable after our tests are completed
				err = csictx.Setenv(context.Background(), common.EnvExternalAccess, "")
				gomega.Expect(err).To(gomega.BeNil())
				_ = ctrlSvc.Init()
			})
		})

		ginkgo.When("host name does not contain ip", func() {
			ginkgo.It("should truncate ip from kubeID and succeed [Block]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

				ginkgo.By("truncating ip", func() {
					clientMock.On("GetHostByName", mock.Anything, validNodeID).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
							},
						}).Once()

					clientMock.On("GetHostByName", mock.Anything, validHostName).
						Return(gopowerstore.Host{ID: validHostID}, nil).Once()
				})

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{}, nil).Once()

				clientMock.On("AttachVolumeToHost", mock.Anything, validHostID, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil).Once()

				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
					}, nil)
				clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
					}, nil)
				clientMock.On("GetFCPorts", mock.Anything).
					Return([]gopowerstore.FcPort{
						{
							Wwn: "58:cc:f0:93:48:a0:03:a3",
						},
					}, nil)

				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{Name: validClusterName}, nil)

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"PORTAL0":        "192.168.1.1:3260",
						"TARGET0":        "iqn",
						"DEVICE_WWN":     "68ccf098003ceb5e4577a20be6d11bf9",
						"LUN_ADDRESS":    "1",
						"NVMETCPPORTAL0": "192.168.1.1:4420",
						"NVMETCPTARGET0": "",
					},
				}))
			})
		})

		ginkgo.When("using nfs nat feature", func() {
			ginkgo.It("should succeed", func() {
				externalAccess := "10.0.0.1"
				_ = csictx.Setenv(context.Background(), common.EnvExternalAccess, externalAccess)
				_ = ctrlSvc.Init()

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID:          validBaseVolID,
						Name:        fsName,
						NasServerID: nasID,
					}, nil)

				apiError := gopowerstore.NewAPIError()
				apiError.StatusCode = http.StatusNotFound

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
					Return(gopowerstore.NFSExport{}, *apiError).Once()

				nfsExportCreate := &gopowerstore.NFSExportCreate{
					Name:         fsName,
					FileSystemID: validBaseVolID,
					Path:         "/" + fsName,
				}
				clientMock.On("CreateNFSExport", mock.Anything, nfsExportCreate).
					Return(gopowerstore.CreateResponse{ID: nfsID}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
					Return(gopowerstore.NFSExport{ID: nfsID}, nil).Once()

				clientMock.On("ModifyNFSExport", mock.Anything, &gopowerstore.NFSExportModify{
					AddRWRootHosts: []string{"127.0.0.1", externalAccess},
				}, nfsID).Return(gopowerstore.CreateResponse{}, nil)

				clientMock.On("GetNAS", mock.Anything, nasID).
					Return(gopowerstore.NAS{
						Name:                            validNasName,
						CurrentPreferredIPv4InterfaceID: interfaceID,
					}, nil)

				clientMock.On("GetFileInterface", mock.Anything, interfaceID).
					Return(gopowerstore.FileInterface{IPAddress: secondValidID}, nil)

				req := getTypicalControllerPublishVolumeRequest("multi-writer", validNodeID, validNfsVolumeID)
				req.VolumeCapability = getVolumeCapabilityNFS()
				req.VolumeContext = map[string]string{controller.KeyFsType: "nfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"nasName":       validNasName,
						"NfsExportPath": secondValidID + ":/",
						"ExportID":      nfsID,
						"allowRoot":     "",
						"HostIP":        "127.0.0.1",
						"NatIP":         "10.0.0.1",
						"nfsAcls":       "",
					},
				}))
			})
		})

		ginkgo.When("volume is already attached to some host", func() {
			ginkgo.When("mapping has same hostID", func() {
				ginkgo.It("should succeed", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

					clientMock.On("GetHostByName", mock.Anything, validNodeID).Return(gopowerstore.Host{ID: validHostID}, nil)

					clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
						Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil).Once()

					clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
						Return([]gopowerstore.IPPoolAddress{
							{
								Address: "192.168.1.1",
								IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
							},
						}, nil)
					clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
						Return([]gopowerstore.IPPoolAddress{
							{
								Address: "192.168.1.1",
								IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
							},
						}, nil)
					clientMock.On("GetFCPorts", mock.Anything).
						Return([]gopowerstore.FcPort{
							{
								Wwn: "58:cc:f0:93:48:a0:03:a3",
							},
						}, nil)

					clientMock.On("GetCluster", mock.Anything).
						Return(gopowerstore.Cluster{Name: validClusterName}, nil)

					req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
					req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

					res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.ControllerPublishVolumeResponse{
						PublishContext: map[string]string{
							"PORTAL0":        "192.168.1.1:3260",
							"TARGET0":        "iqn",
							"DEVICE_WWN":     "68ccf098003ceb5e4577a20be6d11bf9",
							"LUN_ADDRESS":    "1",
							"NVMETCPPORTAL0": "192.168.1.1:4420",
							"NVMETCPTARGET0": "",
						},
					}))
				})
			})

			ginkgo.When("mapping hostID is different", func() {
				prevNodeID := "prev-id"
				ginkgo.It("should fail [single-writer]", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

					clientMock.On("GetHostByName", mock.Anything, validNodeID).Return(gopowerstore.Host{ID: validHostID}, nil)

					clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
						Return([]gopowerstore.HostVolumeMapping{{HostID: prevNodeID, LogicalUnitNumber: 1}}, nil).Once()

					clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
						Return([]gopowerstore.IPPoolAddress{
							{
								Address: "192.168.1.1",
								IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
							},
						}, nil)
					clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
						Return([]gopowerstore.IPPoolAddress{
							{
								Address: "192.168.1.1",
								IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
							},
						}, nil)
					clientMock.On("GetFCPorts", mock.Anything).
						Return([]gopowerstore.FcPort{
							{
								Wwn: "58:cc:f0:93:48:a0:03:a3",
							},
						}, nil)

					clientMock.On("GetCluster", mock.Anything).
						Return(gopowerstore.Cluster{Name: validClusterName}, nil)

					req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
					req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

					res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(
						fmt.Sprintf("volume already present in a different lun mapping on node '%s", prevNodeID)))
				})

				ginkgo.It("should succeed [multi-writer]", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

					clientMock.On("GetHostByName", mock.Anything, validNodeID).Return(gopowerstore.Host{ID: validHostID}, nil)

					clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
						Return([]gopowerstore.HostVolumeMapping{{HostID: prevNodeID, LogicalUnitNumber: 1}}, nil).Once()

					clientMock.On("AttachVolumeToHost", mock.Anything, validHostID, mock.Anything).
						Return(gopowerstore.EmptyResponse(""), nil)

					clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
						Return([]gopowerstore.HostVolumeMapping{
							{HostID: prevNodeID, LogicalUnitNumber: 1},
							{HostID: validHostID, LogicalUnitNumber: 2},
						}, nil).Once()

					clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
						Return([]gopowerstore.IPPoolAddress{
							{
								Address: "192.168.1.1",
								IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
							},
						}, nil)
					clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
						Return([]gopowerstore.IPPoolAddress{
							{
								Address: "192.168.1.1",
								IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
							},
						}, nil)
					clientMock.On("GetFCPorts", mock.Anything).
						Return([]gopowerstore.FcPort{
							{
								Wwn: "58:cc:f0:93:48:a0:03:a3",
							},
						}, nil)

					clientMock.On("GetCluster", mock.Anything).
						Return(gopowerstore.Cluster{Name: validClusterName}, nil)

					req := getTypicalControllerPublishVolumeRequest("multiple-writer", validNodeID, validBlockVolumeID)
					req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

					res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.ControllerPublishVolumeResponse{
						PublishContext: map[string]string{
							"PORTAL0":        "192.168.1.1:3260",
							"TARGET0":        "iqn",
							"DEVICE_WWN":     "68ccf098003ceb5e4577a20be6d11bf9",
							"LUN_ADDRESS":    "2",
							"NVMETCPPORTAL0": "192.168.1.1:4420",
							"NVMETCPTARGET0": "",
						},
					}))
				})
			})
		})

		ginkgo.When("publishing metro volume", func() {
			ginkgo.It("should succeed [Block]", func() {
				// local info
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9", ApplianceID: validApplianceID}, nil)
				clientMock.On("GetHostByName", mock.Anything, validNodeID).Return(gopowerstore.Host{ID: validHostID}, nil)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{}, nil).Once()
				clientMock.On("AttachVolumeToHost", mock.Anything, validHostID, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil).Times(2)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil).Once()
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address:     "192.168.1.1",
							IPPort:      gopowerstore.IPPortInstance{TargetIqn: "iqn"},
							ApplianceID: validApplianceID,
						},
					}, nil).Once()
				clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address:     "192.168.1.1",
							IPPort:      gopowerstore.IPPortInstance{TargetIqn: "iqn"},
							ApplianceID: validApplianceID,
						},
					}, nil).Times(2)
				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{Name: validClusterName, NVMeNQN: "nqn"}, nil).Times(2)
				clientMock.On("GetFCPorts", mock.Anything).
					Return([]gopowerstore.FcPort{
						{
							IsLinkUp:    true,
							Wwn:         "58:cc:f0:93:48:a0:03:a3",
							WwnNVMe:     "58ccf091492b0c22",
							WwnNode:     "58ccf090c9200c22",
							ApplianceID: validApplianceID,
						},
					}, nil).Times(2)

				// remote info
				clientMock.On("GetVolume", mock.Anything, validRemoteVolID).
					Return(gopowerstore.Volume{ID: validRemoteVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9", ApplianceID: validRemoteApplianceID}, nil)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validRemoteVolID).
					Return([]gopowerstore.HostVolumeMapping{}, nil).Once()
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validRemoteVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil).Once()
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address:     "192.168.1.2",
							IPPort:      gopowerstore.IPPortInstance{TargetIqn: "iqn.2015-10.com.dell:dellemc-powerstore-apm00223"},
							ApplianceID: validRemoteApplianceID,
						},
					}, nil).Once()
				clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address:     "192.168.1.2",
							IPPort:      gopowerstore.IPPortInstance{TargetIqn: "iqn.2015-10.com.dell:dellemc-powerstore-apm00223"},
							ApplianceID: validRemoteApplianceID,
						},
					}, nil).Times(2)
				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{Name: validClusterName, NVMeNQN: "nqn.1988-11.com.dell:powerstore:00:303030303030ABCDEFGH"}, nil).Times(2)
				clientMock.On("GetFCPorts", mock.Anything).
					Return([]gopowerstore.FcPort{
						{
							IsLinkUp:    true,
							Wwn:         "58:cc:f0:93:48:a0:03:33",
							WwnNVMe:     "58ccf091492b0c33",
							WwnNode:     "58ccf090c9200c33",
							ApplianceID: validRemoteApplianceID,
						},
					}, nil).Times(2)

				volumeID := fmt.Sprintf("%s/%s/%s:%s/%s", validBaseVolID, firstValidID, "scsi", validRemoteVolID, secondValidID)
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, volumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"PORTAL0":              "192.168.1.1:3260",
						"TARGET0":              "iqn",
						"NVMEFCPORTAL0":        "nn-0x58ccf090c9200c22:pn-0x58ccf091492b0c22",
						"NVMEFCTARGET0":        "nqn",
						"DEVICE_WWN":           "68ccf098003ceb5e4577a20be6d11bf9",
						"LUN_ADDRESS":          "1",
						"FCWWPN0":              "58ccf09348a003a3",
						"NVMETCPTARGET0":       "nqn",
						"NVMETCPPORTAL0":       "192.168.1.1:4420",
						"REMOTE_DEVICE_WWN":    "68ccf098003ceb5e4577a20be6d11bf9",
						"REMOTE_LUN_ADDRESS":   "1",
						"REMOTE_FCWWPN0":       "58ccf09348a00333",
						"REMOTE_TARGET0":       "iqn.2015-10.com.dell:dellemc-powerstore-apm00223",
						"REMOTE_NVMEFCTARGET0": "nqn.1988-11.com.dell:powerstore:00:303030303030ABCDEFGH",
						"REMOTE_PORTAL0":       "192.168.1.2:3260",
						"REMOTE_NVMEFCPORTAL0": "nn-0x58ccf090c9200c33:pn-0x58ccf091492b0c33",
					},
				}))
			})

			ginkgo.It("should fail", func() {
				ip := "127.0.0.1" // we don't have array with this IP
				volumeID := fmt.Sprintf("%s/%s/%s:%s/%s", validBaseVolID, firstValidID, "scsi", validRemoteVolID, ip)
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, volumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}
				req.VolumeCapability = nil

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find remote array with ID"))
			})
		})

		ginkgo.When("volume id is empty", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.VolumeId = ""

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume ID is required"))
			})
		})

		ginkgo.When("volume capability is missing", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.VolumeCapability = nil

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume capability is required"))
			})
		})

		ginkgo.When("access mode is missing", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.VolumeCapability.AccessMode = nil

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("access mode is required"))
			})
		})

		ginkgo.When("access mode is unknown", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.VolumeCapability.AccessMode.Mode = csi.VolumeCapability_AccessMode_UNKNOWN

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(controller.ErrUnknownAccessMode))
			})
		})

		ginkgo.When("kube node id is empty", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.NodeId = ""

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("node ID is required"))
			})
		})

		ginkgo.When("volume does not exist", func() {
			ginkgo.It("should fail [Block]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(fmt.Sprintf("volume with ID '%s' not found", validBaseVolID)))
			})

			ginkgo.It("should fail [NFS]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validNfsVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(fmt.Sprintf("volume with ID '%s' not found", validBaseVolID)))
			})

			ginkgo.When("using v1.2 volume id", func() {
				ginkgo.It("should fail", func() {
					e := errors.New("api-error")
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, e)
					clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{}, e)

					req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBaseVolID)
					req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}
					req.VolumeCapability = nil

					_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure checking volume status"))
				})
			})
		})

		ginkgo.When("node id is not valid", func() {
			ginkgo.It("should fail [Block]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

				clientMock.On("GetHostByName", mock.Anything, validNodeID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					}).Once()

				clientMock.On("GetHostByName", mock.Anything, validHostName).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					}).Once()

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("host with k8s node ID '" + validNodeID + "' not found"))
			})
		})

		ginkgo.When("ip is incorrect", func() {
			ginkgo.It("should fail", func() {
				ip := "127.0.0.1" // we don't have array with this ip
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID,
					validBaseVolID+"/"+ip+"/scsi")
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}
				req.VolumeCapability = nil

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find array with ID"))
			})
		})
	})

	ginkgo.Describe("calling ControllerUnpublishVolume()", func() {
		ginkgo.When("parameters are correct", func() {
			ginkgo.It("should succeed [Block]", func() {
				clientMock.On("GetHostByName", mock.Anything, validNodeID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					}).Once()

				clientMock.On("GetHostByName", mock.Anything, validHostName).
					Return(gopowerstore.Host{ID: validHostID}, nil).Once()

				clientMock.On("DetachVolumeFromHost", mock.Anything, validHostID, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})

			ginkgo.It("should succeed [NFS]", func() {
				exportID := "some-export-id"

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID: validBaseVolID,
					}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{ID: exportID}, nil)

				clientMock.On("ModifyNFSExport", mock.Anything,
					mock.Anything, exportID).Return(gopowerstore.CreateResponse{}, nil)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})

			ginkgo.It("should succeed [NFS] with external access", func() {
				// setting externalAccess environment variable
				err := csictx.Setenv(context.Background(), common.EnvExternalAccess, "10.0.0.0/24")
				gomega.Expect(err).To(gomega.BeNil())
				_ = ctrlSvc.Init()

				exportID := "some-export-id"

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID: validBaseVolID,
					}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{
						ID:          exportID,
						RWRootHosts: []string{"127.0.0.1", "10.0.0.0/255.255.255.0"},
						RWHosts:     []string{"127.0.0.1", "10.0.0.0/255.255.255.0"},
					}, nil)

				clientMock.On("ModifyNFSExport", mock.Anything,
					mock.Anything, exportID).Return(gopowerstore.CreateResponse{}, nil)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerUnpublishVolumeResponse{}))

				// setting externalAccess environment variable
				err = csictx.Setenv(context.Background(), common.EnvExternalAccess, "")
				gomega.Expect(err).To(gomega.BeNil())
				_ = ctrlSvc.Init()
			})
		})

		ginkgo.It("should succeed [NFS] by removing external access from the HostAccessList", func() {
			// setting externalAccess environment variable
			err := csictx.Setenv(context.Background(), common.EnvExternalAccess, "10.0.0.0/16")
			gomega.Expect(err).To(gomega.BeNil())
			_ = ctrlSvc.Init()
			clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.FileSystem{}, nil)

			exportID := "some-export-id"

			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{
					ID: validBaseVolID,
				}, nil)

			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
				Return(gopowerstore.NFSExport{
					ID:          exportID,
					RWRootHosts: []string{"10.0.0.0/255.255.0.0"},
				}, nil)

			clientMock.On("ModifyNFSExport", mock.Anything,
				mock.Anything, exportID).Return(gopowerstore.CreateResponse{}, nil)

			clientMock.On("DeleteFS",
				mock.Anything,
				validBaseVolID).
				Return(gopowerstore.EmptyResponse(""), nil)
			req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

			res, err := ctrlSvc.DeleteVolume(context.Background(), req)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))

			// setting externalAccess environment variable
			err = csictx.Setenv(context.Background(), common.EnvExternalAccess, "")

			gomega.Expect(err).To(gomega.BeNil())
			_ = ctrlSvc.Init()
		})

		ginkgo.It("should return error since HostAccessList contain external as well as Host IP too", func() {
			// setting externalAccess environment variable
			err := csictx.Setenv(context.Background(), common.EnvExternalAccess, "10.0.0.0/16")
			gomega.Expect(err).To(gomega.BeNil())
			_ = ctrlSvc.Init()
			clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.FileSystem{}, nil)

			exportID := "some-export-id"

			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{
					ID: validBaseVolID,
				}, nil)

			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
				Return(gopowerstore.NFSExport{
					ID:          exportID,
					RWRootHosts: []string{"10.0.0.0/255.255.0.0", "10.225.0.0/255.255.255.255"},
				}, nil)

			req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

			_, err = ctrlSvc.DeleteVolume(context.Background(), req)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("cannot be deleted as it has associated NFS or SMB shares"))
			// setting externalAccess environment variable
			err = csictx.Setenv(context.Background(), common.EnvExternalAccess, "")

			gomega.Expect(err).To(gomega.BeNil())
			_ = ctrlSvc.Init()
		})

		ginkgo.When("unpublishing metro volume", func() {
			ginkgo.It("should succeed [Block]", func() {
				clientMock.On("GetHostByName", mock.Anything, mock.Anything).
					Return(gopowerstore.Host{ID: validHostID}, nil).Times(2)
				clientMock.On("DetachVolumeFromHost", mock.Anything, mock.Anything, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil).Times(2)

				volumeID := fmt.Sprintf("%s/%s/%s:%s/%s", validBaseVolID, firstValidID, "scsi", validRemoteVolID, secondValidID)
				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: volumeID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})

			ginkgo.It("should fail", func() {
				ip := "127.0.0.1" // we don't have array with this IP
				volumeID := fmt.Sprintf("%s/%s/%s:%s/%s", validBaseVolID, firstValidID, "scsi", validRemoteVolID, ip)
				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: volumeID, NodeId: validNodeID}

				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("cannot find remote array"))
			})
		})

		ginkgo.When("volume do not exist", func() {
			ginkgo.It("should succeed", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})
		})

		ginkgo.When("volume id is empty", func() {
			ginkgo.It("should fail", func() {
				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: "", NodeId: validNodeID}

				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume ID is required"))
			})
		})

		ginkgo.When("volume id has wrong array id", func() {
			ginkgo.It("should fail", func() {
				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: invalidBlockVolumeID, NodeId: validNodeID}

				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("cannot find array"))
			})
		})

		ginkgo.When("node id is empty", func() {
			ginkgo.It("should fail", func() {
				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: ""}

				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("node ID is required"))
			})
		})

		ginkgo.When("using v1.2 volumes", func() {
			ginkgo.It("should succeed [Block]", func() {
				ginkgo.By("using default array", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{}, nil)
				})

				clientMock.On("GetHostByName", mock.Anything, validNodeID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					}).Once()

				clientMock.On("GetHostByName", mock.Anything, validHostName).
					Return(gopowerstore.Host{ID: validHostID}, nil).Once()

				clientMock.On("DetachVolumeFromHost", mock.Anything, validHostID, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBaseVolID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})

			ginkgo.It("should succeed [NFS]", func() {
				ginkgo.By("using default array", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
							},
						})

					clientMock.On("GetFS", mock.Anything, validBaseVolID).
						Return(gopowerstore.FileSystem{}, nil).Once()
				})

				exportID := "some-export-id"

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID: validBaseVolID,
					}, nil).Once()

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{ID: exportID}, nil)

				clientMock.On("ModifyNFSExport", mock.Anything,
					mock.Anything, exportID).Return(gopowerstore.CreateResponse{}, nil)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBaseVolID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})

			ginkgo.When("volume does not exist", func() {
				ginkgo.It("should succeed", func() {
					ginkgo.By("not finding volume or filesystem", func() {
						clientMock.On("GetVolume", mock.Anything, validBaseVolID).
							Return(gopowerstore.Volume{}, gopowerstore.APIError{
								ErrorMsg: &api.ErrorMsg{
									StatusCode: http.StatusNotFound,
								},
							})

						clientMock.On("GetFS", mock.Anything, validBaseVolID).
							Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
								ErrorMsg: &api.ErrorMsg{
									StatusCode: http.StatusNotFound,
								},
							}).Once()
					})

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBaseVolID, NodeId: validNodeID}

					res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)

					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.ControllerUnpublishVolumeResponse{}))
				})
			})
		})

		ginkgo.When("kube node id is not correct", func() {
			ginkgo.When("no IP found", func() {
				ginkgo.It("should fail [Block]", func() {
					nodeID := "not-valid-id"
					clientMock.On("GetHostByName", mock.Anything, nodeID).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
							},
						}).Once()

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: nodeID}

					_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find IP in nodeID"))
				})

				ginkgo.It("should fail [NFS]", func() {
					nodeID := "not-valid-id"
					clientMock.On("GetFS", mock.Anything, validBaseVolID).
						Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: nodeID}

					_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find IP in nodeID"))
				})
			})

			ginkgo.When("host does not exist", func() {
				ginkgo.It("should fail", func() {
					clientMock.On("GetHostByName", mock.Anything, validNodeID).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
							},
						}).Once()

					clientMock.On("GetHostByName", mock.Anything, validHostName).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
							},
						}).Once()

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: validNodeID}

					_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring("host with k8s node ID '" + validNodeID + "' not found"))
				})
			})

			ginkgo.When("fail to check host", func() {
				ginkgo.It("should fail", func() {
					e := errors.New("some-api-error")
					clientMock.On("GetHostByName", mock.Anything, validNodeID).
						Return(gopowerstore.Host{}, e).Once()

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: validNodeID}

					_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure checking host '" + validNodeID + "' status for volume unpublishing"))
				})
			})
		})

		ginkgo.When("can not check nfs export status", func() {
			ginkgo.It("should fail", func() {
				e := errors.New("some-api-error")
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID: validBaseVolID,
					}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, e)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: validNodeID}
				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure checking nfs export status for volume unpublishing"))
			})
		})

		ginkgo.When("failed to remove hosts", func() {
			ginkgo.It("should fail", func() {
				exportID := "some-export-id"
				e := errors.New("some-api-error")

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID: validBaseVolID,
					}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{ID: exportID}, nil)

				clientMock.On("ModifyNFSExport", mock.Anything,
					mock.Anything, exportID).Return(gopowerstore.CreateResponse{}, e)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: validNodeID}
				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure when removing new host to nfs export"))
			})
		})
	})

	ginkgo.Describe("calling ListVolumes()", func() {
		mockCalls := func() {
			clientMock.On("GetVolumes", mock.Anything).
				Return([]gopowerstore.Volume{
					{
						ID:   "arr1-id1",
						Name: "arr1-vol1",
					},
					{
						ID:   "arr1-id2",
						Name: "arr1-vol2",
					},
				}, nil).Once()
			clientMock.On("GetVolumes", mock.Anything).
				Return([]gopowerstore.Volume{
					{
						ID:   "arr2-id1",
						Name: "arr2-vol1",
					},
				}, nil).Once()
		}

		ginkgo.When("there is no parameters", func() {
			ginkgo.It("should return all volumes from both arrays", func() {
				mockCalls()

				req := &csi.ListVolumesRequest{}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				gomega.Expect(res).To(gomega.Equal(&csi.ListVolumesResponse{
					Entries: []*csi.ListVolumesResponse_Entry{
						{
							Volume: &csi.Volume{
								VolumeId: "arr1-id1",
							},
						},
						{
							Volume: &csi.Volume{
								VolumeId: "arr1-id2",
							},
						},
						{
							Volume: &csi.Volume{
								VolumeId: "arr2-id1",
							},
						},
					},
				}))
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("passing max entries", func() {
			ginkgo.It("should return 'n' entries and next token", func() {
				mockCalls()

				req := &csi.ListVolumesRequest{
					MaxEntries: 1,
				}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				gomega.Expect(res).To(gomega.Equal(&csi.ListVolumesResponse{
					Entries: []*csi.ListVolumesResponse_Entry{
						{
							Volume: &csi.Volume{
								VolumeId: "arr1-id1",
							},
						},
					},
					NextToken: "1",
				}))
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("using next token", func() {
			ginkgo.It("should return volumes starting from token", func() {
				mockCalls()

				req := &csi.ListVolumesRequest{
					MaxEntries:    1,
					StartingToken: "1",
				}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				gomega.Expect(res).To(gomega.Equal(&csi.ListVolumesResponse{
					Entries: []*csi.ListVolumesResponse_Entry{
						{
							Volume: &csi.Volume{
								VolumeId: "arr1-id2",
							},
						},
					},
					NextToken: "2",
				}))
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("using wrong token", func() {
			ginkgo.It("should fail [not parsable]", func() {
				token := "as!512$25%!_" // #nosec G101
				req := &csi.ListVolumesRequest{
					MaxEntries:    1,
					StartingToken: token,
				}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to parse StartingToken: %v into uint32", token))
			})

			ginkgo.It("shoud fail [too high]", func() {
				tokenInt := 200
				token := "200"

				mockCalls()

				req := &csi.ListVolumesRequest{
					MaxEntries:    1,
					StartingToken: token,
				}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("startingToken=%d > len(volumes)=%d", tokenInt, 3))
			})
		})
	})

	ginkgo.Describe("calling ListSnapshots()", func() {
		mockCalls := func() {
			clientMock.On("GetSnapshots", mock.Anything).
				Return([]gopowerstore.Volume{
					{
						ID:   "arr1-id1",
						Name: "arr1-snap1",
					},
					{
						ID:   "arr1-id2",
						Name: "arr1-snap2",
					},
				}, nil).Once()
			clientMock.On("GetFsSnapshots", mock.Anything).
				Return([]gopowerstore.FileSystem{
					{
						ID:   "arr1-id1-fs",
						Name: "arr1-snap1-fs",
					},
				}, nil).Once()
			clientMock.On("GetSnapshots", mock.Anything).
				Return([]gopowerstore.Volume{
					{
						ID:   "arr2-id1",
						Name: "arr2-snap1",
					},
				}, nil).Once()
			clientMock.On("GetFsSnapshots", mock.Anything).
				Return([]gopowerstore.FileSystem{
					{
						ID:   "arr2-id1-fs",
						Name: "arr2-snap1-fs",
					},
				}, nil).Once()
		}

		mockCantParseVolumeID := func(id string) {
			clientMock.On("GetVolume", mock.Anything, id).
				Return(gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				}).Once()

			clientMock.On("GetFS", mock.Anything, id).
				Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				}).Once()
		}

		ginkgo.When("there is no parameters", func() {
			ginkgo.It("should return all volumes from both arrays", func() {
				mockCalls()

				req := &csi.ListSnapshotsRequest{}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.Entries).ToNot(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(5))
				gomega.Expect(res.Entries[0].Snapshot.SnapshotId).To(gomega.Equal("arr1-id1"))
				gomega.Expect(res.Entries[1].Snapshot.SnapshotId).To(gomega.Equal("arr1-id2"))
				gomega.Expect(res.Entries[2].Snapshot.SnapshotId).To(gomega.Equal("arr1-id1-fs"))
				gomega.Expect(res.Entries[3].Snapshot.SnapshotId).To(gomega.Equal("arr2-id1"))
				gomega.Expect(res.Entries[4].Snapshot.SnapshotId).To(gomega.Equal("arr2-id1-fs"))
			})
		})

		ginkgo.When("passing max entries", func() {
			ginkgo.It("should return 'n' entries and next token", func() {
				mockCalls()

				req := &csi.ListSnapshotsRequest{
					MaxEntries: 1,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.Entries).ToNot(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(1))
				gomega.Expect(res.Entries[0].Snapshot.SnapshotId).To(gomega.Equal("arr1-id1"))
				gomega.Expect(res.NextToken).To(gomega.Equal("1"))
			})
		})

		ginkgo.When("using next token", func() {
			ginkgo.It("should return volumes starting from token", func() {
				mockCalls()

				req := &csi.ListSnapshotsRequest{
					MaxEntries:    1,
					StartingToken: "1",
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(res.Entries).ToNot(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(1))
				gomega.Expect(res.Entries[0].Snapshot.SnapshotId).To(gomega.Equal("arr1-id2"))
				gomega.Expect(res.NextToken).To(gomega.Equal("2"))
			})
		})

		ginkgo.When("using wrong token", func() {
			ginkgo.It("should fail [not parsable]", func() {
				token := "as!512$25%!_" // #nosec G101
				req := &csi.ListSnapshotsRequest{
					MaxEntries:    1,
					StartingToken: token,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to parse StartingToken: %v into uint32", token))
			})

			ginkgo.It("shoud fail [too high]", func() {
				tokenInt := 200
				token := "200"

				mockCalls()

				req := &csi.ListSnapshotsRequest{
					MaxEntries:    1,
					StartingToken: token,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("startingToken=%d > len(generalSnapshots)=%d", tokenInt, 5))
			})
		})

		ginkgo.When("passing snapshot id", func() {
			ginkgo.It("should return existing snapshot", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
				req := &csi.ListSnapshotsRequest{
					SnapshotId: validBlockVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(1))
				gomega.Expect(res.Entries[0].Snapshot.SnapshotId).To(gomega.Equal(validBlockVolumeID))
			})

			ginkgo.It("should return existing snapshot [NFS]", func() {
				clientMock.On("GetFsSnapshot", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)
				req := &csi.ListSnapshotsRequest{
					SnapshotId: validNfsVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(1))
				gomega.Expect(res.Entries[0].Snapshot.SnapshotId).To(gomega.Equal(validNfsVolumeID))
			})

			ginkgo.It("should fail [incorrect id]", func() {
				randomID := "something-random"

				ginkgo.By("checking with default array", func() {
					mockCantParseVolumeID(randomID)
				})

				req := &csi.ListSnapshotsRequest{
					SnapshotId: randomID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ListSnapshotsResponse{}))
			})
		})

		ginkgo.When("passing source volume id", func() {
			ginkgo.It("should return all snapshots of that volume", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.Volume{{ID: "snap-id-1"}, {ID: "snap-id-2"}}, nil)
				req := &csi.ListSnapshotsRequest{
					SourceVolumeId: validBlockVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(2))
				gomega.Expect(res.Entries[0].Snapshot.SnapshotId).To(gomega.Equal("snap-id-1"))
				gomega.Expect(res.Entries[1].Snapshot.SnapshotId).To(gomega.Equal("snap-id-2"))
			})

			ginkgo.It("should return all snapshots of the filesystem", func() {
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.FileSystem{{ID: "snap-id-1"}, {ID: "snap-id-2"}}, nil)
				req := &csi.ListSnapshotsRequest{
					SourceVolumeId: validNfsVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(2))
				gomega.Expect(res.Entries[0].Snapshot.SnapshotId).To(gomega.Equal("snap-id-1"))
				gomega.Expect(res.Entries[1].Snapshot.SnapshotId).To(gomega.Equal("snap-id-2"))
			})

			ginkgo.It("should fail [incorrect id]", func() {
				randomID := "something-random"

				ginkgo.By("checking with default array", func() {
					mockCantParseVolumeID(randomID)
				})

				req := &csi.ListSnapshotsRequest{
					SourceVolumeId: randomID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				gomega.Expect(res).To(gomega.Equal(&csi.ListSnapshotsResponse{}))
				gomega.Expect(err).To(gomega.BeNil())
			})
		})
	})

	ginkgo.Describe("calling GetCapacity()", func() {
		ginkgo.When("everything is ok and arrayip is provided", func() {
			ginkgo.It("should succeed", func() {
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				clientMock.On("GetMaxVolumeSize", mock.Anything).Return(int64(-1), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{
						"arrayIP": "192.168.0.1",
					},
				}
				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.AvailableCapacity).To(gomega.Equal(int64(123123123)))
			})
		})

		ginkgo.When("everything is ok and array ip is not provided", func() {
			ginkgo.It("should succeed", func() {
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				clientMock.On("GetMaxVolumeSize", mock.Anything).Return(int64(-1), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{},
				}
				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.AvailableCapacity).To(gomega.Equal(int64(123123123)))
			})
		})

		ginkgo.When("wrong arrayIP in params", func() {
			ginkgo.It("should fail with predefined errmsg", func() {
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				clientMock.On("GetMaxVolumeSize", mock.Anything).Return(int64(-1), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{
						"arrayID": "10.10.10.10",
					},
				}
				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find array with provided id 10.10.10.10"))
			})
		})

		ginkgo.When("everything is correct, but API failed", func() {
			ginkgo.It("should fail with predefined errmsg", func() {
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), errors.New("APIErrorUnexpected"))
				clientMock.On("GetMaxVolumeSize", mock.Anything).Return(int64(-1), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{
						"arrayIP": "192.168.0.1",
					},
				}
				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("APIErrorUnexpected"))
			})
		})

		ginkgo.When("everything is correct, but GetMaxVolumeSize API failed", func() {
			ginkgo.It("MaximumVolumeSize should not be set in the response", func() {
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{},
				}
				clientMock.On("GetMaxVolumeSize", mock.Anything).Return(int64(-1), errors.New("APIErrorUnexpected"))

				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("negative MaximumVolumeSize", func() {
			ginkgo.It("MaximumVolumeSize should not be set in the response", func() {
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{},
				}
				clientMock.On("GetMaxVolumeSize", mock.Anything).Return(int64(-1), nil)

				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				gomega.Expect(res.MaximumVolumeSize).To(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("non negative MaximumVolumeSize", func() {
			ginkgo.It("MaximumVolumeSize should be set in the response", func() {
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetCustomHTTPHeaders").Return(make(http.Header))
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{},
				}
				clientMock.On("GetMaxVolumeSize", mock.Anything).Return(int64(100000), nil)
				res, err := ctrlSvc.GetCapacity(context.Background(), req)

				gomega.Expect(res.MaximumVolumeSize).ToNot(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
			})
		})
	})

	ginkgo.Describe("calling ValidateVolumeCapabilities()", func() {
		ginkgo.BeforeEach(func() { clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{}, nil) })

		ginkgo.When("everything is correct. Mode = SNW,block", func() {
			ginkgo.It("should succeed", func() {
				block := new(csi.VolumeCapability_BlockVolume)
				accessType := new(csi.VolumeCapability_Block)
				accessType.Block = block
				res, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      validBlockVolumeID,
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Confirmed).NotTo(gomega.BeNil())
			})
		})

		ginkgo.When("everything is correct. Mode = SNRO,block", func() {
			ginkgo.It("should succeed", func() {
				block := new(csi.VolumeCapability_BlockVolume)
				accessType := new(csi.VolumeCapability_Block)
				accessType.Block = block
				res, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      validBlockVolumeID,
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Confirmed).NotTo(gomega.BeNil())
			})
		})

		ginkgo.When("everything is correct. Mode = MNRO,block", func() {
			ginkgo.It("should succeed", func() {
				block := new(csi.VolumeCapability_BlockVolume)
				accessType := new(csi.VolumeCapability_Block)
				accessType.Block = block
				res, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      validBlockVolumeID,
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Confirmed).NotTo(gomega.BeNil())
			})
		})

		ginkgo.When("everything is correct. Mode = MNSW,block", func() {
			ginkgo.It("should succeed", func() {
				block := new(csi.VolumeCapability_BlockVolume)
				accessType := new(csi.VolumeCapability_Block)
				accessType.Block = block
				res, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      validBlockVolumeID,
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Confirmed).NotTo(gomega.BeNil())
			})
		})

		ginkgo.When("everything is correct. Mode = MNMW,block", func() {
			ginkgo.It("should fail", func() {
				block := new(csi.VolumeCapability_BlockVolume)
				accessType := new(csi.VolumeCapability_Block)
				accessType.Block = block
				res, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      validBlockVolumeID,
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res.Confirmed).NotTo(gomega.BeNil())
			})
		})

		ginkgo.When("wrong pair of AM and AT. Mode = MNMW,mount", func() {
			ginkgo.It("should fail", func() {
				mount := new(csi.VolumeCapability_MountVolume)
				accessType := new(csi.VolumeCapability_Mount)
				accessType.Mount = mount
				res, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      validBlockVolumeID,
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res.Confirmed).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("multi-node with writer(s) only supported for block access type"))
			})
		})

		ginkgo.When("wrong AT is given", func() {
			ginkgo.It("should fail", func() {
				accessType := new(csi.VolumeCapability_Mount)
				accessType.Mount = nil
				res, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      validBlockVolumeID,
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res.Confirmed).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unknown access type is not Block or Mount"))
			})
		})

		ginkgo.When("AM is nil", func() {
			ginkgo.It("should fail", func() {
				mount := new(csi.VolumeCapability_MountVolume)
				accessType := new(csi.VolumeCapability_Mount)
				accessType.Mount = mount
				res, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      validBlockVolumeID,
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_UNKNOWN},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res.Confirmed).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("access mode cannot be UNKNOWN"))
			})
		})
	})

	ginkgo.Describe("calling ControllerGetCapabilities()", func() {
		ginkgo.When("plugin functions correctly with health monitor capabilities", func() {
			ginkgo.It("should return supported capabilities", func() {
				csictx.Setenv(context.Background(), common.EnvIsHealthMonitorEnabled, "true")
				ctrlSvc.Init()
				res, err := ctrlSvc.ControllerGetCapabilities(context.Background(), &csi.ControllerGetCapabilitiesRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerGetCapabilitiesResponse{
					Capabilities: []*csi.ControllerServiceCapability{
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_GET_CAPACITY,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_CREATE_DELETE_SNAPSHOT,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_LIST_SNAPSHOTS,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_CLONE_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_EXPAND_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_GET_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_LIST_VOLUMES_PUBLISHED_NODES,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_VOLUME_CONDITION,
								},
							},
						},
					},
				}))
			})
		})
		ginkgo.When("plugin functions correctly without health monitor capabilities", func() {
			ginkgo.It("should return supported capabilities", func() {
				csictx.Setenv(context.Background(), common.EnvIsHealthMonitorEnabled, "false")
				ctrlSvc.Init()
				res, err := ctrlSvc.ControllerGetCapabilities(context.Background(), &csi.ControllerGetCapabilitiesRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerGetCapabilitiesResponse{
					Capabilities: []*csi.ControllerServiceCapability{
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_GET_CAPACITY,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_CREATE_DELETE_SNAPSHOT,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_LIST_SNAPSHOTS,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_CLONE_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_EXPAND_VOLUME,
								},
							},
						},
						{
							Type: &csi.ControllerServiceCapability_Rpc{
								Rpc: &csi.ControllerServiceCapability_RPC{
									Type: csi.ControllerServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
								},
							},
						},
					},
				}))
			})
		})
	})

	ginkgo.Describe("calling DiscoverStorageProtectionGroup", func() {
		ginkgo.When("get info about protection group", func() {
			getLocalAndRemoteParams := func(localSystemName string, localAddress string,
				remoteSystemName string, remoteAddress string,
				remoteSerialNumber string, volumeGroupName string,
			) (map[string]string, map[string]string) {
				localParams := map[string]string{
					"globalID":                localAddress,
					"systemName":              localSystemName,
					"managementAddress":       localAddress,
					"remoteSystemName":        remoteSystemName,
					"remoteManagementAddress": remoteAddress,
					"remoteGlobalID":          remoteSerialNumber,
					"VolumeGroupName":         volumeGroupName,
				}

				remoteParams := map[string]string{
					"globalID":                remoteSerialNumber,
					"systemName":              remoteSystemName,
					"managementAddress":       remoteAddress,
					"remoteSystemName":        localSystemName,
					"remoteManagementAddress": localAddress,
					"VolumeGroupName":         volumeGroupName,
				}

				return localParams, remoteParams
			}

			ginkgo.It("should successfully discover protection group if everything is ok", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, Name: validVolumeGroupName}}}, nil)

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{
						RemoteSystemID:   validRemoteSystemID,
						LocalResourceID:  validGroupID,
						RemoteResourceID: validRemoteGroupID,
						StorageElementPairs: []gopowerstore.StorageElementPair{{
							LocalStorageElementID:  validBaseVolID,
							RemoteStorageElementID: validRemoteVolID,
						}},
					}, nil)

				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{Name: validClusterName, ManagementAddress: firstValidID}, nil)

				clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).
					Return(gopowerstore.RemoteSystem{
						Name:              validRemoteSystemName,
						ManagementAddress: secondValidID,
						SerialNumber:      validRemoteSystemGlobalID,
					}, nil)

				req := &csiext.CreateStorageProtectionGroupRequest{
					VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
				}

				res, err := ctrlSvc.CreateStorageProtectionGroup(context.Background(), req)

				localParams, remoteParams := getLocalAndRemoteParams(validClusterName, firstValidID,
					validRemoteSystemName, secondValidID, validRemoteSystemGlobalID, validVolumeGroupName)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csiext.CreateStorageProtectionGroupResponse{
					LocalProtectionGroupId:          validGroupID,
					RemoteProtectionGroupId:         validRemoteGroupID,
					LocalProtectionGroupAttributes:  localParams,
					RemoteProtectionGroupAttributes: remoteParams,
				}))
			})

			ginkgo.It("should fail if volume doesn't exists", func() {
				req := &csiext.CreateStorageProtectionGroupRequest{
					VolumeHandle: "",
				}

				res, err := ctrlSvc.CreateStorageProtectionGroup(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume ID is required"))
			})

			ginkgo.It("should fail if volume is single", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{}, gopowerstore.APIError{})

				req := &csiext.CreateStorageProtectionGroupRequest{
					VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
				}

				res, err := ctrlSvc.CreateStorageProtectionGroup(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
			})

			ginkgo.It("should fail when volume group not in replication session", func() {
				// policy with replication rule not assigned
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID}}}, nil)

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{}, gopowerstore.APIError{})

				req := &csiext.CreateStorageProtectionGroupRequest{
					VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
				}

				res, err := ctrlSvc.CreateStorageProtectionGroup(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
			})
		})
	})

	ginkgo.Describe("calling CreateRemoteVolume", func() {
		ginkgo.When("creating remote volume", func() {
			ginkgo.It("should return info if everything is ok", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID}}}, nil)

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{
						LocalResourceID:  validGroupID,
						RemoteResourceID: validRemoteGroupID,
						RemoteSystemID:   validRemoteSystemID,
						StorageElementPairs: []gopowerstore.StorageElementPair{
							{
								LocalStorageElementID:  validBaseVolID,
								RemoteStorageElementID: validRemoteVolID,
							},
						},
					}, nil)

				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, Size: validVolSize}, nil)

				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{Name: validClusterName}, nil)

				clientMock.On("GetRemoteSystem", mock.Anything, validRemoteSystemID).
					Return(gopowerstore.RemoteSystem{Name: validRemoteSystemName, ManagementAddress: secondValidID, ID: validRemoteSystemID, SerialNumber: validRemoteSystemGlobalID}, nil)

				req := &csiext.CreateRemoteVolumeRequest{
					VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
				}

				res, err := ctrlSvc.CreateRemoteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(
					&csiext.CreateRemoteVolumeResponse{RemoteVolume: &csiext.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      validRemoteVolID + "/" + validRemoteSystemGlobalID + "/" + "iscsi",
						VolumeContext: map[string]string{
							"remoteSystem":      validClusterName,
							"managementAddress": secondValidID,
							"arrayID":           validRemoteSystemGlobalID,
						},
					}}))
			})
			ginkgo.It("should fail if volume id is empty", func() {
				req := &csiext.CreateRemoteVolumeRequest{
					VolumeHandle: "",
				}

				res, err := ctrlSvc.CreateRemoteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume ID is required"))
			})

			ginkgo.It("should fail if volume not in volumeGroup", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{}, gopowerstore.APIError{})

				req := &csiext.CreateRemoteVolumeRequest{
					VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
				}

				res, err := ctrlSvc.CreateRemoteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
			})

			ginkgo.It("should fail if parent volume group not replicated", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{}, gopowerstore.APIError{})

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{}, gopowerstore.APIError{})

				req := &csiext.CreateRemoteVolumeRequest{
					VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
				}
				res, err := ctrlSvc.CreateRemoteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
			})

			ginkgo.It("should fail if volume group not synced yet", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID}}}, nil)

				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, validGroupID).
					Return(gopowerstore.ReplicationSession{
						LocalResourceID:     validGroupID,
						RemoteResourceID:    validRemoteGroupID,
						RemoteSystemID:      validRemoteSystemID,
						StorageElementPairs: []gopowerstore.StorageElementPair{},
					}, nil)

				req := &csiext.CreateRemoteVolumeRequest{
					VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
				}
				res, err := ctrlSvc.CreateRemoteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					fmt.Sprintf("couldn't find volume id %s in storage element pairs of replication session", validBaseVolID)))
			})

			ginkgo.It("should fail if the array id is nil", func() {
				// create volume handle with nil array ID
				req := &csiext.CreateRemoteVolumeRequest{
					VolumeHandle: validBaseVolID + "/" + "/" + "iscsi",
				}
				res, err := ctrlSvc.CreateRemoteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					"failed to find array with given IP",
				))
			})

			ginkgo.It("should fail if a volume group does not exist for the volume", func() {
				// return an empty volume group
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)

				req := &csiext.CreateRemoteVolumeRequest{
					VolumeHandle: validBaseVolID + "/" + firstValidID + "/" + "iscsi",
				}
				res, err := ctrlSvc.CreateRemoteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(
					"replication of volumes that aren't assigned to group is not implemented yet",
				))
			})
		})
	})

	ginkgo.Describe("calling EnsureProtectionPolicyExists", func() {
		ginkgo.When("ensure protection policy exists", func() {
			ginkgo.It("should failed if remote system not in list", func() {
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).
					Return(gopowerstore.RemoteSystem{}, gopowerstore.NewHostIsNotExistError())

				_, err := controller.EnsureProtectionPolicyExists(context.Background(), ctrlSvc.DefaultArray(),
					validGroupName, validRemoteSystemName, validRPO)
				gomega.Expect(err).ToNot(gomega.BeNil())
			})

			ginkgo.It("should return existing policy", func() {
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).
					Return(gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				clientMock.On("GetProtectionPolicyByName", mock.Anything, validPolicyName).
					Return(gopowerstore.ProtectionPolicy{ID: validPolicyID, Name: validPolicyName}, nil)

				res, err := controller.EnsureProtectionPolicyExists(context.Background(), ctrlSvc.DefaultArray(),
					validGroupName, validRemoteSystemName, validRPO)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(validPolicyID))
			})

			ginkgo.It("should successfully create new policy with existing rule", func() {
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).
					Return(gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				clientMock.On("GetProtectionPolicyByName", mock.Anything, validPolicyName).
					Return(gopowerstore.ProtectionPolicy{}, gopowerstore.APIError{})

				clientMock.On("GetReplicationRuleByName", mock.Anything, validRuleName).
					Return(gopowerstore.ReplicationRule{ID: validRuleID}, nil)

				clientMock.On("CreateProtectionPolicy", mock.Anything,
					&gopowerstore.ProtectionPolicyCreate{
						Name:               validPolicyName,
						ReplicationRuleIDs: []string{validRuleID},
					}).Return(gopowerstore.CreateResponse{ID: validPolicyID}, nil)
				res, err := controller.EnsureProtectionPolicyExists(context.Background(), ctrlSvc.DefaultArray(),
					validGroupName, validRemoteSystemName, validRPO)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(validPolicyID))
			})
		})
	})

	ginkgo.Describe("calling EnsureReplicationRuleExists", func() {
		ginkgo.When("ensure replication rule exists", func() {
			ginkgo.It("should successfully create new rule if it doesn't exists", func() {
				clientMock.On("GetReplicationRuleByName", mock.Anything, validRuleName).
					Return(gopowerstore.ReplicationRule{ID: validRuleID}, gopowerstore.APIError{})

				clientMock.On("CreateReplicationRule", mock.Anything,
					&gopowerstore.ReplicationRuleCreate{
						Name:           validRuleName,
						Rpo:            validRPO,
						RemoteSystemID: validRemoteSystemID,
					},
				).Return(gopowerstore.CreateResponse{ID: validRuleID}, nil)

				res, err := controller.EnsureReplicationRuleExists(context.Background(), ctrlSvc.DefaultArray(),
					validGroupName, validRemoteSystemID, gopowerstore.RpoFiveMinutes)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(validRuleID))
			})

			ginkgo.It("should return existing rule", func() {
				clientMock.On("GetReplicationRuleByName", mock.Anything, validRuleName).
					Return(gopowerstore.ReplicationRule{ID: validRuleID}, nil)

				res, err := controller.EnsureReplicationRuleExists(context.Background(), ctrlSvc.DefaultArray(),
					validGroupName, validRemoteSystemID, validRPO)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(validRuleID))
			})

			ginkgo.It("should fail to create a replication rule", func() {
				clientMock.On("GetReplicationRuleByName", mock.Anything, validRuleName).Return(
					gopowerstore.ReplicationRule{ID: validRuleID},
					gopowerstore.NewNotFoundError(),
				)

				// generic error
				apiErr := gopowerstore.NewAPIError()
				apiErr.Message = "injected api error"

				clientMock.On("CreateReplicationRule", mock.Anything,
					&gopowerstore.ReplicationRuleCreate{
						Name:           validRuleName,
						Rpo:            validRPO,
						RemoteSystemID: validRemoteSystemID,
					},
				).Return(gopowerstore.CreateResponse{}, gopowerstore.WrapErr(apiErr))

				res, err := controller.EnsureReplicationRuleExists(context.Background(), ctrlSvc.DefaultArray(),
					validGroupName, validRemoteSystemID, validRPO)

				gomega.Expect(res).To(gomega.BeEmpty())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't create replication rule"))
			})
		})
	})

	ginkgo.Describe("calling ControllerGetVolume", func() {
		ginkgo.When("normal block volume exists on array", func() {
			ginkgo.It("should successfully get the volume", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, State: gopowerstore.VolumeStateEnumReady}, nil)

				clientMock.On("GetHost", mock.Anything, validHostID).Return(gopowerstore.Host{ID: validHostID, Name: validHostName}, nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID}}, nil).Once()

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, nil)

				req := &csi.ControllerGetVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerGetVolumeResponse{
					Volume: &csi.Volume{
						VolumeId: validBaseVolID,
					},
					Status: &csi.ControllerGetVolumeResponse_VolumeStatus{
						PublishedNodeIds: []string{validHostName},
						VolumeCondition: &csi.VolumeCondition{
							Abnormal: false,
							Message:  "",
						},
					},
				}))
			})
		})
		ginkgo.When("normal block volume does not exists on array", func() {
			ginkgo.It("should fail", func() {
				var hosts []string
				clientMock.On("GetVolume", mock.Anything, mock.Anything).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				clientMock.On("GetHost", mock.Anything, validHostID).Return(gopowerstore.Host{ID: validHostID, Name: validHostName}, nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID}}, nil).Once()

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, nil)

				req := &csi.ControllerGetVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerGetVolumeResponse{
					Volume: &csi.Volume{
						VolumeId: validBaseVolID,
					},
					Status: &csi.ControllerGetVolumeResponse_VolumeStatus{
						PublishedNodeIds: hosts,
						VolumeCondition: &csi.VolumeCondition{
							Abnormal: true,
							Message:  fmt.Sprintf("Volume %s is not found", validBaseVolID),
						},
					},
				}))
			})
		})
		ginkgo.When("normal filesystem exists on array", func() {
			ginkgo.It("should successfully get the filesystem", func() {
				var hosts []string
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, State: gopowerstore.VolumeStateEnumReady}, nil)

				clientMock.On("GetHost", mock.Anything, validHostID).Return(gopowerstore.Host{ID: validHostID, Name: validHostName}, nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID}}, nil).Once()

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, nil)

				req := &csi.ControllerGetVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerGetVolumeResponse{
					Volume: &csi.Volume{
						VolumeId: validBaseVolID,
					},
					Status: &csi.ControllerGetVolumeResponse_VolumeStatus{
						PublishedNodeIds: hosts,
						VolumeCondition: &csi.VolumeCondition{
							Abnormal: false,
							Message:  "",
						},
					},
				}))
			})
		})
		ginkgo.When("filesystem does not exists on array", func() {
			ginkgo.It("should fail", func() {
				var hosts []string
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, State: gopowerstore.VolumeStateEnumReady}, nil)

				clientMock.On("GetHost", mock.Anything, validHostID).Return(gopowerstore.Host{ID: validHostID, Name: validHostName}, nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID}}, nil).Once()

				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, nil)

				req := &csi.ControllerGetVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerGetVolumeResponse{
					Volume: &csi.Volume{
						VolumeId: validBaseVolID,
					},
					Status: &csi.ControllerGetVolumeResponse_VolumeStatus{
						PublishedNodeIds: hosts,
						VolumeCondition: &csi.VolumeCondition{
							Abnormal: true,
							Message:  fmt.Sprintf("Filesystem %s is not found", validBaseVolID),
						},
					},
				}))
			})
		})
	})
})

func getTypicalCreateVolumeRequest(name string, size int64) *csi.CreateVolumeRequest {
	req := new(csi.CreateVolumeRequest)
	params := make(map[string]string)
	req.Parameters = params
	req.Name = name
	capacityRange := new(csi.CapacityRange)
	capacityRange.RequiredBytes = size
	capacityRange.LimitBytes = size * 2
	req.CapacityRange = capacityRange
	block := new(csi.VolumeCapability_BlockVolume)
	capability := new(csi.VolumeCapability)
	accessType := new(csi.VolumeCapability_Block)
	accessType.Block = block
	capability.AccessType = accessType
	accessMode := new(csi.VolumeCapability_AccessMode)
	accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
	capability.AccessMode = accessMode
	capabilities := make([]*csi.VolumeCapability, 0)
	capabilities = append(capabilities, capability)
	req.VolumeCapabilities = capabilities

	return req
}

func getTypicalControllerExpandRequest(volid string, size int64) *csi.ControllerExpandVolumeRequest {
	return &csi.ControllerExpandVolumeRequest{
		VolumeId: volid,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: size,
			LimitBytes:    controller.MaxVolumeSizeBytes,
		},
	}
}

func getVolumeCapabilityNFS() *csi.VolumeCapability {
	accessMode := new(csi.VolumeCapability_AccessMode)
	accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
	accessType := new(csi.VolumeCapability_Mount)
	mountVolume := new(csi.VolumeCapability_MountVolume)
	mountVolume.FsType = "nfs"
	accessType.Mount = mountVolume
	capability := new(csi.VolumeCapability)
	capability.AccessMode = accessMode
	capability.AccessType = accessType
	return capability
}

func getTypicalCreateVolumeNFSRequest(name string, size int64) *csi.CreateVolumeRequest {
	req := new(csi.CreateVolumeRequest)
	params := make(map[string]string)
	req.Parameters = params
	req.Name = name

	capacityRange := new(csi.CapacityRange)
	capacityRange.RequiredBytes = size
	capacityRange.LimitBytes = size * 2
	req.CapacityRange = capacityRange

	capabilities := make([]*csi.VolumeCapability, 0)
	capabilities = append(capabilities, getVolumeCapabilityNFS())
	req.VolumeCapabilities = capabilities

	nfsTopology := &csi.Topology{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}
	preferred := []*csi.Topology{nfsTopology}
	accessibilityRequirements := &csi.TopologyRequirement{Preferred: preferred}
	req.AccessibilityRequirements = accessibilityRequirements
	return req
}

func getTypicalControllerPublishVolumeRequest(access, nodeID, volumeID string) *csi.ControllerPublishVolumeRequest {
	capability := new(csi.VolumeCapability)
	accessMode := new(csi.VolumeCapability_AccessMode)
	switch access {
	case "single-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
		break
	case "multiple-reader":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY
		break
	case "multiple-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
		break
	case "unknown":
		accessMode.Mode = csi.VolumeCapability_AccessMode_UNKNOWN
		break
	}
	capability.AccessMode = accessMode

	block := new(csi.VolumeCapability_BlockVolume)
	accessType := new(csi.VolumeCapability_Block)
	accessType.Block = block
	capability.AccessType = accessType

	fmt.Printf("capability.AccessType %v\n", capability.AccessType)
	fmt.Printf("capability.AccessMode %v\n", capability.AccessMode)

	req := new(csi.ControllerPublishVolumeRequest)
	req.VolumeId = volumeID
	req.NodeId = nodeID
	req.Readonly = false
	req.VolumeCapability = capability
	return req
}

func EnsureProtectionPolicyExistsMock() {
	// start ensure protection policy exists
	clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(gopowerstore.RemoteSystem{
		Name: validRemoteSystemName,
		ID:   validRemoteSystemID,
	}, nil)

	clientMock.On("GetProtectionPolicyByName", mock.Anything, validPolicyName).
		Return(gopowerstore.ProtectionPolicy{ID: validPolicyID}, nil)
}

func EnsureProtectionPolicyExistsMockSync() {
	// start ensure protection policy exists
	clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(gopowerstore.RemoteSystem{
		Name: validRemoteSystemName,
		ID:   validRemoteSystemID,
	}, nil)

	clientMock.On("GetProtectionPolicyByName", mock.Anything, validPolicyNameSync).
		Return(gopowerstore.ProtectionPolicy{ID: validPolicyID}, nil)
}
