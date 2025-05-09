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

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/dell/csm-sharednfs/nfs"
	csiext "github.com/dell/dell-csi-extensions/replication"

	"github.com/dell/csi-powerstore/v2/mocks"
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
	validMetroBlockVolumeID      = "39bb1b5f-5624-490d-9ece-18f7b28a904e/globalvolid1/scsi:9f840c56-96e6-4de9-b5a3-27e7c20eaa77/globalvolid2"
	validNfsVolumeID             = "39bb1b5f-5624-490d-9ece-18f7b28a904e/globalvolid2/nfs"
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
	validReplicationPrefix       = "/" + KeyReplicationEnabled
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
	ctrlSvc    *Service
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
		Endpoint:           "https://192.168.0.1/api/rest",
		Username:           "admin",
		GlobalID:           firstValidID,
		Password:           "pass",
		BlockProtocol:      common.ISCSITransport,
		Insecure:           true,
		IsDefault:          true,
		Client:             clientMock,
		IP:                 "192.168.0.1",
		NASCooldownTracker: array.NewNASCooldown(time.Minute, 5),
	}
	second := &array.PowerStoreArray{
		Endpoint:           "https://192.168.0.2/api/rest",
		Username:           "admin",
		GlobalID:           secondValidID,
		Password:           "pass",
		NasName:            validNasName,
		BlockProtocol:      common.NoneTransport,
		Insecure:           true,
		Client:             clientMock,
		IP:                 "192.168.0.2",
		NASCooldownTracker: array.NewNASCooldown(time.Minute, 5),
	}

	arrays[firstValidID] = first
	arrays[secondValidID] = second

	csictx.Setenv(context.Background(), common.EnvReplicationPrefix, "replication.storage.dell.com")
	csictx.Setenv(context.Background(), common.EnvNfsAcls, "A::OWNER@:RWX")

	ctrlSvc = &Service{Fs: fsMock}
	ctrlSvc.SetArrays(arrays)
	ctrlSvc.SetDefaultArray(first)
	ctrlSvc.Init()
}

func addMetaData(createParams interface{}) {
	if t, ok := createParams.(interface {
		MetaData() http.Header
	}); ok {
		t.MetaData().Set(HeaderPersistentVolumeName, "")
		t.MetaData().Set(HeaderPersistentVolumeClaimName, "")
		t.MetaData().Set(HeaderPersistentVolumeClaimNamespace, "")
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
				clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
				clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = firstValidID
				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID:           firstValidID,
							common.KeyArrayVolumeName:   "my-vol",
							common.KeyProtocol:          "scsi",
							common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
							KeyCSIPVCName:               req.Name,
							KeyCSIPVCNamespace:          validNamespaceName,
							common.KeyServiceTag:        validServiceTag,
						},
					},
				}))
			})
		})

		ginkgo.It("should successfully create block volume and vol attributes should be set", func() {
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = firstValidID
			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
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
						KeyCSIPVCName:                 req.Name,
						KeyCSIPVCNamespace:            validNamespaceName,
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
			req.Parameters[ctrlSvc.WithRP(KeyReplicationEnabled)] = "true"
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = validRPO
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRemoteSystem)] = validRemoteSystemName
			req.Parameters[ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces)] = "true"
			req.Parameters[ctrlSvc.WithRP(KeyReplicationVGPrefix)] = "csi"
			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
		})

		ginkgo.It("should create volume and volumeGroup if policy exists - ASYNC", func() {
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationRPO):              validRPO,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should create volume and volumeGroup if policy exists - SYNC", func() {
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = zeroRPO

			// all entities not exists
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			EnsureProtectionPolicyExistsMockSync()

			createGroupRequest := &gopowerstore.VolumeGroupCreate{Name: validGroupNameSync, ProtectionPolicyID: validPolicyID}
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
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationRPO):              zeroRPO,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should create vg with namespace if namespaces not ignored - ASYNC", func() {
			req.Parameters[ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces)] = "false"
			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName

			defer func() {
				req.Parameters[ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces)] = "true"
				req.Parameters[KeyCSIPVCNamespace] = ""
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
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationRPO):              validRPO,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "false",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should create vg with namespace if namespaces not ignored - SYNC", func() {
			req.Parameters[ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces)] = "false"
			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = zeroRPO

			defer func() {
				req.Parameters[ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces)] = "true"
				req.Parameters[KeyCSIPVCNamespace] = ""
			}()

			clientMock.On("GetVolumeGroupByName", mock.Anything, validNamespacedGroupNameSync).
				Return(gopowerstore.VolumeGroup{}, gopowerstore.NewNotFoundError())

			clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).Return(gopowerstore.RemoteSystem{
				Name: validRemoteSystemName,
				ID:   validRemoteSystemID,
			}, nil)

			clientMock.On("GetProtectionPolicyByName", mock.Anything, "pp-"+validNamespacedGroupNameSync).
				Return(gopowerstore.ProtectionPolicy{ID: validPolicyID}, nil)

			createGroupRequest := &gopowerstore.VolumeGroupCreate{Name: validNamespacedGroupNameSync, ProtectionPolicyID: validPolicyID}
			clientMock.On("CreateVolumeGroup", mock.Anything, createGroupRequest).Return(gopowerstore.CreateResponse{ID: validGroupID}, nil)
			clientMock.On("GetVolumeGroup", mock.Anything, validGroupID).Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationRPO):              zeroRPO,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "false",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should create new volume with existing volumeGroup with policy - ASYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupName).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID}, nil)

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationRPO):              validRPO,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should create new volume with existing volumeGroup with policy - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: true}, nil)
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = zeroRPO

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(KeyReplicationRPO):              zeroRPO,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should fail create new volume with existing volumeGroup with policy and when IsWriteOrderConsistent is false - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: false}, nil)
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = zeroRPO

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationRPO):              validRPO,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should create volume and update volumeGroup without policy, but policy exists - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: true}, nil)

			EnsureProtectionPolicyExistsMockSync()

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = zeroRPO
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(KeyReplicationRPO):              zeroRPO,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should fail create volume and update volumeGroup without policy, but policy exists when IsWriteOrderConsistent is false - SYNC", func() {
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: false}, nil)

			EnsureProtectionPolicyExistsMockSync()

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			// Setting Replciation mode and corresponding attributes for SYNC
			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = zeroRPO
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = replicationModeSync
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = zeroRPO

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't ensure protection policy exists"))
		})

		ginkgo.It("should fail when rpo incorrect", func() {
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = "invalidRpo"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("invalid RPO value"))
		})

		ginkgo.It("should fail when rpo not declared in parameters -ASYNC", func() {
			delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationRPO))

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication mode is ASYNC but no RPO specified in storage class"))
		})

		ginkgo.It("should default RPO to Zero when mode is SYNC and RPO is not specified", func() {
			delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationRPO))
			clientMock.On("GetVolumeGroupByName", mock.Anything, validGroupNameSync).
				Return(gopowerstore.VolumeGroup{ID: validGroupID, ProtectionPolicyID: validPolicyID, IsWriteOrderConsistent: true}, nil)

			EnsureProtectionPolicyExistsMockSync()

			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetVolume", context.Background(), mock.Anything).Return(gopowerstore.Volume{ApplianceID: validApplianceID}, nil)
			clientMock.On("GetAppliance", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = "SYNC"
			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, firstValidID, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:                      "my-vol",
						common.KeyProtocol:                             "scsi",
						common.KeyArrayID:                              firstValidID,
						common.KeyVolumeDescription:                    req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:                           validServiceTag,
						KeyCSIPVCName:                                  req.Name,
						KeyCSIPVCNamespace:                             validNamespaceName,
						ctrlSvc.WithRP(KeyReplicationEnabled):          "true",
						ctrlSvc.WithRP(KeyReplicationMode):             replicationModeSync,
						ctrlSvc.WithRP(KeyReplicationRemoteSystem):     validRemoteSystemName,
						ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces): "true",
						ctrlSvc.WithRP(KeyReplicationVGPrefix):         "csi",
					},
				},
			}))
		})

		ginkgo.It("should fail when remote system not declared in parameters", func() {
			delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationRemoteSystem))

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication enabled but no remote system specified in storage class"))
		})

		ginkgo.It("should fail when mode is incorrect", func() {
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = "SYNCMETRO"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("invalid replication mode"))
		})

		ginkgo.It("should fail when mode is ASYNC and RPO is Zero", func() {
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = replicationModeAsync
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = zeroRPO
			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication mode ASYNC requires RPO value to be non Zero"))
		})

		ginkgo.It("should fail when mode is SYNC and RPO is not Zero", func() {
			clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = "SYNC"
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRPO)] = validRPO
			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication mode SYNC requires RPO value to be Zero"))
		})

		ginkgo.It("should fail when volume group prefix not declared in parameters", func() {
			delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationVGPrefix))

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication enabled but no volume group prefix specified in storage class"))
		})

		ginkgo.It("should fail when invalid remote system is specified in parameters for metro volume", func() {
			req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = "METRO"
			req.Parameters[ctrlSvc.WithRP(KeyReplicationRemoteSystem)] = "invalid"

			clientMock.On("GetRemoteSystemByName", mock.Anything, "invalid").Return(gopowerstore.RemoteSystem{}, gopowerstore.NewNotFoundError())

			res, err := ctrlSvc.CreateVolume(context.Background(), req)

			gomega.Expect(res).To(gomega.BeNil())
			gomega.Expect(err).NotTo(gomega.BeNil())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't query remote system by name"))
		})

		ginkgo.Context("replication type is metro", func() {
			var configureMetroRequest *gopowerstore.MetroConfig

			ginkgo.BeforeEach(func() {
				// Default mock function functionality for metro replication.
				// This base functionality can be overridden in the individual test implementation.
				configureMetroRequest = &gopowerstore.MetroConfig{RemoteSystemID: validRemoteSystemID}
				req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = "METRO"

				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationRPO))
				delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces))
				delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationVGPrefix))

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
						VolumeId:      fmt.Sprintf("%s/%s/%s:%s/%s", validBaseVolID, firstValidID, "scsi", validRemoteVolID, secondValidID),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:                  "my-vol",
							common.KeyProtocol:                         "scsi",
							common.KeyArrayID:                          firstValidID,
							common.KeyVolumeDescription:                req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:                       validServiceTag,
							KeyCSIPVCName:                              req.Name,
							KeyCSIPVCNamespace:                         validNamespaceName,
							ctrlSvc.WithRP(KeyReplicationEnabled):      "true",
							ctrlSvc.WithRP(KeyReplicationMode):         "METRO",
							ctrlSvc.WithRP(KeyReplicationRemoteSystem): validRemoteSystemName,
						},
					},
				}))
			})

			ginkgo.It("should continue metro replication on volume to support idempotency when metro was previously configured", func() {
				delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationRPO))
				delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationIgnoreNamespaces))
				delete(req.Parameters, ctrlSvc.WithRP(KeyReplicationVGPrefix))

				clientMock.On("ConfigureMetroVolume", mock.Anything, validBaseVolID, configureMetroRequest).
					Return(gopowerstore.MetroSessionResponse{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusBadRequest,
						},
					})
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
						VolumeId:      fmt.Sprintf("%s/%s/%s:%s/%s", validBaseVolID, firstValidID, "scsi", validRemoteVolID, secondValidID),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:                  "my-vol",
							common.KeyProtocol:                         "scsi",
							common.KeyArrayID:                          firstValidID,
							common.KeyVolumeDescription:                req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:                       validServiceTag,
							KeyCSIPVCName:                              req.Name,
							KeyCSIPVCNamespace:                         validNamespaceName,
							ctrlSvc.WithRP(KeyReplicationEnabled):      "true",
							ctrlSvc.WithRP(KeyReplicationMode):         "METRO",
							ctrlSvc.WithRP(KeyReplicationRemoteSystem): validRemoteSystemName,
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
				req.Parameters[ctrlSvc.WithRP(KeyReplicationRemoteSystem)] = "invalid"

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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring((fmt.Sprintf("replication session %s has a resource type %s, wanted type 'volume'",
					validSessionID, resourceType))))
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

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:   "my-vol",
						common.KeyProtocol:          "nfs",
						common.KeyArrayID:           secondValidID,
						common.KeyNfsACL:            "A::OWNER@:RWX",
						common.KeyNasName:           validNasName,
						common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:        validServiceTag,
						KeyCSIPVCName:               req.Name,
						KeyCSIPVCNamespace:          validNamespaceName,
					},
					AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
				},
			}))
		})

		validNAS1 := gopowerstore.NAS{
			Name:              "nasA",
			OperationalStatus: gopowerstore.Started,
			HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.None},
			FileSystems:       make([]gopowerstore.FileSystem, 1), // 1 FS (should be chosen)
		}

		validNAS2 := gopowerstore.NAS{
			Name:              "nasB",
			OperationalStatus: gopowerstore.Started,
			HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Info},
			FileSystems:       make([]gopowerstore.FileSystem, 2), // 2 FS, but lexicographically larger
		}

		validNAS3 := gopowerstore.NAS{
			Name:              "nasC",
			OperationalStatus: gopowerstore.Started,
			HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Info},
			FileSystems:       make([]gopowerstore.FileSystem, 3),
		}

		invalidNAS4 := gopowerstore.NAS{
			Name:              "nasX",
			OperationalStatus: gopowerstore.Stopped, // Inactive NAS
			HealthDetails:     gopowerstore.HealthDetails{State: gopowerstore.Info},
			FileSystems:       make([]gopowerstore.FileSystem, 1),
		}

		ginkgo.It("should successfully create nfs volume with least used NAS if multiple NAS exist in storage class", func() {
			clientMock.On("GetNASServers", mock.Anything).Return([]gopowerstore.NAS{validNAS1, validNAS2, validNAS3, invalidNAS4}, nil)
			clientMock.On("GetNASByName", mock.Anything, "nasA").Return(gopowerstore.NAS{ID: validNasID}, nil)
			clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
			clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
			clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			req.Parameters[common.KeyNasName] = "nasA, nasB, nasC, nasX"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:   "my-vol",
						common.KeyProtocol:          "nfs",
						common.KeyArrayID:           secondValidID,
						common.KeyNfsACL:            "A::OWNER@:RWX",
						common.KeyNasName:           "nasA",
						common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:        validServiceTag,
						KeyCSIPVCName:               req.Name,
						KeyCSIPVCNamespace:          validNamespaceName,
					},
					AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
				},
			}))
		})

		ginkgo.It("should successfully create nfs volume if only one NAS exist in storage class", func() {
			clientMock.On("GetNASByName", mock.Anything, "nasA").Return(gopowerstore.NAS{ID: validNasID}, nil)
			clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
			clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
			clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			req.Parameters[common.KeyNasName] = "nasA"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
					VolumeContext: map[string]string{
						common.KeyArrayVolumeName:   "my-vol",
						common.KeyProtocol:          "nfs",
						common.KeyArrayID:           secondValidID,
						common.KeyNfsACL:            "A::OWNER@:RWX",
						common.KeyNasName:           "nasA",
						common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
						common.KeyServiceTag:        validServiceTag,
						KeyCSIPVCName:               req.Name,
						KeyCSIPVCNamespace:          validNamespaceName,
					},
					AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
				},
			}))
		})

		ginkgo.It("should fail when there is no least used NAS[Invalid NAS]", func() {
			clientMock.On("GetNASServers", mock.Anything).Return([]gopowerstore.NAS{invalidNAS4}, nil)

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			req.Parameters[common.KeyNasName] = "nasA, nasB, nasC, nasX"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("no suitable NAS server found, please ensure the NAS is running and healthy"))
			gomega.Expect(res).To(gomega.BeNil())
		})

		ginkgo.It("should fail when fs creation limit is exceeded", func() {
			clientMock.On("GetNASServers", mock.Anything).Return([]gopowerstore.NAS{validNAS1, validNAS2, validNAS3, invalidNAS4}, nil)
			clientMock.On("GetNASByName", mock.Anything, "nasA").Return(gopowerstore.NAS{ID: validNasID}, nil)
			clientMock.On("CreateFS", mock.Anything, mock.Anything).
				Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusUnprocessableEntity,
						Message:    "New file system can not be created. The limit of 125 file systems for the NAS server 24aefac2-a796-47dc-886a-c73ff8c1a671 has been reached.",
					},
				})

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			req.Parameters[common.KeyNasName] = "nasA, nasB, nasC, nasX"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("The limit of 125 file systems for the NAS server"))
			gomega.Expect(res).To(gomega.BeNil())
		})

		ginkgo.It("should fail if CreateFS fails with some other API error", func() {
			clientMock.On("GetNASServers", mock.Anything).Return([]gopowerstore.NAS{validNAS1, validNAS2, validNAS3, invalidNAS4}, nil)
			clientMock.On("GetNASByName", mock.Anything, "nasA").Return(gopowerstore.NAS{ID: validNasID}, nil)
			clientMock.On("CreateFS", mock.Anything, mock.Anything).
				Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusForbidden,
						Message:    "some error message",
					},
				})

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			req.Parameters[common.KeyNasName] = "nasA, nasB, nasC, nasX"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("some error message"))
			gomega.Expect(res).To(gomega.BeNil())
		})

		ginkgo.It("should fail if CreateFS fails with some other Non API error", func() {
			clientMock.On("GetNASServers", mock.Anything).Return([]gopowerstore.NAS{validNAS1, validNAS2, validNAS3, invalidNAS4}, nil)
			clientMock.On("GetNASByName", mock.Anything, "nasA").Return(gopowerstore.NAS{ID: validNasID}, nil)
			clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{}, errors.New("some error message"))

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
			req.Parameters[common.KeyNasName] = "nasA, nasB, nasC, nasX"

			res, err := ctrlSvc.CreateVolume(context.Background(), req)
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("some error message"))
			gomega.Expect(res).To(gomega.BeNil())
		})

		ginkgo.It("should successfully create nfs volume & all vol attribute should get set", func() {
			clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
			clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)
			clientMock.On("GetFS", context.Background(), mock.Anything).Return(gopowerstore.FileSystem{NasServerID: validNasID}, nil)
			clientMock.On("GetNAS", context.Background(), mock.Anything).Return(gopowerstore.NAS{CurrentNodeID: validNodeID}, nil)
			clientMock.On("GetApplianceByName", context.Background(), mock.Anything).Return(gopowerstore.ApplianceInstance{ServiceTag: validServiceTag}, nil)

			req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
			req.Parameters[common.KeyArrayID] = secondValidID

			req.Parameters[KeyCSIPVCName] = req.Name
			req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
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
						KeyCSIPVCName:                      req.Name,
						KeyCSIPVCNamespace:                 validNamespaceName,
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
				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:   "my-vol",
							common.KeyProtocol:          "nfs",
							common.KeyArrayID:           secondValidID,
							common.KeyNfsACL:            "0777",
							common.KeyNasName:           validNasName,
							common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:        validServiceTag,
							KeyCSIPVCName:               req.Name,
							KeyCSIPVCNamespace:          validNamespaceName,
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
				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:   "my-vol",
							common.KeyProtocol:          "nfs",
							common.KeyArrayID:           secondValidID,
							common.KeyNfsACL:            "A::GROUP@:RWX",
							common.KeyNasName:           validNasName,
							common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:        validServiceTag,
							KeyCSIPVCName:               req.Name,
							KeyCSIPVCNamespace:          validNamespaceName,
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
				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:   "my-vol",
							common.KeyProtocol:          "nfs",
							common.KeyArrayID:           secondValidID,
							common.KeyNfsACL:            "A::OWNER@:RWX",
							common.KeyNasName:           validNasName,
							common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:        validServiceTag,
							KeyCSIPVCName:               req.Name,
							KeyCSIPVCNamespace:          validNamespaceName,
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
				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName

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
							common.KeyArrayVolumeName:   "my-vol",
							common.KeyProtocol:          "nfs",
							common.KeyArrayID:           secondValidID,
							common.KeyNfsACL:            "",
							common.KeyNasName:           validNasName,
							common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:        validServiceTag,
							KeyCSIPVCName:               req.Name,
							KeyCSIPVCNamespace:          validNamespaceName,
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

				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName

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

				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName

				iscsiTopology := &csi.Topology{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-iscis": "true"}}
				req.AccessibilityRequirements.Preferred = append(req.AccessibilityRequirements.Preferred, iscsiTopology)

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:   "my-vol",
							common.KeyProtocol:          "nfs",
							common.KeyArrayID:           secondValidID,
							common.KeyNfsACL:            "A::OWNER@:RWX",
							common.KeyNasName:           validNasName,
							common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:        validServiceTag,
							KeyCSIPVCName:               req.Name,
							KeyCSIPVCNamespace:          validNamespaceName,
						},
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})
		})

		ginkgo.When("volume name already in use", func() {
			ginkgo.It("should return existing volume [Block]", func() {
				volName := "my-vol"
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
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
							common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:        validServiceTag,
							KeyCSIPVCName:               req.Name,
							KeyCSIPVCNamespace:          validNamespaceName,
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
				req.Parameters[KeyCSIPVCName] = req.Name
				req.Parameters[KeyCSIPVCNamespace] = validNamespaceName
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidID, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayVolumeName:   "my-vol",
							common.KeyProtocol:          "nfs",
							common.KeyArrayID:           secondValidID,
							common.KeyNfsACL:            "A::OWNER@:RWX",
							common.KeyNasName:           validNasName,
							common.KeyVolumeDescription: req.Name + "-" + validNamespaceName,
							common.KeyServiceTag:        validServiceTag,
							KeyCSIPVCName:               req.Name,
							KeyCSIPVCNamespace:          validNamespaceName,
						},
						AccessibleTopology: []*csi.Topology{{Segments: map[string]string{common.Name + "/" + ctrlSvc.Arrays()[secondValidID].GetIP() + "-nfs": "true"}}},
					},
				}))
			})

			ginkgo.When("existing volume size is smaller", func() {
				ginkgo.It("should fail [Block]", func() {
					volName := "my-vol"
					clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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

			ginkgo.It("should fail to create volume using Metro snapshot as a source with Metro storage class [Block]", func() {
				contentSource := &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
					Snapshot: &csi.VolumeContentSource_SnapshotSource{
						SnapshotId: validBlockVolumeID,
					},
				}}

				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.VolumeContentSource = contentSource
				req.Parameters[common.KeyArrayID] = firstValidID
				req.Parameters[ctrlSvc.WithRP(KeyReplicationEnabled)] = "true"
				req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = "METRO"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Configuring Metro is not supported on clones or volumes created from Metro snapshot"))
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
					SizeTotal: validVolSize + ReservedSize,
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

			ginkgo.It("should fail to create volume using Metro volume as a source with Metro storage class [Block]", func() {
				srcID := validBlockVolumeID
				volName := "my-vol"

				contentSource := &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
					Volume: &csi.VolumeContentSource_VolumeSource{
						VolumeId: srcID,
					},
				}}

				req := getTypicalCreateVolumeRequest(volName, validVolSize)
				req.VolumeContentSource = contentSource
				req.Parameters[common.KeyArrayID] = firstValidID
				req.Parameters[ctrlSvc.WithRP(KeyReplicationEnabled)] = "true"
				req.Parameters[ctrlSvc.WithRP(KeyReplicationMode)] = "METRO"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Configuring Metro is not supported on clones or volumes created from Metro snapshot"))
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
					SizeTotal: validVolSize + ReservedSize,
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				req.Parameters[KeyFsType] = "nfs"

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
				req.Parameters[KeyFsTypeOld] = "nfs"

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

		ginkgo.When("nfs replication", func() {
			ginkgo.It("should fail", func() {
				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayID] = secondValidID
				req.Parameters[ctrlSvc.WithRP(KeyReplicationEnabled)] = "true"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("replication not supported for NFS"))
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

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

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

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				clientMock.On("DeleteVolume",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.DeleteVolumeResponse{}))
			})

			ginkgo.It("should fail to delete block volume", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).
					Return(gopowerstore.VolumeGroups{VolumeGroup: []gopowerstore.VolumeGroup{{ID: validGroupID, ProtectionPolicyID: validPolicyID}}}, nil)
				clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeGroupMembers"), validGroupID).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.NewNotFoundError())

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to remove volume"))
			})
		})

		ginkgo.When("delete block metro volume with replication props", func() {
			ginkgo.It("should successfully delete block metro volume", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, MetroReplicationSessionID: validSessionID}, nil)
				endMetroRequest := &gopowerstore.EndMetroVolumeOptions{DeleteRemoteVolume: true}
				clientMock.On("EndMetroVolume", mock.Anything, validBaseVolID, endMetroRequest).Return(gopowerstore.EmptyResponse(""), nil)
				clientMock.On("DeleteVolume", mock.Anything, mock.AnythingOfType("*gopowerstore.VolumeDelete"), validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}
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

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure ending metro session on volume"))
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

		ginkgo.When("array id is not found", func() {
			ginkgo.It("should fail", func() {
				req := &csi.DeleteVolumeRequest{VolumeId: invalidBlockVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find array with provided id"))
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

		ginkgo.When("get block API call fails", func() {
			ginkgo.It("should fail [GetSnapshotsByVolumeID]", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusGatewayTimeout},
				})

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure getting snapshot"))
			})

			ginkgo.It("should fail [GetVolume]", func() {
				clientMock.On("GetVolumeGroupsByVolumeID", mock.Anything, validBaseVolID).Return(gopowerstore.VolumeGroups{}, nil)
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusGatewayTimeout},
				})

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}
				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure getting volume"))
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
				gomega.Expect(res.Snapshot.SizeBytes).To(gomega.Equal(int64(validVolSize - ReservedSize)))
				gomega.Expect(res.Snapshot.SourceVolumeId).To(gomega.Equal(validBaseVolID))
			})
		})

		ginkgo.When("snapshot name is empty", func() {
			ginkgo.It("should fail", func() {
				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validBlockVolumeID,
					Name:           "",
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("name cannot be empty"))
			})
		})

		ginkgo.When("snapshot volume sourceVolID is empty", func() {
			ginkgo.It("should fail [sourceVolumeId is empty]", func() {
				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: "",
					Name:           validSnapName,
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume ID to be snapped is required"))
			})
		})

		ginkgo.When("the array ID could not found", func() {
			ginkgo.It("should return error", func() {
				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: invalidBlockVolumeID,
					Name:           validSnapName,
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find array with given ID"))
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

		ginkgo.When("there is an API error when retrieving the source", func() {
			ginkgo.It("should fail [Block]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(
					gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusGatewayTimeout},
					})

				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validBlockVolumeID,
					Name:           validSnapName,
				}
				_, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find source volume"))
			})

			ginkgo.It("should fail [NFS]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(
					gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusGatewayTimeout},
					})

				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validNfsVolumeID,
					Name:           validSnapName,
				}
				_, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find source volume"))
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

		ginkgo.When("the request is not valid", func() {
			ginkgo.It("should return error", func() {
				req := &csi.DeleteSnapshotRequest{
					SnapshotId: "",
				}

				_, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("snapshot ID to be deleted is required"))
			})
		})

		ginkgo.When("the array ID could not found", func() {
			ginkgo.It("should return error", func() {
				req := &csi.DeleteSnapshotRequest{
					SnapshotId: invalidBlockVolumeID,
				}

				_, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find array with given ID"))
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

			ginkgo.It("should successfully expand scsi volume when metro is enabled", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					MetroReplicationSessionID: validSessionID,
					Size:                      validVolSize,
				}, nil)
				clientMock.On("ModifyVolume",
					mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeModify"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)
				// Return metro session status as paused
				clientMock.On("GetReplicationSessionByID", mock.Anything, validSessionID).Return(gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStatePaused,
				}, nil).Times(1)

				req := getTypicalControllerExpandRequest(validMetroBlockVolumeID, validVolSize*2)
				res, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerExpandVolumeResponse{
					CapacityBytes:         validVolSize * 2,
					NodeExpansionRequired: true,
				}))
			})

			ginkgo.It("should return empty response when current size is already larger than requested size", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					Size: validVolSize * 3,
				}, nil)

				req := getTypicalControllerExpandRequest(validBlockVolumeID, validVolSize*2)
				res, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.ControllerExpandVolumeResponse{}))
			})

			ginkgo.It("should fail to find array ID", func() {
				req := getTypicalControllerExpandRequest(invalidBlockVolumeID, validVolSize*2)
				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to find array with ID"))
			})

			ginkgo.It("should fail to get volume info", func() {
				e := errors.New("some-api-error")
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, e)

				req := getTypicalControllerExpandRequest(validBlockVolumeID, validVolSize*2)
				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("detected SCSI protocol but wasn't able to fetch the volume info"))
			})

			ginkgo.It("should fail to modify volume", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to modify volume size"))
			})

			ginkgo.It("should fail to identify metro volume", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					Size: validVolSize,
				}, nil)

				req := getTypicalControllerExpandRequest(validMetroBlockVolumeID, validVolSize*2)
				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("metro replication session ID is empty for metro volume"))
			})

			ginkgo.It("should fail to get metro session", func() {
				e := errors.New("some-api-error")
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					MetroReplicationSessionID: validSessionID,
					Size:                      validVolSize,
				}, nil)
				clientMock.On("GetReplicationSessionByID", mock.Anything, validSessionID).Return(gopowerstore.ReplicationSession{}, e).Times(1)

				req := getTypicalControllerExpandRequest(validMetroBlockVolumeID, validVolSize*2)
				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("could not get metro replication session"))
			})

			ginkgo.It("should fail if metro session is not paused", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					MetroReplicationSessionID: validSessionID,
					Size:                      validVolSize,
				}, nil)
				// Return error state for pause failure
				clientMock.On("GetReplicationSessionByID", mock.Anything, validSessionID).Return(gopowerstore.ReplicationSession{
					ID:    validSessionID,
					State: gopowerstore.RsStateOk,
				}, nil).Times(1)

				req := getTypicalControllerExpandRequest(validMetroBlockVolumeID, validVolSize*2)
				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("metro replication session not in 'paused' state"))
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
				req := getTypicalControllerExpandRequest(validBlockVolumeID, MaxVolumeSizeBytes+1)

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
				req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
				req.VolumeContext = map[string]string{KeyFsType: "nfs"}

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
				req.VolumeContext = map[string]string{KeyFsType: "nfs"}

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
				req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
				req.VolumeContext = map[string]string{KeyFsType: "nfs"}

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
					req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
					req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
					req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
				req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
				req.VolumeContext = map[string]string{KeyFsType: "xfs"}
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(ErrUnknownAccessMode))
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
				req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
				req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
					req.VolumeContext = map[string]string{KeyFsType: "xfs"}
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
				req.VolumeContext = map[string]string{KeyFsType: "xfs"}

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
				req.VolumeContext = map[string]string{KeyFsType: "xfs"}
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

		ginkgo.When("get volumes return error", func() {
			ginkgo.It("should fail]", func() {
				clientMock.On("GetVolumes", mock.Anything).
					Return([]gopowerstore.Volume{}, gopowerstore.NewNotFoundError())

				req := &csi.ListVolumesRequest{}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to list volumes"))
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

			ginkgo.It("should return empty response", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{}, gopowerstore.NewNotFoundError())

				req := &csi.ListSnapshotsRequest{
					SnapshotId: validBlockVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(0))
			})

			ginkgo.It("should return error when GetFsSnapshot call fails", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusBadRequest,
						},
					})

				req := &csi.ListSnapshotsRequest{
					SnapshotId: validBlockVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to get block snapshot"))
			})

			ginkgo.It("should return empty response [NFS]", func() {
				clientMock.On("GetFsSnapshot", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.NewNotFoundError())

				req := &csi.ListSnapshotsRequest{
					SnapshotId: validNfsVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).ToNot(gomega.BeNil())
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(len(res.Entries)).To(gomega.Equal(0))
			})

			ginkgo.It("should return error when GetFsSnapshot call fails [NFS]", func() {
				clientMock.On("GetFsSnapshot", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusBadRequest,
						},
					})

				req := &csi.ListSnapshotsRequest{
					SnapshotId: validNfsVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to get filesystem snapshot"))
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

			ginkgo.It("should fail [incorrect array id]", func() {
				req := &csi.ListSnapshotsRequest{SnapshotId: invalidBlockVolumeID}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to get array with arrayID"))
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

			ginkgo.It("should fail [incorrect array id]", func() {
				req := &csi.ListSnapshotsRequest{SourceVolumeId: invalidBlockVolumeID}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to get array with arrayID"))
			})

			ginkgo.It("should return error when GetFsSnapshotsByVolumeID call fails", func() {
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.FileSystem{}, gopowerstore.NewNotFoundError())

				req := &csi.ListSnapshotsRequest{
					SourceVolumeId: validNfsVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to list filesystem snapshots"))
			})

			ginkgo.It("should return error when GetSnapshotsByVolumeID call fails", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.Volume{}, gopowerstore.NewNotFoundError())

				req := &csi.ListSnapshotsRequest{
					SourceVolumeId: validBlockVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to list block snapshots"))
			})
		})

		ginkgo.When("get snapshots call fails", func() {
			ginkgo.It("should fail [block]", func() {
				clientMock.On("GetSnapshots", mock.Anything).
					Return([]gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := &csi.ListSnapshotsRequest{}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to list block snapshots"))
			})

			ginkgo.It("should fail [NFS]", func() {
				clientMock.On("GetSnapshots", mock.Anything).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("GetFsSnapshots", mock.Anything).
					Return([]gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

				req := &csi.ListSnapshotsRequest{}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to list filesystem snapshots"))
			})
		})
	})

	ginkgo.Describe("calling GetCapacity()", func() {
		ginkgo.When("everything is ok and arrayip is provided", func() {
			ginkgo.It("should succeed", func() {
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
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

		ginkgo.When("resource ID is null", func() {
			ginkgo.It("should fail", func() {
				mount := new(csi.VolumeCapability_MountVolume)
				accessType := new(csi.VolumeCapability_Mount)
				accessType.Mount = mount
				_, err := ctrlSvc.ValidateVolumeCapabilities(context.Background(), &csi.ValidateVolumeCapabilitiesRequest{
					VolumeId:      "",
					VolumeContext: nil,
					VolumeCapabilities: []*csi.VolumeCapability{
						{
							AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_UNKNOWN},
							AccessType: accessType,
						},
					},
				})
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("No such volume"))
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
									Type: csi.ControllerServiceCapability_RPC_LIST_VOLUMES,
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

			ginkgo.It("should successfully discover protection group of a host-based nfs volume", func() {
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
					VolumeHandle: nfs.CsiNfsPrefixDash + validBaseVolID + "/" + firstValidID + "/" + "iscsi",
					Parameters: map[string]string{
						nfs.CsiNfsParameter: "RWX",
					},
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

				_, err := EnsureProtectionPolicyExists(context.Background(), ctrlSvc.DefaultArray(),
					validGroupName, validRemoteSystemName, validRPO)
				gomega.Expect(err).ToNot(gomega.BeNil())
			})

			ginkgo.It("should return existing policy", func() {
				clientMock.On("GetRemoteSystemByName", mock.Anything, validRemoteSystemName).
					Return(gopowerstore.RemoteSystem{ID: validRemoteSystemID, Name: validRemoteSystemName}, nil)

				clientMock.On("GetProtectionPolicyByName", mock.Anything, validPolicyName).
					Return(gopowerstore.ProtectionPolicy{ID: validPolicyID, Name: validPolicyName}, nil)

				res, err := EnsureProtectionPolicyExists(context.Background(), ctrlSvc.DefaultArray(),
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
				res, err := EnsureProtectionPolicyExists(context.Background(), ctrlSvc.DefaultArray(),
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

				res, err := EnsureReplicationRuleExists(context.Background(), ctrlSvc.DefaultArray(),
					validGroupName, validRemoteSystemID, gopowerstore.RpoFiveMinutes)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(validRuleID))
			})

			ginkgo.It("should return existing rule", func() {
				clientMock.On("GetReplicationRuleByName", mock.Anything, validRuleName).
					Return(gopowerstore.ReplicationRule{ID: validRuleID}, nil)

				res, err := EnsureReplicationRuleExists(context.Background(), ctrlSvc.DefaultArray(),
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

				res, err := EnsureReplicationRuleExists(context.Background(), ctrlSvc.DefaultArray(),
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

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID}}, nil).Once()

				clientMock.On("GetHost", mock.Anything, validHostID).Return(gopowerstore.Host{ID: validHostID, Name: validHostName}, nil)

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

		ginkgo.When("normal block volume exists on array with different state", func() {
			ginkgo.It("should fail", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, State: gopowerstore.VolumeStateEnumInitializing}, nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID}}, nil).Once()

				clientMock.On("GetHost", mock.Anything, validHostID).Return(gopowerstore.Host{ID: validHostID, Name: validHostName}, nil)

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
							Abnormal: true,
							Message:  fmt.Sprintf("Volume %s is in Initializing state", validBaseVolID),
						},
					},
				}))
			})
		})

		ginkgo.When("normal block volume does not exist on array", func() {
			ginkgo.It("should fail", func() {
				var hosts []string
				clientMock.On("GetVolume", mock.Anything, mock.Anything).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})

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

		ginkgo.When("filesystem does not exist on array", func() {
			ginkgo.It("should fail", func() {
				var hosts []string
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

		ginkgo.When("volume id is empty", func() {
			ginkgo.It("should fail", func() {
				req := &csi.ControllerGetVolumeRequest{VolumeId: ""}
				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to parse the volume id"))
			})
		})

		ginkgo.When("block API call fails", func() {
			ginkgo.It("should fail [GetVolume]", func() {
				clientMock.On("GetVolume", mock.Anything, mock.Anything).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.ControllerGetVolumeRequest{VolumeId: validBlockVolumeID}
				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find volume"))
			})

			ginkgo.It("should fail [GetHostVolumeMappingByVolumeID]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, State: gopowerstore.VolumeStateEnumReady}, nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.ControllerGetVolumeRequest{VolumeId: validBlockVolumeID}
				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to get host volume mapping for volume"))
			})

			ginkgo.It("should fail [GetHost]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, State: gopowerstore.VolumeStateEnumReady}, nil)

				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID}}, nil).Once()

				clientMock.On("GetHost", mock.Anything, validHostID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.ControllerGetVolumeRequest{VolumeId: validBlockVolumeID}
				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to get host"))
			})
		})

		ginkgo.When("filesystem API call fails", func() {
			ginkgo.It("should fail [GetFS]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.ControllerGetVolumeRequest{VolumeId: validNfsVolumeID}
				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find filesystem"))
			})

			ginkgo.It("should fail [GetNFSExportByFileSystemID]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.ControllerGetVolumeRequest{VolumeId: validNfsVolumeID}
				res, err := ctrlSvc.ControllerGetVolume(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find nfs export for filesystem"))
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
			LimitBytes:    MaxVolumeSizeBytes,
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
