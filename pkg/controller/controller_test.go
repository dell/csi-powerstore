/*
 *
 * Copyright © 2021 Dell Inc. or its subsidiaries. All Rights Reserved.
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

	"github.com/dell/csi-powerstore/mocks"
	"github.com/dell/csi-powerstore/pkg/controller"
	csictx "github.com/rexray/gocsi/context"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/pkg/array"
	"github.com/dell/csi-powerstore/pkg/common"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

const (
	validBaseVolID     = "39bb1b5f-5624-490d-9ece-18f7b28a904e"
	validBlockVolumeID = "39bb1b5f-5624-490d-9ece-18f7b28a904e/192.168.0.1/scsi"
	validNfsVolumeID   = "39bb1b5f-5624-490d-9ece-18f7b28a904e/192.168.0.2/nfs"
	validNasID         = "24aefac2-a796-47dc-886a-c73ff8c1a671"
	validVolSize       = 16 * 1024 * 1024 * 1024
	firstValidIP       = "192.168.0.1"
	secondValidIP      = "192.168.0.2"
	validNasName       = "my-nas-name"
	validSnapName      = "my-snap"
	validNodeID        = "csi-node-1a47a1b91c444a8a90193d8066669603-127.0.0.1"
	validHostName      = "csi-node-1a47a1b91c444a8a90193d8066669603"
	validHostID        = "24aefac2-a796-47dc-886a-c73ff8c1a671"
)

var (
	clientMock *gopowerstoremock.Client
	fsMock     *mocks.FsInterface
	ctrlSvc    *controller.Service
)

func TestCSIControllerService(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("ctrl-svc.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "CSIControllerService testing suite", []Reporter{junitReporter})
}

func setVariables() {
	clientMock = new(gopowerstoremock.Client)
	fsMock = new(mocks.FsInterface)

	arrays := make(map[string]*array.PowerStoreArray)
	first := &array.PowerStoreArray{
		Endpoint:      "https://192.168.0.1/api/rest",
		Username:      "admin",
		Password:      "pass",
		BlockProtocol: common.ISCSITransport,
		Insecure:      true,
		IsDefault:     true,
		Client:        clientMock,
		IP:            firstValidIP,
	}
	second := &array.PowerStoreArray{
		Endpoint:      "https://192.168.0.2/api/rest",
		Username:      "admin",
		Password:      "pass",
		NasName:       validNasName,
		BlockProtocol: common.NoneTransport,
		Insecure:      true,
		Client:        clientMock,
		IP:            secondValidIP,
	}

	arrays[firstValidIP] = first
	arrays[secondValidIP] = second

	ctrlSvc = &controller.Service{Fs: fsMock}
	ctrlSvc.SetArrays(arrays)
	ctrlSvc.SetDefaultArray(first)
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

var _ = Describe("CSIControllerService", func() {
	BeforeEach(func() {
		setVariables()
	})

	Describe("calling CreateVolume()", func() {
		When("creating block volume", func() {
			It("should successfully create block volume", func() {
				clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayIP] = firstValidIP
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: firstValidIP,
						},
					},
				}))
			})
		})

		When("creating nfs volume", func() {
			It("should successfully create nfs volume", func() {
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)
				clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayIP] = secondValidIP

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidIP, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: secondValidIP,
						},
					},
				}))
			})
		})

		When("volume name already in use", func() {
			It("should return existing volume [Block]", func() {
				volName := "my-vol"
				clientMock.On("CreateVolume", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
							ErrorCode:  gopowerstore.VolumeNameAlreadyUseErrorCode,
						},
					})

				clientMock.On("GetVolumeByName", mock.Anything, volName).Return(gopowerstore.Volume{
					ID:   validBaseVolID,
					Name: volName,
					Size: validVolSize,
				}, nil)

				req := getTypicalCreateVolumeRequest(volName, validVolSize)
				req.Parameters[common.KeyArrayIP] = firstValidIP
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: firstValidIP,
						},
					},
				}))
			})

			It("should return existing volume [NFS]", func() {
				volName := "my-vol"
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)

				clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusUnprocessableEntity,
						ErrorCode:  gopowerstore.FilesystemNameAlreadyUseErrorCode,
					},
				})

				clientMock.On("GetFSByName", mock.Anything, volName).Return(gopowerstore.FileSystem{
					ID:        validBaseVolID,
					Name:      volName,
					SizeTotal: validVolSize,
				}, nil)

				req := getTypicalCreateVolumeNFSRequest(volName, validVolSize)
				req.Parameters[common.KeyArrayIP] = secondValidIP
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidIP, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: secondValidIP,
						},
					},
				}))
			})

			When("existing volume size is smaller", func() {
				It("should fail [Block]", func() {
					volName := "my-vol"
					clientMock.On("CreateVolume", mock.Anything, mock.Anything).
						Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusUnprocessableEntity,
								ErrorCode:  gopowerstore.VolumeNameAlreadyUseErrorCode,
							},
						})

					clientMock.On("GetVolumeByName", mock.Anything, volName).Return(gopowerstore.Volume{
						ID:   validBaseVolID,
						Name: volName,
						Size: validVolSize / 2,
					}, nil)

					req := getTypicalCreateVolumeRequest(volName, validVolSize)
					req.Parameters[common.KeyArrayIP] = firstValidIP
					res, err := ctrlSvc.CreateVolume(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("volume '" + volName + "' already exists but is incompatible volume size"),
					)
				})

				It("should fail [NFS]", func() {
					volName := "my-vol"
					clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, nil)

					clientMock.On("CreateFS", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
							ErrorCode:  gopowerstore.FilesystemNameAlreadyUseErrorCode,
						},
					})

					clientMock.On("GetFSByName", mock.Anything, volName).Return(gopowerstore.FileSystem{
						ID:        validBaseVolID,
						Name:      volName,
						SizeTotal: validVolSize / 2,
					}, nil)

					req := getTypicalCreateVolumeNFSRequest(volName, validVolSize)
					req.Parameters[common.KeyArrayIP] = secondValidIP
					res, err := ctrlSvc.CreateVolume(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(
						ContainSubstring("filesystem '" + volName + "' already exists but is incompatible volume size"),
					)
				})
			})
		})

		When("creating volume from snapshot", func() {
			It("should create volume using snapshot as a source [Block]", func() {
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
				req.Parameters[common.KeyArrayIP] = firstValidIP

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: firstValidIP,
						},
						ContentSource: contentSource,
					},
				}))
			})

			It("should create volume using snapshot as a source [NFS]", func() {
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
				req.Parameters[common.KeyArrayIP] = secondValidIP

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidIP, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: secondValidIP,
						},
						ContentSource: contentSource,
					},
				}))
			})
		})

		When("cloning volume", func() {
			It("should create volume using volume as a source [Block]", func() {
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
				req.Parameters[common.KeyArrayIP] = firstValidIP

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: firstValidIP,
						},
						ContentSource: contentSource,
					},
				}))
			})

			It("should create volume using volume as a source [NFS]", func() {
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
				req.Parameters[common.KeyArrayIP] = secondValidIP

				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, secondValidIP, "nfs"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: secondValidIP,
						},
						ContentSource: contentSource,
					},
				}))
			})
		})

		When("there is no array IP in storage class", func() {
			It("should use default array", func() {
				clientMock.On("CreateVolume", mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{ID: validBaseVolID}, nil)

				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayIP: firstValidIP,
						},
					},
				}))
			})
		})

		When("there array IP passed to storage class is not config", func() {
			It("should fail", func() {
				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.Parameters[common.KeyArrayIP] = "127.0.0.1"
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("can't find array with provided ip"))
			})
		})

		When("requesting block access from nfs volume", func() {
			It("should fail [new key]", func() {
				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.VolumeCapabilities[0].AccessType = &csi.VolumeCapability_Block{
					Block: &csi.VolumeCapability_BlockVolume{},
				}
				req.Parameters[common.KeyArrayIP] = secondValidIP
				req.Parameters[controller.KeyFsType] = "nfs"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("raw block requested from NFS Volume"))
			})

			It("should fail [old key]", func() {
				req := getTypicalCreateVolumeNFSRequest("my-vol", validVolSize)
				req.VolumeCapabilities[0].AccessType = &csi.VolumeCapability_Block{
					Block: &csi.VolumeCapability_BlockVolume{},
				}
				req.Parameters[common.KeyArrayIP] = secondValidIP
				req.Parameters[controller.KeyFsTypeOld] = "nfs"

				res, err := ctrlSvc.CreateVolume(context.Background(), req)
				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("raw block requested from NFS Volume"))
			})
		})

		When("volume name is empty", func() {
			It("should fail", func() {
				req := getTypicalCreateVolumeRequest("", validVolSize)
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("name cannot be empty"))
			})
		})

		When("volume size is incorrect", func() {
			It("should fail", func() {
				req := getTypicalCreateVolumeRequest("my-vol", validVolSize)
				req.CapacityRange.LimitBytes = -1000
				req.CapacityRange.RequiredBytes = -1000
				res, err := ctrlSvc.CreateVolume(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring(
					fmt.Sprintf("bad capacity: volume size bytes %d and limit size bytes: %d must not be negative", req.CapacityRange.RequiredBytes, req.CapacityRange.RequiredBytes),
				))
			})
		})
	})

	Describe("calling DeleteVolume()", func() {
		When("deleting block volume", func() {
			It("should successfully delete block volume", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("DeleteVolume",
					mock.AnythingOfType("*context.emptyCtx"),
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteVolumeResponse{}))
			})
		})

		When("deleting nfs volume", func() {
			It("should successfully delete nfs volume", func() {
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.FileSystem{}, nil)
				clientMock.On("DeleteFS",
					mock.AnythingOfType("*context.emptyCtx"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteVolumeResponse{}))
			})
		})

		When("volume id is not specified", func() {
			It("should fail", func() {
				req := &csi.DeleteVolumeRequest{}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)
				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("volume ID is required"))
			})
		})

		When("there is no array ip in volume id", func() {
			It("should check storage using default array [no volume found]", func() {
				clientMock.On("GetVolume", context.Background(), validBaseVolID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
							ErrorCode:  gopowerstore.InstanceWasNotFound,
						},
					})
				clientMock.On("GetFS", context.Background(), validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
							ErrorCode:  gopowerstore.InstanceWasNotFound,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteVolumeResponse{}))
			})

			It("should check storage using default array [unexpected api error]", func() {
				e := errors.New("api-error")
				clientMock.On("GetVolume", context.Background(), validBaseVolID).
					Return(gopowerstore.Volume{}, e)
				clientMock.On("GetFS", context.Background(), validBaseVolID).
					Return(gopowerstore.FileSystem{}, e)

				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("failure checking volume status"))
			})
		})

		When("when trying delete volume with existing snapshots", func() {
			It("should fail [Block]", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.Volume{
						{
							ID:   "0",
							Name: "name",
						},
					}, nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("snapshots based on this volume still exist"))
			})

			It("should fail [NFS]", func() {
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.FileSystem{
						{
							ID:   "0",
							Name: "name",
						},
					}, nil)

				req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("snapshots based on this volume still exist"))
			})
		})

		When("volume does not exist", func() {
			It("should succeed [Block]", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("DeleteVolume",
					mock.AnythingOfType("*context.emptyCtx"),
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.InstanceWasNotFound,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteVolumeResponse{}))
			})

			It("should succeed [NFS]", func() {
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.FileSystem{}, nil)
				clientMock.On("DeleteFS",
					mock.AnythingOfType("*context.emptyCtx"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.InstanceWasNotFound,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteVolumeResponse{}))
			})
		})

		When("block volume still attached to host", func() {
			It("should fail", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).Return([]gopowerstore.Volume{}, nil)
				clientMock.On("DeleteVolume",
					mock.AnythingOfType("*context.emptyCtx"),
					mock.AnythingOfType("*gopowerstore.VolumeDelete"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusUnprocessableEntity,
							ErrorCode:  gopowerstore.VolumeAttachedToHost,
						},
					})

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("volume with ID '" + validBaseVolID + "' is still attached to host"))
			})
		})

		When("can not connect to API", func() {
			It("should fail [Block]", func() {
				e := errors.New("can't connect")
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.Volume{}, e)

				req := &csi.DeleteVolumeRequest{VolumeId: validBlockVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("failure getting snapshot"))
			})

			It("should fail [NFS]", func() {
				e := errors.New("can't connect")
				clientMock.On("GetFsSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.FileSystem{}, e)

				req := &csi.DeleteVolumeRequest{VolumeId: validNfsVolumeID}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("failure getting snapshot"))
			})
		})

		When("volume id contains unsupported protocol", func() {
			It("should fail", func() {
				req := &csi.DeleteVolumeRequest{VolumeId: validBaseVolID + "/" + firstValidIP + "/smb"}

				res, err := ctrlSvc.DeleteVolume(context.Background(), req)

				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("can't figure out protocol"))
			})
		})
	})

	Describe("calling CreateSnapshot()", func() {
		When("parameters are correct", func() {
			It("should successfully create new snapshot [Block]", func() {
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

				Expect(err).To(BeNil())
				Expect(res.Snapshot.SnapshotId).To(Equal("new-snap-id/192.168.0.1/scsi"))
				Expect(res.Snapshot.SizeBytes).To(Equal(int64(validVolSize)))
				Expect(res.Snapshot.SourceVolumeId).To(Equal(validBaseVolID))
			})

			It("should successfully create new snapshot [NFS]", func() {
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

				Expect(err).To(BeNil())
				Expect(res.Snapshot.SnapshotId).To(Equal("new-snap-id/192.168.0.2/nfs"))
				Expect(res.Snapshot.SizeBytes).To(Equal(int64(validVolSize - controller.ReservedSize)))
				Expect(res.Snapshot.SourceVolumeId).To(Equal(validBaseVolID))
			})
		})

		When("snapshot name already taken", func() {
			It("should fail [sourceVolumeId != snap.sourceVolumeId]", func() {
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

				Expect(res).To(BeNil())
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("snapshot with name '%s' exists, but SourceVolumeId %s doesn't match", "my-snap", validBaseVolID)))
			})

			It("should succeed [same sourceVolumeId]", func() {
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

				Expect(err).To(BeNil())
				Expect(res.Snapshot.SnapshotId).To(Equal("old-snap-id/192.168.0.1/scsi"))
				Expect(res.Snapshot.SizeBytes).To(Equal(int64(validVolSize)))
				Expect(res.Snapshot.SourceVolumeId).To(Equal(validBaseVolID))
			})
		})

		When("there is an API error when creating snapshot", func() {
			It("should return that error", func() {
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
						ErrorCode:  gopowerstore.UnknownVolumeErrorCode,
						Message:    "something went wrong",
					},
				})

				req := &csi.CreateSnapshotRequest{
					SourceVolumeId: validBlockVolumeID,
					Name:           validSnapName,
				}

				res, err := ctrlSvc.CreateSnapshot(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("something went wrong"))
			})
		})
	})

	Describe("calling DeleteSnapshot()", func() {
		When("parameters are correct", func() {
			It("should successfully delete snapshot [Block]", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, nil)

				clientMock.On("DeleteSnapshot", mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"), validBaseVolID).Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validBlockVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteSnapshotResponse{}))
			})

			It("should successfully delete snapshot [NFS]", func() {
				clientMock.On("GetFsSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{}, nil)

				clientMock.On("DeleteFsSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validNfsVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteSnapshotResponse{}))
			})
		})

		When("there is no snapshot", func() {
			It("should return no error [Block]", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, nil)

				clientMock.On("DeleteSnapshot", mock.Anything,
					mock.AnythingOfType("*gopowerstore.VolumeDelete"), validBaseVolID).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusUnprocessableEntity,
						ErrorCode:  gopowerstore.InstanceWasNotFound,
					},
				})

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validBlockVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteSnapshotResponse{}))
			})

			It("should return no error [NFS]", func() {
				clientMock.On("GetFsSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{}, nil)

				clientMock.On("DeleteFsSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusUnprocessableEntity,
						ErrorCode:  gopowerstore.InstanceWasNotFound,
					},
				})

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validNfsVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteSnapshotResponse{}))
			})
		})

		When("there is no such source volume", func() {
			It("should return no error", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusUnprocessableEntity,
						ErrorCode:  gopowerstore.InstanceWasNotFound,
					},
				})

				req := &csi.DeleteSnapshotRequest{
					SnapshotId: validBlockVolumeID,
				}

				res, err := ctrlSvc.DeleteSnapshot(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.DeleteSnapshotResponse{}))
			})
		})
	})

	Describe("calling ControllerExpandVolume()", func() {
		When("expanding scsi volume", func() {
			It("should successfully expand scsi volume", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
					Size: validVolSize,
				}, nil)
				clientMock.On("ModifyVolume",
					mock.AnythingOfType("*context.emptyCtx"),
					mock.AnythingOfType("*gopowerstore.VolumeModify"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := getTypicalControllerExpandRequest(validBlockVolumeID, validVolSize*2)

				res, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerExpandVolumeResponse{
					CapacityBytes:         validVolSize * 2,
					NodeExpansionRequired: true,
				}))
			})

			When("not able to get volume info", func() {
				It("should fail", func() {
					e := errors.New("some-api-error")
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, e)

					req := getTypicalControllerExpandRequest(validBlockVolumeID, validVolSize*2)
					_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("detected SCSI protocol but wasn't able to fetch the volume info"))
				})
			})

			When("not able to modify volume", func() {
				It("should fail", func() {
					e := errors.New("some-api-error")
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{
						Size: validVolSize,
					}, nil)
					clientMock.On("ModifyVolume",
						mock.AnythingOfType("*context.emptyCtx"),
						mock.AnythingOfType("*gopowerstore.VolumeModify"),
						validBaseVolID).
						Return(gopowerstore.EmptyResponse(""), e)

					req := getTypicalControllerExpandRequest(validBlockVolumeID, validVolSize*2)

					_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring(e.Error()))
				})
			})
		})

		When("expanding nfs volume", func() {
			It("should successfully expand nfs volume", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{
					SizeTotal: validVolSize,
				}, nil)
				clientMock.On("ModifyFS",
					mock.AnythingOfType("*context.emptyCtx"),
					mock.AnythingOfType("*gopowerstore.FSModify"),
					validBaseVolID).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := getTypicalControllerExpandRequest(validNfsVolumeID, validVolSize*2)

				res, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerExpandVolumeResponse{
					CapacityBytes:         validVolSize * 2,
					NodeExpansionRequired: false,
				}))
			})

			When("not able to modify filesystem", func() {
				It("should fail", func() {
					e := errors.New("some-api-error")
					clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{
						SizeTotal: validVolSize,
					}, nil)
					clientMock.On("ModifyFS",
						mock.AnythingOfType("*context.emptyCtx"),
						mock.AnythingOfType("*gopowerstore.FSModify"),
						validBaseVolID).
						Return(gopowerstore.EmptyResponse(""), e)

					req := getTypicalControllerExpandRequest(validNfsVolumeID, validVolSize*2)

					_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)

					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring(e.Error()))
				})
			})
		})

		When("volume id is incorrect", func() {
			It("should fail", func() {
				e := errors.New("api-error")
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, e)
				clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{}, e)

				req := getTypicalControllerExpandRequest(validBaseVolID, validVolSize*2)

				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to parse the volume id"))
			})
		})

		When("requested size exceeds limit", func() {
			It("should fail", func() {
				req := getTypicalControllerExpandRequest(validBlockVolumeID, controller.MaxVolumeSizeBytes+1)

				_, err := ctrlSvc.ControllerExpandVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("volume exceeds allowed limit"))
			})
		})
	})

	Describe("calling ControllerPublishVolume()", func() {
		fsName := "testFS"
		nfsID := "1ae5edac1-a796-886a-47dc-c72a3j8clw031"
		nasID := "some-nas-id"
		interfaceID := "215as1223-d124-ss1h-njh4-c72a3j8clw031"

		When("parameters are correct", func() {
			It("should succeed [Block]", func() {
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

				clientMock.On("GetFCPorts", mock.Anything).
					Return([]gopowerstore.FcPort{
						{
							IsLinkUp: true,
							Wwn:      "58:cc:f0:93:48:a0:03:a3",
						},
					}, nil)

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"PORTAL0":     "192.168.1.1:3260",
						"TARGET0":     "iqn",
						"DEVICE_WWN":  "68ccf098003ceb5e4577a20be6d11bf9",
						"LUN_ADDRESS": "1",
						"FCWWPN0":     "58ccf09348a003a3",
					},
				}))
			})

			It("should succeed [NFS]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID:          validBaseVolID,
						Name:        fsName,
						NasServerID: nasID,
					}, nil)

				apiError := gopowerstore.NewAPIError()
				apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
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
					AddHosts: &[]string{"127.0.0.1"},
				}, nfsID).Return(gopowerstore.CreateResponse{}, nil)

				clientMock.On("GetNAS", mock.Anything, nasID).
					Return(gopowerstore.NAS{
						Name:                            validNasName,
						CurrentPreferredIPv4InterfaceId: interfaceID,
					}, nil)

				clientMock.On("GetFileInterface", mock.Anything, interfaceID).
					Return(gopowerstore.FileInterface{IpAddress: secondValidIP}, nil)

				req := getTypicalControllerPublishVolumeRequest("multiple-writer", validNodeID, validNfsVolumeID)
				req.VolumeCapability = getVolumeCapabilityNFS()
				req.VolumeContext = map[string]string{controller.KeyFsType: "nfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"nasName":       validNasName,
						"NfsExportPath": secondValidIP + ":/",
					},
				}))
			})
		})

		When("host name does not contain ip", func() {
			It("should truncate ip from kubeID and succeed [Block]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

				By("truncating ip", func() {
					clientMock.On("GetHostByName", mock.Anything, validNodeID).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
								ErrorCode:  gopowerstore.NoHostObjectFoundCode,
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

				clientMock.On("GetFCPorts", mock.Anything).
					Return([]gopowerstore.FcPort{
						{
							Wwn: "58:cc:f0:93:48:a0:03:a3",
						},
					}, nil)

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"PORTAL0":     "192.168.1.1:3260",
						"TARGET0":     "iqn",
						"DEVICE_WWN":  "68ccf098003ceb5e4577a20be6d11bf9",
						"LUN_ADDRESS": "1",
					},
				}))
			})
		})

		When("using nfs nat feature", func() {
			It("should succeed", func() {
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
				apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
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
					AddHosts: &[]string{"127.0.0.1", externalAccess},
				}, nfsID).Return(gopowerstore.CreateResponse{}, nil)

				clientMock.On("GetNAS", mock.Anything, nasID).
					Return(gopowerstore.NAS{
						Name:                            validNasName,
						CurrentPreferredIPv4InterfaceId: interfaceID,
					}, nil)

				clientMock.On("GetFileInterface", mock.Anything, interfaceID).
					Return(gopowerstore.FileInterface{IpAddress: secondValidIP}, nil)

				req := getTypicalControllerPublishVolumeRequest("multi-writer", validNodeID, validNfsVolumeID)
				req.VolumeCapability = getVolumeCapabilityNFS()
				req.VolumeContext = map[string]string{controller.KeyFsType: "nfs"}

				res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"nasName":       validNasName,
						"NfsExportPath": secondValidIP + ":/",
					},
				}))
			})
		})

		When("volume is already attached to some host", func() {
			When("mapping has same hostID", func() {
				It("should succeed", func() {
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

					clientMock.On("GetFCPorts", mock.Anything).
						Return([]gopowerstore.FcPort{
							{
								Wwn: "58:cc:f0:93:48:a0:03:a3",
							},
						}, nil)

					req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
					req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

					res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

					Expect(err).To(BeNil())
					Expect(res).To(Equal(&csi.ControllerPublishVolumeResponse{
						PublishContext: map[string]string{
							"PORTAL0":     "192.168.1.1:3260",
							"TARGET0":     "iqn",
							"DEVICE_WWN":  "68ccf098003ceb5e4577a20be6d11bf9",
							"LUN_ADDRESS": "1",
						},
					}))
				})
			})

			When("mapping hostID is different", func() {
				prevNodeID := "prev-id"
				It("should fail [single-writer]", func() {
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

					clientMock.On("GetFCPorts", mock.Anything).
						Return([]gopowerstore.FcPort{
							{
								Wwn: "58:cc:f0:93:48:a0:03:a3",
							},
						}, nil)

					req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
					req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

					res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

					Expect(res).To(BeNil())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring(
						fmt.Sprintf("volume already present in a different lun mapping on node '%s", prevNodeID)))
				})

				It("should succeed [multi-writer]", func() {
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

					clientMock.On("GetFCPorts", mock.Anything).
						Return([]gopowerstore.FcPort{
							{
								Wwn: "58:cc:f0:93:48:a0:03:a3",
							},
						}, nil)

					req := getTypicalControllerPublishVolumeRequest("multiple-writer", validNodeID, validBlockVolumeID)
					req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

					res, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

					Expect(err).To(BeNil())
					Expect(res).To(Equal(&csi.ControllerPublishVolumeResponse{
						PublishContext: map[string]string{
							"PORTAL0":     "192.168.1.1:3260",
							"TARGET0":     "iqn",
							"DEVICE_WWN":  "68ccf098003ceb5e4577a20be6d11bf9",
							"LUN_ADDRESS": "1",
						},
					}))
				})
			})
		})

		When("volume id is empty", func() {
			It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.VolumeId = ""

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("volume ID is required"))
			})
		})

		When("volume capability is missing", func() {
			It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.VolumeCapability = nil

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("volume capability is required"))
			})
		})

		When("access mode is missing", func() {
			It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.VolumeCapability.AccessMode = nil

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("access mode is required"))
			})
		})

		When("access mode is unknown", func() {
			It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.VolumeCapability.AccessMode.Mode = csi.VolumeCapability_AccessMode_UNKNOWN

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring(controller.ErrUnknownAccessMode))
			})
		})

		When("kube node id is empty", func() {
			It("should fail", func() {
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)

				req.NodeId = ""

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("node ID is required"))
			})
		})

		When("volume does not exist", func() {
			It("should fail [Block]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.UnknownVolumeErrorCode,
						},
					})

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("volume with ID '%s' not found", validBaseVolID)))
			})

			It("should fail [NFS]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.UnknownVolumeErrorCode,
						},
					})

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validNfsVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("volume with ID '%s' not found", validBaseVolID)))
			})

			When("using v1.2 volume id", func() {
				It("should fail", func() {
					e := errors.New("api-error")
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).Return(gopowerstore.Volume{}, e)
					clientMock.On("GetFS", mock.Anything, validBaseVolID).Return(gopowerstore.FileSystem{}, e)

					req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBaseVolID)
					req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}
					req.VolumeCapability = nil

					_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("failure checking volume status"))
				})
			})
		})

		When("node id is not valid", func() {
			It("should fail [Block]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)

				clientMock.On("GetHostByName", mock.Anything, validNodeID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.NoHostObjectFoundCode,
						},
					}).Once()

				clientMock.On("GetHostByName", mock.Anything, validHostName).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.NoHostObjectFoundCode,
						},
					}).Once()

				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID, validBlockVolumeID)
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("host with k8s node ID '" + validNodeID + "' not found"))
			})
		})

		When("ip is incorrect", func() {
			It("should fail", func() {
				ip := "127.0.0.1" // we don't have array with this ip
				req := getTypicalControllerPublishVolumeRequest("single-writer", validNodeID,
					validBaseVolID+"/"+ip+"/scsi")
				req.VolumeContext = map[string]string{controller.KeyFsType: "xfs"}
				req.VolumeCapability = nil

				_, err := ctrlSvc.ControllerPublishVolume(context.Background(), req)

				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to find array with given IP"))
			})
		})
	})

	Describe("calling ControllerUnpublishVolume()", func() {
		When("parameters are correct", func() {
			It("should succeed [Block]", func() {
				clientMock.On("GetHostByName", mock.Anything, validNodeID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.NoHostObjectFoundCode,
						},
					}).Once()

				clientMock.On("GetHostByName", mock.Anything, validHostName).
					Return(gopowerstore.Host{ID: validHostID}, nil).Once()

				clientMock.On("DetachVolumeFromHost", mock.Anything, validHostID, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})

			It("should succeed [NFS]", func() {
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
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})
		})

		When("volume do not exist", func() {
			It("should succeed", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.InstanceWasNotFound,
						},
					})

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})
		})

		When("volume id is empty", func() {
			It("should fail", func() {
				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: "", NodeId: validNodeID}

				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("volume ID is required"))
			})
		})

		When("node id is empty", func() {
			It("should fail", func() {
				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: ""}

				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("node ID is required"))
			})
		})

		When("using v1.2 volumes", func() {
			It("should succeed [Block]", func() {
				By("using default array", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{}, nil)
				})

				clientMock.On("GetHostByName", mock.Anything, validNodeID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							ErrorCode:  gopowerstore.NoHostObjectFoundCode,
						},
					}).Once()

				clientMock.On("GetHostByName", mock.Anything, validHostName).
					Return(gopowerstore.Host{ID: validHostID}, nil).Once()

				clientMock.On("DetachVolumeFromHost", mock.Anything, validHostID, mock.Anything).
					Return(gopowerstore.EmptyResponse(""), nil)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBaseVolID, NodeId: validNodeID}

				res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})

			It("should succeed [NFS]", func() {
				By("using default array", func() {
					clientMock.On("GetVolume", mock.Anything, validBaseVolID).
						Return(gopowerstore.Volume{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
								ErrorCode:  gopowerstore.InstanceWasNotFound,
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
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerUnpublishVolumeResponse{}))
			})

			When("volume does not exist", func() {
				It("should succeed", func() {
					By("not finding volume or filesystem", func() {
						clientMock.On("GetVolume", mock.Anything, validBaseVolID).
							Return(gopowerstore.Volume{}, gopowerstore.APIError{
								ErrorMsg: &api.ErrorMsg{
									StatusCode: http.StatusNotFound,
									ErrorCode:  gopowerstore.InstanceWasNotFound,
								},
							})

						clientMock.On("GetFS", mock.Anything, validBaseVolID).
							Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
								ErrorMsg: &api.ErrorMsg{
									StatusCode: http.StatusNotFound,
									ErrorCode:  gopowerstore.InstanceWasNotFound,
								},
							}).Once()
					})

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBaseVolID, NodeId: validNodeID}

					res, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)

					Expect(err).To(BeNil())
					Expect(res).To(Equal(&csi.ControllerUnpublishVolumeResponse{}))
				})
			})
		})

		When("kube node id is not correct", func() {
			When("no IP found", func() {
				It("should fail [Block]", func() {
					nodeID := "not-valid-id"
					clientMock.On("GetHostByName", mock.Anything, nodeID).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
								ErrorCode:  gopowerstore.NoHostObjectFoundCode,
							},
						}).Once()

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: nodeID}

					_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("can't find IP in nodeID"))
				})

				It("should fail [NFS]", func() {
					nodeID := "not-valid-id"
					clientMock.On("GetFS", mock.Anything, validBaseVolID).
						Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: nodeID}

					_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("can't find IP in nodeID"))
				})

			})

			When("host does not exist", func() {
				It("should fail", func() {
					clientMock.On("GetHostByName", mock.Anything, validNodeID).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
								ErrorCode:  gopowerstore.NoHostObjectFoundCode,
							},
						}).Once()

					clientMock.On("GetHostByName", mock.Anything, validHostName).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
								ErrorCode:  gopowerstore.NoHostObjectFoundCode,
							},
						}).Once()

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: validNodeID}

					_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("host with k8s node ID '" + validNodeID + "' not found"))
				})
			})

			When("fail to check host", func() {
				It("should fail", func() {
					e := errors.New("some-api-error")
					clientMock.On("GetHostByName", mock.Anything, validNodeID).
						Return(gopowerstore.Host{}, e).Once()

					req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validBlockVolumeID, NodeId: validNodeID}

					_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("failure checking host '" + validNodeID + "' status for volume unpublishing"))
				})
			})
		})

		When("can not check nfs export status", func() {
			It("should fail", func() {
				e := errors.New("some-api-error")
				clientMock.On("GetFS", mock.Anything, validBaseVolID).
					Return(gopowerstore.FileSystem{
						ID: validBaseVolID,
					}, nil)

				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
					Return(gopowerstore.NFSExport{}, e)

				req := &csi.ControllerUnpublishVolumeRequest{VolumeId: validNfsVolumeID, NodeId: validNodeID}
				_, err := ctrlSvc.ControllerUnpublishVolume(context.Background(), req)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failure checking nfs export status for volume unpublishing"))
			})
		})

		When("failed to remove hosts", func() {
			It("should fail", func() {
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
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failure when removing new host to nfs export"))
			})
		})
	})

	Describe("calling ListVolumes()", func() {
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

		When("there is no parameters", func() {
			It("should return all volumes from both arrays", func() {
				mockCalls()

				req := &csi.ListVolumesRequest{}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				Expect(res).To(Equal(&csi.ListVolumesResponse{
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
				Expect(err).To(BeNil())
			})
		})

		When("passing max entries", func() {
			It("should return 'n' entries and next token", func() {
				mockCalls()

				req := &csi.ListVolumesRequest{
					MaxEntries: 1,
				}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				Expect(res).To(Equal(&csi.ListVolumesResponse{
					Entries: []*csi.ListVolumesResponse_Entry{
						{
							Volume: &csi.Volume{
								VolumeId: "arr1-id1",
							},
						},
					},
					NextToken: "1",
				}))
				Expect(err).To(BeNil())
			})
		})

		When("using next token", func() {
			It("should return volumes starting from token", func() {
				mockCalls()

				req := &csi.ListVolumesRequest{
					MaxEntries:    1,
					StartingToken: "1",
				}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				Expect(res).To(Equal(&csi.ListVolumesResponse{
					Entries: []*csi.ListVolumesResponse_Entry{
						{
							Volume: &csi.Volume{
								VolumeId: "arr1-id2",
							},
						},
					},
					NextToken: "2",
				}))
				Expect(err).To(BeNil())
			})
		})

		When("using wrong token", func() {
			It("should fail [not parsable]", func() {
				token := "as!512$25%!_"
				req := &csi.ListVolumesRequest{
					MaxEntries:    1,
					StartingToken: token,
				}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to parse StartingToken: %v into uint32", token))
			})

			It("shoud fail [too high]", func() {
				tokenInt := 200
				token := "200"

				mockCalls()

				req := &csi.ListVolumesRequest{
					MaxEntries:    1,
					StartingToken: token,
				}
				res, err := ctrlSvc.ListVolumes(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("startingToken=%d > len(volumes)=%d", tokenInt, 3))
			})
		})
	})

	Describe("calling ListSnapshots()", func() {
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
			clientMock.On("GetSnapshots", mock.Anything).
				Return([]gopowerstore.Volume{
					{
						ID:   "arr2-id1",
						Name: "arr2-snap1",
					},
				}, nil).Once()
		}

		mockCantParseVolumeID := func(id string) {
			clientMock.On("GetVolume", mock.Anything, id).
				Return(gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
						ErrorCode:  gopowerstore.InstanceWasNotFound,
					},
				}).Once()

			clientMock.On("GetFS", mock.Anything, id).
				Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
						ErrorCode:  gopowerstore.InstanceWasNotFound,
					},
				}).Once()
		}

		When("there is no parameters", func() {
			It("should return all volumes from both arrays", func() {
				mockCalls()

				req := &csi.ListSnapshotsRequest{}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).ToNot(BeNil())
				Expect(res.Entries).ToNot(BeNil())
				Expect(len(res.Entries)).To(Equal(3))
				Expect(res.Entries[0].Snapshot.SnapshotId).To(Equal("arr1-id1"))
				Expect(res.Entries[1].Snapshot.SnapshotId).To(Equal("arr1-id2"))
				Expect(res.Entries[2].Snapshot.SnapshotId).To(Equal("arr2-id1"))
			})
		})

		When("passing max entries", func() {
			It("should return 'n' entries and next token", func() {
				mockCalls()

				req := &csi.ListSnapshotsRequest{
					MaxEntries: 1,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).ToNot(BeNil())
				Expect(res.Entries).ToNot(BeNil())
				Expect(len(res.Entries)).To(Equal(1))
				Expect(res.Entries[0].Snapshot.SnapshotId).To(Equal("arr1-id1"))
				Expect(res.NextToken).To(Equal("1"))
			})
		})

		When("using next token", func() {
			It("should return volumes starting from token", func() {
				mockCalls()

				req := &csi.ListSnapshotsRequest{
					MaxEntries:    1,
					StartingToken: "1",
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res).ToNot(BeNil())
				Expect(res.Entries).ToNot(BeNil())
				Expect(len(res.Entries)).To(Equal(1))
				Expect(res.Entries[0].Snapshot.SnapshotId).To(Equal("arr1-id2"))
				Expect(res.NextToken).To(Equal("2"))
			})
		})

		When("using wrong token", func() {
			It("should fail [not parsable]", func() {
				token := "as!512$25%!_"
				req := &csi.ListSnapshotsRequest{
					MaxEntries:    1,
					StartingToken: token,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to parse StartingToken: %v into uint32", token))
			})

			It("shoud fail [too high]", func() {
				tokenInt := 200
				token := "200"

				mockCalls()

				req := &csi.ListSnapshotsRequest{
					MaxEntries:    1,
					StartingToken: token,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("startingToken=%d > len(volumes)=%d", tokenInt, 3))
			})
		})

		When("passing snapshot id", func() {
			It("should return existing snapshot", func() {
				clientMock.On("GetSnapshot", mock.Anything, validBaseVolID).
					Return(gopowerstore.Volume{ID: validBaseVolID}, nil)
				req := &csi.ListSnapshotsRequest{
					SnapshotId: validBlockVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				Expect(res).ToNot(BeNil())
				Expect(err).To(BeNil())
				Expect(len(res.Entries)).To(Equal(1))
				Expect(res.Entries[0].Snapshot.SnapshotId).To(Equal(validBlockVolumeID))
			})

			It("should fail [incorrect id]", func() {
				randomID := "something-random"

				By("checking with default array", func() {
					mockCantParseVolumeID(randomID)
				})

				req := &csi.ListSnapshotsRequest{
					SnapshotId: randomID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ListSnapshotsResponse{}))
			})
		})

		When("passing source volume id", func() {
			It("should return all snapshot of that volume", func() {
				clientMock.On("GetSnapshotsByVolumeID", mock.Anything, validBaseVolID).
					Return([]gopowerstore.Volume{{ID: "snap-id-1"}, {ID: "snap-id-2"}}, nil)
				req := &csi.ListSnapshotsRequest{
					SourceVolumeId: validBlockVolumeID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				Expect(res).ToNot(BeNil())
				Expect(err).To(BeNil())
				Expect(len(res.Entries)).To(Equal(2))
				Expect(res.Entries[0].Snapshot.SnapshotId).To(Equal("snap-id-1"))
				Expect(res.Entries[1].Snapshot.SnapshotId).To(Equal("snap-id-2"))
			})

			It("should fail [incorrect id]", func() {
				randomID := "something-random"

				By("checking with default array", func() {
					mockCantParseVolumeID(randomID)
				})

				req := &csi.ListSnapshotsRequest{
					SourceVolumeId: randomID,
				}
				res, err := ctrlSvc.ListSnapshots(context.Background(), req)
				Expect(res).To(Equal(&csi.ListSnapshotsResponse{}))
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("calling GetCapacity()", func() {
		When("everything is ok and arrayip is provided", func() {
			It("should succeed", func() {
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{
						"arrayIP": "192.168.0.1",
					},
				}
				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res.AvailableCapacity).To(Equal(int64(123123123)))
			})
		})

		When("everything is ok and array ip is not provided", func() {
			It("should succeed", func() {
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{},
				}
				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				Expect(err).To(BeNil())
				Expect(res.AvailableCapacity).To(Equal(int64(123123123)))
			})
		})

		When("wrong arrayIP in params", func() {
			It("should fail with predefined errmsg", func() {
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), nil)
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{
						"arrayIP": "10.10.10.10",
					},
				}
				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("can't find array with provided ip 10.10.10.10"))
			})
		})

		When("everything is correct, but API failed", func() {
			It("should fail with predefined errmsg", func() {
				clientMock.On("GetCapacity", mock.Anything).Return(int64(123123123), errors.New("APIErrorUnexpected"))
				req := &csi.GetCapacityRequest{
					Parameters: map[string]string{
						"arrayIP": "192.168.0.1",
					},
				}
				res, err := ctrlSvc.GetCapacity(context.Background(), req)
				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("APIErrorUnexpected"))
			})
		})
	})

	Describe("calling ValidateVolumeCapabilities()", func() {
		BeforeEach(func() { clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{}, nil) })

		When("everything is correct. Mode = SNW,block", func() {
			It("should succeed", func() {
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
				Expect(err).To(BeNil())
				Expect(res.Confirmed).NotTo(BeNil())
			})
		})

		When("everything is correct. Mode = SNRO,block", func() {
			It("should succeed", func() {
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
				Expect(err).To(BeNil())
				Expect(res.Confirmed).NotTo(BeNil())
			})
		})

		When("everything is correct. Mode = MNRO,block", func() {
			It("should succeed", func() {
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
				Expect(err).To(BeNil())
				Expect(res.Confirmed).NotTo(BeNil())
			})
		})

		When("everything is correct. Mode = MNSW,block", func() {
			It("should succeed", func() {
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
				Expect(err).To(BeNil())
				Expect(res.Confirmed).NotTo(BeNil())
			})
		})

		When("everything is correct. Mode = MNMW,block", func() {
			It("should fail", func() {
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
				Expect(err).To(BeNil())
				Expect(res.Confirmed).NotTo(BeNil())
			})
		})

		When("wrong pair of AM and AT. Mode = MNMW,mount", func() {
			It("should fail", func() {
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
				Expect(err).ToNot(BeNil())
				Expect(res.Confirmed).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("multi-node with writer(s) only supported for block access type"))
			})
		})

		When("wrong AT is given", func() {
			It("should fail", func() {
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
				Expect(err).ToNot(BeNil())
				Expect(res.Confirmed).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("unknown access type is not Block or Mount"))
			})
		})

		When("AM is nil", func() {
			It("should fail", func() {
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
				Expect(err).ToNot(BeNil())
				Expect(res.Confirmed).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("access mode cannot be UNKNOWN"))
			})
		})
	})

	Describe("calling ControllerGetCapabilities()", func() {
		When("plugin functions correctly", func() {
			It("should return supported capabilities", func() {
				res, err := ctrlSvc.ControllerGetCapabilities(context.Background(), &csi.ControllerGetCapabilitiesRequest{})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.ControllerGetCapabilitiesResponse{
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
									Type: csi.ControllerServiceCapability_RPC_LIST_VOLUMES,
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
