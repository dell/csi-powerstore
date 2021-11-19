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

package node

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/mocks"
	"github.com/dell/csi-powerstore/pkg/array"
	"github.com/dell/csi-powerstore/pkg/common"
	"github.com/dell/csi-powerstore/pkg/controller"
	"github.com/dell/gobrick"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gofsutil"
	"github.com/dell/goiscsi"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var (
	iscsiConnectorMock *mocks.ISCSIConnector
	fcConnectorMock    *mocks.FcConnector
	utilMock           *mocks.UtilInterface
	fsMock             *mocks.FsInterface
	nodeSvc            *Service
	clientMock         *gopowerstoremock.Client
	ctrlMock           *mocks.ControllerInterface
	iscsiLibMock       *goiscsi.MockISCSI
)

const (
	validBaseVolumeID   = "39bb1b5f-5624-490d-9ece-18f7b28a904e"
	validBlockVolumeID  = "39bb1b5f-5624-490d-9ece-18f7b28a904e/gid1/scsi"
	validNfsVolumeID    = "39bb1b5f-5624-490d-9ece-18f7b28a904e/gid2/nfs"
	validVolSize        = 16 * 1024 * 1024 * 1024
	validLUNID          = "3"
	validLUNIDINT       = 3
	nodeStagePrivateDir = "test/stage"
	unimplementedErrMsg = "rpc error: code = Unimplemented desc = "
	validNodeID         = "csi-node-1a47a1b91c444a8a90193d8066669603-127.0.0.1"
	validHostID         = "e8f4c5f8-c2fc-4df4-bd99-c292c12b55be"
	testErrMsg          = "test err"
	validDeviceWWN      = "68ccf09800e23ab798312a05426acae0"
	validDevPath        = "/dev/sdag"
	validDevName        = "sdag"
	validNfsExportPath  = "/mnt/nfs"
	validTargetPath     = "/var/lib/kubelet/pods/dac33335-a31d-11e9-b46e-005056917428/" +
		"volumes/kubernetes.io~csi/csi-d91431aba3/mount"
	validStagingPath = "/var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/" +
		"staging/csi-44b46e98ae/c875b4f0-172e-4238-aec7-95b379eb55db"
	firstValidIP       = "gid1"
	secondValidIP      = "gid2"
	validNasName       = "my-nas-name"
	validEphemeralName = "ephemeral-39bb1b5f-5624-490d-9ece-18f7b28a904e/gid1/scsi"
	ephemerallockfile  = "/var/lib/kubelet/plugins/kubernetes.io/csi/pv/ephemeral/39bb1b5f-5624-490d-9ece-18f7b28a904e/gid1/scsi/id"
)

var (
	validFCTargetsWWPN           = []string{"58ccf09348a003a3", "58ccf09348a002a3"}
	validFCTargetsWWPNPowerstore = []string{"58:cc:f0:93:48:a0:03:a3", "58:cc:f0:93:48:a0:02:a3"}
	validFCTargetsInfo           = []gobrick.FCTargetInfo{{WWPN: validFCTargetsWWPN[0]},
		{WWPN: validFCTargetsWWPN[1]}}
	validISCSIInitiators = []string{"iqn.1994-05.com.redhat:4db86abbe3c", "iqn.1994-05.com.redhat:2950c9ca441b"}
	validISCSIPortals    = []string{"192.168.1.1:3260", "192.168.1.2:3260"}
	validISCSITargets    = []string{"iqn.2015-10.com.dell:dellemc-powerstore-fnm00180700173-a-39f17e0e",
		"iqn.2015-10.com.dell:dellemc-powerstore-fnm00180700173-b-10de15a5"}
	validISCSITargetInfo = []gobrick.ISCSITargetInfo{
		{Portal: validISCSIPortals[0], Target: validISCSITargets[0]},
		{Portal: validISCSIPortals[1], Target: validISCSITargets[1]}}
	validGobrickISCSIVolumeINFO = gobrick.ISCSIVolumeInfo{
		Targets: []gobrick.ISCSITargetInfo{
			{Portal: validISCSITargetInfo[0].Portal,
				Target: validISCSITargetInfo[0].Target},
			{Portal: validISCSITargetInfo[1].Portal, Target: validISCSITargetInfo[1].Target}},
		Lun: validLUNIDINT}
	validGobrickFCVolumeINFO = gobrick.FCVolumeInfo{
		Targets: []gobrick.FCTargetInfo{
			{WWPN: validFCTargetsWWPN[0]},
			{WWPN: validFCTargetsWWPN[1]}},
		Lun: validLUNIDINT}
	validGobrickDevice = gobrick.Device{Name: validDevName, WWN: validDeviceWWN, MultipathID: validDeviceWWN}
)

func TestCSINodeService(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("node-svc.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "CSINodeService testing suite", []Reporter{junitReporter})
}

func getTestArrays() map[string]*array.PowerStoreArray {
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
	return arrays
}

func setVariables() {
	iscsiConnectorMock = new(mocks.ISCSIConnector)
	fcConnectorMock = new(mocks.FcConnector)
	utilMock = new(mocks.UtilInterface)
	fsMock = new(mocks.FsInterface)
	ctrlMock = new(mocks.ControllerInterface)
	clientMock = new(gopowerstoremock.Client)
	iscsiLibMock = goiscsi.NewMockISCSI(nil)

	arrays := getTestArrays()

	nodeSvc = &Service{
		Fs:             fsMock,
		ctrlSvc:        ctrlMock,
		iscsiConnector: iscsiConnectorMock,
		fcConnector:    fcConnectorMock,
		iscsiLib:       iscsiLibMock,
		nodeID:         validNodeID,
		useFC:          false,
		initialized:    true,
	}

	nodeSvc.SetArrays(arrays)
	nodeSvc.SetDefaultArray(arrays[firstValidIP])
}

var _ = Describe("CSINodeService", func() {
	BeforeEach(func() {
		setVariables()
	})

	Describe("calling Init()", func() {
		When("there is no suitable host", func() {
			It("should create this host", func() {
				nodeSvc.nodeID = ""

				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
					Return(validFCTargetsWWPN, nil)

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})
				clientMock.On("GetHosts", mock.Anything).Return(
					[]gopowerstore.Host{{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{{
							PortName: "not-matching-port-name",
							PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
						}},
						Name: "host-name",
					}}, nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				nodeSvc.opts.NodeNamePrefix = ""
				err := nodeSvc.Init()
				Expect(err).To(BeNil())
			})
		})
		When("failed to read nodeID file", func() {
			It("should fail", func() {
				nodeSvc.nodeID = ""

				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), errors.New("no such file"))

				err := nodeSvc.Init()
				Expect(err.Error()).To(ContainSubstring("no such file"))
			})
		})
		When("failed to get outbound ip", func() {
			It("should fail", func() {
				nodeSvc.nodeID = ""

				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					errors.New("failed to dial"),
				)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
					Return(validFCTargetsWWPN, nil)

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})
				clientMock.On("GetHosts", mock.Anything).Return(
					[]gopowerstore.Host{{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{{
							PortName: "not-matching-port-name",
							PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
						}},
						Name: "host-name",
					}}, nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				nodeSvc.opts.NodeNamePrefix = ""
				err := nodeSvc.Init()
				Expect(err.Error()).To(ContainSubstring("Could not connect to PowerStore array"))
			})
		})
		When("failed to get node id", func() {
			It("should fail", func() {
				nodeSvc.nodeID = ""

				fsMock.On("ReadFile", mock.Anything).Return([]byte("toooooooooooooooooooooo-looooooooooooooooooooooooooooooooooooooooong"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
					Return(validFCTargetsWWPN, nil)

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})
				clientMock.On("GetHosts", mock.Anything).Return(
					[]gopowerstore.Host{{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{{
							PortName: "not-matching-port-name",
							PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
						}},
						Name: "host-name",
					}}, nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				nodeSvc.opts.NodeNamePrefix = ""
				err := nodeSvc.Init()
				Expect(err.Error()).To(ContainSubstring("node name prefix is too long"))
			})
		})

		When("there IS a suitable host", func() {
			When("nodeID == hostName", func() {
				It("should reuse host [no initiator updates]", func() {
					iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
						Return(validISCSIInitiators, nil)
					fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
						Return(validFCTargetsWWPN, nil)

					clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
						Return(gopowerstore.Host{
							ID: "host-id",
							Initiators: []gopowerstore.InitiatorInstance{{
								PortName: validISCSIInitiators[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
								{
									PortName: validISCSIInitiators[1],
									PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
								}},
							Name: "host-name",
						}, nil)
					err := nodeSvc.Init()
					Expect(err).To(BeNil())
				})

				It("should modify host [update initiators]", func() {
					iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
						Return(validISCSIInitiators, nil)
					fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
						Return(validFCTargetsWWPN, nil)

					clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
						Return(gopowerstore.Host{
							ID: "host-id",
							Initiators: []gopowerstore.InitiatorInstance{{
								PortName: "not-matching-port-name",
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							}},
							Name: "host-name",
						}, nil)

					clientMock.On("ModifyHost", mock.Anything, mock.Anything, "host-id").
						Return(gopowerstore.CreateResponse{}, nil)

					err := nodeSvc.Init()
					Expect(err).To(BeNil())
				})
			})

			When("nodeID != hostName", func() {
				It("should reuse host", func() {
					nodeSvc.nodeID = ""
					fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
						Return(validISCSIInitiators, nil)
					fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
						Return(validFCTargetsWWPN, nil)

					clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
							},
						})
					clientMock.On("GetHosts", mock.Anything).Return(
						[]gopowerstore.Host{{
							ID: "host-id",
							Initiators: []gopowerstore.InitiatorInstance{{
								PortName: validISCSIInitiators[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							}},
							Name: "host-name",
						}}, nil)

					err := nodeSvc.Init()
					Expect(err).To(BeNil())
				})

				It("should reuse host [CHAP]", func() {
					nodeSvc.nodeID = ""
					_ = csictx.Setenv(context.Background(), common.EnvEnableCHAP, "true")
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)

					iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
						Return(validISCSIInitiators, nil)
					fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
						Return(validFCTargetsWWPN, nil)

					clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
						Return(gopowerstore.Host{}, gopowerstore.APIError{
							ErrorMsg: &api.ErrorMsg{
								StatusCode: http.StatusNotFound,
							},
						})
					clientMock.On("GetHosts", mock.Anything).Return(
						[]gopowerstore.Host{{
							ID: "host-id",
							Initiators: []gopowerstore.InitiatorInstance{{
								PortName: validISCSIInitiators[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							}},
							Name: "host-name",
						}}, nil)
					clientMock.On("ModifyHost", mock.Anything, mock.Anything, "host-id").
						Return(gopowerstore.CreateResponse{ID: "host-id"}, nil)

					err := nodeSvc.Init()
					Expect(err).To(BeNil())
				})
			})
		})

		When("using FC", func() {
			It("should create FC host", func() {
				nodeSvc.Arrays()[firstValidIP].BlockProtocol = common.FcTransport
				nodeSvc.nodeID = ""
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				_ = csictx.Setenv(context.Background(), common.EnvFCPortsFilterFilePath, "filter-path")

				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil).Once()
				fsMock.On("ReadFile", "filter-path").
					Return([]byte(validFCTargetsWWPNPowerstore[0]+","+validFCTargetsWWPNPowerstore[1]), nil).Once()

				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
					Return(validFCTargetsWWPN, nil)

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
						},
					})
				clientMock.On("GetHosts", mock.Anything).Return(
					[]gopowerstore.Host{{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{{
							PortName: "not-matching-port-name",
							PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
						}},
						Name: "host-name",
					}}, nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)

				err := nodeSvc.Init()
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("calling NodeStage()", func() {
		stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)

		When("using iSCSI", func() {
			It("should successfully stage iSCSI volume", func() {
				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil)

				scsiStageVolumeOK(utilMock, fsMock)
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		When("using FC", func() {
			It("should successfully stage FC volume", func() {
				nodeSvc.useFC = true
				fcConnectorMock.On("ConnectVolume", mock.Anything, gobrick.FCVolumeInfo{
					Targets: validFCTargetsInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil)

				scsiStageVolumeOK(utilMock, fsMock)
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		When("using NFS", func() {
			It("should successfully stage NFS volume", func() {
				stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
				utilMock.On("Mount", mock.Anything, validNfsExportPath, stagingPath, "").Return(nil)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkdirAll", stagingPath, mock.Anything).Return(nil).Once()
				fsMock.On("MkdirAll", filepath.Join(stagingPath, commonNfsVolumeFolder), mock.Anything).Return(nil).Once()
				fsMock.On("Chmod", filepath.Join(stagingPath, commonNfsVolumeFolder), os.ModeSticky|os.ModePerm).Return(nil)
				fsMock.On("GetUtil").Return(utilMock)

				publishContext := getValidPublishContext()
				publishContext["NfsExportPath"] = validNfsExportPath

				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    publishContext,
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "multi-writer", "nfs"),
				})

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		When("volume is already staged", func() {
			It("should return that stage is successful [SCSI]", func() {
				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil)

				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					},
				}
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("", nil)

				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeStageVolumeResponse{}))
			})

			It("should return that stage is successful [NFS]", func() {
				publishContext := getValidPublishContext()
				publishContext["NfsExportPath"] = validNfsExportPath

				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					},
				}
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("", nil)

				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    publishContext,
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "multi-writer", "nfs"),
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		When("missing volume capabilities", func() {
			It("should fail", func() {
				req := &csi.NodeStageVolumeRequest{}

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)
				Expect(res).To(BeNil())
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("volume capability is required"))
			})
		})

		When("missing volume VolumeId", func() {
			It("should fail", func() {
				req := &csi.NodeStageVolumeRequest{
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					StagingTargetPath: nodeStagePrivateDir,
				}

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)
				Expect(res).To(BeNil())
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("volume ID is required"))
			})
		})

		When("missing volume stage path", func() {
			It("should fail", func() {
				req := &csi.NodeStageVolumeRequest{
					VolumeCapability: getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					VolumeId:         validBlockVolumeID,
				}

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)
				Expect(res).To(BeNil())
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("staging target path is required"))
			})
		})

		When("device is found but not ready", func() {
			BeforeEach(func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
						Source: "volume-deleted",
					},
				}

				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil)

				// Stage
				utilMock.On("BindMount", mock.Anything, "/dev",
					filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(nil).Once()
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(4)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).
					Return(mountInfo, nil).Twice()
				fsMock.On("MkFileIdempotent", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).
					Return(true, nil).Once()
				fsMock.On("GetUtil").Return(utilMock)

				// Unstage
				fsMock.On("GetUtil").Return(utilMock).Once()
				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil).Once()
			})

			It("should unstage and stage again", func() {
				fsMock.On("Remove", stagingPath).Return(nil).Once()

				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeStageVolumeResponse{}))
			})

			When("unstaging fails", func() {
				It("should fail", func() {
					e := errors.New("os-error")
					fsMock.On("Remove", stagingPath).Return(e).Once()
					fsMock.On("IsNotExist", e).Return(false)

					res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
						VolumeId:          validBlockVolumeID,
						PublishContext:    getValidPublishContext(),
						StagingTargetPath: nodeStagePrivateDir,
						VolumeCapability: getCapabilityWithVoltypeAccessFstype(
							"mount", "single-writer", "ext4"),
					})
					Expect(err).ToNot(BeNil())
					Expect(res).To(BeNil())
					Expect(err.Error()).To(ContainSubstring("failed to unmount volume"))
				})
			})
		})

		When("publish context is incorrect", func() {
			It("should fail [deviceWWN]", func() {
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    map[string]string{},
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("deviceWWN must be in publish context"))
			})

			It("should fail [volumeLUNAddress]", func() {
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId: validBlockVolumeID,
					PublishContext: map[string]string{
						common.PublishContextDeviceWWN: validDeviceWWN,
					},
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("volumeLUNAddress must be in publish context"))
			})

			It("should fail [iscsiTargets]", func() {
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId: validBlockVolumeID,
					PublishContext: map[string]string{
						common.PublishContextDeviceWWN:  validDeviceWWN,
						common.PublishContextLUNAddress: validLUNID,
					},
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("iscsiTargets data must be in publish context"))
			})

			It("should fail [fcTargets]", func() {
				nodeSvc.useFC = true
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId: validBlockVolumeID,
					PublishContext: map[string]string{
						common.PublishContextDeviceWWN:  validDeviceWWN,
						common.PublishContextLUNAddress: validLUNID,
					},
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("fcTargets data must be in publish context"))
			})
		})

		When("can not connect device", func() {
			It("should fail", func() {
				e := errors.New("connection-error")
				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, e)

				scsiStageVolumeOK(utilMock, fsMock)
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to find device after multiple discovery attempts"))
			})
		})

		When("mount fails", func() {
			It("should fail", func() {
				e := errors.New("mount-error")
				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkFileIdempotent", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(true, nil)
				fsMock.On("GetUtil").Return(utilMock)

				utilMock.On("BindMount", mock.Anything, "/dev", filepath.Join(nodeStagePrivateDir, validBaseVolumeID)).Return(e)

				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				Expect(err).ToNot(BeNil())
				Expect(res).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("error bind disk"))
			})
		})
	})

	Describe("calling NodeUnstage()", func() {
		stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)

		When("unstaging block volume", func() {
			It("should succeed [iSCSI]", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil)

				fsMock.On("Remove", stagingPath).Return(nil)
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeUnstageVolumeResponse{}))
			})
			It("should fail, no targetPath [iSCSI]", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil)

				fsMock.On("Remove", stagingPath).Return(nil)
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				_, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: "",
				})
				Expect(err.Error()).To(ContainSubstring("staging target path is required"))
			})
			It("should fail, because no mounts [iSCSI]", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, errors.New("fail"))
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil)

				fsMock.On("Remove", stagingPath).Return(nil)
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				_, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				Expect(err.Error()).To(ContainSubstring("could not reliably determine existing mount for path"))
			})
			It("should fail, failed to unmount [iSCSI]", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(errors.New("failed unmount"))

				fsMock.On("Remove", stagingPath).Return(nil)
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				_, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				Expect(err.Error()).To(ContainSubstring("could not unmount de"))
			})
			It("should succeed, without path in mouninfo [iSCSI]", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   "invalid",
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", mock.Anything).Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil)

				fsMock.On("Remove", stagingPath).Return(nil)
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeUnstageVolumeResponse{}))
			})
			It("should succeed [FC]", func() {
				nodeSvc.useFC = true
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil)

				fsMock.On("Remove", stagingPath).Return(nil)
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0640)).Return(nil)

				fcConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeUnstageVolumeResponse{}))
			})
		})
		When("unstaging nfs volume", func() {
			It("should succeed", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil)

				fsMock.On("Remove", stagingPath).Return(nil)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validNfsVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeUnstageVolumeResponse{}))
			})
		})
	})

	Describe("calling NodePublish()", func() {
		stagingPath := filepath.Join(validStagingPath, validBaseVolumeID)

		When("publishing block volume as mount", func() {
			It("should succeed", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("", nil)
				fsMock.On("ExecCommand", "mkfs.ext4", "-E", "nodiscard", "-F", stagingPath).Return([]byte{}, nil)
				utilMock.On("Mount", mock.Anything, stagingPath, validTargetPath, "").Return(nil)

				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", ""),
					Readonly:          false,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		When("publishing block volume as mount with RO", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("", nil)
				fsMock.On("ExecCommand", "mkfs.ext4", "-E", "nodiscard", "-F", stagingPath).Return([]byte{}, nil)
				utilMock.On("Mount", mock.Anything, stagingPath, validTargetPath, "").Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", ""),
					Readonly:          true,
				})
				Expect(err.Error()).To(ContainSubstring("RO mount required but no fs detected on staged volume"))
			})
		})
		When("publishing block volume as mount with RO, fs exists", func() {
			It("should succeed", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("ext4", nil)
				fsMock.On("ExecCommand", "mkfs.ext4", "-E", "nodiscard", "-F", stagingPath).Return([]byte{}, nil)
				utilMock.On("Mount", mock.Anything, stagingPath, validTargetPath, "ext4", "ro").Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          true,
				})
				Expect(err).To(BeNil())
			})
		})
		When("publishing block volume as mount and unable to create dirs", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(errors.New("failed"))
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("", nil)
				fsMock.On("ExecCommand", "mkfs.ext4", "-E", "nodiscard", "-F", stagingPath).Return([]byte{}, nil)
				utilMock.On("Mount", mock.Anything, stagingPath, validTargetPath, "").Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", ""),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("can't create target dir"))
			})
		})
		When("publishing block volume as mount and getformat fails", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("", errors.New("failed"))
				fsMock.On("ExecCommand", "mkfs.ext4", "-E", "nodiscard", "-F", stagingPath).Return([]byte{}, nil)
				utilMock.On("Mount", mock.Anything, stagingPath, validTargetPath, "").Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", ""),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("error while trying to detect fs"))
			})
		})
		When("publishing block volume as mount and disk preformatted", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("ext4", nil)
				fsMock.On("ExecCommand", "mkfs.ext4", "-E", "nodiscard", "-F", stagingPath).Return([]byte{}, nil)
				utilMock.On("Mount", mock.Anything, stagingPath, validTargetPath, "ext4").Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "xfs"),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("Target device already formatted"))
			})
		})
		When("publishing formatting failed", func() {
			It("should succeed", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("GetDiskFormat", mock.Anything, stagingPath).Return("", nil)
				fsMock.On("ExecCommand", "mkfs.ext4", "-E", "nodiscard", "-F", stagingPath).Return([]byte{}, errors.New("failed"))
				utilMock.On("Mount", mock.Anything, stagingPath, validTargetPath, "").Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", ""),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("can't format staged device"))
			})
		})
		When("publishing block volume as raw block", func() {
			It("should succeed", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkFileIdempotent", validTargetPath).Return(true, nil)
				utilMock.On("BindMount", mock.Anything, stagingPath, validTargetPath).Return(nil)

				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		When("publishing block volume as raw block with RO", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkFileIdempotent", validTargetPath).Return(true, nil)
				utilMock.On("BindMount", mock.Anything, stagingPath, validTargetPath, "ro").Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          true,
				})
				Expect(err.Error()).To(ContainSubstring("read only not supported for Block Volume"))
			})
		})
		When("publishing block and unable to create target", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkFileIdempotent", validTargetPath).Return(false, errors.New("failed"))
				utilMock.On("BindMount", mock.Anything, stagingPath, validTargetPath).Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("can't create target file"))
			})
		})
		When("publishing block and unable to bind disk", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				fsMock.On("MkFileIdempotent", validTargetPath).Return(true, nil)
				utilMock.On("BindMount", mock.Anything, stagingPath, validTargetPath).Return(errors.New("failed to bind"))

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("error bind disk"))
			})
		})
		When("publishing nfs volume", func() {
			It("should succeed", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("Stat", filepath.Join(stagingPath, commonNfsVolumeFolder)).Return(&mocks.FileInfo{}, nil)
				stagingPath := filepath.Join(stagingPath, commonNfsVolumeFolder)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("BindMount", mock.Anything, stagingPath, validTargetPath).Return(nil)

				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "multi-writer", "nfs"),
					Readonly:          false,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		When("No volume ID specified", func() {
			It("should fail", func() {
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          "",
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("volume ID is required"))
				Expect(res).To(BeNil())
			})
		})
		When("No target path specified", func() {
			It("should fail", func() {
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        "",
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("targetPath is required"))
				Expect(res).To(BeNil())
			})
		})
		When("Invalid volume capabilities specified", func() {
			It("should fail", func() {
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  nil,
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("VolumeCapability is required"))
				Expect(res).To(BeNil())
			})
		})
		When("No staging target path specified", func() {
			It("should fail", func() {
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: "",
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				Expect(err.Error()).To(ContainSubstring("stagingPath is required"))
				Expect(res).To(BeNil())
			})
		})
		When("unable to create target dir", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("Stat", filepath.Join(stagingPath, commonNfsVolumeFolder)).Return(&mocks.FileInfo{}, nil)
				stagingPath := filepath.Join(stagingPath, commonNfsVolumeFolder)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(errors.New("fail"))
				utilMock.On("BindMount", mock.Anything, stagingPath, validTargetPath).Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "multi-writer", "nfs"),
					Readonly:          true,
				})
				Expect(err.Error()).To(ContainSubstring("can't create target folder"))
			})
		})
		When("publishing nfs with ro", func() {
			It("should succeed", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("Stat", filepath.Join(stagingPath, commonNfsVolumeFolder)).Return(&mocks.FileInfo{}, nil)
				stagingPath := filepath.Join(stagingPath, commonNfsVolumeFolder)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("BindMount", mock.Anything, stagingPath, validTargetPath, "ro").Return(nil)

				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "multi-writer", "nfs"),
					Readonly:          true,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		When("unable to bind disk", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("Stat", filepath.Join(stagingPath, commonNfsVolumeFolder)).Return(&mocks.FileInfo{}, nil)
				stagingPath := filepath.Join(stagingPath, commonNfsVolumeFolder)

				fsMock.On("MkdirAll", validTargetPath, mock.Anything).Return(nil)
				utilMock.On("BindMount", mock.Anything, stagingPath, validTargetPath, "ro").Return(errors.New("bind failed"))

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "multi-writer", "nfs"),
					Readonly:          true,
				})
				Expect(err.Error()).To(ContainSubstring("error bind disk"))
			})
		})
	})

	Describe("calling NodeUnpublish()", func() {
		When("unpublishing block volume", func() {
			It("should succeed", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, os.ErrNotExist)
				utilMock.On("Unmount", mock.Anything, validTargetPath).Return(nil)

				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeUnpublishVolumeResponse{}))
			})
		})
		When("unpublishing nfs volume", func() {
			It("should succeed", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, os.ErrNotExist)
				utilMock.On("Unmount", mock.Anything, validTargetPath).Return(nil)

				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validNfsVolumeID,
					TargetPath: validTargetPath,
				})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeUnpublishVolumeResponse{}))
			})
		})
		When("No target path specified", func() {
			It("should fail", func() {

				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: "",
				})
				Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = target path required"))
				Expect(res).To(BeNil())
			})
		})
		When("Unable to get volID", func() {
			It("should fail", func() {

				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   "",
					TargetPath: validTargetPath,
				})
				Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = volume ID is required"))
				Expect(res).To(BeNil())
			})
		})
		When("Unable to get TargetMounts", func() {
			It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(nil, errors.New("error"))
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, os.ErrNotExist)
				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				Expect(err.Error()).To(ContainSubstring("could not reliably determine existing mount status"))
				Expect(res).To(BeNil())
			})
		})
		When("Unable to perform unmount", func() {
			It("should fail", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, os.ErrNotExist)
				utilMock.On("Unmount", mock.Anything, validTargetPath).Return(errors.New("Unmount failed"))
				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				Expect(err.Error()).To(ContainSubstring("could not unmount dev"))
				Expect(res).To(BeNil())
			})
		})
	})

	Describe("calling NodeExpandVolume() online", func() {
		stagingPath := filepath.Join(validStagingPath, validBaseVolumeID)
		When("everything is correct", func() {
			It("should succeed [ext4]", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "",
					MountPoint:  stagingPath,
				}, nil)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("FindFSType", mock.Anything, mock.Anything).Return("ext4", nil)
				fsMock.On("ExecCommandOutput", mock.Anything, mock.Anything, mock.Anything).Return([]byte("version 5.0.0"), nil)
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err).To(BeNil())
				Ω(res).To(Equal(&csi.NodeExpandVolumeResponse{}))
			})
			It("should succeed [xfs]", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "",
					MountPoint:  stagingPath,
				}, nil)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("FindFSType", mock.Anything, mock.Anything).Return("xfs", nil)
				fsMock.On("ExecCommandOutput", mock.Anything, mock.Anything, mock.Anything).Return([]byte("version 5.0.0"), nil)
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err).To(BeNil())
				Ω(res).To(Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		When("it failed to find mount info", func() {
			It("should fail ResizeFS() [xfs]", func() {
				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "",
					MountPoint:  stagingPath,
				}, nil)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("FindFSType", mock.Anything, mock.Anything).Return("xfs", nil)
				fsMock.On("ExecCommandOutput", mock.Anything, mock.Anything, mock.Anything).Return([]byte("version 5.0.0"), nil)
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("resize Failed ext4"))
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err.Error()).To(ContainSubstring("resize Failed ext4"))
				Ω(res).To(BeNil())
			})
			It("should fail ResizeFS() [ext4]", func() {
				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "",
					MountPoint:  stagingPath,
				}, nil)

				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("FindFSType", mock.Anything, mock.Anything).Return("ext4", nil)
				fsMock.On("ExecCommandOutput", mock.Anything, mock.Anything, mock.Anything).Return([]byte("version 5.0.0"), nil)
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("resize Failed xfs"))
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err.Error()).To(ContainSubstring("resize Failed xfs"))
				Ω(res).To(BeNil())
			})
		})

	})

	Describe("calling NodeExpandVolume() offline", func() {
		stagingPath := filepath.Join(validStagingPath, validBaseVolumeID)
		When("everything is correct", func() {
			It("should succeed [ext4]", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "",
					MountPoint:  stagingPath,
				}, errors.New("offline")).Times(1)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(nil)
				fsMock.On("RemoveAll", mock.Anything).Return(nil)

				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "",
					MountPoint:  stagingPath,
				}, nil).Times(1)

				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("FindFSType", mock.Anything, mock.Anything).Return("ext4", nil)
				fsMock.On("ExecCommandOutput", mock.Anything, mock.Anything, mock.Anything).Return([]byte("version 5.0.0"), nil)
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err).To(BeNil())
				Ω(res).To(Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		When("using multipath", func() {
			It("should succeed [ext4]", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("offline")).Times(1)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(nil)
				fsMock.On("RemoveAll", mock.Anything).Return(nil)

				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, nil).Times(1)

				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("ResizeMultipath", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("FindFSType", mock.Anything, mock.Anything).Return("xfs", nil)
				fsMock.On("ExecCommandOutput", mock.Anything, mock.Anything, mock.Anything).Return([]byte("version 5.0.0"), nil)
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err).To(BeNil())
				Ω(res).To(Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		When("using block mode", func() {
			It("should succeed [ext4]", func() {

				fsMock.On("GetUtil").Return(utilMock)

				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
					Wwn:         "naa.6090a038f0cd4e5bdaa8248e6856d4fe:3",
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("block")).Times(1)
				utilMock.On("GetSysBlockDevicesForVolumeWWN", mock.Anything, mock.Anything).Return([]string{"sda", "sdx"}, nil)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("GetMpathNameFromDevice", mock.Anything, mock.Anything).Return("mpatha", nil)
				utilMock.On("ResizeMultipath", mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, true))
				Ω(err).To(BeNil())
				Ω(res).To(Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		When("Unable to parse volid", func() {
			It("should fail", func() {
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
					Wwn:         "naa.6090a038f0cd4e5bdaa8248e6856d4fe:3",
				}, nil)
				_, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest("", true))
				Ω(err.Error()).To(ContainSubstring("incorrect volume id"))

			})
		})
		When("no target path", func() {
			It("should fail", func() {

				fsMock.On("GetUtil").Return(utilMock)

				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
					Wwn:         "naa.6090a038f0cd4e5bdaa8248e6856d4fe:3",
				}, nil)

				_, err := nodeSvc.NodeExpandVolume(context.Background(), &csi.NodeExpandVolumeRequest{
					VolumeId:   validBlockVolumeID,
					VolumePath: "",
					CapacityRange: &csi.CapacityRange{
						RequiredBytes: 2234234,
						LimitBytes:    controller.MaxVolumeSizeBytes,
					},
				})
				Ω(err.Error()).To(ContainSubstring("targetPath is required"))

			})
		})
		When("volume is not found", func() {
			It("should fail", func() {

				fsMock.On("GetUtil").Return(utilMock)

				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
					Wwn:         "naa.6090a038f0cd4e5bdaa8248e6856d4fe:3",
				}, errors.New("err")).Times(1)

				_, err := nodeSvc.NodeExpandVolume(context.Background(), &csi.NodeExpandVolumeRequest{
					VolumeId:   validBlockVolumeID,
					VolumePath: validTargetPath,
					CapacityRange: &csi.CapacityRange{
						RequiredBytes: 2234234,
						LimitBytes:    controller.MaxVolumeSizeBytes,
					},
				})
				Ω(err.Error()).To(ContainSubstring("Volume not found"))

			})
		})
		When("Unable to create mount target", func() {
			It("should fail", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("offline")).Times(1)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(errors.New("Unable to create dirs"))
				_, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err.Error()).To(ContainSubstring("Failed to find mount info for"))

			})
		})
		When("Unable to perform mount", func() {
			It("should fail", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("offline")).Times(1)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("bad mount"))
				_, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err.Error()).To(ContainSubstring("Failed to find mount info for"))

			})
		})
		When("Unable to perform unmount", func() {
			It("should succeed", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("offline")).Times(1)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(errors.New("unmount error"))
				fsMock.On("RemoveAll", mock.Anything).Return(errors.New("removeerror"))

				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, nil).Times(1)

				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("ResizeMultipath", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("FindFSType", mock.Anything, mock.Anything).Return("xfs", nil)
				fsMock.On("ExecCommandOutput", mock.Anything, mock.Anything, mock.Anything).Return([]byte("version 5.0.0"), nil)
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err).To(BeNil())
				Ω(res).To(Equal(&csi.NodeExpandVolumeResponse{}))

			})
		})
		When("Unable to find mount info", func() {
			It("should fail", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("offline")).Times(1)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(errors.New("unmount error"))
				fsMock.On("RemoveAll", mock.Anything).Return(errors.New("removeerror"))

				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("again")).Times(1)

				_, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err.Error()).To(ContainSubstring("Failed to find mount info for"))

			})
		})
		When("Unable to rescan the device", func() {
			It("should fail", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("offline")).Times(1)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(errors.New("unmount error"))
				fsMock.On("RemoveAll", mock.Anything).Return(errors.New("removeerror"))

				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, nil).Times(1)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(errors.New("Failed to rescan device"))
				_, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err.Error()).To(ContainSubstring("Failed to rescan device"))

			})
		})
		When("Unable to resize mpath", func() {
			It("should fail", func() {

				fsMock.On("GetUtil").Return(utilMock)
				clientMock.On("GetVolume", mock.Anything, mock.Anything).Return(gopowerstore.Volume{
					Description: "",
					ID:          validBlockVolumeID,
					Name:        "name",
					Size:        controller.MaxVolumeSizeBytes / 200,
				}, nil)
				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, errors.New("offline")).Times(1)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(errors.New("unmount error"))
				fsMock.On("RemoveAll", mock.Anything).Return(errors.New("removeerror"))

				utilMock.On("GetMountInfoFromDevice", mock.Anything, mock.Anything).Return(&gofsutil.DeviceMountInfo{
					DeviceNames: []string{validDevName},
					MPathName:   "/dev/mpatha",
					MountPoint:  stagingPath,
				}, nil).Times(1)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("ResizeMultipath", mock.Anything, mock.Anything).Return(errors.New("mpath resize error"))
				_, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				Ω(err.Error()).To(ContainSubstring("mpath resize error"))

			})
		})
	})

	Describe("Calling EphemeralNodePublish()", func() {
		When("everything's correct", func() {
			It("should succeed", func() {
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil).Times(2)
				fsMock.On("Create", mock.Anything).Return(&os.File{}, nil)
				fsMock.On("WriteString", mock.Anything, mock.Anything).Return(0, nil)
				ctrlMock.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolumeID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID: firstValidIP,
						},
					},
				}, nil)
				ctrlMock.On("ControllerPublishVolume", mock.Anything, mock.Anything).Return(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"LUN_ADDRESS": validLUNID,
						"DEVICE_WWN":  validDeviceWWN,
						"PORTAL0":     validISCSIPortals[0],
						"PORTAL1":     validISCSIPortals[1],
						"TARGET0":     validISCSITargets[0],
						"TARGET1":     validISCSITargets[1],
						"FCWWPN0":     "58ccf09348a003a3",
						"FCWWPN1":     "58ccf09348a002a3",
					},
				}, nil)
				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil)
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("BindMount", mock.Anything, "/dev", mock.Anything).Return(nil)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkFileIdempotent", mock.Anything).Return(true, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
				utilMock.On("GetDiskFormat", mock.Anything, mock.Anything).Return("", nil)
				fsMock.On("ExecCommand", "mkfs.ext4", "-E", "nodiscard", "-F", mock.Anything).Return([]byte{}, nil)
				utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, "ext4").Return(nil)
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          false,
					VolumeContext: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "2Gi",
					},
				})
				Ω(err).To(BeNil())
				Ω(res).To(Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		When("Child ControllerPublish() is failing", func() {
			capabilities := getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4")
			It("should cleanup and call unpublish", func() {
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil).Times(2)
				fsMock.On("Create", mock.Anything).Return(&os.File{}, nil)
				fsMock.On("WriteString", mock.Anything, mock.Anything).Return(0, nil)
				ctrlMock.On("CreateVolume", mock.Anything, &csi.CreateVolumeRequest{
					Name:               validEphemeralName,
					CapacityRange:      &csi.CapacityRange{LimitBytes: 2147483648, RequiredBytes: 2147483648},
					VolumeCapabilities: []*csi.VolumeCapability{capabilities},
					Parameters: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "2Gi"},
				}).Return(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolumeID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID: firstValidIP,
						},
					},
				}, nil)
				ctrlMock.On("ControllerPublishVolume", mock.Anything, &csi.ControllerPublishVolumeRequest{
					VolumeId: validBlockVolumeID,
					NodeId:   validNodeID,
					VolumeContext: map[string]string{
						common.KeyArrayID: firstValidIP,
					},
					VolumeCapability: getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
				}).Return(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"LUN_ADDRESS": validLUNID,
						"DEVICE_WWN":  validDeviceWWN,
						"PORTAL0":     validISCSIPortals[0],
						"PORTAL1":     validISCSIPortals[1],
						"TARGET0":     validISCSITargets[0],
						"TARGET1":     validISCSITargets[1],
						"FCWWPN0":     "58ccf09348a003a3",
						"FCWWPN1":     "58ccf09348a002a3",
					},
				}, errors.New("Oops I failed"))
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", mock.Anything).Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, os.ErrNotExist)
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          false,
					VolumeContext: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "2Gi",
					},
				})
				Ω(err.Error()).To(ContainSubstring("inline ephemeral controller publish failed"))
			})
		})
		When("Child NodeStage() is failing", func() {
			It("should cleanup and call unpublish", func() {
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil).Times(2)
				fsMock.On("Create", mock.Anything).Return(&os.File{}, nil)
				fsMock.On("WriteString", mock.Anything, mock.Anything).Return(0, nil)
				ctrlMock.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolumeID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID: firstValidIP,
						},
					},
				}, nil)
				ctrlMock.On("ControllerPublishVolume", mock.Anything, mock.Anything).Return(&csi.ControllerPublishVolumeResponse{
					PublishContext: map[string]string{
						"LUN_ADDRESS": validLUNID,
						"DEVICE_WWN":  validDeviceWWN,
						"PORTAL0":     validISCSIPortals[0],
						"PORTAL1":     validISCSIPortals[1],
						"TARGET0":     validISCSITargets[0],
						"TARGET1":     validISCSITargets[1],
						"FCWWPN0":     "58ccf09348a003a3",
						"FCWWPN1":     "58ccf09348a002a3",
					},
				}, nil)

				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil)
				utilMock.On("BindMount", mock.Anything, "/dev", mock.Anything).Return(nil)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkFileIdempotent", mock.Anything).Return(true, errors.New("error"))
				fsMock.On("GetUtil").Return(utilMock)

				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", mock.Anything).Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, os.ErrNotExist)
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          false,
					VolumeContext: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "2Gi",
					},
				})
				Ω(err.Error()).To(ContainSubstring("inline ephemeral node stage failed"))
			})
		})
		When("Failed to parse size. Bad string", func() {
			It("should fail", func() {
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil).Times(2)
				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          false,
					VolumeContext: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "Dear SP please give me enough capacity",
					},
				})
				Ω(err.Error()).To(ContainSubstring("inline ephemeral parse size failed"))
			})
		})
		When("Failed to create mount paths", func() {
			It("should fail", func() {
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, os.ErrNotExist)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(errors.New("err")).Times(2)
				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          false,
					VolumeContext: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "2 Gi",
					},
				})
				Ω(err.Error()).To(ContainSubstring("Unable to create directory for mounting ephemeral volumes"))
			})
		})
		When("Inline ephemeral create volume fails", func() {
			It("should fail", func() {
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil).Times(2)
				fsMock.On("Create", mock.Anything).Return(&os.File{}, nil)
				fsMock.On("WriteString", mock.Anything, mock.Anything).Return(0, nil)
				ctrlMock.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolumeID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID: firstValidIP,
						},
					},
				}, errors.New("Failed"))
				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          false,
					VolumeContext: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "2 Gi",
					},
				})
				Ω(err.Error()).To(ContainSubstring("inline ephemeral create volume failed"))
			})
		})
		When("fs.Create after createVolume fails", func() {
			It("should fail", func() {
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil).Times(2)
				fsMock.On("Create", mock.Anything).Return(&os.File{}, errors.New("Failed to create"))
				fsMock.On("WriteString", mock.Anything, mock.Anything).Return(0, nil)
				ctrlMock.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolumeID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID: firstValidIP,
						},
					},
				}, nil)
				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          false,
					VolumeContext: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "2 Gi",
					},
				})
				Ω(err.Error()).To(ContainSubstring("Failed to create"))
			})
		})
		When("fs.Writestring fails", func() {
			It("should fail", func() {
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
				fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil).Times(2)
				fsMock.On("Create", mock.Anything).Return(&os.File{}, nil)
				fsMock.On("WriteString", mock.Anything, mock.Anything).Return(0, errors.New("Failed to write string"))
				ctrlMock.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{
					Volume: &csi.Volume{
						CapacityBytes: validVolSize,
						VolumeId:      filepath.Join(validBaseVolumeID, firstValidIP, "scsi"),
						VolumeContext: map[string]string{
							common.KeyArrayID: firstValidIP,
						},
					},
				}, nil)
				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					Readonly:          false,
					VolumeContext: map[string]string{
						"csi.storage.k8s.io/ephemeral": "true",
						"size":                         "2 Gi",
					},
				})
				Ω(err.Error()).To(ContainSubstring("Failed to write string"))
			})
		})
	})
	When("everything's correct", func() {
		It("should succeed", func() {
			fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
			fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil).Times(2)
			fsMock.On("Create", mock.Anything).Return(&os.File{}, nil)
			fsMock.On("WriteString", mock.Anything, mock.Anything).Return(0, nil)
			ctrlMock.On("CreateVolume", mock.Anything, mock.Anything).Return(&csi.CreateVolumeResponse{
				Volume: &csi.Volume{
					CapacityBytes: validVolSize,
					VolumeId:      filepath.Join(validBaseVolumeID, firstValidIP, "scsi"),
					VolumeContext: map[string]string{
						common.KeyArrayID: firstValidIP,
					},
				},
			}, nil)
			ctrlMock.On("ControllerPublishVolume", mock.Anything, mock.Anything).Return(&csi.ControllerPublishVolumeResponse{
				PublishContext: map[string]string{
					"LUN_ADDRESS": validLUNID,
					"DEVICE_WWN":  validDeviceWWN,
					"PORTAL0":     validISCSIPortals[0],
					"PORTAL1":     validISCSIPortals[1],
					"TARGET0":     validISCSITargets[0],
					"TARGET1":     validISCSITargets[1],
					"FCWWPN0":     "58ccf09348a003a3",
					"FCWWPN1":     "58ccf09348a002a3",
				},
			}, nil)
			iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
				Targets: validISCSITargetInfo,
				Lun:     validLUNIDINT,
			}).Return(gobrick.Device{}, nil)
			fsMock.On("GetUtil").Return(utilMock)
			utilMock.On("BindMount", mock.Anything, "/dev", mock.Anything).Return(nil)
			fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
			fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
			fsMock.On("MkFileIdempotent", mock.Anything).Return(true, nil)
			fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
			fsMock.On("MkdirAll", mock.Anything, mock.Anything).Return(nil)
			utilMock.On("GetDiskFormat", mock.Anything, mock.Anything).Return("", nil)
			fsMock.On("ExecCommand", "mkfs.xfs", "-K", mock.Anything, "-m", mock.Anything).Return([]byte{}, nil)
			utilMock.On("Mount", mock.Anything, mock.Anything, mock.Anything, "xfs", mock.Anything).Return(errors.New("err"))
			_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
				VolumeId:          validBlockVolumeID,
				PublishContext:    getValidPublishContext(),
				StagingTargetPath: validStagingPath,
				TargetPath:        validTargetPath,
				VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "xfs"),
				Readonly:          false,
				VolumeContext: map[string]string{
					"csi.storage.k8s.io/ephemeral": "true",
					"size":                         "2Gi",
				},
			})
			Ω(err.Error()).To(ContainSubstring("inline ephemeral node publish failed"))
		})
	})

	Describe("Calling EphemeralNodeUnPublish()", func() {
		When("everything is correct", func() {
			It("should succeed", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}
				fsMock.On("ReadFile", ephemerallockfile).Return([]byte(validBlockVolumeID), nil)
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(nil)

				fsMock.On("Remove", mock.Anything).Return(nil)
				fsMock.On("WriteFile", mock.Anything, mock.Anything, os.FileMode(0640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, mock.Anything).Return(nil)

				fsMock.On("Remove", mock.Anything).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)
				fsMock.On("ReadFile", mock.Anything).Return([]byte("Some data"), nil)
				ctrlMock.On("ControllerUnpublishVolume", mock.Anything, &csi.ControllerUnpublishVolumeRequest{
					VolumeId: validBlockVolumeID,
					NodeId:   validNodeID,
				}).Return(&csi.ControllerUnpublishVolumeResponse{}, nil)
				ctrlMock.On("DeleteVolume", mock.Anything, &csi.DeleteVolumeRequest{
					VolumeId: validBlockVolumeID,
				}).Return(&csi.DeleteVolumeResponse{}, nil)
				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				Ω(err).To(BeNil())
				Ω(res).To(Equal(&csi.NodeUnpublishVolumeResponse{}))
			})
		})
		When("no vlocak file", func() {
			It("should fail", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}
				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(nil)

				fsMock.On("Remove", mock.Anything).Return(nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", ephemerallockfile).Return([]byte(validBlockVolumeID), os.ErrNotExist)
				_, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				Ω(err.Error()).To(ContainSubstring("Was unable to read lockfile"))
			})
		})
		When("controller unpublish fails", func() {
			It("should fail", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}
				fsMock.On("ReadFile", ephemerallockfile).Return([]byte(validBlockVolumeID), nil)
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(nil)

				fsMock.On("Remove", mock.Anything).Return(nil)
				fsMock.On("WriteFile", mock.Anything, mock.Anything, os.FileMode(0640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, mock.Anything).Return(nil)

				fsMock.On("Remove", mock.Anything).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)
				fsMock.On("ReadFile", mock.Anything).Return([]byte("Some data"), nil)
				ctrlMock.On("ControllerUnpublishVolume", mock.Anything, &csi.ControllerUnpublishVolumeRequest{
					VolumeId: validBlockVolumeID,
					NodeId:   validNodeID,
				}).Return(&csi.ControllerUnpublishVolumeResponse{}, errors.New("failed"))
				ctrlMock.On("DeleteVolume", mock.Anything, &csi.DeleteVolumeRequest{
					VolumeId: validBlockVolumeID,
				}).Return(&csi.DeleteVolumeResponse{}, nil)
				_, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				Ω(err.Error()).To(ContainSubstring("Inline ephemeral controller unpublish"))
			})
		})
		When("controller delete volume fails", func() {
			It("should fail", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}
				fsMock.On("ReadFile", ephemerallockfile).Return([]byte(validBlockVolumeID), nil)
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, nil)

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, mock.Anything).Return(nil)

				fsMock.On("Remove", mock.Anything).Return(nil)
				fsMock.On("WriteFile", mock.Anything, mock.Anything, os.FileMode(0640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, mock.Anything).Return(nil)

				fsMock.On("Remove", mock.Anything).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)
				fsMock.On("ReadFile", mock.Anything).Return([]byte("Some data"), nil)
				ctrlMock.On("ControllerUnpublishVolume", mock.Anything, &csi.ControllerUnpublishVolumeRequest{
					VolumeId: validBlockVolumeID,
					NodeId:   validNodeID,
				}).Return(&csi.ControllerUnpublishVolumeResponse{}, nil)
				ctrlMock.On("DeleteVolume", mock.Anything, &csi.DeleteVolumeRequest{
					VolumeId: validBlockVolumeID,
				}).Return(&csi.DeleteVolumeResponse{}, errors.New("failed"))
				_, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				Ω(err.Error()).To(ContainSubstring("failed"))
			})
		})
	})

	Describe("calling NodeGetInfo()", func() {
		When("managing multiple arrays", func() {
			It("should return correct topology segments", func() {
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
					}, nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":   "true",
							common.Name + "/" + firstValidIP + "-iscsi": "true",
							common.Name + "/" + secondValidIP + "-nfs":  "true",
						},
					},
				}))
			})
		})

		When("we can not get targets from array", func() {
			It("should not return iscsi topology key", func() {
				e := "internal error"
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, errors.New(e))
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})

				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":  "true",
							common.Name + "/" + secondValidIP + "-nfs": "true",
						},
					},
				}))
			})
		})

		When("target can not be discovered", func() {
			It("should not return iscsi topology key", func() {
				goiscsi.GOISCSIMock.InduceDiscoveryError = true

				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
					}, nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":  "true",
							common.Name + "/" + secondValidIP + "-nfs": "true",
						},
					},
				}))
			})
		})

		When("using FC", func() {
			It("should return FC topology segments", func() {
				nodeSvc.useFC = true
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				clientMock.On("GetHostByName", mock.Anything, nodeSvc.nodeID).
					Return(gopowerstore.Host{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{
							{
								ActiveSessions: []gopowerstore.ActiveSessionInstance{
									{
										PortName: validFCTargetsWWPN[0],
									},
								},
								PortName: validFCTargetsWWPN[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumFC,
							},
							{
								ActiveSessions: []gopowerstore.ActiveSessionInstance{
									{
										PortName: validFCTargetsWWPN[1],
									},
								},
								PortName: validFCTargetsWWPN[1],
								PortType: gopowerstore.InitiatorProtocolTypeEnumFC,
							}},
						Name: "host-name",
					}, nil)

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				Expect(err).To(BeNil())
				Expect(res).To(Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":  "true",
							common.Name + "/" + firstValidIP + "-fc":   "true",
							common.Name + "/" + secondValidIP + "-nfs": "true",
						},
					},
				}))
			})

			When("reusing host", func() {
				It("should properly deal with additional IPs", func() {
					nodeSvc.useFC = true
					nodeID := nodeSvc.nodeID
					nodeSvc.nodeID = nodeID + "-" + "192.168.0.1"
					nodeSvc.reusedHost = true
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					clientMock.On("GetHostByName", mock.Anything, nodeID).
						Return(gopowerstore.Host{
							ID: "host-id",
							Initiators: []gopowerstore.InitiatorInstance{
								{
									ActiveSessions: []gopowerstore.ActiveSessionInstance{
										{
											PortName: validFCTargetsWWPN[0],
										},
									},
									PortName: validFCTargetsWWPN[0],
									PortType: gopowerstore.InitiatorProtocolTypeEnumFC,
								},
								{
									ActiveSessions: []gopowerstore.ActiveSessionInstance{
										{
											PortName: validFCTargetsWWPN[1],
										},
									},
									PortName: validFCTargetsWWPN[1],
									PortType: gopowerstore.InitiatorProtocolTypeEnumFC,
								}},
							Name: "host-name",
						}, nil)

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					Expect(err).To(BeNil())
					Expect(res).To(Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + firstValidIP + "-fc":   "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
					}))
				})

				When("there is no ip in nodeID", func() {
					It("should not return FC topology key", func() {
						nodeSvc.useFC = true
						nodeID := nodeSvc.nodeID
						nodeSvc.nodeID = "nodeid-with-no-ip"
						nodeSvc.reusedHost = true
						conn, _ := net.Dial("udp", "127.0.0.1:80")
						fsMock.On("NetDial", mock.Anything).Return(
							conn,
							nil,
						)
						clientMock.On("GetHostByName", mock.Anything, nodeID).
							Return(gopowerstore.Host{
								ID: "host-id",
								Initiators: []gopowerstore.InitiatorInstance{
									{
										ActiveSessions: []gopowerstore.ActiveSessionInstance{
											{
												PortName: validFCTargetsWWPN[0],
											},
										},
										PortName: validFCTargetsWWPN[0],
										PortType: gopowerstore.InitiatorProtocolTypeEnumFC,
									},
									{
										ActiveSessions: []gopowerstore.ActiveSessionInstance{
											{
												PortName: validFCTargetsWWPN[1],
											},
										},
										PortName: validFCTargetsWWPN[1],
										PortType: gopowerstore.InitiatorProtocolTypeEnumFC,
									}},
								Name: "host-name",
							}, nil)

						res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
						Expect(err).To(BeNil())
						Expect(res).To(Equal(&csi.NodeGetInfoResponse{
							NodeId: nodeSvc.nodeID,
							AccessibleTopology: &csi.Topology{
								Segments: map[string]string{
									common.Name + "/" + firstValidIP + "-nfs":  "true",
									common.Name + "/" + secondValidIP + "-nfs": "true",
								},
							},
						}))
					})
				})
			})

			When("we can not get info about hosts from array", func() {
				It("should not return FC topology key", func() {
					nodeSvc.useFC = true
					e := "internal error"
					clientMock.On("GetHostByName", mock.Anything, nodeSvc.nodeID).
						Return(gopowerstore.Host{}, errors.New(e))
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					Expect(err).To(BeNil())
					Expect(res).To(Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
					}))
				})
			})

			When("host initiators is empty", func() {
				It("should not return FC topology key", func() {
					nodeSvc.useFC = true
					clientMock.On("GetHostByName", mock.Anything, nodeSvc.nodeID).
						Return(gopowerstore.Host{
							ID:         "host-id",
							Initiators: []gopowerstore.InitiatorInstance{},
							Name:       "host-name",
						}, nil)
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					Expect(err).To(BeNil())
					Expect(res).To(Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
					}))
				})
			})

			When("there is no active sessions", func() {
				It("should not return FC topology key", func() {
					nodeSvc.useFC = true
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					clientMock.On("GetHostByName", mock.Anything, nodeSvc.nodeID).
						Return(gopowerstore.Host{
							ID: "host-id",
							Initiators: []gopowerstore.InitiatorInstance{
								{
									PortName: validFCTargetsWWPN[0],
									PortType: gopowerstore.InitiatorProtocolTypeEnumFC,
								},
								{
									PortName: validFCTargetsWWPN[1],
									PortType: gopowerstore.InitiatorProtocolTypeEnumFC,
								}},
							Name: "host-name",
						}, nil)

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					Expect(err).To(BeNil())
					Expect(res).To(Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
					}))
				})
			})
		})
	})

	Describe("Calling NodeGetCapabilities()", func() {
		It("should return predefined parameters with health monitor", func() {
			csictx.Setenv(context.Background(), common.EnvIsHealthMonitorEnabled, "true")

			nodeSvc.nodeID = ""

			fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
			conn, _ := net.Dial("udp", "127.0.0.1:80")
			fsMock.On("NetDial", mock.Anything).Return(
				conn,
				nil,
			)
			iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
				Return(validISCSIInitiators, nil)
			fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
				Return(validFCTargetsWWPN, nil)

			clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
				Return(gopowerstore.Host{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				})
			clientMock.On("GetHosts", mock.Anything).Return(
				[]gopowerstore.Host{{
					ID: "host-id",
					Initiators: []gopowerstore.InitiatorInstance{{
						PortName: "not-matching-port-name",
						PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
					}},
					Name: "host-name",
				}}, nil)
			clientMock.On("CreateHost", mock.Anything, mock.Anything).
				Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
			nodeSvc.opts.NodeNamePrefix = ""
			nodeSvc.Init()

			res, err := nodeSvc.NodeGetCapabilities(context.Background(), &csi.NodeGetCapabilitiesRequest{})
			Ω(err).To(BeNil())
			Ω(res).To(Equal(&csi.NodeGetCapabilitiesResponse{
				Capabilities: []*csi.NodeServiceCapability{
					{Type: &csi.NodeServiceCapability_Rpc{
						Rpc: &csi.NodeServiceCapability_RPC{
							Type: csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
						},
					},
					},
					{
						Type: &csi.NodeServiceCapability_Rpc{
							Rpc: &csi.NodeServiceCapability_RPC{
								Type: csi.NodeServiceCapability_RPC_EXPAND_VOLUME,
							},
						},
					},
					{
						Type: &csi.NodeServiceCapability_Rpc{
							Rpc: &csi.NodeServiceCapability_RPC{
								Type: csi.NodeServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
							},
						},
					},
					{
						Type: &csi.NodeServiceCapability_Rpc{
							Rpc: &csi.NodeServiceCapability_RPC{
								Type: csi.NodeServiceCapability_RPC_GET_VOLUME_STATS,
							},
						},
					},
					{
						Type: &csi.NodeServiceCapability_Rpc{
							Rpc: &csi.NodeServiceCapability_RPC{
								Type: csi.NodeServiceCapability_RPC_VOLUME_CONDITION,
							},
						},
					},
				},
			}))
		})
	})

	Describe("Calling getInitiators()", func() {
		When("Only iSCSI inititators are on node", func() {
			It("should succeed", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return(validISCSIInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return([]string{}, nil)
				iinit, fcinit, err := nodeSvc.getInitiators()
				Ω(iinit).To(Equal([]string{
					"iqn.1994-05.com.redhat:4db86abbe3c",
					"iqn.1994-05.com.redhat:2950c9ca441b"}))
				Ω(fcinit).To(BeNil())
				Ω(err).To(BeNil())
			})
		})
		When("Both FC ans iSCSI initiators are on node", func() {
			It("should succeed", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return(validISCSIInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return(validFCTargetsWWPN, nil)
				iinit, fcinit, err := nodeSvc.getInitiators()
				Ω(iinit).To(Equal([]string{
					"iqn.1994-05.com.redhat:4db86abbe3c",
					"iqn.1994-05.com.redhat:2950c9ca441b"}))
				Ω(fcinit).To(Equal([]string{
					"58:cc:f0:93:48:a0:03:a3",
					"58:cc:f0:93:48:a0:02:a3"}))
				Ω(err).To(BeNil())
			})
		})
		When("Neither FC nor iSCSI initiators are found on node", func() {
			It("should succeed [NFS only]", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return([]string{}, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return([]string{}, nil)
				iinit, fcinit, err := nodeSvc.getInitiators()
				Ω(len(iinit)).To(Equal(0))
				Ω(len(fcinit)).To(Equal(0))
				Ω(err).To(BeNil())
			})
		})
		When("Only FC initiators are on node", func() {
			It("should succeed", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return([]string{}, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return(validFCTargetsWWPN, nil)
				iinit, fcinit, err := nodeSvc.getInitiators()
				Ω(iinit).To(Equal([]string{}))
				Ω(fcinit).To(Equal([]string{
					"58:cc:f0:93:48:a0:03:a3",
					"58:cc:f0:93:48:a0:02:a3"}))
				Ω(err).To(BeNil())
			})
		})
	})
	Describe("calling Node Get Volume Stats", func() {
		When("volume path missing", func() {
			It("should fail", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{ID: validBaseVolumeID, State: gopowerstore.VolumeStateEnumReady}, nil)

				clientMock.On("GetFS", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.FileSystem{ID: validBaseVolumeID}, nil)

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: ""}

				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(
					ContainSubstring("no volume Path provided"),
				)
			})
		})
	})
})

func TestInitConnectors(t *testing.T) {
	arrays := getTestArrays()
	nodeSvc = &Service{
		Fs:             fsMock,
		ctrlSvc:        nil,
		iscsiConnector: nil,
		fcConnector:    nil,
		iscsiLib:       nil,
		nodeID:         validNodeID,
		useFC:          false,
		initialized:    true,
	}
	nodeSvc.SetArrays(arrays)
	nodeSvc.SetDefaultArray(arrays[firstValidIP])
	t.Run("success test", func(t *testing.T) {
		nodeSvc.initConnectors()
	})
}

func TestGetNodeOptions(t *testing.T) {
	arrays := getTestArrays()
	nodeSvc = &Service{
		Fs:             fsMock,
		ctrlSvc:        nil,
		iscsiConnector: nil,
		fcConnector:    nil,
		iscsiLib:       nil,
		nodeID:         validNodeID,
		useFC:          false,
		initialized:    true,
	}
	nodeSvc.SetArrays(arrays)
	nodeSvc.SetDefaultArray(arrays[firstValidIP])
	t.Run("success test", func(t *testing.T) {
		csictx.Setenv(context.Background(), common.EnvNodeIDFilePath, "")
		csictx.Setenv(context.Background(), common.EnvNodeNamePrefix, "")
		csictx.Setenv(context.Background(), common.EnvKubeNodeName, "")
		csictx.Setenv(context.Background(), common.EnvNodeChrootPath, "")
		csictx.Setenv(context.Background(), common.EnvTmpDir, "")
		csictx.Setenv(context.Background(), common.EnvFCPortsFilterFilePath, "")
		csictx.Setenv(context.Background(), common.EnvEnableCHAP, "")
		getNodeOptions()

	})
}

func getNodeVolumeExpandValidRequest(volid string, isBlock bool) *csi.NodeExpandVolumeRequest {
	var size int64 = controller.MaxVolumeSizeBytes / 100
	if !isBlock {
		req := csi.NodeExpandVolumeRequest{
			VolumeId:   volid,
			VolumePath: validTargetPath,
			CapacityRange: &csi.CapacityRange{
				RequiredBytes: size,
				LimitBytes:    controller.MaxVolumeSizeBytes,
			},
		}
		return &req
	}
	req := csi.NodeExpandVolumeRequest{
		VolumeId:   volid,
		VolumePath: validTargetPath + "/csi/volumeDevices/publish/",
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: size,
			LimitBytes:    controller.MaxVolumeSizeBytes,
		},
	}
	return &req
}
