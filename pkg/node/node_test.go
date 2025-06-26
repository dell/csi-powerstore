/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"

	// "github.com/onsi/ginkgo/reporters"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/common/k8sutils"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/gobrick"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gofsutil"
	"github.com/dell/goiscsi"
	"github.com/dell/gonvme"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	ginkgo "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	gomega "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

var (
	iscsiConnectorMock      *mocks.ISCSIConnector
	nvmeConnectorMock       *mocks.NVMEConnector
	fcConnectorMock         *mocks.FcConnector
	utilMock                *mocks.UtilInterface
	fsMock                  *mocks.FsInterface
	nodeSvc                 *Service
	clientMock              *gopowerstoremock.Client
	ctrlMock                *mocks.ControllerInterface
	iscsiLibMock            *goiscsi.MockISCSI
	nvmeLibMock             *gonvme.MockNVMe
	nodeLabelsRetrieverMock *mocks.NodeLabelsRetrieverInterface
	nodeLabelsModifierMock  *mocks.NodeLabelsModifierInterface
)

const (
	validBaseVolumeID    = "39bb1b5f-5624-490d-9ece-18f7b28a904e"
	validBlockVolumeID   = "39bb1b5f-5624-490d-9ece-18f7b28a904e/gid1/scsi"
	validClusterName     = "localSystemName"
	validNfsVolumeID     = "39bb1b5f-5624-490d-9ece-18f7b28a904e/gid2/nfs"
	validRemoteVolID     = "9f840c56-96e6-4de9-b5a3-27e7c20eaa77"
	invalidBlockVolumeID = "39bb1b5f-5624-490d-9ece-18f7b28a904e/gid3/scsi"
	validVolSize         = 16 * 1024 * 1024 * 1024
	validLUNID           = "3"
	validLUNIDINT        = 3
	nodeStagePrivateDir  = "test/stage"
	unimplementedErrMsg  = "rpc error: code = Unimplemented desc = "
	validNodeID          = "csi-node-1a47a1b91c444a8a90193d8066669603-127.0.0.1"
	validHostID          = "e8f4c5f8-c2fc-4df4-bd99-c292c12b55be"
	validHostName        = "csi-node-1a47a1b91c444a8a90193d8066669603"
	testErrMsg           = "test err"
	validDeviceWWN       = "68ccf09800e23ab798312a05426acae0"
	validDevPath         = "/dev/sdag"
	validDevName         = "sdag"
	validNfsExportPath   = "/mnt/nfs"
	validTargetPath      = "/var/lib/kubelet/pods/dac33335-a31d-11e9-b46e-005056917428/" +
		"volumes/kubernetes.io~csi/csi-d91431aba3/mount"
	validStagingPath = "/var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/" +
		"staging/csi-44b46e98ae/c875b4f0-172e-4238-aec7-95b379eb55db"
	firstValidIP       = "gid1"
	secondValidIP      = "gid2"
	firstGlobalID      = "unique1"
	secondGlobalID     = "unique2"
	validNasName       = "my-nas-name"
	validNasID         = "e8f4c5f8-c2fc-4df4-bd99-c292c12b55be"
	validNfsServerID   = "e8f4c5f8-c2fc-4dd2-bd99-c292c12b55be"
	validEphemeralName = "ephemeral-39bb1b5f-5624-490d-9ece-18f7b28a904e/gid1/scsi"
	ephemerallockfile  = "/var/lib/kubelet/plugins/kubernetes.io/csi/pv/ephemeral/39bb1b5f-5624-490d-9ece-18f7b28a904e/gid1/scsi/id"
)

var (
	validFCTargetsWWPN           = []string{"58ccf09348a003a3", "58ccf09348a002a3"}
	validFCTargetWWNNVMe         = []string{"58ccf090496008aa", "58ccf090496008aa"}
	validFCTargetWWNNode         = []string{"58ccf090c96008aa", "58ccf090c96008aa"}
	validFCTargetsWWPNPowerstore = []string{"58:cc:f0:93:48:a0:03:a3", "58:cc:f0:93:48:a0:02:a3"}
	validFCTargetsInfo           = []gobrick.FCTargetInfo{
		{WWPN: validFCTargetsWWPN[0]},
		{WWPN: validFCTargetsWWPN[1]},
	}
	validISCSIInitiators = []string{"iqn.1994-05.com.redhat:4db86abbe3c", "iqn.1994-05.com.redhat:2950c9ca441b"}
	validISCSIPortals    = []string{"192.168.1.1:3260", "192.168.1.2:3260"}
	validISCSITargets    = []string{
		"iqn.2015-10.com.dell:dellemc-powerstore-fnm00180700173-a-39f17e0e",
		"iqn.2015-10.com.dell:dellemc-powerstore-fnm00180700173-b-10de15a5",
	}
	validNVMEInitiators = []string{
		"nqn.2014-08.org.nvmexpress:uuid:02a08600-57d6-4089-8736-bf1f7326990e",
		"nqn.2014-08.org.nvmexpress:uuid:fa363a22-1c74-44f3-9932-1c35d5cf5c4d",
	}
	validNVMETCPPortals = []string{"192.168.1.1:4420", "192.168.1.2:4420"}
	validNVMETCPTargets = []string{
		"nqn.1988-11.com.dell:powerstore:00:e6e2d5b871f1403E169D",
		"nqn.1988-11.com.dell:powerstore:00:e6e2d5b871f1403E169D",
	}
	validNVMEFCPortals = []string{"nn-0x11ccf090c9200b1a:pn-0x11ccf09149280b1a", "nn-0x11ccf090c9200b1a:pn-0x11ccf09149280b1a"}
	validNVMEFCTargets = []string{
		"nqn.1988-11.com.dell:powerstore:00:e6e2d5b871f1403E169D",
		"nqn.1988-11.com.dell:powerstore:00:e6e2d5b871f1403E169D",
	}
	validISCSITargetInfo = []gobrick.ISCSITargetInfo{
		{Portal: validISCSIPortals[0], Target: validISCSITargets[0]},
		{Portal: validISCSIPortals[1], Target: validISCSITargets[1]},
	}
	validGobrickISCSIVolumeINFO = gobrick.ISCSIVolumeInfo{
		Targets: []gobrick.ISCSITargetInfo{
			{
				Portal: validISCSITargetInfo[0].Portal,
				Target: validISCSITargetInfo[0].Target,
			},
			{Portal: validISCSITargetInfo[1].Portal, Target: validISCSITargetInfo[1].Target},
		},
		Lun: validLUNIDINT,
	}
	validNVMETCPTargetInfo = []gobrick.NVMeTargetInfo{
		{Portal: validNVMETCPPortals[0], Target: validNVMETCPTargets[0]},
		{Portal: validNVMETCPPortals[1], Target: validNVMETCPTargets[1]},
	}
	validGobrickNVMETCPVolumeINFO = gobrick.NVMeVolumeInfo{
		Targets: []gobrick.NVMeTargetInfo{
			{
				Portal: validNVMETCPTargetInfo[0].Portal,
				Target: validNVMETCPTargetInfo[0].Target,
			},
			{Portal: validNVMETCPTargetInfo[1].Portal, Target: validNVMETCPTargetInfo[1].Target},
		},
		WWN: validDeviceWWN,
	}
	validNVMEFCTargetInfo = []gobrick.NVMeTargetInfo{
		{Portal: validNVMEFCPortals[0], Target: validNVMEFCTargets[0]},
		{Portal: validNVMEFCPortals[1], Target: validNVMEFCTargets[1]},
	}
	validGobrickNVMEFCVolumeINFO = gobrick.NVMeVolumeInfo{
		Targets: []gobrick.NVMeTargetInfo{
			{
				Portal: validNVMEFCTargetInfo[0].Portal,
				Target: validNVMEFCTargetInfo[0].Target,
			},
			{Portal: validNVMEFCTargetInfo[1].Portal, Target: validNVMEFCTargetInfo[1].Target},
		},
		WWN: validDeviceWWN,
	}
	validGobrickFCVolumeINFO = gobrick.FCVolumeInfo{
		Targets: []gobrick.FCTargetInfo{
			{WWPN: validFCTargetsWWPN[0]},
			{WWPN: validFCTargetsWWPN[1]},
		},
		Lun: validLUNIDINT,
	}
	validGobrickDevice = gobrick.Device{Name: validDevName, WWN: validDeviceWWN, MultipathID: validDeviceWWN}

	validRemoteISCSIPortals = []string{"192.168.1.3:3260", "192.168.1.4:3260"}
	validRemoteISCSITargets = []string{
		"iqn.2015-10.com.dell:dellemc-powerstore-fnm00180700174-a-39f17e0e",
		"iqn.2015-10.com.dell:dellemc-powerstore-fnm00180700174-b-10de15a5",
	}
	validRemoteFCTargetsWWPN   = []string{"58ccf09348a003a4", "58ccf09348a002a4"}
	validRemoteISCSITargetInfo = []gobrick.ISCSITargetInfo{
		{Portal: validRemoteISCSIPortals[0], Target: validRemoteISCSITargets[0]},
		{Portal: validRemoteISCSIPortals[1], Target: validRemoteISCSITargets[1]},
	}
)

func TestCSINodeService(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	junitReporter := reporters.NewJUnitReporter("node-svc.xml")
	ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "CSINodeService testing suite", []ginkgo.Reporter{junitReporter})
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
		GlobalID:      firstGlobalID,
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
		GlobalID:      secondGlobalID,
		Client:        clientMock,
		IP:            secondValidIP,
	}

	arrays[firstValidIP] = first
	arrays[secondValidIP] = second
	return arrays
}

func setVariables() {
	iscsiConnectorMock = new(mocks.ISCSIConnector)
	nvmeConnectorMock = new(mocks.NVMEConnector)
	fcConnectorMock = new(mocks.FcConnector)
	utilMock = new(mocks.UtilInterface)
	fsMock = new(mocks.FsInterface)
	ctrlMock = new(mocks.ControllerInterface)
	clientMock = new(gopowerstoremock.Client)
	iscsiLibMock = goiscsi.NewMockISCSI(nil)
	nvmeLibMock = gonvme.NewMockNVMe(nil)
	nodeLabelsRetrieverMock = new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
	nodeLabelsModifierMock = new(mocks.NodeLabelsModifierInterface)
	k8sutils.NodeLabelsModifier = nodeLabelsModifierMock
	arrays := getTestArrays()

	nodeSvc = &Service{
		Fs:              fsMock,
		ctrlSvc:         ctrlMock,
		iscsiConnector:  iscsiConnectorMock,
		nvmeConnector:   nvmeConnectorMock,
		fcConnector:     fcConnectorMock,
		iscsiLib:        iscsiLibMock,
		nvmeLib:         nvmeLibMock,
		nodeID:          validNodeID,
		initialized:     true,
		isPodmonEnabled: false,
	}
	nodeSvc.iscsiTargets = make(map[string][]string)
	nodeSvc.nvmeTargets = make(map[string][]string)
	nodeSvc.useFC = make(map[string]bool)
	nodeSvc.useNVME = make(map[string]bool)
	old := ReachableEndPoint
	func() { ReachableEndPoint = old }()
	ReachableEndPoint = func(ip string) bool {
		if ip == "192.168.1.1:3260" || ip == "192.168.1.2:3260" || ip == "192.168.1.3:3260" || ip == "192.168.1.4:3260" {
			return true
		}
		return false
	}
	nodeSvc.SetArrays(arrays)
	nodeSvc.SetDefaultArray(arrays[firstValidIP])
}

func setDefaultNodeLabelsMock() {
	nodeLabelsRetrieverMock.On("BuildConfigFromFlags", mock.Anything, mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("GetNVMeUUIDs", mock.Anything).Return(nil, nil)
	nodeLabelsModifierMock.On("AddNVMeLabels", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
}

var _ = ginkgo.Describe("CSINodeService", func() {
	ginkgo.BeforeEach(func() {
		setVariables()
	})
	nasData := []gopowerstore.NAS{
		{
			NfsServers: []gopowerstore.NFSServerInstance{
				{
					IsNFSv4Enabled: true,
					IsNFSv3Enabled: false,
				},
			},
		},
	}
	ginkgo.Describe("calling Init()", func() {
		ginkgo.When("there is no suitable host", func() {
			ginkgo.It("should create this host", func() {
				nodeSvc.nodeID = ""
				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				setDefaultNodeLabelsMock()
				nodeSvc.opts.NodeNamePrefix = ""
				err := nodeSvc.Init()
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("failed to read nodeID file", func() {
			ginkgo.It("should fail", func() {
				nodeSvc.nodeID = ""

				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), errors.New("no such file"))
				setDefaultNodeLabelsMock()

				err := nodeSvc.Init()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("no such file"))
			})
		})
		ginkgo.When("failed to get outbound ip", func() {
			ginkgo.It("should fail", func() {
				nodeSvc.nodeID = ""

				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					errors.New("failed to dial"),
				)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
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
				setDefaultNodeLabelsMock()
				nodeSvc.opts.NodeNamePrefix = ""
				err := nodeSvc.Init()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Could not connect to PowerStore array"))
			})
		})
		ginkgo.When("failed to get node id", func() {
			ginkgo.It("should fail", func() {
				nodeSvc.nodeID = ""

				fsMock.On("ReadFile", mock.Anything).Return([]byte("toooooooooooooooooooooo-looooooooooooooooooooooooooooooooooooooooong"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
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
				setDefaultNodeLabelsMock()
				nodeSvc.opts.NodeNamePrefix = ""
				err := nodeSvc.Init()
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("node name prefix is too long"))
			})
		})

		ginkgo.When("there IS a suitable host", func() {
			ginkgo.When("nodeID != hostName", func() {
				ginkgo.It("should reuse host", func() {
					nodeSvc.nodeID = ""
					fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
						Return(validISCSIInitiators, nil)
					nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
						Return(validNVMEInitiators, nil)
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
					setDefaultNodeLabelsMock()

					err := nodeSvc.Init()
					gomega.Expect(err).To(gomega.BeNil())
				})

				ginkgo.It("should reuse host [CHAP]", func() {
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
					nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
						Return(validNVMEInitiators, nil)
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
					setDefaultNodeLabelsMock()

					err := nodeSvc.Init()
					gomega.Expect(err).To(gomega.BeNil())
				})
			})
		})

		ginkgo.When("using FC", func() {
			ginkgo.It("should create FC host", func() {
				nodeSvc.Arrays()[firstValidIP].BlockProtocol = common.FcTransport
				nodeSvc.nodeID = ""
				nodeSvc.useFC[firstGlobalID] = true
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
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
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
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				setDefaultNodeLabelsMock()

				err := nodeSvc.Init()
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("using NVMe", func() {
			ginkgo.It("should create NVMe host", func() {
				nodeSvc.Arrays()[firstValidIP].BlockProtocol = common.NVMEFCTransport
				nodeSvc.nodeID = ""
				nodeSvc.useNVME[firstGlobalID] = true
				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
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
							PortType: gopowerstore.InitiatorProtocolTypeEnumNVME,
						}},
						Name: "host-name",
					}}, nil)

				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				setDefaultNodeLabelsMock()

				err := nodeSvc.Init()
				gomega.Expect(err).To(gomega.BeNil())
			})

			ginkgo.It("should create NVMe host and check for duplicate UUIDs", func() {
				nodeSvc.Arrays()[firstValidIP].BlockProtocol = common.NVMEFCTransport
				nodeSvc.nodeID = ""
				nodeSvc.useNVME[firstGlobalID] = true
				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
					Return(validFCTargetsWWPN, nil)

				nodeSvc.opts.KubeNodeName = common.EnvKubeNodeName
				nodeSvc.opts.KubeConfigPath = common.EnvKubeConfigPath
				nodeLabelsRetrieverMock.On("GetNVMeUUIDs", mock.Anything).Return(
					map[string]string{
						"node1": "duplicate-uuid",
						"node2": "duplicate-uuid",
					},
					nil,
				)

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
							PortType: gopowerstore.InitiatorProtocolTypeEnumNVME,
						}},
						Name: "host-name",
					}}, nil)

				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				setDefaultNodeLabelsMock()

				err := nodeSvc.Init()
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("protocol flag initialization", func() {
			ginkgo.It("should have correct entry for each array - NVMeTCP and iSCSI", func() {
				nodeSvc.Arrays()[firstValidIP].BlockProtocol = common.NVMETCPTransport
				nodeSvc.Arrays()[secondValidIP].BlockProtocol = common.ISCSITransport
				nodeSvc.nodeID = ""
				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(conn, nil)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
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
							PortType: gopowerstore.InitiatorProtocolTypeEnumNVME,
						}},
						Name: "host-name",
					}}, nil)
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				setDefaultNodeLabelsMock()

				err := nodeSvc.Init()
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(nodeSvc.useNVME[firstGlobalID]).To(gomega.BeTrue())
				gomega.Expect(nodeSvc.useFC[firstGlobalID]).To(gomega.BeFalse())
				gomega.Expect(nodeSvc.useNVME[secondGlobalID]).To(gomega.BeFalse())
				gomega.Expect(nodeSvc.useFC[secondGlobalID]).To(gomega.BeFalse())
			})

			ginkgo.It("should have correct entry for each array - iSCSI and NVMeFC", func() {
				nodeSvc.Arrays()[firstValidIP].BlockProtocol = common.ISCSITransport
				nodeSvc.Arrays()[secondValidIP].BlockProtocol = common.NVMEFCTransport
				nodeSvc.nodeID = ""
				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(conn, nil)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
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
							PortType: gopowerstore.InitiatorProtocolTypeEnumNVME,
						}},
						Name: "host-name",
					}}, nil)
				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				setDefaultNodeLabelsMock()

				err := nodeSvc.Init()
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(nodeSvc.useNVME[firstGlobalID]).To(gomega.BeFalse())
				gomega.Expect(nodeSvc.useFC[firstGlobalID]).To(gomega.BeFalse())
				gomega.Expect(nodeSvc.useNVME[secondGlobalID]).To(gomega.BeTrue())
				gomega.Expect(nodeSvc.useFC[secondGlobalID]).To(gomega.BeTrue())
			})

			ginkgo.It("should set useNVME/useFC when transport is not set", func() {
				nodeSvc.useNVME[firstGlobalID] = false
				nodeSvc.useFC[firstGlobalID] = false
				nodeSvc.nodeID = ""
				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(conn, nil)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return(validNVMEInitiators, nil)
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
							PortType: gopowerstore.InitiatorProtocolTypeEnumNVME,
						}},
						Name: "host-name",
					}}, nil)

				clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
				clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
				setDefaultNodeLabelsMock()

				nodeSvc.Arrays()[firstValidIP].BlockProtocol = "default_protocol"

				err := nodeSvc.Init()
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(nodeSvc.useNVME[firstGlobalID]).To(gomega.BeTrue())
				gomega.Expect(nodeSvc.useFC[firstGlobalID]).To(gomega.BeTrue())
			})
		})

		ginkgo.When("using NFS when length of all initiators is 0", func() {
			ginkgo.It("should probe successfully", func() {
				nodeSvc.nodeID = ""
				// setup mocks
				fsMock.On("ReadFile", mock.Anything).Return([]byte("my-host-id"), nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(conn, nil)
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).
					Return([]string{}, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
					Return([]string{}, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).
					Return([]string{}, nil)

				err := nodeSvc.Init()
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(nodeSvc.useNVME[firstGlobalID]).To(gomega.BeFalse())
				gomega.Expect(nodeSvc.useFC[firstGlobalID]).To(gomega.BeFalse())
				gomega.Expect(nodeSvc.useNVME[secondGlobalID]).To(gomega.BeFalse())
				gomega.Expect(nodeSvc.useFC[secondGlobalID]).To(gomega.BeFalse())
				gomega.Expect(nodeSvc.useNFS).To(gomega.BeTrue())
			})
		})
	})

	ginkgo.Describe("calling nodeProbe", func() {
		ginkgo.When("failed to get host on array", func() {
			ginkgo.It("should fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							Message:    "not found",
						},
					})
				arrays := getTestArrays()
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("not found"))
			})
		})

		ginkgo.When("failed to get host on array but it's NFS only", func() {
			ginkgo.It("should not fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{
							StatusCode: http.StatusNotFound,
							Message:    "not found",
						},
					})
				nodeSvc.useNFS = true
				arrays := getTestArrays()
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				gomega.Expect(err).To(gomega.BeNil())
				nodeSvc.useNFS = false
			})
		})

		ginkgo.When("got host on array but iscsi initiators are not present", func() {
			ginkgo.It("should fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID:         "host-id",
						Initiators: []gopowerstore.InitiatorInstance{},
						Name:       "host-name",
					}, nil)

				arrays := getTestArrays()

				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{
						Name:    validClusterName,
						NVMeNQN: validNVMEInitiators[0],
					}, nil)
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("no active iscsi sessions"))
			})
		})

		ginkgo.When("got host on array but nvme initiators are not present", func() {
			ginkgo.It("should fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID:         "host-id",
						Initiators: []gopowerstore.InitiatorInstance{},
						Name:       "host-name",
					}, nil)

				arrays := getTestArrays()
				nodeSvc.useNVME[firstGlobalID] = true
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{
						Name:    validClusterName,
						NVMeNQN: validNVMEInitiators[0],
					}, nil)
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				nodeSvc.useNVME[firstGlobalID] = false
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("no active nvme sessions"))
			})
		})

		ginkgo.When("got host on array but iscsi initiators are not present and UseNFS is true at the beginning", func() {
			ginkgo.It("should not fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{
							{
								PortName: validISCSIPortals[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
						},
						Name: "host-name",
					}, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{
						Name:    validClusterName,
						NVMeNQN: validNVMEInitiators[0],
					}, nil)
				nodeSvc.useNFS = true
				arrays := getTestArrays()
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				nodeSvc.useNFS = false
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("got host on array but nvme initiators are not present and UseNFS is true at the beginning", func() {
			ginkgo.It("should not fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{
							{
								PortName: validISCSIPortals[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
						},
						Name: "host-name",
					}, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{
						Name:    validClusterName,
						NVMeNQN: validNVMEInitiators[0],
					}, nil)
				nodeSvc.useNFS = true
				nodeSvc.useNVME[firstGlobalID] = true
				arrays := getTestArrays()
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				nodeSvc.useNFS = false
				nodeSvc.useNVME[firstGlobalID] = false
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("got host on array but it's NFS type at the beginning but later found iscsi active sessions", func() {
			ginkgo.It("should not fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{
							{
								ActiveSessions: []gopowerstore.ActiveSessionInstance{
									{
										PortName: validISCSITargets[0],
									},
								},
								PortName: validISCSIPortals[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
							{
								ActiveSessions: []gopowerstore.ActiveSessionInstance{
									{
										PortName: validISCSITargets[1],
									},
								},
								PortName: validISCSIPortals[1],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
						},
						Name: "host-name",
					}, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				arrays := getTestArrays()
				nodeSvc.useNFS = true
				nodeSvc.iscsiTargets[firstGlobalID] = []string{"iqn.2015-10.com.dell:dellemc-foobar-123-a-7ceb34a0"}
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(nodeSvc.useNFS).To(gomega.BeFalse())
			})
		})

		ginkgo.When("got host on array but it's NFS type at the beginning but later found nvme active sessions", func() {
			ginkgo.It("should not fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{
							{
								ActiveSessions: []gopowerstore.ActiveSessionInstance{
									{
										PortName: validNVMETCPTargets[0],
									},
								},
								PortName: validNVMETCPPortals[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumNVME,
							},
							{
								ActiveSessions: []gopowerstore.ActiveSessionInstance{
									{
										PortName: validNVMETCPTargets[1],
									},
								},
								PortName: validNVMETCPPortals[1],
								PortType: gopowerstore.InitiatorProtocolTypeEnumNVME,
							},
						},
						Name: "host-name",
					}, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				arrays := getTestArrays()
				nodeSvc.useNFS = true
				nodeSvc.useNVME[firstGlobalID] = true
				nodeSvc.nvmeTargets[firstGlobalID] = []string{"nqn.1988-11.com.dell.mock:00:e6e2d5b871f1403E169D0"}
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				nodeSvc.useNVME[firstGlobalID] = false
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(nodeSvc.useNFS).To(gomega.BeFalse())
			})
		})

		ginkgo.When("host as well as initiators are present but active sessions are not present on node", func() {
			ginkgo.It("should fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{
							{
								PortName: validISCSIInitiators[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
							{
								PortName: validISCSIInitiators[1],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
						},
						Name: "host-name",
					}, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, nil)
				arrays := getTestArrays()
				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("no active iscsi sessions"))
			})
		})

		ginkgo.When("host as well as iscsi active sessions are present on array", func() {
			ginkgo.It("should not fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID: "host-id",
						Initiators: []gopowerstore.InitiatorInstance{
							{
								PortName: validISCSIInitiators[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
							{
								PortName: validISCSIInitiators[1],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
						},
						Name: "host-name",
					}, nil)
				arrays := getTestArrays()
				nodeSvc.iscsiTargets[firstGlobalID] = []string{"iqn.2015-10.com.dell:dellemc-foobar-123-a-7ceb34a0"}
				nodeSvc.startNodeToArrayConnectivityCheck(context.Background())

				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("host as well as active sessions are present on array for FC protocol", func() {
			ginkgo.It("should not fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
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
							},
						},
						Name: "host-name",
					}, nil)

				arrays := getTestArrays()
				if nodeSvc.useNVME[firstGlobalID] {
					nodeSvc.useNVME[firstGlobalID] = false
				}
				if !nodeSvc.useFC[firstGlobalID] {
					nodeSvc.useFC[firstGlobalID] = true
				}

				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				gomega.Expect(err).To(gomega.BeNil())
			})
		})

		ginkgo.When("host entry is found but no Active session on array for FC protocol", func() {
			ginkgo.It("should not fail", func() {
				nodeSvc.nodeID = "some-random-text"

				clientMock.On("GetHostByName", mock.Anything, mock.AnythingOfType("string")).Return(
					gopowerstore.Host{
						ID:         "host-id",
						Initiators: []gopowerstore.InitiatorInstance{},
						Name:       "host-name",
					}, nil)

				arrays := getTestArrays()
				if nodeSvc.useNVME[firstGlobalID] {
					nodeSvc.useNVME[firstGlobalID] = false
				}
				nodeSvc.useFC[firstGlobalID] = true

				err := nodeSvc.nodeProbe(context.Background(), arrays["gid1"])
				gomega.Expect(err).ToNot(gomega.BeNil())
				if nodeSvc.useFC[firstGlobalID] {
					nodeSvc.useFC[firstGlobalID] = false
				}
			})
		})
	})

	ginkgo.Describe("calling NodeStage()", func() {
		stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)

		ginkgo.When("using iSCSI", func() {
			ginkgo.It("should successfully stage iSCSI volume", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		ginkgo.When("using NVMeFC", func() {
			ginkgo.It("should successfully stage NVMeFC volume", func() {
				nodeSvc.useNVME[firstGlobalID] = true
				nodeSvc.useFC[firstGlobalID] = true
				nvmeConnectorMock.On("ConnectVolume", mock.Anything, gobrick.NVMeVolumeInfo{
					Targets: validNVMEFCTargetInfo,
					WWN:     validDeviceWWN,
				}, true).Return(gobrick.Device{}, nil)

				scsiStageVolumeOK(utilMock, fsMock)
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		ginkgo.When("using FC", func() {
			ginkgo.It("should successfully stage FC volume", func() {
				nodeSvc.useFC[firstGlobalID] = true
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		ginkgo.When("using NFS", func() {
			ginkgo.It("should successfully stage NFS volume", func() {
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

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		ginkgo.When("using NFS with posix acls", func() {
			ginkgo.It("should successfully stage NFS volume", func() {
				nfsv4ACLsMock := new(mocks.NFSv4ACLsInterface)

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
				publishContext[common.KeyNasName] = validNasName
				publishContext[common.KeyNfsACL] = "0777"

				nfsServers := []gopowerstore.NFSServerInstance{
					{
						ID:             validNfsServerID,
						IsNFSv4Enabled: true,
					},
				}

				clientMock.On("GetNfsServer", mock.Anything, validNasName).Return(gopowerstore.NFSServerInstance{ID: validNfsServerID, IsNFSv4Enabled: true}, nil)
				clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID, NfsServers: nfsServers}, nil)
				nfsv4ACLsMock.On("SetNfsv4Acls", mock.Anything, mock.Anything).Return(nil)

				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    publishContext,
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "multi-writer", "nfs"),
				})

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		ginkgo.When("using NFS with NFSv4 acls", func() {
			ginkgo.It("should successfully stage NFS volume", func() {
				nfsv4ACLsMock := new(mocks.NFSv4ACLsInterface)

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
				publishContext[common.KeyNfsACL] = "A::OWNER@:RWX"

				nfsServers := []gopowerstore.NFSServerInstance{
					{
						ID:             validNfsServerID,
						IsNFSv4Enabled: true,
					},
				}

				nfsv4ACLsMock.On("SetNfsv4Acls", mock.Anything, mock.Anything).Return(nil)
				clientMock.On("GetNASByName", mock.Anything, "").Return(gopowerstore.NAS{ID: validNasID, NfsServers: nfsServers}, nil)
				clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{ID: validNfsServerID, IsNFSv4Enabled: true}, nil)

				nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    publishContext,
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "multi-writer", "nfs"),
				})
			})
		})

		ginkgo.When("using iSCSI for Metro volume", func() {
			ginkgo.It("should successfully stage Metro iSCSI volume", func() {
				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil).Times(2)
				iscsiConnectorMock.On("ConnectVolume", mock.Anything, gobrick.ISCSIVolumeInfo{
					Targets: validRemoteISCSITargetInfo,
					Lun:     validLUNIDINT,
				}).Return(gobrick.Device{}, nil).Times(2)

				scsiStageVolumeOK(utilMock, fsMock)
				scsiStageRemoteMetroVolumeOK(utilMock, fsMock)
				metroVolumeID := fmt.Sprintf("%s:%s/%s", validBlockVolumeID, validRemoteVolID, secondValidIP)
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          metroVolumeID,
					PublishContext:    getValidRemoteMetroPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		ginkgo.When("volume is already staged", func() {
			ginkgo.It("should return that stage is successful [SCSI]", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})

			ginkgo.It("should return that stage is successful [NFS]", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})
		})

		ginkgo.When("missing volume capabilities", func() {
			ginkgo.It("should fail", func() {
				req := &csi.NodeStageVolumeRequest{}

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume capability is required"))
			})
		})

		ginkgo.When("missing volume VolumeID", func() {
			ginkgo.It("should fail", func() {
				req := &csi.NodeStageVolumeRequest{
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					StagingTargetPath: nodeStagePrivateDir,
				}

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume ID is required"))
			})
		})

		ginkgo.When("invalid array ID", func() {
			ginkgo.It("should fail", func() {
				req := &csi.NodeStageVolumeRequest{
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeId:          invalidBlockVolumeID,
				}

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find array with ID"))
			})
		})

		ginkgo.When("missing volume stage path", func() {
			ginkgo.It("should fail", func() {
				req := &csi.NodeStageVolumeRequest{
					VolumeCapability: getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4"),
					VolumeId:         validBlockVolumeID,
				}

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).NotTo(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("staging target path is required"))
			})
		})

		ginkgo.When("device is found but not ready", func() {
			ginkgo.BeforeEach(func() {
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

			ginkgo.It("should unstage and stage again", func() {
				fsMock.On("Remove", stagingPath).Return(nil).Once()

				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeStageVolumeResponse{}))
			})

			ginkgo.When("unstaging fails", func() {
				ginkgo.It("should fail", func() {
					e := errors.New("os-error")
					fsMock.On("Remove", stagingPath).Return(e).Once()
					fsMock.On("IsNotExist", e).Return(false)
					fsMock.On("IsDeviceOrResourceBusy", e).Return(false)

					res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
						VolumeId:          validBlockVolumeID,
						PublishContext:    getValidPublishContext(),
						StagingTargetPath: nodeStagePrivateDir,
						VolumeCapability: getCapabilityWithVoltypeAccessFstype(
							"mount", "single-writer", "ext4"),
					})
					gomega.Expect(err).ToNot(gomega.BeNil())
					gomega.Expect(res).To(gomega.BeNil())
					gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to unmount volume"))
				})
			})
		})

		ginkgo.When("publish context is incorrect", func() {
			ginkgo.It("should fail [deviceWWN]", func() {
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    map[string]string{},
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("deviceWWN must be in publish context"))
			})

			ginkgo.It("should fail [volumeLUNAddress]", func() {
				res, err := nodeSvc.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId: validBlockVolumeID,
					PublishContext: map[string]string{
						common.PublishContextDeviceWWN: validDeviceWWN,
					},
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "single-writer", "ext4"),
				})
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volumeLUNAddress must be in publish context"))
			})

			ginkgo.It("should fail [iscsiTargets]", func() {
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
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("iscsiTargets data must be in publish context"))
			})

			ginkgo.It("should fail [nvmefcTargets]", func() {
				nodeSvc.useNVME[firstGlobalID] = true
				nodeSvc.useFC[firstGlobalID] = true
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
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("NVMeFC Targets data must be in publish context"))
			})

			ginkgo.It("should fail [nvmetcpTargets]", func() {
				nodeSvc.useNVME[firstGlobalID] = true
				nodeSvc.useFC[firstGlobalID] = false
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
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("NVMeTCP Targets data must be in publish context"))
			})

			ginkgo.It("should fail [fcTargets]", func() {
				nodeSvc.useFC[firstGlobalID] = true
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
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("fcTargets data must be in publish context"))
			})
		})

		ginkgo.When("can not connect device", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("unable to find device after multiple discovery attempts"))
			})
		})

		ginkgo.When("mount fails", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("error bind disk"))
			})
		})

		ginkgo.When("when mount call fails [NFS]", func() {
			publishContext := getValidPublishContext()
			publishContext["NfsExportPath"] = validNfsExportPath
			var req *csi.NodeStageVolumeRequest
			ginkgo.BeforeEach(func() {
				req = &csi.NodeStageVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    publishContext,
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "multi-writer", "nfs"),
				}
			})

			ginkgo.It("should fail [MkdirAll target folder]", func() {
				stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkdirAll", stagingPath, mock.Anything).Return(errors.New("some-error"))

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't create target folder"))
			})

			ginkgo.It("should fail [Mount]", func() {
				stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkdirAll", stagingPath, mock.Anything).Return(nil).Once()
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("Mount", mock.Anything, validNfsExportPath, stagingPath, "").Return(errors.New("some-error"))

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("error mount nfs share"))
			})

			ginkgo.It("should fail [MkdirAll common folder]", func() {
				stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkdirAll", stagingPath, mock.Anything).Return(nil).Once()
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("Mount", mock.Anything, validNfsExportPath, stagingPath, "").Return(nil)
				fsMock.On("MkdirAll", filepath.Join(stagingPath, commonNfsVolumeFolder), mock.Anything).Return(errors.New("some-error"))

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't create common folder"))
			})

			ginkgo.It("should fail [Chmod]", func() {
				stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkdirAll", stagingPath, mock.Anything).Return(nil).Once()
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("Mount", mock.Anything, validNfsExportPath, stagingPath, "").Return(nil)
				fsMock.On("MkdirAll", filepath.Join(stagingPath, commonNfsVolumeFolder), mock.Anything).Return(nil)
				fsMock.On("Chmod", filepath.Join(stagingPath, commonNfsVolumeFolder), os.ModeSticky|os.ModePerm).Return(errors.New("some-error"))

				res, err := nodeSvc.NodeStageVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't change permissions of folder"))
			})
		})

		ginkgo.When("when ModifyNFSExport call fails [NFS]", func() {
			ginkgo.It("should fail", func() {
				stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)
				fsMock.On("MkdirAll", stagingPath, mock.Anything).Return(nil).Once()
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("Mount", mock.Anything, validNfsExportPath, stagingPath, "").Return(nil)
				fsMock.On("MkdirAll", filepath.Join(stagingPath, commonNfsVolumeFolder), mock.Anything).Return(nil)
				fsMock.On("Chmod", filepath.Join(stagingPath, commonNfsVolumeFolder), os.ModeSticky|os.ModePerm).Return(nil)
				clientMock.On("ModifyNFSExport", mock.Anything, mock.Anything, mock.Anything).Return(gopowerstore.CreateResponse{}, errors.New("some-error"))

				publishContext := getValidPublishContext()
				publishContext["NfsExportPath"] = validNfsExportPath
				publishContext["allowRoot"] = "false"
				publishContext["NatIP"] = "192.168.1.1"
				req := &csi.NodeStageVolumeRequest{
					VolumeId:          validNfsVolumeID,
					PublishContext:    publishContext,
					StagingTargetPath: nodeStagePrivateDir,
					VolumeCapability: getCapabilityWithVoltypeAccessFstype(
						"mount", "multi-writer", "nfs"),
				}
				res, err := nodeSvc.NodeStageVolume(context.Background(), req)

				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failure when modifying nfs export"))
			})
		})
	})

	ginkgo.Describe("calling NodeUnstage()", func() {
		stagingPath := filepath.Join(nodeStagePrivateDir, validBaseVolumeID)

		ginkgo.When("unstaging block volume", func() {
			ginkgo.It("should succeed [iSCSI]", func() {
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
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnstageVolumeResponse{}))
			})
			ginkgo.It("should fail, no targetPath [iSCSI]", func() {
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
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				_, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: "",
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("staging target path is required"))
			})
			ginkgo.It("should fail, invalid array ID", func() {
				_, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          invalidBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't find array with ID"))
			})
			ginkgo.It("should fail, because no mounts [iSCSI]", func() {
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
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				_, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("could not reliably determine existing mount for path"))
			})
			ginkgo.It("should fail, failed to unmount [iSCSI]", func() {
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
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				_, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("could not unmount de"))
			})
			ginkgo.It("should succeed, without path in mouninfo [iSCSI]", func() {
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
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnstageVolumeResponse{}))
			})

			ginkgo.It("should succeed for Metro volume [iSCSI]", func() {
				mountInfo := []gofsutil.Info{{Device: validDevName, Path: stagingPath}}
				remoteStagingPath := filepath.Join(nodeStagePrivateDir, validRemoteVolID)
				remoteMountInfo := []gofsutil.Info{{Device: validDevName, Path: remoteStagingPath}}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(4)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil).Once()
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(remoteMountInfo, nil).Once()

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil).Once()
				utilMock.On("Unmount", mock.Anything, remoteStagingPath).Return(nil).Once()
				fsMock.On("Remove", stagingPath).Return(nil)
				fsMock.On("Remove", remoteStagingPath).Return(nil)
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validRemoteVolID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil).Once()
				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validRemoteVolID)).Return(nil).Once()
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				metroVolumeID := fmt.Sprintf("%s:%s/%s", validBlockVolumeID, validRemoteVolID, secondValidIP)
				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          metroVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnstageVolumeResponse{}))
			})

			ginkgo.It("should succeed [FC]", func() {
				nodeSvc.useFC[firstGlobalID] = true
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
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				fcConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnstageVolumeResponse{}))
			})

			ginkgo.It("should succeed [NVMe]", func() {
				nodeSvc.useNVME[firstGlobalID] = true
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
				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				nvmeConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnstageVolumeResponse{}))
			})
			ginkgo.It("should succeed, on device or resource busy error", func() {
				remnantStagingPath := "/noderoot/" + stagingPath
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   stagingPath,
					}, {
						Device: validDevName,
						Path:   remnantStagingPath,
					},
				}

				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(4)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				utilMock.On("Unmount", mock.Anything, stagingPath).Return(nil)

				fsMock.On("Remove", stagingPath).Return(errors.New("remove " + stagingPath + ": device or resource busy")).Once()
				fsMock.On("IsDeviceOrResourceBusy", mock.Anything).Return(true)
				utilMock.On("Unmount", mock.Anything, remnantStagingPath).Return(nil)
				fsMock.On("Remove", stagingPath).Return(nil).Once()
				fsMock.On("IsNotExist", mock.Anything).Return(false)

				fsMock.On("WriteFile", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID), []byte(validDevName), os.FileMode(0o640)).Return(nil)

				iscsiConnectorMock.On("DisconnectVolumeByDeviceName", mock.Anything, validDevName).Return(nil)

				fsMock.On("Remove", path.Join(nodeSvc.opts.TmpDir, validBaseVolumeID)).Return(nil)

				res, err := nodeSvc.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          validBlockVolumeID,
					StagingTargetPath: nodeStagePrivateDir,
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnstageVolumeResponse{}))
			})
		})
		ginkgo.When("unstaging nfs volume", func() {
			ginkgo.It("should succeed", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnstageVolumeResponse{}))
			})
		})
	})

	ginkgo.Describe("calling NodePublish()", func() {
		stagingPath := filepath.Join(validStagingPath, validBaseVolumeID)

		ginkgo.When("publishing block volume as mount", func() {
			ginkgo.It("should succeed", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		ginkgo.When("publishing block volume as mount with RO", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("RO mount required but no fs detected on staged volume"))
			})
		})
		ginkgo.When("publishing block volume as mount with RO, fs exists", func() {
			ginkgo.It("should succeed", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
			})
		})
		ginkgo.When("publishing block volume as mount and unable to create dirs", func() {
			ginkgo.It("should fail", func() {
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
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "multiple-reader", ""),
					Readonly:          false,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't create target dir"))
			})
		})
		ginkgo.When("publishing block volume as mount and getformat fails", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("error while trying to detect fs"))
			})
		})
		ginkgo.When("publishing block volume as mount and disk preformatted", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Target device already formatted"))
			})
		})
		ginkgo.When("publishing formatting failed", func() {
			ginkgo.It("should succeed", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't format staged device"))
			})
		})
		ginkgo.When("publishing block volume as mount with multi-writer", func() {
			ginkgo.It("should fail", func() {
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("mount", "multiple-writer", ""),
					Readonly:          false,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("Mount volumes do not support AccessMode MULTI_NODE_MULTI_WRITER"))
			})
		})
		ginkgo.When("publishing block volume as raw block", func() {
			ginkgo.It("should succeed", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		ginkgo.When("publishing block volume as raw block with RO", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("read only not supported for Block Volume"))
			})
		})
		ginkgo.When("publishing block and unable to create target", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't create target file"))
			})
		})
		ginkgo.When("publishing block and unable to bind disk", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("error bind disk"))
			})
		})
		ginkgo.When("publishing block and unable to get target mounts", func() {
			ginkgo.It("should fail", func() {
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, errors.New("fail"))

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't check mounts for path"))
			})
		})
		ginkgo.When("publishing block but volume already mounted with different capabilities", func() {
			ginkgo.It("should fail", func() {
				mountInfo := []gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
						Opts:   []string{"ro"},
					},
				}
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(mountInfo, nil)

				_, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume already mounted but with different capabilities"))
			})
		})
		ginkgo.When("publishing nfs volume", func() {
			ginkgo.It("should succeed", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		ginkgo.When("No volume ID specified", func() {
			ginkgo.It("should fail", func() {
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          "",
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("volume ID is required"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
		ginkgo.When("No target path specified", func() {
			ginkgo.It("should fail", func() {
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        "",
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("targetPath is required"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
		ginkgo.When("Invalid volume capabilities specified", func() {
			ginkgo.It("should fail", func() {
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: validStagingPath,
					TargetPath:        validTargetPath,
					VolumeCapability:  nil,
					Readonly:          false,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("VolumeCapability is required"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
		ginkgo.When("No staging target path specified", func() {
			ginkgo.It("should fail", func() {
				res, err := nodeSvc.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          validBlockVolumeID,
					PublishContext:    getValidPublishContext(),
					StagingTargetPath: "",
					TargetPath:        validTargetPath,
					VolumeCapability:  getCapabilityWithVoltypeAccessFstype("block", "single-writer", "ext4"),
					Readonly:          false,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("stagingPath is required"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
		ginkgo.When("unable to create target dir", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't create target folder"))
			})
		})
		ginkgo.When("publishing nfs with ro", func() {
			ginkgo.It("should succeed", func() {
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
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		ginkgo.When("unable to bind disk", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("error bind disk"))
			})
		})
	})

	ginkgo.Describe("calling NodeUnpublish()", func() {
		ginkgo.When("unpublishing block volume", func() {
			ginkgo.It("should succeed", func() {
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
				fsMock.On("Remove", mock.Anything).Return(nil)

				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnpublishVolumeResponse{}))
			})
		})
		ginkgo.When("unpublishing nfs volume", func() {
			ginkgo.It("should succeed", func() {
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
				fsMock.On("Remove", mock.Anything).Return(nil)

				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validNfsVolumeID,
					TargetPath: validTargetPath,
				})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeUnpublishVolumeResponse{}))
			})
		})
		ginkgo.When("No target path specified", func() {
			ginkgo.It("should fail", func() {
				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: "",
				})
				gomega.Expect(err.Error()).To(gomega.Equal("rpc error: code = InvalidArgument desc = target path required"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
		ginkgo.When("Unable to get volID", func() {
			ginkgo.It("should fail", func() {
				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   "",
					TargetPath: validTargetPath,
				})
				gomega.Expect(err.Error()).To(gomega.Equal("rpc error: code = InvalidArgument desc = volume ID is required"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
		ginkgo.When("Unable to get TargetMounts", func() {
			ginkgo.It("should fail", func() {
				fsMock.On("GetUtil").Return(utilMock)
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil).Times(2)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return(nil, errors.New("error"))
				fsMock.On("Stat", mock.Anything).Return(&mocks.FileInfo{}, os.ErrNotExist)
				res, err := nodeSvc.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   validBlockVolumeID,
					TargetPath: validTargetPath,
				})
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("could not reliably determine existing mount status"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
		ginkgo.When("Unable to perform unmount", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("could not unmount dev"))
				gomega.Expect(res).To(gomega.BeNil())
			})
		})
	})

	ginkgo.Describe("calling NodeExpandVolume() online", func() {
		stagingPath := filepath.Join(validStagingPath, validBaseVolumeID)
		ginkgo.When("everything is correct", func() {
			ginkgo.It("should succeed [ext4]", func() {
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
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodeExpandVolumeResponse{}))
			})
			ginkgo.It("should succeed [xfs]", func() {
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
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		ginkgo.When("it failed to find mount info", func() {
			ginkgo.It("should fail ResizeFS() [xfs]", func() {
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
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("resize Failed ext4"))
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("resize Failed ext4"))
				gomega.Ω(res).To(gomega.BeNil())
			})
			ginkgo.It("should fail ResizeFS() [ext4]", func() {
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
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("resize Failed xfs"))
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("resize Failed xfs"))
				gomega.Ω(res).To(gomega.BeNil())
			})
		})
	})

	ginkgo.Describe("calling NodeExpandVolume() offline", func() {
		stagingPath := filepath.Join(validStagingPath, validBaseVolumeID)
		ginkgo.When("everything is correct", func() {
			ginkgo.It("should succeed [ext4]", func() {
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
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		ginkgo.When("using multipath", func() {
			ginkgo.It("should succeed [ext4]", func() {
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
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		ginkgo.When("using block mode", func() {
			ginkgo.It("should succeed [ext4]", func() {
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
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		ginkgo.When("using NFS mode", func() {
			// workaround for https://github.com/kubernetes/kubernetes/issues/131419
			ginkgo.It("should succeed [nfs]", func() {
				// nothing to mock as it is a NO-OP
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validNfsVolumeID, false))
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		ginkgo.When("the request is missing the Volume ID", func() {
			ginkgo.It("should fail", func() {
				_, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest("", true))
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("unable to parse volume handle. volumeHandle is empty"))
			})
		})
		ginkgo.When("the array ID is not valid", func() {
			ginkgo.It("should fail", func() {
				_, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(invalidBlockVolumeID, true))
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("failed to find array with given ID"))
			})
		})
		ginkgo.When("no target path", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("targetPath is required"))
			})
		})
		ginkgo.When("volume is not found", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Volume not found"))
			})
		})
		ginkgo.When("Unable to create mount target", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Failed to find mount info for"))
			})
		})
		ginkgo.When("Unable to perform mount", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Failed to find mount info for"))
			})
		})
		ginkgo.When("Unable to perform unmount", func() {
			ginkgo.It("should succeed", func() {
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
				utilMock.On("ResizeFS", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				res, err := nodeSvc.NodeExpandVolume(context.Background(), getNodeVolumeExpandValidRequest(validBlockVolumeID, false))
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodeExpandVolumeResponse{}))
			})
		})
		ginkgo.When("Unable to find mount info", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Failed to find mount info for"))
			})
		})
		ginkgo.When("Unable to rescan the device", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Failed to rescan device"))
			})
		})
		ginkgo.When("Unable to resize mpath", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("mpath resize error"))
			})
		})
	})

	ginkgo.Describe("Calling EphemeralNodePublish()", func() {
		ginkgo.When("everything's correct", func() {
			ginkgo.It("should succeed", func() {
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
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodePublishVolumeResponse{}))
			})
		})
		ginkgo.When("Child ControllerPublish() is failing", func() {
			capabilities := getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "ext4")
			ginkgo.It("should cleanup and call unpublish", func() {
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
						"size":                         "2Gi",
					},
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
				fsMock.On("Remove", mock.Anything).Return(nil)

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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("inline ephemeral controller publish failed"))
			})
		})
		ginkgo.When("Child NodeStage() is failing", func() {
			ginkgo.It("should cleanup and call unpublish", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("inline ephemeral node stage failed"))
			})
		})
		ginkgo.When("Failed to parse size. Bad string", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("inline ephemeral parse size failed"))
			})
		})
		ginkgo.When("Failed to create mount paths", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Unable to create directory for mounting ephemeral volumes"))
			})
		})
		ginkgo.When("Inline ephemeral create volume fails", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("inline ephemeral create volume failed"))
			})
		})
		ginkgo.When("fs.Create after createVolume fails", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Failed to create"))
			})
		})
		ginkgo.When("fs.Writestring fails", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Failed to write string"))
			})
		})
	})
	ginkgo.When("everything's correct", func() {
		ginkgo.It("should succeed", func() {
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
			gomega.Ω(err.Error()).To(gomega.ContainSubstring("inline ephemeral node publish failed"))
		})
	})

	ginkgo.Describe("Calling EphemeralNodeUnPublish()", func() {
		ginkgo.When("everything is correct", func() {
			ginkgo.It("should succeed", func() {
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
				fsMock.On("WriteFile", mock.Anything, mock.Anything, os.FileMode(0o640)).Return(nil)

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
				gomega.Ω(err).To(gomega.BeNil())
				gomega.Ω(res).To(gomega.Equal(&csi.NodeUnpublishVolumeResponse{}))
			})
		})
		ginkgo.When("no vlocak file", func() {
			ginkgo.It("should fail", func() {
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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Was unable to read lockfile"))
			})
		})
		ginkgo.When("controller unpublish fails", func() {
			ginkgo.It("should fail", func() {
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
				fsMock.On("WriteFile", mock.Anything, mock.Anything, os.FileMode(0o640)).Return(nil)

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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("Inline ephemeral controller unpublish"))
			})
		})
		ginkgo.When("controller delete volume fails", func() {
			ginkgo.It("should fail", func() {
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
				fsMock.On("WriteFile", mock.Anything, mock.Anything, os.FileMode(0o640)).Return(nil)

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
				gomega.Ω(err.Error()).To(gomega.ContainSubstring("failed"))
			})
		})
	})

	ginkgo.Describe("calling NodeGetInfo()", func() {
		ginkgo.When("managing multiple arrays", func() {
			ginkgo.It("should return correct topology segments", func() {
				nasData[0].NfsServers[0].IsNFSv4Enabled = false
				nasData[0].NfsServers[0].IsNFSv3Enabled = false
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
						{
							Address: "192.168.1.2",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn2"},
						},
					}, nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				setDefaultNodeLabelsMock()

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-iscsi": "true",
						},
					},
					MaxVolumesPerNode: 0,
				}))
			})
		})
		nasData[0].NfsServers[0].IsNFSv3Enabled = true
		ginkgo.When("node label max-powerstore-volumes-per-node is set and retrieved successfully", func() {
			ginkgo.It("should return correct MaxVolumesPerNode in response", func() {
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
						{
							Address: "192.168.1.2",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn2"},
						},
					}, nil)

				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				nodeLabelsRetrieverMock.On("BuildConfigFromFlags", mock.Anything, mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(map[string]string{"max-powerstore-volumes-per-node": "2"}, nil)
				nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":   "true",
							common.Name + "/" + firstValidIP + "-iscsi": "true",
							common.Name + "/" + secondValidIP + "-nfs":  "true",
						},
					},
					MaxVolumesPerNode: 2,
				}))
			})
		})

		ginkgo.When("there is some issue while retrieving node labels", func() {
			ginkgo.It("should return proper error", func() {
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
						{
							Address: "192.168.1.2",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn2"},
						},
					}, nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				nodeLabelsRetrieverMock.On("BuildConfigFromFlags", mock.Anything, mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, errors.New("Unable to create kubeclientset"))
				nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":   "true",
							common.Name + "/" + firstValidIP + "-iscsi": "true",
							common.Name + "/" + secondValidIP + "-nfs":  "true",
						},
					},
					MaxVolumesPerNode: 0,
				}))
			})
		})

		ginkgo.When("MaxVolumesPerNode is set via environment variable at the time of installation", func() {
			ginkgo.It("should return correct MaxVolumesPerNode in response", func() {
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
						{
							Address: "192.168.1.2",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn2"},
						},
					}, nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				setDefaultNodeLabelsMock()
				nodeSvc.opts.MaxVolumesPerNode = 2

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":   "true",
							common.Name + "/" + firstValidIP + "-iscsi": "true",
							common.Name + "/" + secondValidIP + "-nfs":  "true",
						},
					},
					MaxVolumesPerNode: 2,
				}))
			})
		})

		ginkgo.When("Portals are not discoverable", func() {
			ginkgo.It("should return correct topology segments", func() {
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.5",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
						{
							Address: "192.168.1.6",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn2"},
						},
					}, nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				setDefaultNodeLabelsMock()

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":  "true",
							common.Name + "/" + secondValidIP + "-nfs": "true",
						},
					},
					MaxVolumesPerNode: 0,
				}))
			})
		})

		ginkgo.When("we can not get targets from array", func() {
			ginkgo.It("should not return iscsi topology key", func() {
				e := "internal error"
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
					Return([]gopowerstore.IPPoolAddress{}, errors.New(e))
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				setDefaultNodeLabelsMock()

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":  "true",
							common.Name + "/" + secondValidIP + "-nfs": "true",
						},
					},
					MaxVolumesPerNode: 0,
				}))
			})
		})

		ginkgo.When("target can not be discovered", func() {
			ginkgo.It("should not return iscsi topology key", func() {
				goiscsi.GOISCSIMock.InduceDiscoveryError = true
				gonvme.GONVMEMock.InduceDiscoveryError = true
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
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
				setDefaultNodeLabelsMock()

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":  "true",
							common.Name + "/" + secondValidIP + "-nfs": "true",
						},
					},
					MaxVolumesPerNode: 0,
				}))
				gonvme.GONVMEMock.InduceDiscoveryError = false
			})
		})

		ginkgo.When("using FC", func() {
			ginkgo.It("should return FC topology segments", func() {
				nodeSvc.useFC[firstGlobalID] = true
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
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
							},
						},
						Name: "host-name",
					}, nil)
				setDefaultNodeLabelsMock()

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":  "true",
							common.Name + "/" + firstValidIP + "-fc":   "true",
							common.Name + "/" + secondValidIP + "-nfs": "true",
						},
					},
					MaxVolumesPerNode: 0,
				}))
			})

			ginkgo.When("reusing host", func() {
				ginkgo.It("should properly deal with additional IPs", func() {
					nodeSvc.useFC[firstGlobalID] = true
					nodeID := nodeSvc.nodeID
					nodeSvc.nodeID = nodeID + "-" + "192.168.0.1"
					nodeSvc.reusedHost = true
					clientMock.On("GetNASServers", mock.Anything).
						Return(nasData, nil)
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
								},
							},
							Name: "host-name",
						}, nil)
					setDefaultNodeLabelsMock()

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + firstValidIP + "-fc":   "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
						MaxVolumesPerNode: 0,
					}))
				})

				ginkgo.When("there is no ip in nodeID", func() {
					ginkgo.It("should not return FC topology key", func() {
						nodeSvc.useFC[firstGlobalID] = true
						nodeID := nodeSvc.nodeID
						nodeSvc.nodeID = "nodeid-with-no-ip"
						nodeSvc.reusedHost = true
						conn, _ := net.Dial("udp", "127.0.0.1:80")
						clientMock.On("GetNASServers", mock.Anything).
							Return(nasData, nil)
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
									},
								},
								Name: "host-name",
							}, nil)
						setDefaultNodeLabelsMock()

						res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
						gomega.Expect(err).To(gomega.BeNil())
						gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
							NodeId: nodeSvc.nodeID,
							AccessibleTopology: &csi.Topology{
								Segments: map[string]string{
									common.Name + "/" + firstValidIP + "-nfs":  "true",
									common.Name + "/" + secondValidIP + "-nfs": "true",
								},
							},
							MaxVolumesPerNode: 0,
						}))
					})
				})
			})

			ginkgo.When("we can not get info about hosts from array", func() {
				ginkgo.It("should not return FC topology key", func() {
					nodeSvc.useFC[firstGlobalID] = true
					e := "internal error"
					clientMock.On("GetNASServers", mock.Anything).
						Return(nasData, nil)
					clientMock.On("GetHostByName", mock.Anything, nodeSvc.nodeID).
						Return(gopowerstore.Host{}, errors.New(e))
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					setDefaultNodeLabelsMock()

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
						MaxVolumesPerNode: 0,
					}))
				})
			})

			ginkgo.When("host initiators is empty", func() {
				ginkgo.It("should not return FC topology key", func() {
					nodeSvc.useFC[firstGlobalID] = true
					clientMock.On("GetNASServers", mock.Anything).
						Return(nasData, nil)
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
					setDefaultNodeLabelsMock()

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
						MaxVolumesPerNode: 0,
					}))
				})
			})

			ginkgo.When("there is no active sessions", func() {
				ginkgo.It("should not return FC topology key", func() {
					nodeSvc.useFC[firstGlobalID] = true
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					clientMock.On("GetNASServers", mock.Anything).
						Return(nasData, nil)
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
								},
							},
							Name: "host-name",
						}, nil)
					setDefaultNodeLabelsMock()

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
						MaxVolumesPerNode: 0,
					}))
				})
			})
		})

		ginkgo.When("using NVMeFC", func() {
			ginkgo.It("should return NVMeFC topology segments", func() {
				nodeSvc.useNVME[firstGlobalID] = true
				nodeSvc.useFC[firstGlobalID] = true
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{
						Name:    validClusterName,
						NVMeNQN: validNVMEInitiators[0],
					}, nil)
				clientMock.On("GetFCPorts", mock.Anything).
					Return([]gopowerstore.FcPort{
						{
							WwnNVMe:  validFCTargetWWNNVMe[0],
							WwnNode:  validFCTargetWWNNode[0],
							IsLinkUp: true,
						},
					}, nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				setDefaultNodeLabelsMock()

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":    "true",
							common.Name + "/" + firstValidIP + "-nvmefc": "true",
							common.Name + "/" + secondValidIP + "-nfs":   "true",
						},
					},
					MaxVolumesPerNode: 0,
				}))
			})

			ginkgo.When("NVMeFC targets cannot be discovered", func() {
				ginkgo.It("should not return NVMeFC topology segments", func() {
					nodeSvc.useNVME[firstGlobalID] = true
					nodeSvc.useFC[firstGlobalID] = true
					clientMock.On("GetNASServers", mock.Anything).
						Return(nasData, nil)
					clientMock.On("GetCluster", mock.Anything).
						Return(gopowerstore.Cluster{
							Name:    validClusterName,
							NVMeNQN: validNVMEInitiators[0],
						}, nil)
					clientMock.On("GetFCPorts", mock.Anything).
						Return([]gopowerstore.FcPort{
							{
								WwnNVMe: validFCTargetWWNNVMe[0],
								WwnNode: validFCTargetWWNNode[0],
							},
						}, nil)
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					setDefaultNodeLabelsMock()

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
						MaxVolumesPerNode: 0,
					}))
				})
			})
		})

		ginkgo.When("using NVMeTCP", func() {
			ginkgo.It("should return NVMeTCP topology segments", func() {
				nodeSvc.useNVME[firstGlobalID] = true
				nodeSvc.useFC[firstGlobalID] = false
				clientMock.On("GetNASServers", mock.Anything).
					Return(nasData, nil)
				clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).Return([]gopowerstore.IPPoolAddress{
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
				clientMock.On("GetCluster", mock.Anything).
					Return(gopowerstore.Cluster{
						Name:    validClusterName,
						NVMeNQN: validNVMEInitiators[0],
					}, nil)
				conn, _ := net.Dial("udp", "127.0.0.1:80")
				fsMock.On("NetDial", mock.Anything).Return(
					conn,
					nil,
				)
				setDefaultNodeLabelsMock()

				res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
					NodeId: nodeSvc.nodeID,
					AccessibleTopology: &csi.Topology{
						Segments: map[string]string{
							common.Name + "/" + firstValidIP + "-nfs":     "true",
							common.Name + "/" + firstValidIP + "-nvmetcp": "true",
							common.Name + "/" + secondValidIP + "-nfs":    "true",
						},
					},
					MaxVolumesPerNode: 0,
				}))
			})

			ginkgo.When("target can not be discovered", func() {
				ginkgo.It("should not return nvme topology key", func() {
					goiscsi.GOISCSIMock.InduceDiscoveryError = true
					gonvme.GONVMEMock.InduceDiscoveryError = true
					nodeSvc.useNVME[firstGlobalID] = true
					nodeSvc.useFC[firstGlobalID] = false
					clientMock.On("GetNASServers", mock.Anything).
						Return(nasData, nil)
					clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).Return([]gopowerstore.IPPoolAddress{
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
					clientMock.On("GetCluster", mock.Anything).
						Return(gopowerstore.Cluster{
							Name:    validClusterName,
							NVMeNQN: validNVMEInitiators[0],
						}, nil)
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					setDefaultNodeLabelsMock()

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
						MaxVolumesPerNode: 0,
					}))
					gonvme.GONVMEMock.InduceDiscoveryError = false
				})
			})

			ginkgo.When("we cannot get NVMeTCP targets from the array", func() {
				ginkgo.It("should not return NVMeTCP topology segments", func() {
					nodeSvc.useNVME[firstGlobalID] = true
					nodeSvc.useFC[firstGlobalID] = false
					e := "internalerror"
					clientMock.On("GetNASServers", mock.Anything).
						Return(nasData, nil)
					clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).Return([]gopowerstore.IPPoolAddress{
						{
							Address: "192.168.1.1",
							IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
						},
					}, nil)
					clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
						Return([]gopowerstore.IPPoolAddress{}, errors.New(e))
					clientMock.On("GetCluster", mock.Anything).
						Return(gopowerstore.Cluster{
							Name:    validClusterName,
							NVMeNQN: validNVMEInitiators[0],
						}, nil)
					conn, _ := net.Dial("udp", "127.0.0.1:80")
					fsMock.On("NetDial", mock.Anything).Return(
						conn,
						nil,
					)
					setDefaultNodeLabelsMock()

					res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
					gomega.Expect(err).To(gomega.BeNil())
					gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
						NodeId: nodeSvc.nodeID,
						AccessibleTopology: &csi.Topology{
							Segments: map[string]string{
								common.Name + "/" + firstValidIP + "-nfs":  "true",
								common.Name + "/" + secondValidIP + "-nfs": "true",
							},
						},
						MaxVolumesPerNode: 0,
					}))
				})
			})
		})
	})

	// ginkgo.Describe("calling NodeGetInfo() when nfs is disabled", func() {
	// 	ginkgo.When("managing multiple arrays", func() {
	// 		ginkgo.It("should return correct topology segments", func() {
	// 			nasData[0].NfsServers[0].IsNFSv4Enabled = false
	// 			nasData[0].NfsServers[0].IsNFSv3Enabled = false
	// 			clientMock.On("GetNASServers", mock.Anything).
	// 				Return(nasData, nil)
	// 			clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
	// 				Return([]gopowerstore.IPPoolAddress{
	// 					{
	// 						Address: "192.168.1.1",
	// 						IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
	// 					},
	// 					{
	// 						Address: "192.168.1.2",
	// 						IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn2"},
	// 					},
	// 				}, nil)
	// 			conn, _ := net.Dial("udp", "127.0.0.1:80")
	// 			fsMock.On("NetDial", mock.Anything).Return(
	// 				conn,
	// 				nil,
	// 			)
	// 			setDefaultNodeLabelsMock()

	// 			res, err := nodeSvc.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
	// 			gomega.Expect(err).To(gomega.BeNil())
	// 			gomega.Expect(res).To(gomega.Equal(&csi.NodeGetInfoResponse{
	// 				NodeId: nodeSvc.nodeID,
	// 				AccessibleTopology: &csi.Topology{
	// 					Segments: map[string]string{},
	// 				},
	// 				MaxVolumesPerNode: 0,
	// 			}))
	// 		})
	// 	})
	// })

	ginkgo.Describe("Calling NodeGetCapabilities()", func() {
		ginkgo.It("should return predefined parameters with health monitor", func() {
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
			nvmeConnectorMock.On("GetInitiatorName", mock.Anything).
				Return(validNVMEInitiators, nil)
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
			clientMock.On("GetCustomHTTPHeaders").Return(api.NewSafeHeader().GetHeader())
			clientMock.On("GetSoftwareMajorMinorVersion", context.Background()).Return(float32(3.0), nil)
			clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
			clientMock.On("CreateHost", mock.Anything, mock.Anything).
				Return(gopowerstore.CreateResponse{ID: validHostID}, nil)
			setDefaultNodeLabelsMock()
			nodeSvc.opts.NodeNamePrefix = ""
			nodeSvc.Init()

			res, err := nodeSvc.NodeGetCapabilities(context.Background(), &csi.NodeGetCapabilitiesRequest{})
			gomega.Ω(err).To(gomega.BeNil())
			gomega.Ω(res).To(gomega.Equal(&csi.NodeGetCapabilitiesResponse{
				Capabilities: []*csi.NodeServiceCapability{
					{
						Type: &csi.NodeServiceCapability_Rpc{
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

	ginkgo.Describe("Calling getInitiators()", func() {
		ginkgo.When("Only iSCSI initiators are on node", func() {
			ginkgo.It("should succeed", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).Return([]string{}, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return([]string{}, nil)
				iinit, fcinit, nvmeinit, err := nodeSvc.getInitiators()
				gomega.Ω(iinit).To(gomega.Equal([]string{
					"iqn.1994-05.com.redhat:4db86abbe3c",
					"iqn.1994-05.com.redhat:2950c9ca441b",
				}))
				gomega.Ω(nvmeinit).To(gomega.Equal([]string{}))
				gomega.Ω(fcinit).To(gomega.BeNil())
				gomega.Ω(err).To(gomega.BeNil())
			})
		})
		ginkgo.When("Only NVMe initiators are on node", func() {
			ginkgo.It("should succeed", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return([]string{}, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).Return(validNVMEInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return([]string{}, nil)
				iinit, fcinit, nvmeinit, err := nodeSvc.getInitiators()
				gomega.Ω(nvmeinit).To(gomega.Equal([]string{
					"nqn.2014-08.org.nvmexpress:uuid:02a08600-57d6-4089-8736-bf1f7326990e",
					"nqn.2014-08.org.nvmexpress:uuid:fa363a22-1c74-44f3-9932-1c35d5cf5c4d",
				}))
				gomega.Ω(iinit).To(gomega.Equal([]string{}))
				gomega.Ω(fcinit).To(gomega.BeNil())
				gomega.Ω(err).To(gomega.BeNil())
			})
		})
		ginkgo.When("NVMe, FC and iSCSI initiators are on node", func() {
			ginkgo.It("should succeed", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return(validISCSIInitiators, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).Return(validNVMEInitiators, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return(validFCTargetsWWPN, nil)
				iinit, fcinit, nvmeinit, err := nodeSvc.getInitiators()
				gomega.Ω(iinit).To(gomega.Equal([]string{
					"iqn.1994-05.com.redhat:4db86abbe3c",
					"iqn.1994-05.com.redhat:2950c9ca441b",
				}))
				gomega.Ω(nvmeinit).To(gomega.Equal([]string{
					"nqn.2014-08.org.nvmexpress:uuid:02a08600-57d6-4089-8736-bf1f7326990e",
					"nqn.2014-08.org.nvmexpress:uuid:fa363a22-1c74-44f3-9932-1c35d5cf5c4d",
				}))
				gomega.Ω(fcinit).To(gomega.Equal([]string{
					"58:cc:f0:93:48:a0:03:a3",
					"58:cc:f0:93:48:a0:02:a3",
				}))
				gomega.Ω(err).To(gomega.BeNil())
			})
		})
		ginkgo.When("Neither NVMe nor FC nor iSCSI initiators are found on node", func() {
			ginkgo.It("should succeed [NFS only]", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return([]string{}, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).Return([]string{}, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return([]string{}, nil)
				iinit, fcinit, nvmeinit, err := nodeSvc.getInitiators()
				gomega.Ω(len(iinit)).To(gomega.Equal(0))
				gomega.Ω(len(nvmeinit)).To(gomega.Equal(0))
				gomega.Ω(len(fcinit)).To(gomega.Equal(0))
				gomega.Ω(err).To(gomega.BeNil())
			})
		})
		ginkgo.When("Only FC initiators are on node", func() {
			ginkgo.It("should succeed", func() {
				iscsiConnectorMock.On("GetInitiatorName", mock.Anything).Return([]string{}, nil)
				fcConnectorMock.On("GetInitiatorPorts", mock.Anything).Return(validFCTargetsWWPN, nil)
				nvmeConnectorMock.On("GetInitiatorName", mock.Anything).Return([]string{}, nil)
				iinit, fcinit, nvmeinit, err := nodeSvc.getInitiators()
				gomega.Ω(iinit).To(gomega.Equal([]string{}))
				gomega.Ω(nvmeinit).To(gomega.Equal([]string{}))
				gomega.Ω(fcinit).To(gomega.Equal([]string{
					"58:cc:f0:93:48:a0:03:a3",
					"58:cc:f0:93:48:a0:02:a3",
				}))
				gomega.Ω(err).To(gomega.BeNil())
			})
		})
	})
	ginkgo.Describe("calling NodeExpandRawBlockVolume() offline", func() {
		ginkgo.When("Error is encountered", func() {
			ginkgo.It("should return error ", func() {
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("GetSysBlockDevicesForVolumeWWN", mock.Anything, mock.Anything).Return(
					[]string{"nvme0n1,nvme0n2"},
					errors.New("Error"),
				)
				_, err := nodeSvc.nodeExpandRawBlockVolume(context.Background(), "")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})
		ginkgo.When("Devicenames is empty", func() {
			ginkgo.It("should return error ", func() {
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("GetSysBlockDevicesForVolumeWWN", mock.Anything, mock.Anything).Return(
					[]string{},
					nil,
				)
				_, err := nodeSvc.nodeExpandRawBlockVolume(context.Background(), "")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})
		ginkgo.When("error encountered in getnvmecontroller", func() {
			ginkgo.It("should return error ", func() {
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("GetSysBlockDevicesForVolumeWWN", mock.Anything, mock.Anything).Return(
					[]string{"nvme0n1,nvme0n2"},
					nil,
				)
				utilMock.On("GetNVMeController", mock.Anything).Return(
					"nvmecontroller-dev1",
					errors.New("Error"),
				)
				_, err := nodeSvc.nodeExpandRawBlockVolume(context.Background(), "")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})
		ginkgo.When("DeviceRescan fail", func() {
			ginkgo.It("should return error", func() {
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("GetSysBlockDevicesForVolumeWWN", mock.Anything, mock.Anything).Return(
					[]string{"fcnvme0n1,fcnvme0n2"},
					nil,
				)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(
					errors.New("Error"),
				)
				utilMock.On("GetMpathNameFromDevice", mock.Anything, mock.Anything).Return(
					"",
					errors.New("Error"),
				)
				_, err := nodeSvc.nodeExpandRawBlockVolume(context.Background(), "")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})
		ginkgo.When("GetMpathNameFromDevice fail", func() {
			ginkgo.It("should return error", func() {
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("GetSysBlockDevicesForVolumeWWN", mock.Anything, mock.Anything).Return(
					[]string{"fcnvme0n1,fcnvme0n2"},
					nil,
				)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(
					nil,
				)
				utilMock.On("GetMpathNameFromDevice", mock.Anything, mock.Anything).Return(
					"",
					errors.New("Error"),
				)
				_, err := nodeSvc.nodeExpandRawBlockVolume(context.Background(), "")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})
		ginkgo.When("ResizeMultipath fail", func() {
			ginkgo.It("should return error", func() {
				fsMock.On("GetUtil").Return(utilMock)
				utilMock.On("GetSysBlockDevicesForVolumeWWN", mock.Anything, mock.Anything).Return(
					[]string{"fcnvme0n1,fcnvme0n2"},
					nil,
				)
				utilMock.On("DeviceRescan", mock.Anything, mock.Anything).Return(
					nil,
				)
				utilMock.On("GetMpathNameFromDevice", mock.Anything, mock.Anything).Return(
					"mpath",
					nil,
				)
				utilMock.On("ResizeMultipath", mock.Anything, mock.Anything).Return(
					errors.New("Error"),
				)
				_, err := nodeSvc.nodeExpandRawBlockVolume(context.Background(), "")
				gomega.Expect(err).ToNot(gomega.BeNil())
			})
		})
	})
	ginkgo.Describe("calling NodeGetVolumeStats()", func() {
		ginkgo.When("volume ID is missing", func() {
			ginkgo.It("should fail", func() {
				req := &csi.NodeGetVolumeStatsRequest{VolumeId: "", VolumePath: ""}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("no volume ID provided"))
			})
		})

		ginkgo.When("volume path is missing", func() {
			ginkgo.It("should fail", func() {
				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: ""}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("no volume Path provided"))
			})
		})

		ginkgo.When("array ID is invalid", func() {
			ginkgo.It("should fail", func() {
				req := &csi.NodeGetVolumeStatsRequest{VolumeId: invalidBlockVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find array with given ID"))
			})
		})

		ginkgo.When("API call fails [block]", func() {
			ginkgo.It("should fail [GetVolume]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find volume"))
			})

			ginkgo.It("should fail [GetHostVolumeMappingByVolumeID]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{ID: validBaseVolumeID, Size: controller.MaxVolumeSizeBytes / 200}, nil)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolumeID).
					Return([]gopowerstore.HostVolumeMapping{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to get host volume mapping for volume"))
			})

			ginkgo.It("should fail [GetHost]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{ID: validBaseVolumeID, Size: controller.MaxVolumeSizeBytes / 200}, nil)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolumeID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil)
				clientMock.On("GetHost", mock.Anything, validHostID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to get host"))
			})
		})

		ginkgo.When("API call fails with not found error [block]", func() {
			ginkgo.It("should return stats as abnormal [GetVolume]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("Volume %s is not found", validBaseVolumeID),
					},
				}))
			})

			ginkgo.It("should return stats as abnormal [GetHost]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{ID: validBaseVolumeID, Size: controller.MaxVolumeSizeBytes / 200}, nil)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolumeID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil)
				clientMock.On("GetHost", mock.Anything, validHostID).
					Return(gopowerstore.Host{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("host %s is not attached to volume %s", validNodeID, validBaseVolumeID),
					},
				}))
			})
		})

		ginkgo.When("host mapping not found as expected [block]", func() {
			ginkgo.It("should return stats as abnormal [no active initiator]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{ID: validBaseVolumeID, Size: controller.MaxVolumeSizeBytes / 200}, nil)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolumeID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil)
				clientMock.On("GetHost", mock.Anything, validHostID).
					Return(gopowerstore.Host{ID: validHostID, Name: validHostName}, nil)

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("host %s has no active initiator connection", validNodeID),
					},
				}))
			})

			ginkgo.It("should return stats as abnormal [not attached]", func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{ID: validBaseVolumeID, Size: controller.MaxVolumeSizeBytes / 200}, nil)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolumeID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil)
				clientMock.On("GetHost", mock.Anything, validHostID).
					Return(gopowerstore.Host{
						ID:   validHostID,
						Name: validHostName,
						Initiators: []gopowerstore.InitiatorInstance{
							{
								ActiveSessions: []gopowerstore.ActiveSessionInstance{
									{
										PortName: validISCSITargets[0],
									},
								},
								PortName: validISCSIPortals[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
						},
					}, nil)

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validBlockVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("host %s is not attached to volume %s", validNodeID, validBaseVolumeID),
					},
				}))
			})
		})

		ginkgo.When("API call fails [NFS]", func() {
			ginkgo.It("should fail [GetFS]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validNfsVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find filesystem "))
			})

			ginkgo.It("should fail [GetNFSExportByFileSystemID]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.FileSystem{ID: validBaseVolumeID}, nil)
				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.NFSExport{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusBadRequest},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validNfsVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to find nfs export for filesystem"))
			})
		})

		ginkgo.When("API call fails with not found error [NFS]", func() {
			ginkgo.It("should return stats as abnormal [GetFS]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validNfsVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("Filesystem %s is not found", validBaseVolumeID),
					},
				}))
			})

			ginkgo.It("should return stats as abnormal [GetNFSExportByFileSystemID]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.FileSystem{ID: validBaseVolumeID}, nil)
				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.NFSExport{}, gopowerstore.APIError{
						ErrorMsg: &api.ErrorMsg{StatusCode: http.StatusNotFound},
					})

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validNfsVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("NFS export for volume %s is not found", validBaseVolumeID),
					},
				}))
			})
		})

		ginkgo.When("NFS export not found as expected [NFS]", func() {
			ginkgo.It("should return stats as abnormal [not attached]", func() {
				clientMock.On("GetFS", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.FileSystem{ID: validBaseVolumeID}, nil)
				clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.NFSExport{
						ID:      "some-export-id",
						ROHosts: []string{},
					}, nil)

				req := &csi.NodeGetVolumeStatsRequest{VolumeId: validNfsVolumeID, VolumePath: validTargetPath}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("host %s is not attached to NFS export for filesystem %s", validNodeID, validBaseVolumeID),
					},
				}))
			})
		})

		ginkgo.When("there are issues with mount paths", func() {
			ginkgo.BeforeEach(func() {
				clientMock.On("GetVolume", mock.Anything, validBaseVolumeID).
					Return(gopowerstore.Volume{ID: validBaseVolumeID, Size: controller.MaxVolumeSizeBytes / 200}, nil)
				clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolumeID).
					Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil)
				clientMock.On("GetHost", mock.Anything, validHostID).
					Return(gopowerstore.Host{
						ID:   validHostID,
						Name: validNodeID,
						Initiators: []gopowerstore.InitiatorInstance{
							{
								ActiveSessions: []gopowerstore.ActiveSessionInstance{
									{
										PortName: validISCSITargets[0],
									},
								},
								PortName: validISCSIPortals[0],
								PortType: gopowerstore.InitiatorProtocolTypeEnumISCSI,
							},
						},
					}, nil)
			})

			ginkgo.It("should fail for getTargetMount() error [stagingPath]", func() {
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, errors.New("fail"))

				req := &csi.NodeGetVolumeStatsRequest{
					VolumeId:          validBlockVolumeID,
					VolumePath:        validTargetPath,
					StagingTargetPath: nodeStagePrivateDir,
				}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't check mounts for path"))
			})

			ginkgo.It("should return stats as abnormal for getTargetMount() error [stagingPath]", func() {
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				req := &csi.NodeGetVolumeStatsRequest{
					VolumeId:          validBlockVolumeID,
					VolumePath:        validTargetPath,
					StagingTargetPath: nodeStagePrivateDir,
				}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("staging target path %s not mounted for volume %s", nodeStagePrivateDir, validBaseVolumeID),
					},
				}))
			})

			ginkgo.It("should fail for getTargetMount() error [volumePath]", func() {
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, errors.New("fail"))

				req := &csi.NodeGetVolumeStatsRequest{
					VolumeId:          validBlockVolumeID,
					VolumePath:        validTargetPath,
					StagingTargetPath: "",
				}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(res).To(gomega.BeNil())
				gomega.Expect(err).ToNot(gomega.BeNil())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring("can't check mounts for path"))
			})

			ginkgo.It("should return stats as abnormal for getTargetMount() error [volumePath]", func() {
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{}, nil)

				req := &csi.NodeGetVolumeStatsRequest{
					VolumeId:          validBlockVolumeID,
					VolumePath:        validTargetPath,
					StagingTargetPath: "",
				}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("volume path %s not mounted for volume %s", validTargetPath, validBaseVolumeID),
					},
				}))
			})

			ginkgo.It("should return stats as abnormal for ReadDir() error", func() {
				fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte{}, nil)
				fsMock.On("ParseProcMounts", context.Background(), mock.Anything).Return([]gofsutil.Info{
					{
						Device: validDevName,
						Path:   validTargetPath,
					},
				}, nil)

				req := &csi.NodeGetVolumeStatsRequest{
					VolumeId:          validBlockVolumeID,
					VolumePath:        validTargetPath,
					StagingTargetPath: "",
				}
				res, err := nodeSvc.NodeGetVolumeStats(context.Background(), req)

				gomega.Expect(err).To(gomega.BeNil())
				gomega.Expect(res).To(gomega.Equal(&csi.NodeGetVolumeStatsResponse{
					VolumeCondition: &csi.VolumeCondition{
						Abnormal: true,
						Message:  fmt.Sprintf("volume path %s not accessible for volume %s", validTargetPath, validBaseVolumeID),
					},
				}))
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
		initialized:    true,
	}
	nodeSvc.SetArrays(arrays)
	nodeSvc.SetDefaultArray(arrays[firstValidIP])
	t.Run("success test", func(_ *testing.T) {
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
		initialized:    true,
	}
	nodeSvc.SetArrays(arrays)
	nodeSvc.SetDefaultArray(arrays[firstValidIP])
	t.Run("success test", func(_ *testing.T) {
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

type MockService struct {
	// Add fields to mock dependencies if needed
	*Service
}

func TestIsRemoteToOtherArray(t *testing.T) {
	originalGetAllRemoteSystemsFunc := getAllRemoteSystemsFunc
	defer func() {
		getAllRemoteSystemsFunc = originalGetAllRemoteSystemsFunc
	}()
	tests := []struct {
		name       string
		s          *Service
		arrA       *array.PowerStoreArray
		arrB       *array.PowerStoreArray
		setupMocks func()
		wantErr    bool
		want       bool
	}{
		{
			name: "Array B is not remote to Array A",
			arrA: &array.PowerStoreArray{GlobalID: "arrayA"},
			arrB: &array.PowerStoreArray{GlobalID: "arrayB"},
			setupMocks: func() {
				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "arrayA" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "arrayC",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "arrayD",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "Error fetching remotes for Array A",
			arrA: &array.PowerStoreArray{GlobalID: "arrayA"},
			arrB: &array.PowerStoreArray{GlobalID: "arrayB"},
			setupMocks: func() {
				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "arrayA" {
						return nil, fmt.Errorf("failed to get remoteSystem")
					}

					return nil, nil
				}
			},
			wantErr: true,
			want:    false,
		},
		{
			name: "Error fetching remotes for Array B",
			arrA: &array.PowerStoreArray{GlobalID: "arrayA"},
			arrB: &array.PowerStoreArray{GlobalID: "arrayB"},
			setupMocks: func() {
				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "arrayB" {
						return nil, fmt.Errorf("failed to get remoteSystem")
					}

					return nil, nil
				}
			},
			wantErr: true,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			got := tt.s.isRemoteToOtherArray(context.Background(), tt.arrA, tt.arrB)

			if got == tt.want {
				log.Info("Success")
			} else {
				t.Errorf("Service.isRemoteToOtherArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleNoLabelMatchRegistration(t *testing.T) {
	originalGetArrayfn := getArrayfn
	originalGetIsHostAlreadyRegistered := getIsHostAlreadyRegistered
	originalGetAllRemoteSystemsFunc := getAllRemoteSystemsFunc
	originalGetIsRemoteToOtherArray := getIsRemoteToOtherArray
	originalRegisterHostFunc := registerHostFunc

	defer func() {
		getArrayfn = originalGetArrayfn
		getIsHostAlreadyRegistered = originalGetIsHostAlreadyRegistered
		getAllRemoteSystemsFunc = originalGetAllRemoteSystemsFunc
		getIsRemoteToOtherArray = originalGetIsRemoteToOtherArray
		registerHostFunc = originalRegisterHostFunc
	}()

	tests := []struct {
		s              *MockService
		name           string
		initiators     []string
		nodeLabels     map[string]string
		arrayAddedList map[string]bool
		arr            *array.PowerStoreArray
		setupMocks     func()
		wantErr        bool
		want           bool
	}{
		{
			name:           "No array labels match node labels",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.2",
						},
					}
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}
			},
			wantErr: false,
			want:    true,
		},
		{
			name:           "Success Host Registration",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone3"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					log.Infof("Inside RegisterHost")
					return nil
				}
			},
			wantErr: false,
			want:    true,
		},
		{
			name:           "Host Already register",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone3"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return true
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					log.Infof("Inside RegisterHost")
					return nil
				}
			},
			wantErr: false,
			want:    true,
		},
		{
			name:           "Local connectivity",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					log.Infof("Inside RegisterHost")
					return nil
				}
			},
			wantErr: false,
			want:    true,
		},
		{
			name:           "Failed to Register host",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					log.Infof("Inside RegisterHost")
					return fmt.Errorf("failed to registerHost")
				}
			},
			wantErr: true,
			want:    false,
		},
		{
			name:           "Fail to get remote system",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
						},
					}
				}

				getAllRemoteSystemsFunc = func(_ *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					log.Infof("Inside Remote Systems")
					return nil, fmt.Errorf("failed to get remoteSystem")
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					log.Infof("Inside RegisterHost")
					return fmt.Errorf("failed to registerHost")
				}
			},
			wantErr: true,
			want:    false,
		},
		// Add more test cases here
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockService)
			tt.setupMocks()

			log.Infof("Test")
			got, err := mockService.handleNoLabelMatchRegistration(context.Background(), tt.arr, tt.initiators, tt.nodeLabels, tt.arrayAddedList)

			if (err != nil) != tt.wantErr {
				t.Errorf("Service.handleLabelMatchRegistration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got == tt.want {
				log.Info("Success")
			}
		})
	}
}

func TestHandleLabelMatchRegistration(t *testing.T) {
	originalGetArrayfn := getArrayfn
	originalGetIsHostAlreadyRegistered := getIsHostAlreadyRegistered
	originalGetAllRemoteSystemsFunc := getAllRemoteSystemsFunc
	originalGetIsRemoteToOtherArray := getIsRemoteToOtherArray
	originalRegisterHostFunc := registerHostFunc

	defer func() {
		getArrayfn = originalGetArrayfn
		getIsHostAlreadyRegistered = originalGetIsHostAlreadyRegistered
		getAllRemoteSystemsFunc = originalGetAllRemoteSystemsFunc
		getIsRemoteToOtherArray = originalGetIsRemoteToOtherArray
		registerHostFunc = originalRegisterHostFunc
	}()

	tests := []struct {
		s              *MockService
		name           string
		initiators     []string
		nodeLabels     map[string]string
		arrayAddedList map[string]bool
		arr            *array.PowerStoreArray
		setupMocks     func()
		wantErr        bool
		want           bool
	}{
		{
			name:           "No array labels match node labels",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.2",
						},
					}
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}
			},
			wantErr: false,
			want:    false,
		},
		{
			name:           "No array labels match node labels -2",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone3"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					log.Infof("Inside RegisterHost")
					return nil
				}
			},
			wantErr: false,
			want:    false,
		},
		{
			name:           "No array labels match node labels - 3",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone3"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					log.Infof("Inside RegisterHost")
					return fmt.Errorf("failed to registerHost")
				}
			},
			wantErr: true,
			want:    true,
		},
		{
			name:           "Host Already Registered",
			initiators:     []string{"init1"},
			nodeLabels:     map[string]string{"topology.kubernetes.io/zone1": "zone1"},
			arrayAddedList: map[string]bool{},
			arr: &array.PowerStoreArray{
				Endpoint:      "https://10.198.0.1/api/rest",
				GlobalID:      "Array1",
				Username:      "admin",
				Password:      "Pass",
				Insecure:      true,
				BlockProtocol: "auto",
				MetroTopology: "Uniform",
				Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
				IP:            "10.198.0.1",
			},
			setupMocks: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return true
				}

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return true
				}

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					log.Infof("Inside RegisterHost")
					return fmt.Errorf("failed to registerHost")
				}
			},
			wantErr: false,
			want:    false,
		},
		// Add more test cases here
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockService)
			tt.setupMocks()

			log.Infof("Test")
			got, err := mockService.handleLabelMatchRegistration(context.Background(), tt.arr, tt.initiators, tt.nodeLabels, tt.arrayAddedList)

			if (err != nil) != tt.wantErr {
				t.Errorf("Service.handleLabelMatchRegistration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got == tt.want {
				log.Infof("Test passed")
			}
		})
	}
}

// Unit test for createHost
func TestService_createHost(t *testing.T) {
	originalGetArrayfn := getArrayfn
	originalGetIsHostAlreadyRegistered := getIsHostAlreadyRegistered
	originalGetAllRemoteSystemsFunc := getAllRemoteSystemsFunc
	originalGetIsRemoteToOtherArray := getIsRemoteToOtherArray
	originalRegisterHostFunc := registerHostFunc
	nodeLabelsRetrieverMock = new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
	nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(map[string]string{"topology.kubernetes.io/zone1": "zone1"}, nil)
	nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)
	clientMock = new(gopowerstoremock.Client)
	clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
	clientMock.On("CreateHost", mock.Anything, mock.Anything).
		Return(gopowerstore.CreateResponse{ID: validHostID}, nil)

	defer func() {
		getArrayfn = originalGetArrayfn
		getIsHostAlreadyRegistered = originalGetIsHostAlreadyRegistered
		getAllRemoteSystemsFunc = originalGetAllRemoteSystemsFunc
		getIsRemoteToOtherArray = originalGetIsRemoteToOtherArray
		registerHostFunc = originalRegisterHostFunc
	}()

	getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
		return false
	}

	getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
		if arr.GlobalID == "Array2" {
			return []gopowerstore.RemoteSystem{
				{
					ID:                  "arrayid1",
					Name:                "Pstore1",
					Description:         "",
					SerialNumber:        "Array1",
					ManagementAddress:   "10.198.0.1",
					DataConnectionState: "OK",
					Capabilities:        []string{"Synchronous_Block_Replication"},
				},
			}, nil
		}

		return []gopowerstore.RemoteSystem{
			{
				ID:                  "arrayid2",
				Name:                "Pstore2",
				Description:         "",
				SerialNumber:        "Array2",
				ManagementAddress:   "10.198.0.2",
				DataConnectionState: "OK",
				Capabilities:        []string{"Synchronous_Block_Replication"},
			},
		}, nil
	}

	type args struct {
		ctx        context.Context
		initiators []string
	}

	tests := []struct {
		name    string
		s       *MockService
		setup   func()
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "Successful host creation 1",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}
			},
			want:    []string{"Array1", "Array2"},
			wantErr: false,
		},
		{
			name: "Successful host creation 2",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}
			},
			want:    []string{"Array1", "Array2"},
			wantErr: false,
		},
		{
			name: "Successful host creation 3",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}
			},
			want:    []string{"Array1", "Array2"},
			wantErr: false,
		},
		{
			name: "Failure host creation - Label don't match",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Failed to get node labels",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				nodeLabelsRetrieverMock = new(mocks.NodeLabelsRetrieverInterface)
				k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
				nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("failed to get node labels"))
				nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)

				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Host Registration Failure: Both array more than one labels",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				nodeLabelsRetrieverMock = new(mocks.NodeLabelsRetrieverInterface)
				k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
				nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(map[string]string{"topology.kubernetes.io/zone1": "zone1"}, nil)
				nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)

				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Host Registration Failure: One array has more than one labels",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Failed: To get remote systems when both Array Label matches with Node Labels",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}

				getAllRemoteSystemsFunc = func(_ *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					return nil, fmt.Errorf("failed to get remote systems")
				}
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Failed: To get remote systems when one Array Label matches with Node Labels",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}

				getAllRemoteSystemsFunc = func(_ *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					return nil, fmt.Errorf("failed to get remote systems")
				}
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Host Registration Failure - Array belongs to different zones",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				nodeLabelsRetrieverMock = new(mocks.NodeLabelsRetrieverInterface)
				k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
				nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(map[string]string{"topology.kubernetes.io/zone1": "zone1", "topology.kubernetes.io/zone2": "zone2"}, nil)
				nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)

				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}
					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Successful Host Registration with Co-Local and Co-remote",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				nodeLabelsRetrieverMock = new(mocks.NodeLabelsRetrieverInterface)
				k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
				nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(map[string]string{"topology.kubernetes.io/zone2": "zone2"}, nil)
				nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)

				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone2": "zone2"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}
					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}
			},
			want:    []string{"Array1", "Array2"},
			wantErr: false,
		},
		{
			name: "Host Registration Failure - Host Already registerd",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				nodeLabelsRetrieverMock = new(mocks.NodeLabelsRetrieverInterface)
				k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
				nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything).Return(map[string]string{"topology.kubernetes.io/zone1": "zone1"}, nil)
				nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
				nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)

				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}

				getAllRemoteSystemsFunc = func(_ *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					return nil, fmt.Errorf("failed to get remote systems")
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return true
				}
			},
			want:    []string{"Array1", "Array2"},
			wantErr: false,
		},
		{
			name: "Host Registration Failure - Create Host API fail",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}
					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				clientMock = new(gopowerstoremock.Client)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{}, fmt.Errorf("failed to create host"))
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Host Registration Failure with Local only",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							Client:        clientMock,
						},
					}
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				clientMock = new(gopowerstoremock.Client)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{}, fmt.Errorf("failed to create host"))
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Host Registration Failure - getIsRemoteToOtherArray",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					log.Infof("InsideGetArray")

					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}

					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				clientMock = new(gopowerstoremock.Client)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{ID: validHostID}, nil)

				getIsRemoteToOtherArray = func(_ *Service, _ context.Context, _, _ *array.PowerStoreArray) bool {
					return false
				}
			},
			want:    []string{"Array1", "Array2"},
			wantErr: false,
		},
		{
			name: "Host Registration Failure - Register Host fail",
			s: &MockService{
				Service: &Service{},
			},
			args: args{
				ctx:        context.TODO(),
				initiators: []string{"initiator1", "initiator2"},
			},
			setup: func() {
				getArrayfn = func(_ *Service) map[string]*array.PowerStoreArray {
					return map[string]*array.PowerStoreArray{
						"Array1": {
							Endpoint:      "https://10.198.0.1/api/rest",
							GlobalID:      "Array1",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone2"},
							IP:            "10.198.0.1",
							Client:        clientMock,
						},
						"Array2": {
							Endpoint:      "https://10.198.0.2/api/rest",
							GlobalID:      "Array2",
							Username:      "admin",
							Password:      "Pass",
							Insecure:      true,
							BlockProtocol: "auto",
							MetroTopology: "Uniform",
							Labels:        map[string]string{"topology.kubernetes.io/zone1": "zone1"},
							IP:            "10.198.0.2",
							Client:        clientMock,
						},
					}
				}

				getAllRemoteSystemsFunc = func(arr *array.PowerStoreArray, _ context.Context) ([]gopowerstore.RemoteSystem, error) {
					if arr.GlobalID == "Array2" {
						return []gopowerstore.RemoteSystem{
							{
								ID:                  "arrayid1",
								Name:                "Pstore1",
								Description:         "",
								SerialNumber:        "Array1",
								ManagementAddress:   "10.198.0.1",
								DataConnectionState: "OK",
								Capabilities:        []string{"Synchronous_Block_Replication"},
							},
						}, nil
					}
					return []gopowerstore.RemoteSystem{
						{
							ID:                  "arrayid2",
							Name:                "Pstore2",
							Description:         "",
							SerialNumber:        "Array2",
							ManagementAddress:   "10.198.0.2",
							DataConnectionState: "OK",
							Capabilities:        []string{"Synchronous_Block_Replication"},
						},
					}, nil
				}

				getIsHostAlreadyRegistered = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ []string) bool {
					return false
				}

				clientMock = new(gopowerstoremock.Client)
				clientMock.On("SetCustomHTTPHeaders", mock.Anything).Return(nil)
				clientMock.On("CreateHost", mock.Anything, mock.Anything).
					Return(gopowerstore.CreateResponse{}, fmt.Errorf("failed to create host"))

				registerHostFunc = func(_ *Service, _ context.Context, _ gopowerstore.Client, _ string, _ []string, _ gopowerstore.HostConnectivityEnum) error {
					return fmt.Errorf("failed to register Host")
				}
			},
			want:    []string{},
			wantErr: true,
		},
		// Add more test cases as needed
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			got, err := tt.s.createHost(tt.args.ctx, tt.args.initiators)

			if (err != nil) != tt.wantErr {
				t.Errorf("Service.createHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(tt.want) == 0 && got == "" {
				// Special case: want is empty and got is empty
				return
			}

			found := false
			for _, expected := range tt.want {
				log.Infof("got %v expected %v", got, expected)
				if got == expected {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Service.createHost() = %v, want one of %v", got, tt.want)
			}
		})
	}
}

func TestCheckIQNS(t *testing.T) {
	tests := []struct {
		name       string
		IQNs       []string
		host       gopowerstore.Host
		wantAdd    []string
		wantDelete []string
	}{
		{
			name: "IQNs to add and delete",
			IQNs: []string{"iqn1", "iqn2", "iqn3"},
			host: gopowerstore.Host{
				Initiators: []gopowerstore.InitiatorInstance{
					{PortName: "iqn2"},
					{PortName: "iqn4"},
				},
			},
			wantAdd:    []string{"iqn1", "iqn3"},
			wantDelete: []string{"iqn4"},
		},
		{
			name: "No IQNs to add or delete",
			IQNs: []string{"iqn1", "iqn2"},
			host: gopowerstore.Host{
				Initiators: []gopowerstore.InitiatorInstance{
					{PortName: "iqn1"},
					{PortName: "iqn2"},
				},
			},
			wantAdd:    []string{},
			wantDelete: []string{},
		},
		{
			name: "All IQNs to add",
			IQNs: []string{"iqn1", "iqn2"},
			host: gopowerstore.Host{
				Initiators: []gopowerstore.InitiatorInstance{},
			},
			wantAdd:    []string{"iqn1", "iqn2"},
			wantDelete: []string{},
		},
		{
			name: "All IQNs to delete",
			IQNs: []string{},
			host: gopowerstore.Host{
				Initiators: []gopowerstore.InitiatorInstance{
					{PortName: "iqn1"},
					{PortName: "iqn2"},
				},
			},
			wantAdd:    []string{},
			wantDelete: []string{"iqn1", "iqn2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Infof("Test: %s", tt.name)
			gotAdd, gotDelete := checkIQNS(tt.IQNs, tt.host)

			if !elementsMatch(gotAdd, tt.wantAdd) {
				t.Errorf("checkIQNS() = gotAdd %v, wantAdd %v", gotAdd, tt.wantAdd)
			}

			if !elementsMatch(gotDelete, tt.wantDelete) {
				t.Errorf("checkIQNS() = gotDelete %v, wantDelete %v", gotDelete, tt.wantDelete)
			}

			if elementsMatch(gotAdd, tt.wantAdd) && elementsMatch(gotDelete, tt.wantDelete) {
				log.Info("Success")
			}
		})
	}
}

func elementsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int)
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		if m[v] == 0 {
			return false
		}
		m[v]--
	}
	return true
}
