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
	"fmt"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/gopowerstore"
	repgrpc "github.com/csi-addons/spec/lib/go/replication"
	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = ginkgo.Describe("CSI-Addons VolumeGroup Helpers", func() {
	ginkgo.Describe("getVolumeGroupName", func() {
		ginkgo.It("should generate volume group name with all parameters", func() {
			name := getVolumeGroupName("test-prefix", "vg-123", "Five_Minutes", "remote-array")
			gomega.Expect(name).ToNot(gomega.BeEmpty())
			gomega.Expect(name).To(gomega.ContainSubstring("test-prefix"))
		})

		ginkgo.It("should truncate name to 128 characters", func() {
			longPrefix := "very-long-prefix-that-will-make-the-name-exceed-128-characters-when-combined-with-other-parameters"
			name := getVolumeGroupName(longPrefix, "vg-123", "Five_Minutes", "remote-array-with-long-name")
			gomega.Expect(len(name)).To(gomega.BeNumerically("<=", 128))
		})
	})

	ginkgo.Describe("getVolumeGroupPrefix", func() {
		ginkgo.It("should extract volume group prefix from parameters", func() {
			params := map[string]string{
				CSIAddonsParamVolumeGroupPrefix: "custom-prefix",
			}
			prefix := getVolumeGroupPrefix(params)
			gomega.Expect(prefix).To(gomega.Equal("custom-prefix"))
		})

		ginkgo.It("should return default prefix when parameter not set", func() {
			params := map[string]string{}
			prefix := getVolumeGroupPrefix(params)
			gomega.Expect(prefix).To(gomega.Equal(defaultVGPrefix))
		})
	})

	ginkgo.Describe("checkExistingReplicationVolumeGroup", func() {
		var testArray *array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			testArray = &array.PowerStoreArray{
				Client:   clientMock,
				GlobalID: "test-array-id",
			}
		})

		ginkgo.It("should return nil when volume not found", func() {
			clientMock.On("GetVolume", mock.Anything, "vol-1").Return(gopowerstore.Volume{}, fmt.Errorf("not found"))

			vg, err := checkExistingReplicationVolumeGroup(context.Background(), testArray, []string{"vol-1"}, "test-prefix")

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(vg).To(gomega.BeNil())
		})

		ginkgo.It("should return nil when GetVolume fails", func() {
			clientMock.On("GetVolume", mock.Anything, "vol-1").Return(gopowerstore.Volume{}, errors.New("api error"))

			vg, err := checkExistingReplicationVolumeGroup(context.Background(), testArray, []string{"vol-1"}, "test-prefix")

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(vg).To(gomega.BeNil())
		})

		ginkgo.It("should find volume in replication volume group", func() {
			vgID := "vg-123"
			volumeID := "vol-1"

			clientMock.On("GetVolume", mock.Anything, volumeID).Return(gopowerstore.Volume{
				ID: volumeID,
				VolumeGroup: []gopowerstore.VolumeGroup{
					{ID: vgID},
				},
			}, nil)

			vg1 := gopowerstore.VolumeGroup{
				ID:   vgID,
				Name: "test-prefix-vg",
			}
			clientMock.On("GetVolumeGroup", mock.Anything, vgID).Return(vg1, nil)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, vgID).Return(
				gopowerstore.ReplicationSession{ID: "session-1"}, nil)

			vg, err := checkExistingReplicationVolumeGroup(context.Background(), testArray, []string{volumeID}, "test-prefix")

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(vg).ToNot(gomega.BeNil())
			gomega.Expect(vg.ID).To(gomega.Equal(vgID))
		})

		ginkgo.It("should skip volume group without replication session", func() {
			vgID := "vg-123"
			volumeID := "vol-1"

			clientMock.On("GetVolume", mock.Anything, volumeID).Return(gopowerstore.Volume{
				ID: volumeID,
				VolumeGroup: []gopowerstore.VolumeGroup{
					{ID: vgID},
				},
			}, nil)

			vg1 := gopowerstore.VolumeGroup{
				ID:   vgID,
				Name: "test-prefix-vg",
			}
			clientMock.On("GetVolumeGroup", mock.Anything, vgID).Return(vg1, nil)

			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, vgID).Return(
				gopowerstore.ReplicationSession{}, errors.New("not found"))

			vg, err := checkExistingReplicationVolumeGroup(context.Background(), testArray, []string{volumeID}, "test-prefix")

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(vg).To(gomega.BeNil())
		})
	})

	ginkgo.Describe("mapReplicationSessionStateToStatus", func() {
		ginkgo.It("should map OK state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateOk)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_HEALTHY))
			gomega.Expect(msg).To(gomega.ContainSubstring("synchronized"))
		})

		ginkgo.It("should map Synchronizing state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateSynchronizing)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("synchronizing"))
		})

		ginkgo.It("should map Paused state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStatePaused)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_ERROR))
			gomega.Expect(msg).To(gomega.ContainSubstring("paused"))
		})

		ginkgo.It("should map Failed_Over state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateFailedOver)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("failed over"))
		})

		ginkgo.It("should map unknown state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus("UnknownState")
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_UNKNOWN))
			gomega.Expect(msg).To(gomega.ContainSubstring("UnknownState"))
		})
	})

	ginkgo.Describe("mapReplicationSessionStateToStatus additional states", func() {
		ginkgo.It("should map Initializing state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateInitializing)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("initializing"))
		})

		ginkgo.It("should map Resuming state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateResuming)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("resuming"))
		})

		ginkgo.It("should map Reprotecting state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateReprotecting)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("reprotecting"))
		})

		ginkgo.It("should map PausedForMigration state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStatePausedForMigration)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_ERROR))
			gomega.Expect(msg).To(gomega.ContainSubstring("migration"))
		})

		ginkgo.It("should map PausedForNdu state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStatePausedForNdu)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_ERROR))
			gomega.Expect(msg).To(gomega.ContainSubstring("NDU"))
		})

		ginkgo.It("should map SystemPaused state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateSystemPaused)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_ERROR))
			gomega.Expect(msg).To(gomega.ContainSubstring("system paused"))
		})

		ginkgo.It("should map Error state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateError)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_ERROR))
			gomega.Expect(msg).To(gomega.ContainSubstring("error"))
		})

		ginkgo.It("should map Fractured state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateFractured)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_ERROR))
			gomega.Expect(msg).To(gomega.ContainSubstring("fractured"))
		})

		ginkgo.It("should map FailingOver state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateFailingOver)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("failing over"))
		})

		ginkgo.It("should map FailingOverForDR state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateFailingOverForDR)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("DR"))
		})

		ginkgo.It("should map PartialCutoverForMigration state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStatePartialCutoverForMigration)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("migration"))
		})

		ginkgo.It("should map SwitchingToMetroSync state correctly", func() {
			status, msg := mapReplicationSessionStateToStatus(gopowerstore.RsStateSwitchingToMetroSync)
			gomega.Expect(status).To(gomega.Equal(repgrpc.GetVolumeReplicationInfoResponse_DEGRADED))
			gomega.Expect(msg).To(gomega.ContainSubstring("metro sync"))
		})
	})

	ginkgo.Describe("getDefaultCapability", func() {
		ginkgo.It("should return default volume capability", func() {
			capability := getDefaultCapability()
			gomega.Expect(capability).ToNot(gomega.BeNil())
			gomega.Expect(capability.GetMount()).ToNot(gomega.BeNil())
			gomega.Expect(capability.GetMount().FsType).To(gomega.Equal("ext4"))
			gomega.Expect(capability.GetAccessMode()).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("vgGetParameters", func() {
		ginkgo.It("should return error when params are nil", func() {
			_, err := vgGetParameters(nil)
			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return error when sourceArray is missing", func() {
			params := map[string]string{
				targetArrayParameter: "target-id",
			}
			_, err := vgGetParameters(params)
			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return error when targetArray is missing", func() {
			params := map[string]string{
				sourceArrayParameter: "source-id",
			}
			_, err := vgGetParameters(params)
			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should succeed with valid params", func() {
			params := map[string]string{
				sourceArrayParameter: "source-id",
				targetArrayParameter: "target-id",
			}
			result, err := vgGetParameters(params)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(result).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("findVolumeGroupOnArray", func() {
		var testArray *array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			testArray = &array.PowerStoreArray{
				Client:   clientMock,
				GlobalID: "test-array-id",
			}
		})

		ginkgo.It("should return error when volumeGroupID is empty", func() {
			_, err := findVolumeGroupOnArray(context.Background(), testArray, "")
			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should find VG by exact ID", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, "vg-123").Return(
				gopowerstore.VolumeGroup{ID: "vg-123", Name: defaultVGPrefix + "-vg"}, nil)

			vg, err := findVolumeGroupOnArray(context.Background(), testArray, "vg-123")
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(vg).ToNot(gomega.BeNil())
			gomega.Expect(vg.ID).To(gomega.Equal("vg-123"))
		})

		ginkgo.It("should fall back to name search when ID not found", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, "content-uid").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{
				{ID: "vg-1", Name: "content-uid"},
			}, nil)

			vg, err := findVolumeGroupOnArray(context.Background(), testArray, "content-uid")
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(vg).ToNot(gomega.BeNil())
			gomega.Expect(vg.ID).To(gomega.Equal("vg-1"))
		})

		ginkgo.It("should return error when VG not found by ID or name", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, "missing-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return([]gopowerstore.VolumeGroup{
				{ID: "vg-1", Name: defaultVGPrefix + "-other-vg"},
			}, nil)

			_, err := findVolumeGroupOnArray(context.Background(), testArray, "missing-vg")
			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should return error when GetVolumeGroups fails", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, "some-vg").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, errors.New("api error"))

			_, err := findVolumeGroupOnArray(context.Background(), testArray, "some-vg")
			gomega.Expect(err).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("findArrayWithVolumeGroupID", func() {
		ginkgo.BeforeEach(func() {
			setVariables()
		})

		ginkgo.It("should return error when volumeGroupID is empty", func() {
			_, _, err := findArrayWithVolumeGroupID(context.Background(), ctrlSvc.Arrays(), "")
			gomega.Expect(err).ToNot(gomega.BeNil())
		})

		ginkgo.It("should find VG by ID on array", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, "vg-id-123").Return(
				gopowerstore.VolumeGroup{ID: "vg-id-123", Name: defaultVGPrefix + "-vg"}, nil)

			arr, vg, err := findArrayWithVolumeGroupID(context.Background(), ctrlSvc.Arrays(), "vg-id-123")
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(arr).ToNot(gomega.BeNil())
			gomega.Expect(vg).ToNot(gomega.BeNil())
			gomega.Expect(vg.ID).To(gomega.Equal("vg-id-123"))
		})

		ginkgo.It("should return nil when VG not found", func() {
			clientMock.On("GetVolumeGroup", mock.Anything, "non-existent").Return(
				gopowerstore.VolumeGroup{}, errors.New("not found"))
			clientMock.On("GetVolumeGroups", mock.Anything).Return(
				[]gopowerstore.VolumeGroup{}, errors.New("not found"))

			arr, vg, err := findArrayWithVolumeGroupID(context.Background(), ctrlSvc.Arrays(), "non-existent")
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(arr).To(gomega.BeNil())
			gomega.Expect(vg).To(gomega.BeNil())
		})
	})

	ginkgo.Describe("removeMembersFromVolumeGroup", func() {
		var testArray *array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			testArray = &array.PowerStoreArray{
				Client:   clientMock,
				GlobalID: "test-array-id",
			}
		})

		ginkgo.It("should remove volumes from volume group", func() {
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			err := removeMembersFromVolumeGroup(context.Background(), testArray, "vg-123", []string{"vol-1", "vol-2"})
			gomega.Expect(err).To(gomega.BeNil())
		})

		ginkgo.It("should return error when removal fails", func() {
			clientMock.On("RemoveMembersFromVolumeGroup", mock.Anything, mock.Anything, mock.Anything).Return(
				gopowerstore.EmptyResponse(""), errors.New("removal failed"))

			err := removeMembersFromVolumeGroup(context.Background(), testArray, "vg-123", []string{"vol-1"})
			gomega.Expect(err).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("unassignProtectionPolicyFromVolumeGroup", func() {
		var testArray *array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			testArray = &array.PowerStoreArray{
				Client:   clientMock,
				GlobalID: "test-array-id",
			}
		})

		ginkgo.It("should do nothing when no protection policy is assigned", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 "vg-123",
				ProtectionPolicyID: "",
			}
			err := unassignProtectionPolicyFromVolumeGroup(context.Background(), testArray, vg)
			gomega.Expect(err).To(gomega.BeNil())
		})

		ginkgo.It("should unassign protection policy successfully", func() {
			vg := &gopowerstore.VolumeGroup{
				ID:                 "vg-123",
				ProtectionPolicyID: "pp-123",
			}
			clientMock.On("UpdateVolumeGroupProtectionPolicy", mock.Anything, "vg-123", mock.Anything).Return(
				gopowerstore.EmptyResponse(""), nil)

			err := unassignProtectionPolicyFromVolumeGroup(context.Background(), testArray, vg)
			gomega.Expect(err).To(gomega.BeNil())
		})
	})

	ginkgo.Describe("ExecuteActionOnReplicationSession", func() {
		var testArray *array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			testArray = &array.PowerStoreArray{
				Client:   clientMock,
				GlobalID: "test-array-id",
			}
		})

		ginkgo.It("should return error when replication session not found", func() {
			clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, "vg-123").Return(
				gopowerstore.ReplicationSession{}, errors.New("not found"))

			err := ExecuteActionOnReplicationSession(context.Background(), testArray, "vg-123", gopowerstore.RsActionPause)
			gomega.Expect(err).ToNot(gomega.BeNil())
		})
	})

	ginkgo.Describe("findArrayWithVolumeGroup", func() {
		var arrayMap map[string]*array.PowerStoreArray

		ginkgo.BeforeEach(func() {
			setVariables()
			arrayMap = map[string]*array.PowerStoreArray{
				"source-array": {
					Client:   clientMock,
					GlobalID: "source-array",
				},
				"target-array": {
					Client:   clientMock,
					GlobalID: "target-array",
				},
			}
		})

		ginkgo.It("should find volume group on source array", func() {
			vgName := "test-vg"
			vg := gopowerstore.VolumeGroup{
				ID:                       "vg-123",
				Name:                     vgName,
				IsReplicationDestination: false,
			}

			clientMock.On("GetVolumeGroupByName", mock.Anything, vgName).Return(vg, nil).Once()

			foundArray, foundVG, err := findArrayWithVolumeGroup(context.Background(), arrayMap, vgName, "source-array", "target-array", false)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(foundArray).ToNot(gomega.BeNil())
			gomega.Expect(foundArray.GlobalID).To(gomega.Equal("source-array"))
			gomega.Expect(foundVG).ToNot(gomega.BeNil())
			gomega.Expect(foundVG.ID).To(gomega.Equal("vg-123"))
		})

		ginkgo.It("should find volume group on target array when not on source", func() {
			vgName := "test-vg"
			vg := gopowerstore.VolumeGroup{
				ID:                       "vg-456",
				Name:                     vgName,
				IsReplicationDestination: true,
			}

			// First call for source array returns error
			clientMock.On("GetVolumeGroupByName", mock.Anything, vgName).Return(gopowerstore.VolumeGroup{}, errors.New("not found")).Once()
			// Second call for target array succeeds
			clientMock.On("GetVolumeGroupByName", mock.Anything, vgName).Return(vg, nil).Once()

			foundArray, foundVG, err := findArrayWithVolumeGroup(context.Background(), arrayMap, vgName, "source-array", "target-array", true)

			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(foundArray).ToNot(gomega.BeNil())
			gomega.Expect(foundArray.GlobalID).To(gomega.Equal("target-array"))
			gomega.Expect(foundVG).ToNot(gomega.BeNil())
			gomega.Expect(foundVG.ID).To(gomega.Equal("vg-456"))
		})

		ginkgo.It("should return error when volume group name is empty", func() {
			foundArray, foundVG, err := findArrayWithVolumeGroup(context.Background(), arrayMap, "", "source-array", "target-array", false)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(foundArray).To(gomega.BeNil())
			gomega.Expect(foundVG).To(gomega.BeNil())
		})

		ginkgo.It("should return error when source array not found", func() {
			foundArray, foundVG, err := findArrayWithVolumeGroup(context.Background(), arrayMap, "test-vg", "invalid-array", "target-array", false)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(foundArray).To(gomega.BeNil())
			gomega.Expect(foundVG).To(gomega.BeNil())
		})

		ginkgo.It("should return error when target array not found", func() {
			foundArray, foundVG, err := findArrayWithVolumeGroup(context.Background(), arrayMap, "test-vg", "source-array", "invalid-array", false)

			gomega.Expect(err).ToNot(gomega.BeNil())
			gomega.Expect(foundArray).To(gomega.BeNil())
			gomega.Expect(foundVG).To(gomega.BeNil())
		})
	})
})
