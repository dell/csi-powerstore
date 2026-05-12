/* Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.

 * Dell Technologies, Dell and other trademarks are trademarks of Dell Inc.
 * or its subsidiaries. Other trademarks may be trademarks of their respective
 * owners.
 *
 */

package groupcontroller

import (
	"context"
	"fmt"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	csictx "github.com/dell/gocsi/context"
	csi "github.com/container-storage-interface/spec/lib/go/csi"
	ginkgo "github.com/onsi/ginkgo"

	gomega "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

type testEnv struct {
	groupClient *Service
}

var env *testEnv

func getTestEnv() *testEnv {
	return &testEnv{
		groupClient: &Service{},
	}
}

func TestCSIGroupControllerService(t *testing.T) {
	defaultK8sConfigFunc := k8sutils.InClusterConfigFunc
	defaultK8sClientsetFunc := k8sutils.NewForConfigFunc

	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewClientset(), nil
	}

	defer func() {
		k8sutils.InClusterConfigFunc = defaultK8sConfigFunc
		k8sutils.NewForConfigFunc = defaultK8sClientsetFunc
	}()

	gomega.RegisterFailHandler(ginkgo.Fail)
	junitReporter := reporters.NewJUnitReporter("grp-ctrl-svc.xml")
	ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "CSIGroupControllerService testing suite", []ginkgo.Reporter{junitReporter})
}

func setVariables() {
	env = getTestEnv()
	if err := csictx.Setenv(context.Background(), identifiers.EnvIsHealthMonitorEnabled, "true"); err != nil {
		panic(fmt.Sprintf("Failed to set %s: %v", identifiers.EnvIsHealthMonitorEnabled, err))
	}
	if err := csictx.Setenv(context.Background(), identifiers.EnvAllowAutoRoundOffFilesystemSize, "true"); err != nil {
		panic(fmt.Sprintf("Failed to set %s: %v", identifiers.EnvAllowAutoRoundOffFilesystemSize, err))
	}
	_ = env.groupClient.Init()
}

var _ = ginkgo.Describe("CSI GroupController service", func() {
	ginkgo.BeforeEach(func() {
		setVariables()
	})

	ginkgo.It("advertises CREATE_DELETE_GET_VOLUME_GROUP_SNAPSHOT capability", func() {
		resp, err := env.groupClient.GroupControllerGetCapabilities(context.Background(), &csi.GroupControllerGetCapabilitiesRequest{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(resp.GetCapabilities()).To(gomega.HaveLen(1))
		got := resp.GetCapabilities()[0].GetRpc().GetType()
		gomega.Expect(got).To(gomega.Equal(csi.GroupControllerServiceCapability_RPC_CREATE_DELETE_GET_VOLUME_GROUP_SNAPSHOT))
	})

	ginkgo.It("returns error for CreateVolumeGroupSnapshot with empty name", func() {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name: "",
		}
		_, err := env.groupClient.CreateVolumeGroupSnapshot(context.Background(), req)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("name cannot be empty"))
	})

	ginkgo.It("returns error for CreateVolumeGroupSnapshot when no arrays configured", func() {
		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/array1/scsi"},
		}
		_, err := env.groupClient.CreateVolumeGroupSnapshot(context.Background(), req)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("no arrays available for validation"))
	})

	ginkgo.It("uses fallback array when no default array is set", func() {
		// This test covers the fallback logic where there are arrays but no default is set
		// Set up arrays without setting a default array
		testArrays := map[string]*array.PowerStoreArray{
			"array1": {
				GlobalID: "array1",
			},
		}
		env.groupClient.SetArrays(testArrays)
		// Don't set default array - this should trigger fallback logic

		req := &csi.CreateVolumeGroupSnapshotRequest{
			Name:            "test-snapshot",
			SourceVolumeIds: []string{"vol1/array1/scsi"},
		}

		// The test should reach the fallback logic and then fail at volume validation
		// since the volume ID parsing will fail with the fallback array
		_, err := env.groupClient.CreateVolumeGroupSnapshot(context.Background(), req)
		gomega.Expect(err).To(gomega.HaveOccurred())
		// Should fail at volume validation stage, not at array availability stage
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("array array1 not found"))
	})

	ginkgo.It("returns error for GetVolumeGroupSnapshot with empty ID", func() {
		req := &csi.GetVolumeGroupSnapshotRequest{
			GroupSnapshotId: "",
		}
		_, err := env.groupClient.GetVolumeGroupSnapshot(context.Background(), req)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("group snapshot ID cannot be empty"))
	})

	ginkgo.It("returns error for DeleteVolumeGroupSnapshot with empty ID", func() {
		req := &csi.DeleteVolumeGroupSnapshotRequest{
			GroupSnapshotId: "",
		}
		_, err := env.groupClient.DeleteVolumeGroupSnapshot(context.Background(), req)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("group snapshot ID cannot be empty"))
	})
})
