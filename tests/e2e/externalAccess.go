/*
 *
 * Copyright © 2022-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package e2etest

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/gopowerstore"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/deployment"
	fpv "k8s.io/kubernetes/test/e2e/framework/pv"
	fss "k8s.io/kubernetes/test/e2e/framework/statefulset"
)

/*

	Create NFS SC.
	Create PVC using above SC.
	Deployment having 10 replicas using above PVC.
	Scale down to 1 pod.
	Check if externalAccess is present in the NFS Export after scaling down to 1 pod
	Scale down to 0 pods.
	Cleanup the NS, i.e. SC, PVC, Pod.


*/

var (
	testParameters   map[interface{}]interface{}
	deploymentObject *v1.Deployment
	mountPath        = "/data"
	extCredential    ExternaAccess
)

// ExternaAccess for storing ExternalAccess credentials
type ExternaAccess struct {
	EndPoint         string
	UserName         string
	Password         string
	ExternalAccessIP string
	NASServer        string
	TestStatefulset  bool
}

var _ = ginkgo.Describe("External Access Test", func() {
	// Building a namespace api object, basename external-access
	var (
		namespace string
		client    clientset.Interface
	)

	framework.TestContext.VerifyServiceAccount = false
	f := framework.NewDefaultFramework("external-access")
	// prevent annoying psp warning

	// f.SkipPrivilegedPSPBinding = true
	defer ginkgo.GinkgoRecover()
	framework.Logf("run e2e test default timeouts  %#v ", f.Timeouts)
	ginkgo.BeforeEach(func() {
		namespace = getNamespaceToRunTests(f)
		client = f.ClientSet
		bootstrap()
	})

	ginkgo.AfterEach(func() {
		_, cancel := context.WithCancel(context.Background())
		defer cancel()
		DeleteDeployment(client, deploymentObject, namespace)
		if extCredential.TestStatefulset {
			ginkgo.By(fmt.Sprintf("Deleting all statefulsets in namespace: %v", namespace))
			fss.DeleteAllStatefulSets(client, namespace)
		}
	})

	// in case you want to log and exit	framework.Fail("stop test")

	// Test for external Access feature check
	ginkgo.It("[csi-externalAccess] Verify Host Access List for exteral access", func() {
		curtime := time.Now().Unix()
		nBig, err := rand.Int(rand.Reader, big.NewInt(27))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		randomValue := nBig.Int64()
		val := strconv.FormatInt(int64(randomValue), 10)
		curtimestring := strconv.FormatInt(curtime, 10)
		scName := "exteral-access-sc-" + curtimestring + val

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ginkgo.By("Creating NFS Storage Class & PVC")

		// get array credential from config file
		extCredential = getExternalAccessCredential(testParameters["externalAccess"])

		testParameters["allowRoot"] = "true"
		testParameters["csi.storage.k8s.io/fstype"] = "nfs"
		testParameters["nasName"] = extCredential.NASServer

		ds := fmt.Sprintf("%v", testParameters["diskSize"])
		storageclasspvc, pvclaim, err := createPVCAndStorageClass(client,
			namespace, nil, testParameters, ds, nil, storagev1.VolumeBindingImmediate, true, "ReadWriteMany", scName)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		defer func() {
			err = client.StorageV1().StorageClasses().Delete(ctx, storageclasspvc.Name, *metav1.NewDeleteOptions(0))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}()

		ginkgo.By("Expect PVC's claim status to be in Bound state")
		err = fpv.WaitForPersistentVolumeClaimPhase(corev1.ClaimBound, client,
			pvclaim.Namespace, pvclaim.Name, framework.Poll, 2*time.Minute)

		gomega.Expect(err).NotTo(gomega.HaveOccurred(),
			fmt.Sprintf("Failed to find the volume in bound state with err: %v", err))

		podLabels := map[string]string{
			"app": "dell-wip",
		}
		// Deployment is a resource to deploy a stateless application, if using a PVC, all replicas will be using the same Volume
		ginkgo.By("Creating Deployment having 10 replicas")
		deploymentObject, err = deployment.CreateDeployment(client, 10, podLabels, nil, namespace, []*corev1.PersistentVolumeClaim{pvclaim}, fmt.Sprintf("%v", testParameters["execCommand"]))
		gomega.Expect(err).NotTo(gomega.HaveOccurred(),
			fmt.Sprintf("Failed to create deployment resource with err: %v", err))

		ginkgo.By("Deployment got created")
		// now get the pvc, more intrested in volumeId
		v := getPvFromClaim(client, namespace, pvclaim.Name)
		framework.Logf("Volume Name that got attached to all pods: %s", v.GetName())

		ginkgo.By("Scaling down to 1 replica")
		ScaleDownDeployment(client, deploymentObject, namespace, 1)

		// fetch the NFS export object from array to avoid conflict in the response
		// Get host access list from array for above volume
		clientOptions := gopowerstore.NewClientOptions()
		clientOptions.SetInsecure(true)
		clientForArray, err := gopowerstore.NewClientWithArgs(
			extCredential.EndPoint, extCredential.UserName, extCredential.Password, clientOptions)

		gomega.Expect(err).NotTo(gomega.HaveOccurred(),
			fmt.Sprintf("Failed to connect with PowerStore Array, err: %v", err))
		checkExternalAccessPresence(ctx, clientForArray, extCredential.ExternalAccessIP, v.GetName(), true)

		// now in NFS Export only externalIP will be present and other node's IP will be deleted
		ScaleDownDeployment(client, deploymentObject, namespace, 0)
		checkExternalAccessPresence(ctx, clientForArray, extCredential.ExternalAccessIP, v.GetName(), true)

		err = fpv.DeletePersistentVolumeClaim(client, pvclaim.Name, namespace)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(),
			fmt.Sprintf("Unable to delete PVC with err: %v", err))

		if extCredential.TestStatefulset {
			// statefulset logic
			scName2 := scName + "stateful-set"
			sc, err := createStorageClass(client, testParameters, nil, "",
				storagev1.VolumeBindingImmediate,
				true, scName2)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			defer func() {
				err := client.StorageV1().StorageClasses().Delete(ctx, sc.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}()

			statefulset := GetStatefulSetFromManifest(namespace)
			ginkgo.By("Creating statefulset")

			statefulset.Spec.VolumeClaimTemplates[len(statefulset.Spec.VolumeClaimTemplates)-1].Spec.AccessModes[0] = corev1.ReadWriteMany

			statefulset.Spec.VolumeClaimTemplates[len(statefulset.Spec.VolumeClaimTemplates)-1].
				Annotations["volume.beta.kubernetes.io/storage-class"] = scName2

			CreateStatefulSet(namespace, statefulset, client)

			defer func() {
				ginkgo.By(fmt.Sprintf("Deleting all statefulsets in namespace: %v", namespace))
				fss.DeleteAllStatefulSets(client, namespace)
			}()
			replicas := *(statefulset.Spec.Replicas)
			// Waiting for pods status to be Ready
			fss.WaitForStatusReadyReplicas(client, statefulset, replicas)

			gomega.Expect(fss.CheckMount(client, statefulset, mountPath)).NotTo(gomega.HaveOccurred())

			ssPodsBeforeScaleDown := fss.GetPodList(client, statefulset)
			gomega.Expect(ssPodsBeforeScaleDown.Items).NotTo(gomega.BeEmpty(),
				fmt.Sprintf("Unable to get list of Pods from the Statefulset: %v", statefulset.Name))
			gomega.Expect(len(ssPodsBeforeScaleDown.Items) == int(replicas)).To(gomega.BeTrue(),
				"Number of Pods in the statefulset should match with number of replicas")

			// Get the list of Volumes attached to Pods before scale down
			for _, sspod := range ssPodsBeforeScaleDown.Items {
				_, err := client.CoreV1().Pods(namespace).Get(ctx, sspod.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				for _, volumespec := range sspod.Spec.Volumes {
					if volumespec.PersistentVolumeClaim != nil {
						pv := getPvFromClaim(client, statefulset.Namespace, volumespec.PersistentVolumeClaim.ClaimName)
						gomega.Expect(pv).NotTo(gomega.BeNil())
					}
				}
			}

			// 1
			replicas = 1
			ginkgo.By(fmt.Sprintf("Scaling down statefulsets to number of Replica: %v", replicas))
			_, scaledownErr := fss.Scale(client, statefulset, replicas)
			gomega.Expect(scaledownErr).NotTo(gomega.HaveOccurred())
			fss.WaitForStatusReplicas(client, statefulset, replicas)
			ssPodsAfterScaleDown := fss.GetPodList(client, statefulset)
			gomega.Expect(ssPodsAfterScaleDown.Items).NotTo(gomega.BeEmpty(),
				fmt.Sprintf("Unable to get list of Pods from the Statefulset: %v", statefulset.Name))
			gomega.Expect(len(ssPodsAfterScaleDown.Items) == int(replicas)).To(gomega.BeTrue(),
				"Number of Pods in the statefulset should match with number of replicas")

			var pv *corev1.PersistentVolume
			// Get the list of Volumes attached to Pods after scale down
			// for us one iteration is also okay to have since PV Id/Name will be same.
			for _, sspod := range ssPodsAfterScaleDown.Items {
				_, err := client.CoreV1().Pods(namespace).Get(ctx, sspod.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				for _, volumespec := range sspod.Spec.Volumes {
					if volumespec.PersistentVolumeClaim != nil {
						pv = getPvFromClaim(client, statefulset.Namespace, volumespec.PersistentVolumeClaim.ClaimName)
						gomega.Expect(pv).NotTo(gomega.BeNil())
					}
				}
			}

			checkExternalAccessPresence(ctx, clientForArray, extCredential.ExternalAccessIP, pv.GetName(), true)

			// deleting all pods
			replicas = 0
			ginkgo.By(fmt.Sprintf("Scaling down statefulsets to number of Replica: %v", replicas))
			_, scaledownErr = fss.Scale(client, statefulset, replicas)
			gomega.Expect(scaledownErr).NotTo(gomega.HaveOccurred())
			fss.WaitForStatusReplicas(client, statefulset, replicas)
			ssPodsAfterScaleDown = fss.GetPodList(client, statefulset)
			gomega.Expect(len(ssPodsAfterScaleDown.Items) == int(replicas)).To(gomega.BeTrue(),
				"Number of Pods in the statefulset should match with number of replicas")

			err = fpv.DeletePersistentVolumeClaim(client, pv.Name, namespace)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(),
				fmt.Sprintf("Unable to delete PVC with err: %v", err))
		}
	})
})

func getExternalAccessCredential(credential interface{}) (ext ExternaAccess) {
	myMap := credential.(map[interface{}]interface{})
	ext.EndPoint = fmt.Sprintf("%v", myMap["endPoint"])
	ext.UserName = fmt.Sprintf("%v", myMap["userName"])
	ext.Password = fmt.Sprintf("%v", myMap["password"])
	ext.NASServer = fmt.Sprintf("%v", myMap["NASServer"])
	ext.ExternalAccessIP = fmt.Sprintf("%v", myMap["externalAccessIP"])
	ext.TestStatefulset, _ = strconv.ParseBool(fmt.Sprintf("%v", myMap["testStatefulset"]))
	return ext
}

func checkExternalAccessPresence(ctx context.Context, clientForArray gopowerstore.Client, externalAccessIP string, vol string, shouldBePresent bool) {
	nfsExport, err := clientForArray.GetNFSExportByName(ctx, vol)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(),
		fmt.Sprintf("Failed to GET NFS export details from Array, err: %v", err))
	present := common.ExternalAccessAlreadyAdded(nfsExport, externalAccessIP)
	if shouldBePresent && !present {
		gomega.Expect(present).NotTo(gomega.BeFalse(),
			"External access should be present on host access list on array")
	}
	if !shouldBePresent && present {
		gomega.Expect(present).NotTo(gomega.BeTrue(),
			"External access should not be present on host access list on array")
	}
}
