/*
 *
 * Copyright © 2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/deployment"
	"k8s.io/kubernetes/test/e2e/framework/manifest"
	fpv "k8s.io/kubernetes/test/e2e/framework/pv"
	fss "k8s.io/kubernetes/test/e2e/framework/statefulset"

	"k8s.io/kubernetes/test/e2e/framework/testfiles"

	"github.com/onsi/ginkgo/v2"
)

// getNamespaceToRunTests returns the namespace in which the tests are expected
// to run. For test setups, returns random namespace name
func getNamespaceToRunTests(f *framework.Framework) string {
	return f.Namespace.Name
}

// not usedgit git
// bootstrap function takes care of initializing necessary tests context for e2e tests
func bootstrap(withoutDc ...bool) {
	var err error
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	// ctx
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	if framework.TestContext.RepoRoot != "" {
		testfiles.AddFileSource(testfiles.RootFileSource{Root: framework.TestContext.RepoRoot})
	}
	framework.TestContext.Provider = "local"
}

// getPvFromClaim returns PersistentVolume for requested claim.
func getPvFromClaim(client clientset.Interface, namespace string, claimName string) *v1.PersistentVolume {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pvclaim, err := client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, claimName, metav1.GetOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	pv, err := client.CoreV1().PersistentVolumes().Get(ctx, pvclaim.Spec.VolumeName, metav1.GetOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return pv
}

// DeleteDeployment : delete on the basis of namespace and deployment name
func DeleteDeployment(client clientset.Interface, deploymentObject *apps.Deployment, namespace string) {
	deletePolicy := metav1.DeletePropagationForeground
	deploymentsClient := client.AppsV1().Deployments(namespace)
	err := deploymentsClient.Delete(context.TODO(), deploymentObject.Name, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	framework.ExpectNoError(err)
}

// ScaleDownDeployment : Decreasing the replica count
func ScaleDownDeployment(client clientset.Interface, deploymentObject *apps.Deployment, namespace string, replicaCount int32) {
	s, err := client.AppsV1().
		Deployments(namespace).
		GetScale(context.TODO(), deploymentObject.Name, metav1.GetOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	sc := *s
	sc.Spec.Replicas = replicaCount

	_, err = client.AppsV1().
		Deployments(namespace).
		UpdateScale(context.TODO(),
			deploymentObject.Name, &sc, metav1.UpdateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	// wait for few seconds to delete pods
	for i := 0; i < 2; i++ {
		time.Sleep(10 * time.Second)
		s, err := client.AppsV1().
			Deployments(namespace).
			GetScale(context.TODO(), deploymentObject.Name, metav1.GetOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		if s.Spec.Replicas == replicaCount {
			break
		}
	}
}

// CreateStatefulSet creates a StatefulSet from the manifest at manifestPath in the given namespace.
func CreateStatefulSet(ns string, ss *apps.StatefulSet, c clientset.Interface) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	framework.Logf(fmt.Sprintf("Creating statefulset %v/%v with %d replicas and selector %+v",
		ss.Namespace, ss.Name, *(ss.Spec.Replicas), ss.Spec.Selector))

	_, err := c.AppsV1().StatefulSets(ns).Create(ctx, ss, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	fss.WaitForRunningAndReady(c, *ss.Spec.Replicas, ss)
}

// CreateDeployment creates a deployment in the provided namespace
func CreateDeployment() (ns string, ss *apps.Deployment, c clientset.Interface) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	framework.Logf(fmt.Sprintf("Creating Deployment %v/%v with %d replicas and selector %+v",
		ss.Namespace, ss.Name, *(ss.Spec.Replicas), ss.Spec.Selector))

	_, err := c.AppsV1().Deployments(ns).Create(ctx, ss, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	deployment.WaitForDeploymentComplete(c, ss)
	return
}

// GetStatefulSetFromManifest creates a StatefulSet from the statefulset.yaml
// file present in the manifest path.
func GetStatefulSetFromManifest(ns string) *apps.StatefulSet {
	pwd, _ := os.Getwd()
	manifestPath := pwd + "/testing-manifests/statefulset/"

	ssManifestFilePath := filepath.Join(manifestPath, "statefulset.yaml")
	framework.Logf("Parsing statefulset from %v", ssManifestFilePath)
	ss, err := manifest.StatefulSetFromManifest(ssManifestFilePath, ns)
	framework.ExpectNoError(err)
	return ss
}

// createPVCAndStorageClass helps creates a storage class with specified name,
// storageclass parameters and PVC using storage class.
func createPVCAndStorageClass(client clientset.Interface, pvcnamespace string,
	pvclaimlabels map[string]string, testParameters map[interface{}]interface{}, ds string,
	allowedTopologies []v1.TopologySelectorLabelRequirement, bindingMode storagev1.VolumeBindingMode,
	allowVolumeExpansion bool, accessMode v1.PersistentVolumeAccessMode,
	names ...string) (*storagev1.StorageClass, *v1.PersistentVolumeClaim, error) {
	scName := ""
	if len(names) > 0 {
		scName = names[0]
	}

	storageclass, err := createStorageClass(client, testParameters,
		allowedTopologies, "", bindingMode, allowVolumeExpansion, scName)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	pvclaim, err := createPVC(client, pvcnamespace, pvclaimlabels, ds, storageclass, accessMode)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return storageclass, pvclaim, err
}

// createStorageClass helps creates a storage class with specified name,
// storageclass parameters.
func createStorageClass(client clientset.Interface, testParameters map[interface{}]interface{},
	allowedTopologies []v1.TopologySelectorLabelRequirement,
	scReclaimPolicy v1.PersistentVolumeReclaimPolicy, bindingMode storagev1.VolumeBindingMode,
	allowVolumeExpansion bool, scName string) (*storagev1.StorageClass, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var storageclass *storagev1.StorageClass
	var err error
	isStorageClassPresent := false
	// since array's credentials are present in testParameters map, setting it as nil to not print sensitive data
	testParameters["externalAccess"] = nil
	ginkgo.By(fmt.Sprintf("Creating StorageClass %s with scParameters: %+v and allowedTopologies: %+v "+
		"and ReclaimPolicy: %+v and allowVolumeExpansion: %t",
		scName, testParameters, allowedTopologies, scReclaimPolicy, allowVolumeExpansion))

	storageclass, err = client.StorageV1().StorageClasses().Get(ctx, scName, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		gomega.Expect(err).To(gomega.HaveOccurred())
	}

	if storageclass != nil && err == nil {
		isStorageClassPresent = true
	}

	if !isStorageClassPresent {
		storageclass, err = client.StorageV1().StorageClasses().Create(ctx, getStorageClassSpec(scName,
			testParameters, allowedTopologies, scReclaimPolicy, bindingMode, allowVolumeExpansion), metav1.CreateOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), fmt.Sprintf("Failed to create storage class with err: %v", err))
	}

	return storageclass, err
}

// getStorageClassSpec returns Storage Class Spec with supplied storage
// class parameters.
func getStorageClassSpec(scName string, testParameters map[interface{}]interface{},
	allowedTopologies []v1.TopologySelectorLabelRequirement, scReclaimPolicy v1.PersistentVolumeReclaimPolicy,
	bindingMode storagev1.VolumeBindingMode, allowVolumeExpansion bool) *storagev1.StorageClass {

	/* vals := make([]string, 0)
	vals = append(vals, testParameters["e2eCSIDriverName"])

	topo := v1.TopologySelectorLabelRequirement{
		Key:    testParameters["e2eCSIDriverName"] + "/" + testParameters["scParamStorageSystemValue"],
		Values: vals,
	}
	*/
	// allowedTopologies = append(allowedTopologies, topo)

	if bindingMode == "" {
		bindingMode = storagev1.VolumeBindingWaitForFirstConsumer
	}

	var sc = &storagev1.StorageClass{
		TypeMeta: metav1.TypeMeta{
			Kind: "StorageClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "sc-",
		},
		Provisioner:          fmt.Sprintf("%v", testParameters["e2eCSIDriverName"]),
		VolumeBindingMode:    &bindingMode,
		AllowVolumeExpansion: &allowVolumeExpansion,
	}
	// If scName is specified, use that name, else auto-generate storage class
	// name.

	if scName != "" {
		sc.ObjectMeta = metav1.ObjectMeta{
			Name: scName,
		}
	}

	if testParameters != nil {
		testParametersMap := make(map[string]string)
		for k, v := range testParameters {
			xType := fmt.Sprintf("%T", v)
			// since we are using a common file(e2e-values) for configuration so the easiest way here is to pick the values that is of string not object
			if xType == "string" {
				testParametersMap[fmt.Sprintf("%v", k)] = fmt.Sprintf("%v", v)
			}
		}
		sc.Parameters = testParametersMap
	}
	if allowedTopologies != nil {
		sc.AllowedTopologies = []v1.TopologySelectorTerm{
			{
				MatchLabelExpressions: allowedTopologies,
			},
		}
	}
	if scReclaimPolicy != "" {
		sc.ReclaimPolicy = &scReclaimPolicy
	}

	return sc
}

// createPVC helps creates pvc with given namespace and labels using given
// storage class.
func createPVC(client clientset.Interface, pvcnamespace string, pvclaimlabels map[string]string, ds string,
	storageclass *storagev1.StorageClass, accessMode v1.PersistentVolumeAccessMode) (*v1.PersistentVolumeClaim, error) {

	pvcspec := getPersistentVolumeClaimSpecWithStorageClass(pvcnamespace, ds, storageclass, pvclaimlabels, accessMode)

	ginkgo.By(fmt.Sprintf("Creating PVC using the Storage Class %s with disk size %s and labels: %+v accessMode: %+v",
		storageclass.Name, ds, pvclaimlabels, accessMode))

	pvclaim, err := fpv.CreatePVC(client, pvcnamespace, pvcspec)

	gomega.Expect(err).NotTo(gomega.HaveOccurred(), fmt.Sprintf("Failed to create pvc with err: %v", err))
	framework.Logf("PVC created: %v in namespace: %v", pvclaim.Name, pvcnamespace)
	return pvclaim, err
}

// getPersistentVolumeClaimSpecWithStorageClass return the PersistentVolumeClaim
// spec with specified storage class.
func getPersistentVolumeClaimSpecWithStorageClass(namespace string, ds string, storageclass *storagev1.StorageClass,
	pvclaimlabels map[string]string, accessMode v1.PersistentVolumeAccessMode) *v1.PersistentVolumeClaim {
	disksize := fmt.Sprintf("%v", testParameters["diskSize"])
	if ds != "" {
		disksize = ds
	}
	if accessMode == "" {
		// If accessMode is not specified, set the default accessMode.
		accessMode = v1.ReadWriteOnce
	}
	claim := &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "pvc-",
			Namespace:    namespace,
		},
		Spec: v1.PersistentVolumeClaimSpec{
			AccessModes: []v1.PersistentVolumeAccessMode{
				accessMode,
			},
			Resources: v1.ResourceRequirements{
				Requests: v1.ResourceList{
					v1.ResourceName(v1.ResourceStorage): resource.MustParse(disksize),
				},
			},
			StorageClassName: &(storageclass.Name),
		},
	}

	if pvclaimlabels != nil {
		claim.Labels = pvclaimlabels
	}
	return claim
}

func readYaml(values string) (map[interface{}]interface{}, error) {
	yfile, err := os.ReadFile(filepath.Clean(values))
	if err != nil {
		return nil, err
	}
	data := make(map[interface{}]interface{})
	err = yaml.Unmarshal(yfile, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
