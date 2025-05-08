/*
 *
 * Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

/*
  Multi-NAS Storage Test Workflow:
  1. Create a StorageClass with multiple NAS servers.
  2. Identify the least-utilized NAS server using GetLeastUsedActiveNAS.
  3. Create a PVC associated with the StorageClass.
  4. Validate that the PVC is assigned to the least-used NAS by checking its annotations.
*/
/*
 var _ = Describe("Multiple NAS Test", func() {
	 var (
		 namespace string
		 client    clientset.Interface
		 f         = framework.NewDefaultFramework("multi-nas")
	 )

	 framework.TestContext.VerifyServiceAccount = false

	 BeforeEach(func() {
		 namespace = getNamespaceToRunTests(f)
		 client = f.ClientSet
		 bootstrap()
	 })

	 AfterEach(func() {
		 ctx, cancel := context.WithCancel(context.Background())
		 defer cancel()
		 cleanupResources(ctx, client, namespace)
	 })

	 It("should provision PVC using the least utilized NAS", func() {
		 ctx, cancel := context.WithCancel(context.Background())
		 defer cancel()

		 scName, pvcName := generateUniqueNames()

		 nasServers := getNASServers()
		 arrayID := getArrayID()
		 extCredential := getExternalAccessCredential(testParameters["externalAccess"])
		 clientForArray := initializePowerStoreClient(extCredential)

		 leastUsedNAS, err := common.GetLeastUsedActiveNAS(ctx, *clientForArray, nasServers)
		 Expect(err).NotTo(HaveOccurred())

		 By("Creating StorageClass")
		 storageClass := createNASStorageClass(scName, arrayID, nasServers)
		 _, err = client.StorageV1().StorageClasses().Create(ctx, storageClass, metav1.CreateOptions{})
		 Expect(err).NotTo(HaveOccurred())
		 DeferCleanup(func() { client.StorageV1().StorageClasses().Delete(ctx, scName, metav1.DeleteOptions{}) })

		 By("Creating PVC")
		 pvc := createPersistentVolumeClaim(pvcName, namespace, scName)
		 _, err = client.CoreV1().PersistentVolumeClaims(namespace).Create(ctx, pvc, metav1.CreateOptions{})
		 Expect(err).NotTo(HaveOccurred())
		 DeferCleanup(func() { client.CoreV1().PersistentVolumeClaims(namespace).Delete(ctx, pvcName, metav1.DeleteOptions{}) })

		 By("Waiting for PVC to be bound")
		 waitForPVCBound(ctx, client, namespace, pvcName)

		 By("Verifying NAS Server Assignment")
		 verifyNASAssignment(client, ctx, namespace, pvcName, leastUsedNAS)
	 })
 })

 func cleanupResources(ctx context.Context, client clientset.Interface, namespace string) {
	 By(fmt.Sprintf("Deleting all resources in namespace: %v", namespace))

	 err := client.CoreV1().Pods(namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
	 Expect(err).NotTo(HaveOccurred())

	 err = client.CoreV1().PersistentVolumeClaims(namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
	 Expect(err).NotTo(HaveOccurred())

	 err = client.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	 Expect(err).NotTo(HaveOccurred())
 }

 func generateUniqueNames() (string, string) {
	 curtime := strconv.FormatInt(time.Now().Unix(), 10)
	 nBig, err := rand.Int(rand.Reader, big.NewInt(27))
	 Expect(err).NotTo(HaveOccurred())
	 return "multi-nas-sc-" + curtime + strconv.FormatInt(nBig.Int64(), 10), "multi-nas-pvc-" + curtime + strconv.FormatInt(nBig.Int64(), 10)
 }

 func getNASServers() []string {
	 nasServers, ok := testParameters["mutiNASServers"].([]interface{})
	 Expect(ok).To(BeTrue())

	 var strSlice []string
	 for _, v := range nasServers {
		 strSlice = append(strSlice, v.(string))
	 }
	 return strSlice
 }

 func getArrayID() string {
	 arrayID, ok := testParameters["arrayID"].(string)
	 Expect(ok).To(BeTrue())
	 return arrayID
 }

 func initializePowerStoreClient(extCredential ExternaAccess) *gopowerstore.Client {
	 clientOptions := gopowerstore.NewClientOptions()
	 clientOptions.SetInsecure(true)
	 clientForArray, err := gopowerstore.NewClientWithArgs(extCredential.EndPoint, extCredential.UserName, extCredential.Password, clientOptions)
	 Expect(err).NotTo(HaveOccurred())
	 return &clientForArray
 }

 func createNASStorageClass(name, arrayID string, nasServers []string) *storagev1.StorageClass {
	 return &storagev1.StorageClass{
		 ObjectMeta:  metav1.ObjectMeta{Name: name},
		 Provisioner: "csi-powerstore.dellemc.com",
		 Parameters: map[string]string{
			 "arrayID":                   arrayID,
			 "csi.storage.k8s.io/fstype": "nfs",
			 "nasName":                   strings.Join(nasServers, ","),
			 "allowRoot":                 "true",
		 },
		 VolumeBindingMode: func() *storagev1.VolumeBindingMode {
			 mode := storagev1.VolumeBindingImmediate
			 return &mode
		 }(),
	 }
 }

 func createPersistentVolumeClaim(name, namespace, scName string) *v1.PersistentVolumeClaim {
	 return &v1.PersistentVolumeClaim{
		 ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		 Spec: v1.PersistentVolumeClaimSpec{
			 AccessModes: []v1.PersistentVolumeAccessMode{v1.ReadWriteMany},
			 Resources: v1.VolumeResourceRequirements{
				 Requests: v1.ResourceList{v1.ResourceStorage: resource.MustParse("8Gi")},
			 },
			 StorageClassName: &scName,
		 },
	 }
 }

 func waitForPVCBound(ctx context.Context, client clientset.Interface, namespace, pvcName string) {
	 Eventually(func() v1.PersistentVolumeClaimPhase {
		 pvc, err := client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, pvcName, metav1.GetOptions{})
		 if err != nil {
			 return ""
		 }
		 return pvc.Status.Phase
	 }, 2*time.Minute, 10*time.Second).Should(Equal(v1.ClaimBound))
 }

 func verifyNASAssignment(client clientset.Interface, ctx context.Context, namespace, pvcName, expectedNAS string) {
	 // Get the PVC
	 pvc, err := client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, pvcName, metav1.GetOptions{})
	 Expect(err).NotTo(HaveOccurred())
	 pvName := pvc.Spec.VolumeName

	 // Get the corresponding PV
	 pv, err := client.CoreV1().PersistentVolumes().Get(ctx, pvName, metav1.GetOptions{})
	 Expect(err).NotTo(HaveOccurred())
	 usedNAS := pv.Spec.CSI.VolumeAttributes["nasName"]

	 Expect(usedNAS).To(Equal(expectedNAS), "Expected NAS server %s but got %s", expectedNAS, usedNAS)
 }
*/
