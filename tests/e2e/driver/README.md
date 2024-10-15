# PowerStore Metro End-to-End Testing

This suite of tests deploys a CSI-PowerStore metro storage class and associated workloads to dynamically provision PowerStore metro replicated volumes.
After successfully deploying the workloads and provisioning the storage, the test will confirm:

- The metro volume is mounted with multiple device mount paths on the Kubernetes worker node for the provisioned csi persistent volume (PV).
- Multiple host paths exist between the Kubernetes worker node and the PowerStore array for each side of the metro volume.
- All host paths are in 'active ready' state.
- The persistent volume is writable.
- The persistent volume continues to be writable after taking down all host paths for one of the two PowerStore arrays in the metro replication session.

## Prerequisites

- A Kubernetes or OpenShift cluster.
- Two PowerStore arrays.
- CSI-PowerStore installed and Kubernetes secrets configured for both PowerStore arrays.
- Multipath configured on the Kubernetes nodes with at least 2 paths for each of the PowerStore array.

## Test Setup

-  Configure the test storage class at `./resources/sc.yaml`, providing the source PowerStore array's Global ID to `parameters.arrayID:` and the 
remote PowerStore array system name to `parameters.replication.storage.dell.com/remoteSystem:`.
- __*Optional Recommended:*__ Setup ssh keys between the machine where this test is executed and the Kubernetes nodes where workload resources are deployed
(typically worker nodes).
> __*Note:*__ If ssh keys are not configured, the user may be prompted to authenticate via password at runtime.

## Test Execution

Execute the shell script `./metro-e2e.sh`. Provide the username for the machine where the Kubernetes workloads will be deployed using the `-u` option.
Provide the path to any ssh keys required to authenticate with the Kubernetes worker nodes using the `-k` option.

```bash
./metro-e2e.sh -u root -k $HOME/.ssh/id_rsa
```

## Test Reports

Test results are written to a csv file, `./reports/test_results.csv`, and a python script is executed to use the csv file to generate a JUnit report.
The JUnit report will automatically be generated at the end of the test run at `./metro-e2e-report.xml`.