# CSI PowerStore E2E Tests


## Prerequisites
* A working Kubernetes cluster with csi-powerstore driver installed.
* A PowerStore storage system.

## Test Setup
* Set the KUBECONFIG environment variable using `export KUBECONFIG=/path/to/.kube/config`, replacing the path with the path to your kubeconfig.
If $KUBECONFIG is unset, the test suite will attempt to locate the config under `$HOME/.kube/config`.
* Update `./e2e-values.yaml` with the necessary test values.

## Running tests
Execute the run script to run the tests.
```
./run.sh
```

## Updating Modules
The several modules imported from k8s.io appear to intentionally leave module versions set to v0.0.0. Without overwriting this version and specifying the module version, this test package will be unable to build its go.mod file. To fix this and specify the desired version, you must give the version using the 'replace' keyword in the go.mod file.

When updating modules for this test package, make sure to update the list of replaced versions at the bottom of the go.mod file.