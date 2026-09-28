# Sanity Tests For CSI PowerStore

Testing done by standard test suite from [Sanity Test Command Line Program](https://github.com/kubernetes-csi/csi-test/tree/master/cmd/csi-sanity)

## Prerequisites

To run these tests you need to:

1. Build and install the csi-sanity binary:

```sh
git clone https://github.com/kubernetes-csi/csi-test.git
cd csi-test
make build-sanity
cp cmd/csi-sanity/csi-sanity /usr/local/bin/
```

2. Build the driver binary:

```sh
cd csi-powerstore/
make build
```

3. Fill in the following files in tests/sanity/; anything with a "REPLACE" prefix needs to be replaced with a real value:

- config.yaml, this file will be used by the binary built in step 2 (from now on, referred to as "the binary" for short) to connect to array
- setup-driver-controller-sanity.sh, this file is used to start the driver's controller service from the binary
- setup-driver-node-sanity.sh, this file is used to start the driver's node service from the binary
- params.yaml, this file is used by the sanity test to pass in parameters that would be defined in the storageclass
- mutable-params.yaml, this file contains parameters that will be updated in Modify Volume requests
- [Optional] driver-config-params.yaml, this file controls how the binary's logger is configured

4. Install Disaster Recovery (DR) CRD from operatorconfig/moduleconfig/common/disaster-recovery/dr-crds.yaml in csm-operator repository.
```sh
kubectl apply -f dr-crds.yaml
```

## Running

1. Run the shell script to setup the driver's node service

```sh
./setup-driver-node-sanity.sh
...
{"level":"info","msg":"node service registered","time":"2025-06-04T21:11:42.493415761+01:00"}
{"endpoint":"unix:///root/csi-powerstore/tests/sanity/node.sock","level":"info","msg":"serving","time":"2025-06-04T21:11:42.493449589+01:00"}
```

2. In a new terminal window, run the shell script to setup the driver's controller service

```sh
./setup-driver-controller-sanity.sh
...
{"level":"info","msg":"node service registered","time":"2025-06-04T21:11:42.493415761+01:00"}
{"endpoint":"unix:///root/csi-powerstore/tests/sanity/node.sock","level":"info","msg":"serving","time":"2025-06-04T21:11:42.493449589+01:00"}
```

3. In (another) new terminal window, run the shell script to run the sanity test

```sh
./run-csi-sanity.sh
```

Tests should pass in 10-12 minutes

```sh
Ran 68 of 92 Specs in 706.781 seconds
SUCCESS! -- 68 Passed | 0 Failed | 1 Pending | 23 Skipped
```

## Running Modify Volume Tests

To specifically test the volume modification capability (`ControllerModifyVolume` RPC), you need to provide the mutable parameters and use Ginkgo to focus on those tests.

1. Create a `mutable-params.yaml` file in the `tests/sanity/` directory with the desired mutable attributes. For example:
```yaml
# This file contains mutable parameters for CSI volume modification tests
# These parameters will be used to test the ControllerModifyVolume RPC
# You can update the parameters as needed

Description: "sanity test description"
PerformancePolicyID: "valid-performance-policy-id"
```

2. Run the `csi-sanity` command, passing the `--csi.testvolumemutableparameters` flag along with `--ginkgo.focus="ModifyVolume"` to isolate those specific test cases:

```sh
csi-sanity \
  --csi.controllerendpoint=controller.sock \
  --csi.endpoint=node.sock \
  --csi.testvolumeparameters=params.yaml \
  --csi.testvolumemutableparameters=mutable-params.yaml \
  --ginkgo.focus="ModifyVolume" \
  --ginkgo.v
```

Alternatively, you can add `--ginkgo.focus="ModifyVolume"` and `--csi.testvolumemutableparameters=mutable-params.yaml` to your existing `run-csi-sanity.sh` script (which already includes `--csi.testvolumeparameters=params.yaml`) and execute it.
