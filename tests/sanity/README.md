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
- [Optional] driver-config-params.yaml, this file controls how the binary's logger is configured

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
