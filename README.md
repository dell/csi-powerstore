# CSI Driver for Dell EMC PowerStore
**Repository for CSI Driver for Dell EMC PowerStore development project**

## Description
CSI Driver for Dell EMC PowerStore is a Container Storage Interface ([CSI](https://github.com/container-storage-interface/spec)) driver that provides support for provisioning persistent storage using Dell EMC PowerStore.

It supports CSI specification version 1.1.

## Building

This project is a Go module (see golang.org Module information for explanation).
The dependencies for this project are listed in the go.mod file.

To build the source, execute `make clean build`.

To run unit tests, execute `make test`.

To build a docker image, execute `make docker`.

## Runtime Dependencies
Both the Controller and the Node portions of the driver can only be run on nodes with network connectivity to a Dell EMC PowerStore server (which is used by the driver). 

The Node portion of the driver can only be run on nodes that have the iscsi-initiator-utils package installed. 

You can verify said runtime dependencies by running the `verify.sh` script located inside of the helm directory.

## Installation

- Clone the repository
```git clone https://github.com/dell/csi-powerstore```

_Notice: After release driver will be available at_ ```github.com/dell/csi-powestore```


- Enter helm folder and copy values file
```
# copying values.yaml
cd csi-powerstore/helm
cp csi-powerstore/values.yaml ./myvalues.yaml
```
- Edit myvalues.yaml using your favorite text editor and change the following parameters:

| Parameter        | Description           |
| ------------- |:-------------:|
| powerStoreApi     | This value defines full URL path to PowerStore API |
| powerStoreApiUser      | Username to login to PowerStore API       |
| powerStoreApiPassword | Password to login to PowerStore API |


- (Optional) Customize additional parameters in myvalues.yaml if required.

- Run the “install.sh” shell script, it will check your cluster with verify.sh script and install driver using helm
```
# running install.sh
chmod +x install.sh verify.sh uninstall.sh upgrade.sh
./install.sh
```



## Using driver

A number of test helm charts and scripts are found in the directory test/helm.
Product Guide provides descriptions of how to run these and explains how they work.

If you want to interact with the driver directly, you can use the Container Storage Client (`csc`) program provided via the [GoCSI](https://github.com/rexray/gocsi) project:

```bash
$ go get github.com/rexray/gocsi
$ go install github.com/rexray/gocsi/csc
```
(This is only recommended for developers.)

Then, have `csc` use the same `CSI_ENDPOINT`, and you can issue commands to the driver. Some examples...

Get the driver's supported versions and driver info:

```bash
$ ./csc -v 0.1.0 -e csi.sock identity plugin-info
...
"url"="https://github.com/dell/csi-powerstore"
```

## Capable operational modes
The CSI spec defines a set of AccessModes that a volume can have. The CSI Driver for Dell EMC PowerStore supports the following modes for volumes that will be mounted as a filesystem:

```go
// Can only be published once as read/write on a single node,
// at any given time.
SINGLE_NODE_WRITER = 1;

// Can only be published once as readonly on a single node,
// at any given time.
SINGLE_NODE_READER_ONLY = 2;

// Can be published as readonly at multiple nodes simultaneously.
MULTI_NODE_READER_ONLY = 3;
```

This means that volumes can be mounted to either single node at a time, with read-write or read-only permission, or can be mounted on multiple nodes, but all must be read-only.

For volumes that are used as block devices, only the following are supported:

```go
// Can only be published as read/write on a single node, at
// any given time.
SINGLE_NODE_WRITER = 1;

// Can be published as read/write at multiple nodes
// simultaneously.
MULTI_NODE_MULTI_WRITER = 5;
```

This means that giving a workload read-only access to a block device is not supported.

In general, volumes should be formatted with xfs or ext4.

## Support
The CSI Driver for Dell EMC PowerStore image available on Dockerhub is officially supported by Dell EMC.
 
The source code available on Github is unsupported and provided solely under the terms of the license attached to the source code. For clarity, Dell EMC does not provide support for any source code modifications.
 
For any CSI driver setup, configuration issues, questions or feedback, join the Dell EMC Container community at https://www.dell.com/community/Containers/bd-p/Containers
 
For any Dell EMC storage issues, please contact Dell support at: https://www.dell.com/support.

