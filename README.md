# CSI PowerStore

[![Go Report Card](https://goreportcard.com/badge/github.com/dell/csi-powerstore)](https://goreportcard.com/report/github.com/dell/csi-powerstore)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/dell/csi-powerstore/blob/master/LICENSE)
[![Docker](https://img.shields.io/docker/pulls/dellemc/csi-powerstore.svg?logo=docker)](https://hub.docker.com/r/dellemc/csi-powerstore)
[![Last Release](https://img.shields.io/github/v/release/dell/csi-powerstore?label=latest&style=flat-square)](https://github.com/dell/csi-powerstore/releases)

This repository contains [Container Storage Interface (CSI)](https://github.com/container-storage-interface/) driver for Dell EMC PowerStore 

## Overview
CSI PowerStore is a [Container Storage Interface (CSI)](https://github.com/container-storage-interface/) driver that provides support for provisioning persistent storage using Dell EMC PowerStore.

It supports CSI specification version 1.1.

This project may be compiled as a stand-alone binary using Golang that, when run, provides a valid CSI endpoint. This project can also be built as a Golang plug-in in order to extend the functionality of other programs.

For Documentation, please go to [Dell CSI Driver Documentation](https://dell.github.io/storage-plugin-docs).

## Support

The CSI Driver for Dell EMC PowerStore image, which is the built driver code, is available on DockerHub and is officially supported by Dell EMC.

The source code for CSI Driver for Dell EMC PowerStore available on GitHub is unsupported and provided solely under the terms of the license attached to the source code. For clarity, Dell EMC does not provide support for any source code modifications.

For any CSI driver issues, questions or feedback, join the [Dell EMC Container community](https://www.dell.com/community/Containers/bd-p/Containers).

## Building

This project is a Go module (see golang.org Module information for explanation).
The dependencies for this project are listed in the go.mod file.

To build the source, execute `make clean build`.

To run unit tests, execute `make test`.

To build a docker image, execute `make docker`.

## Runtime Dependencies

Both the Controller and the Node portions of the driver can only be run on nodes with network connectivity to a Dell EMC PowerStore server (which is used by the driver). 

If you want to use iSCSI as a transport protocol be sure that `iscsi-initiator-utils` package is installed on your node. 

If you want to use FC be sure that zoning of Host Bus Adapters to the FC port directors was done. 

If you want to use NFS be sure to enable it in `myvalues.yaml` and configure NAS server on PowerStore

## Installation
This is brief description of installation procedure, for more detailed installation instructions go to [Helm Installation](https://dell.github.io/storage-plugin-docs/docs/installation/helm/powerstore/) page of documentation. 

Installation in a Kubernetes cluster should be done using the scripts within the `dell-csi-helm-installer` directory. 

#### Prerequisites
- Upstream Kubernetes versions 1.17, 1.18, 1.19 or 1.20 or OpenShift versions 4.5, 4.6
- You can access your cluster with `kubectl` and `helm`

#### Procedure
1. Run `git clone https://github.com/dell/csi-powerstore.git` to clone the git repository
2. Ensure that you've created namespace where you want to install the driver. You can run `kubectl create namespace csi-powerstore` to create a new one. 
3. Edit the `helm/secret.yaml`, point to correct namespace and replace the values for the username and password parameters.
    These values can be obtained using base64 encoding as described in the following example:
    ```
    echo -n "myusername" | base64
    echo -n "mypassword" | base64
    ```
   where *myusername* & *mypassword* are credentials that would be used for accessing PowerStore API
4. Create the secret by running `kubectl create -f helm/secret.yaml` 
5. Copy the default values.yaml file `cd dell-csi-helm-installer && cp ../helm/csi-powerstore/values.yaml ./my-powerstore-settings.yaml`
6. Edit the newly created file and provide values for the following parameters:
    - *powerStoreApi*: defines the full URL path to the PowerStore API
    - *volumeNamePrefix*: defines the string added to each volume that the CSI driver creates
    - *nodeNamePrefix*: defines the string added to each node that the CSI driver registers
    - *nodeIDPath*: defines a path to file with a unique identifier identifying the node in the Kubernetes cluster
    - *connection.transportProtocol*: defines which transport protocol to use (FC, ISCSI, None, or auto).
    - *connection.nfs.enable*: enables or disables NFS support
    - *connection.nfs.nasServerName*: points to the NAS server that would be used
7. Install the driver using `csi-install.sh` bash script by running `./csi-install.sh --namespace csi-powerstore --values ./my-powerstore-settings.yaml` 


## Using driver
To check if the driver is functioning correctly you can run simple tests from directory `test/simple`
[Test PowerStore Driver](https://dell.github.io/storage-plugin-docs/docs/installation/test/powerstore) page of documentation provides descriptions of how to run these and explains how they work.

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
```

This means that volumes can be mounted to either single node at a time, with read-write or read-only permission, or can be mounted on multiple nodes, but all must be read-only.

For volumes that are used as raw block devices or NFS volumes, the following are supported:

```go
// Can only be published as read/write on a single node, at
// any given time.
SINGLE_NODE_WRITER = 1;

// Can be published as read/write at multiple nodes
// simultaneously.
MULTI_NODE_MULTI_WRITER = 5;
```

This means that giving a workload read-only access to a block device is not supported.

In general, block volumes should be formatted with xfs or ext4.

