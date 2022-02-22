# CSI Driver for Dell EMC PowerStore

[![Go Report Card](https://goreportcard.com/badge/github.com/dell/csi-powerstore?style=flat-square)](https://goreportcard.com/report/github.com/dell/csi-powerstore)
[![License](https://img.shields.io/github/license/dell/csi-powerstore?style=flat-square&color=blue&label=License)](https://github.com/dell/csi-powerstore/blob/master/LICENSE)
[![Docker](https://img.shields.io/docker/pulls/dellemc/csi-powerstore.svg?logo=docker&style=flat-square&label=Pulls)](https://hub.docker.com/r/dellemc/csi-powerstore)
[![Last Release](https://img.shields.io/github/v/release/dell/csi-powerstore?label=Latest&style=flat-square&logo=go)](https://github.com/dell/csi-powerstore/releases)

**Repository for CSI Driver for Dell EMC PowerStore**

## Description
CSI Driver for PowerStore is part of the [CSM (Container Storage Modules)](https://github.com/dell/csm) open-source suite of Kubernetes storage enablers for Dell EMC products. CSI Driver for PowerStore is a Container Storage Interface (CSI) driver that provides support for provisioning persistent storage using Dell EMC PowerStore storage array. 

It supports CSI specification version 1.3.

This project may be compiled as a stand-alone binary using Golang that, when run, provides a valid CSI endpoint. It also can be used as a precompiled container image.

## Support
For any CSI driver issues, questions or feedback, please follow our [support process](https://github.com/dell/csm/blob/main/docs/SUPPORT.md)

## Building
This project is a Go module (see golang.org Module information for explanation).
The dependencies for this project are listed in the go.mod file.

To build the source, execute `make clean build`.

To run unit tests, execute `make test`.

To build an image, execute `make docker`.

## Runtime Dependencies

Both the Controller and the Node portions of the driver can only be run on nodes with network connectivity to a Dell EMC PowerStore server (which is used by the driver). 

If you want to use iSCSI as a transport protocol be sure that `iscsi-initiator-utils` package is installed on your node. 

If you want to use FC be sure that zoning of Host Bus Adapters to the FC port directors was done. 

If you want to use NFS be sure to enable it in `myvalues.yaml` or in your storage classes, and configure corresponding NAS servers on PowerStore.

## Driver Installation
Please consult the [Installation Guide](https://dell.github.io/csm-docs/docs/csidriver/installation)

## Using Driver
Please refer to the section `Testing Drivers` in the [Documentation](https://dell.github.io/csm-docs/docs/csidriver/installation/test/) for more info.

## Documentation
For more detailed information on the driver, please refer to [Container Storage Modules documentation](https://dell.github.io/csm-docs/).
