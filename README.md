# :lock: **Important Notice**
Starting with Container Storage Modules `v1.16.0`, this repository will transition to a closed-source model.<br>
* The current version remains open source and will continue to be available under the existing license.
* Customers will continue to receive access to enhanced features, timely updates, and official support through our commercial offerings.
* We remain committed to the open-source community - users engaging through Dell community channels will continue to receive guidance and support via Dell Support.

We sincerely appreciate the support and contributions from the community over the years.<br>
For access requests or inquiries, please contact the maintainers directly at [Dell Support](https://www.dell.com/support/kbdoc/en-in/000188046/container-storage-interface-csi-drivers-and-container-storage-modules-csm-how-to-get-support).

# :lock: **Important Notice**
Starting with Container Storage Modules `v1.16.0`, this repository will transition to a closed-source model.<br>
* The current version remains open source and will continue to be available under the existing license.
* Customers will continue to receive access to enhanced features, timely updates, and official support through our commercial offerings.
* We remain committed to the open-source community - users engaging through Dell community channels will continue to receive guidance and support via Dell Support.

We sincerely appreciate the support and contributions from the community over the years.<br>
For access requests or inquiries, please contact the maintainers directly at [Dell Support](https://www.dell.com/support/kbdoc/en-in/000188046/container-storage-interface-csi-drivers-and-container-storage-modules-csm-how-to-get-support)

# CSI Driver for Dell PowerStore

[![Go Report Card](https://goreportcard.com/badge/github.com/dell/csi-powerstore?style=flat-square)](https://goreportcard.com/report/github.com/dell/csi-powerstore)
[![License](https://img.shields.io/github/license/dell/csi-powerstore?style=flat-square&color=blue&label=License)](https://github.com/dell/csi-powerstore/blob/master/LICENSE)
[![Docker](https://img.shields.io/docker/pulls/dellemc/csi-powerstore.svg?logo=docker&style=flat-square&label=Pulls)](https://hub.docker.com/r/dellemc/csi-powerstore)
[![Last Release](https://img.shields.io/github/v/release/dell/csi-powerstore?label=Latest&style=flat-square&logo=go)](https://github.com/dell/csi-powerstore/releases)

**Repository for CSI Driver for Dell PowerStore**

## Description
CSI Driver for PowerStore is part of the [CSM (Container Storage Modules)](https://github.com/dell/csm) open-source suite of Kubernetes storage enablers for Dell products. CSI Driver for PowerStore is a Container Storage Interface (CSI) driver that provides support for provisioning persistent storage using Dell PowerStore storage array. 

This project may be compiled as a stand-alone binary using Golang that, when run, provides a valid CSI endpoint. It also can be used as a precompiled container image.

## Table of Contents

* [Code of Conduct](https://github.com/dell/csm/blob/main/docs/CODE_OF_CONDUCT.md)
* [Maintainer Guide](https://github.com/dell/csm/blob/main/docs/MAINTAINER_GUIDE.md)
* [Committer Guide](https://github.com/dell/csm/blob/main/docs/COMMITTER_GUIDE.md)
* [Contributing Guide](https://github.com/dell/csm/blob/main/docs/CONTRIBUTING.md)
* [List of Adopters](https://github.com/dell/csm/blob/main/docs/ADOPTERS.md)
* [Support](#support)
* [Security](https://github.com/dell/csm/blob/main/docs/SECURITY.md)
* [Building](#building)
* [Runtime Dependecies](#runtime-dependencies)
* [Documentation](#documentation)

## Support
For any issues, questions or feedback, please contact [Dell support](https://www.dell.com/support/incidents-online/en-us/contactus/product/container-storage-modules).

## Building
This project is a Go module (see golang.org Module information for explanation).
The dependencies for this project are listed in the go.mod file.

To build the source, execute `make clean build`.

To run unit tests, execute `make test`.

To build an image, execute `make docker`.

## Runtime Dependencies

Both the Controller and the Node portions of the driver can only be run on nodes with network connectivity to a Dell PowerStore server (which is used by the driver). 

If you want to use iSCSI as a transport protocol be sure that `iscsi-initiator-utils` package is installed on your node. 

If you want to use FC be sure that zoning of Host Bus Adapters to the FC port directors was done. 

If you want to use NFS be sure to enable it in `myvalues.yaml` or in your storage classes, and configure corresponding NAS servers on PowerStore.

If you want to use NVMe/TCP be sure that the `nvme-cli` package is installed on your node.

If you want to use NVMe/FC be sure that the NVMeFC zoning of the Host Bus Adapters to the Fibre Channel port is done.

## Documentation
For more detailed information on the driver, please refer to [Container Storage Modules documentation](https://dell.github.io/csm-docs/).
