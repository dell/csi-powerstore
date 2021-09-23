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

### Prerequisites
- Upstream Kubernetes versions 1.19, 1.20 or 1.21 or OpenShift versions 4.6 (EUS), 4.7
- You can access your cluster with `kubectl` and `helm`
- Optionally ensure that you have both [Volume Snapshot CRDs](https://github.com/kubernetes-csi/external-snapshotter/tree/v4.0.0/client/config/crd)
 and [common snapshot controller](https://github.com/kubernetes-csi/external-snapshotter/tree/v4.0.0/deploy/kubernetes/snapshot-controller) installed in your Kubernetes cluster and Snaphot feature is enabled in your copy of `values.yaml` if you want to use the feature.

### Procedure
1. Run `git clone https://github.com/dell/csi-powerstore.git` to clone the git repository
2. Ensure that you've created namespace where you want to install the driver. You can run `kubectl create namespace csi-powerstore` to create a new one. 
3. Edit `helm/secret.yaml`, correct namespace field to point to your desired namespace
4. Edit `helm/config.yaml` file and configure connection information for your PowerStore arrays changing following parameters:
    - *endpoint*: defines the full URL path to the PowerStore API.
    - *globalID*: specifies what storage cluster the driver should use
    - *username*, *password*: defines credentials for connecting to array.
    - *skipCertificateValidation*: defines if we should use insecure connection or not.
    - *isDefault*: defines if we should treat the current array as a default.
    - *blockProtocol*: defines what SCSI transport protocol we should use (FC, ISCSI, None, or auto).
    - *nasName*: defines what NAS should be used for NFS volumes.
 
    Add more blocks similar to above for each PowerStore array if necessary. 
5. Create storage classes using ones from `helm/samples/storageclass` folder as an example and apply them to the Kubernetes cluster by running `kubectl create -f <path_to_storageclass_file>`
    > If you don't specify `arrayID` parameter in the storage class then the array that was specified as the default would be used for provisioning volumes. `arrayID` corresponds to `globalID` of storage cluster.
6. Create the secret by running ```sed "s/CONFIG_YAML/`cat helm/config.yaml | base64 -w0`/g" helm/secret.yaml | kubectl apply -f -```
7. Copy the default values.yaml file `cd dell-csi-helm-installer && cp ../helm/csi-powerstore/values.yaml ./my-powerstore-settings.yaml`
8. Edit the newly created file and provide values for the following parameters:
    - *volumeNamePrefix*: defines the string added to each volume that the CSI driver creates
    - *nodeNamePrefix*: defines the string added to each node that the CSI driver registers
    - *nodeIDPath*: defines a path to file with a unique identifier identifying the node in the Kubernetes cluster
    - *externalAccess*: defines additional entries for hostAccess of NFS volumes, single IP address and subnet are valid entries.
9. Install the driver using `csi-install.sh` bash script by running `./csi-install.sh --namespace csi-powerstore --values ./my-powerstore-settings.yaml` 

## Using Driver
Please refer to the section `Testing Drivers` in the [Documentation](https://dell.github.io/csm-docs/docs/csidriver/installation/test/) for more info.

## Documentation
For more detailed information on the driver, please refer to [Container Storage Modules documentation](https://dell.github.io/csm-docs/).
