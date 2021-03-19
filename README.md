# CSI Driver for Dell EMC PowerStore

[![Go Report Card](https://goreportcard.com/badge/github.com/dell/csi-powerstore?style=flat-square)](https://goreportcard.com/report/github.com/dell/csi-powerstore)
[![License](https://img.shields.io/github/license/dell/csi-powerstore?style=flat-square&color=blue&label=License)](https://github.com/dell/csi-powerstore/blob/master/LICENSE)
[![Docker](https://img.shields.io/docker/pulls/dellemc/csi-powerstore.svg?logo=docker&style=flat-square&label=Pulls)](https://hub.docker.com/r/dellemc/csi-powerstore)
[![Last Release](https://img.shields.io/github/v/release/dell/csi-powerstore?label=Latest&style=flat-square&logo=go)](https://github.com/dell/csi-powerstore/releases)

**Repository for CSI Driver for Dell EMC PowerStore**

## Description
CSI Driver for Dell EMC PowerStore is a Container Storage Interface [(CSI)](https://github.com/container-storage-interface/spec) driver that provides support for provisioning persistent storage using Dell EMC PowerStore storage array.

It supports CSI specification version 1.2.

This project may be compiled as a stand-alone binary using Golang that, when run, provides a valid CSI endpoint.
It also can be used as a precompiled container image.

For Documentation, please go to [Dell CSI Driver Documentation](https://dell.github.io/storage-plugin-docs).

## Support
The CSI Driver for Dell EMC PowerStore image, which is the built driver code, is available on DockerHub and is officially supported by Dell EMC.

The source code for CSI Driver for Dell EMC PowerStore available on GitHub is unsupported and provided solely under the terms of the license attached to the source code. 

For clarity, Dell EMC does not provide support for any source code modifications.

For any CSI driver issues, questions or feedback, join the [Dell EMC Container community](https://www.dell.com/community/Containers/bd-p/Containers).

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

If you want to use NFS be sure to enable it in `myvalues.yaml`, configure NAS server on PowerStore and have client-side NFS utilities (e.g. nfs-utils on RHEL/CentOS) installed on your nodes.

## Driver Installation
Please consult the [Installation Guide](https://dell.github.io/storage-plugin-docs/docs/installation/)

Below is a brief description of installation procedure using Helm. For more detailed installation instructions go to [Helm Installation](https://dell.github.io/storage-plugin-docs/docs/installation/helm/powerstore/) page of documentation. 

As referenced in the guide, installation in a Kubernetes cluster should be done using the scripts within the `dell-csi-helm-installer` directory. For more detailed information on the scripts, consult the [README.md](dell-csi-helm-installer/README.md)

### Prerequisites
- Upstream Kubernetes versions 1.18, 1.19 or 1.20 or OpenShift versions 4.6, 4.7
- You can access your cluster with `kubectl` and `helm`
- Ensure that you have both [Volume Snapshot CRDs](https://github.com/kubernetes-csi/external-snapshotter/tree/v4.0.0/client/config/crd)
 and [common snapshot controller](https://github.com/kubernetes-csi/external-snapshotter/tree/v4.0.0/deploy/kubernetes/snapshot-controller) installed in your Kubernetes cluster

### Procedure
1. Run `git clone https://github.com/dell/csi-powerstore.git` to clone the git repository
2. Ensure that you've created namespace where you want to install the driver. You can run `kubectl create namespace csi-powerstore` to create a new one. 
3. Edit `helm/secret.yaml`, correct namespace field to point to your desired namespace
4. Edit `helm/config.yaml` file and configure connection information for your PowerStore arrays changing following parameters:
    - *endpoint*: defines the full URL path to the PowerStore API
    - *username*, *password*: defines credentials for connecting to array
    - *insecure*: defines if we should use insecure connection or not
    - *default*: defines if we should treat the current array as a default
    - *block-protocol*: defines what SCSI transport protocol we should use (FC, ISCSI, None, or auto)
    - *nas-name*: defines what NAS should be used for NFS volumes
    
    Add more blocks similar to above for each PowerStore array if necessary. 
5. Create storage classes using ones from `helm/samples/storageclass` folder as an example and apply them to the Kubernetes cluster by running `kubectl create -f <path_to_storageclass_file>`
    > If you don't specify `arrayIP` parameter in the storage class then the array that was specified as the default would be used for provisioning volumes
6. Create the secret by running ```sed "s/CONFIG_YAML/`cat helm/config.yaml | base64 -w0`/g" helm/secret.yaml | kubectl apply -f -```
7. Copy the default values.yaml file `cd dell-csi-helm-installer && cp ../helm/csi-powerstore/values.yaml ./my-powerstore-settings.yaml`
8. Edit the newly created file and provide values for the following parameters:
    - *volumeNamePrefix*: defines the string added to each volume that the CSI driver creates
    - *nodeNamePrefix*: defines the string added to each node that the CSI driver registers
    - *nodeIDPath*: defines a path to file with a unique identifier identifying the node in the Kubernetes cluster
    - *externalAccess*: defines additional entries for hostAccess of NFS volumes, single IP address and subnet are valid entries.
9. Install the driver using `csi-install.sh` bash script by running `./csi-install.sh --namespace csi-powerstore --values ./my-powerstore-settings.yaml` 

## Using Driver
Please refer to the section `Testing Drivers` in the [Documentation](https://dell.github.io/storage-plugin-docs/docs/installation/test/) for more info.

## Documentation
For more detailed information on the driver, please refer to [Dell Storage Documentation](https://dell.github.io/storage-plugin-docs/docs/) 

For a detailed set of information on supported platforms and driver capabilities, please refer to the [Features and Capabilities Documentation](https://dell.github.io/storage-plugin-docs/docs/dell-csi-driver/) 
