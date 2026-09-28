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

### VolumeGroupSnapshot Support
This driver now supports VolumeGroupSnapshot functionality as defined in CSI specification 1.11. This feature allows creating crash-consistent snapshots of multiple volumes simultaneously.

#### Key Features
- **CreateVolumeGroupSnapshot**: Create snapshots of multiple volumes simultaneously
- **DeleteVolumeGroupSnapshot**: Delete a group snapshot and all member snapshots
- **GetVolumeGroupSnapshot**: Retrieve information about a group snapshot
- **Write-Order Consistency**: All snapshots in the group are taken at the same point-in-time
- **CSI Spec 1.11 Compliance**: Full compliance with CSI specification requirements

### Metrics Instrumentation

The CSI Driver for PowerStore includes comprehensive Prometheus metrics collection for monitoring driver health, array capacity, volume metrics, NFS metrics, replication sessions, and performance metrics.

#### Enabling Metrics

Metrics collection can be enabled by setting the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `X_CSI_METRICS_ENABLED` | Enable metrics collection and HTTP server | `false` |
| `X_CSI_METRICS_PORT` | Port for metrics HTTP server | `8443` |
| `X_CSI_METRICS_TLS_CERT_FILE` | Path to TLS certificate file | |
| `X_CSI_METRICS_TLS_KEY_FILE` | Path to TLS key file | |
| `X_CSI_METRICS_POLL_INTERVAL` | Metrics collection interval | `1m` |
| `X_CSI_METRICS_LEADER_ELECTION_ENABLED` | Enable leader election for controller array metrics collection | `false` |
| `X_CSI_METRICS_LEADER_ELECTION_LEASE_DURATION` | Leader election lease duration | `60s` |
| `X_CSI_METRICS_LEADER_ELECTION_RENEW_DEADLINE` | Leader election renew deadline | `40s` |
| `X_CSI_METRICS_LEADER_ELECTION_RETRY_PERIOD` | Leader election retry period | `5s` |

#### Metrics Categories

The driver exposes the following metrics categories:

- **Driver Health Metrics**: Operation counts, errors, and latency for CSI operations
- **Array Health Metrics**: PowerStore array health status and management endpoint information
- **Appliance Metrics**: Per-appliance capacity, health, and physical storage metrics
- **Volume Metrics**: Volume count by protocol, size, attachment status, health, and NVMe transport metrics
- **NFS Metrics**: NFS server health, export counts, and share counts
- **Replication Metrics**: Replication session state, RPO, remote system reachability, and data connection state
- **Performance Metrics**: Cluster and appliance-level IOPS, bandwidth, latency, and FE port metrics

**Note**: Node-level performance metrics and drive wear metrics are not implemented due to gopowerstore library limitations. The library provides performance metrics methods that require node/drive IDs as input, but does not provide node/drive enumeration methods.

#### Accessing Metrics

Once enabled, metrics are available at `http://<driver-pod-ip>:<metrics-port>/metrics`. These can be scraped by Prometheus or compatible monitoring systems.

For detailed documentation on available metrics and their labels, please refer to the [AGENTS.md](AGENTS.md#metrics-instrumentation) file.
