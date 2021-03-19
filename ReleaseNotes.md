# Release Notes - CSI PowerStore v1.3.0

## New Features/Changes
- Added support for Kubernetes v1.20
- Added support for OpenShift 4.7 with RHEL and CoreOS worker nodes
- Added support for Red Hat Enterprise Linux (RHEL) 8.3
- Added support for managing multiple PowerStore arrays from one driver
- Added support for configuring custom IPs/sub-networks for NFS exports
- Added support for automatic generation of CHAP credentials
- Changed code structure of the project
- Removed storage classes from helm template 

## Fixed Issues
There are no fixed issues in this release.

## Known Issues

| Issue | Workaround |
|-------|------------|
| Slow volume attached/detach | If your Kubernetes 1.17 or 1.18 cluster has a lot of VolumeAttachment objects, the attach/detach operations will be very slow. This is a known issue and affects all CSI plugins. It is tracked here: CSI VolumeAttachment slows pod startup time. To get around this problem you can upgrade to latest Kubernetes/OpenShift patches, which contains a partial fix: 1.17.8+, 1.18.5+|
| Topology related node labels are not removed automatically.  | Currently, when the driver is uninstalled, topology related node labels are not getting removed automatically. There is an open issue in the Kubernetes to fix this. Until the fix is released you need to manually remove the node labels |
