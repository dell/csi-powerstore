# VolumeAttributesClass Samples for Modify Volume

These samples demonstrate how to use `VolumeAttributesClass` to modify the mutable parameters of an existing volume dynamically in Kubernetes.

## Valid Mutable Parameters

The CSI PowerStore driver supports the following mutable parameters depending on the volume type:

### Block Volumes
- `Description`
- `PerformancePolicyID`
- `ProtectionPolicyID`
- `AppType`
- `AppTypeOther`

### NFS (File System) Volumes
- `Description`
- `ProtectionPolicyID`
- `PerformancePolicyID`

**Important:** Attempting to update unsupported parameters for a volume type (e.g., passing `AppType` to an NFS volume) will result in an invalid argument error.

## Specifying Policies by Name

For both `PerformancePolicyID` and `ProtectionPolicyID`, you can specify the value in two ways:
1. **By exact ID:** Provide the raw ID string (e.g., `PerformancePolicyID: "12345678-abcd-1234-abcd-123456789abc"`).
2. **By Policy Name:** Prefix the value with `name:` to have the driver dynamically resolve the name to its corresponding ID (e.g., `PerformancePolicyID: "name:my-performance-policy"`).

## Usage
1. Apply the `VolumeAttributesClass` YAML.
2. Update your `PersistentVolumeClaim` (PVC) spec to reference the applied `VolumeAttributesClass` in the `volumeAttributesClassName` field.
