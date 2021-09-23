### Examples for storage classes

For the driver to work you need storage classes created in the Kubernetes cluster. 
You can take the ones located here as example and modify them as you see fit. 

You can change following parameters: 

- *arrayIP*: specifies what array driver should use to provision volumes, 
if not specified driver will use array specified as `default` in `helm/config.yaml`
- *FsType*: specifies what filesystem type driver should use, possible variants `ext4`, `xfs`, `nfs`,
if not specified driver will use `ext4` by default

If you want you can also add topology constraints by adding `allowedTopologies` parameter
```yaml
allowedTopologies:
  - matchLabelExpressions: 
      - key: csi-powerstore.dellemc.com/12.34.56.78-iscsi
# replace "-iscsi" with "-fc" or "-nfs" at the end to use FC or NFS enabled hosts
# replace "12.34.56.78" with PowerStore endpoint IP
        values:
          - "true"
```
