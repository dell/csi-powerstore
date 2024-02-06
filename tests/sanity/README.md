## Sanity Tests For CSI PowerStore

Testing done by standard test suite from [Sanity Test Command Line Program](https://github.com/kubernetes-csi/csi-test/tree/master/cmd/csi-sanity) 

### Building Image 

To run these tests you need to build an image by yourself and upload it to any available repository.

### Running

#### Prerequisites
Copy the `values.yaml` from `sanity-csi-powerstore` folder to folder with `install-sanity.sh` script and rename it to myvalues.
In `myvalues.yaml` ,`/helm/secret.yaml`, `params.yaml` point to your PowerStore array.
Install to kubernetes cluster by running install-sanity.sh. 
> It will install bare version of driver without any sidecar containers

To run the tests run the `install-sanity.sh` script with full path to your csi-sanity image as first argument

Example: 
```
./install-sanity.sh csi-sanity:latest
```

Wait until testing is finished
