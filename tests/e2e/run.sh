#!/bin/bash
LOGFILE="log.output"

createNameSpace(){
    echo "Going to create namespace "| tee -a ${LOGFILE}
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        echo "Please provide namespace as an argument"| tee -a ${LOGFILE}
        exit 2;
    fi
    NAMESPACE=$1

    echo kubectl create namespace $NAMESPACE| tee -a ${LOGFILE}
    kubectl create namespace $NAMESPACE
}

getPVName(){
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        echo "Please provide namespace as an argument"| tee -a ${LOGFILE}
        exit 2;
    fi
    NAMESPACE=$1
    PVNAME=$(kubectl get pvc -n "${NAMESPACE}" | awk '$3 ~ /csivol/ { print $3 }')
    echo $PVNAME
}

# add comments for the args to make it more dynamic for future reference in case if someone wants reuse it
createNFSSC() {
    echo "Going to create NFS SC "| tee -a ${LOGFILE}
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        echo "Please provide namespace as an argument"| tee -a ${LOGFILE}
        exit 2;
    fi
    NAMESPACE=$1
    echo "apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
    name: powerstore-$NAMESPACE-nfs
provisioner: csi-powerstore.dellemc.com
parameters:
    arrayID: unique
    csi.storage.k8s.io/fstype: nfs
    nasName: "\"astral-nas\""
    allowRoot: "\"false\""
allowVolumeExpansion: true
reclaimPolicy: "\"Delete\""
volumeBindingMode: "\"Immediate\"""> powerstore-$NAMESPACE-nfs.yaml

    echo "Going to create StorageClass powerstore-$NAMESPACE-nfs " | tee -a ${LOGFILE}
    kubectl delete -f powerstore-$NAMESPACE-nfs.yaml
    echo kubectl create -f powerstore-$NAMESPACE-nfs.yaml| tee -a ${LOGFILE}
    kubectl create -f powerstore-$NAMESPACE-nfs.yaml
}

createNFSPVC(){
    echo "Going to create NFS PVC "| tee -a ${LOGFILE}
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        echo "Please provide namespace as an argument"| tee -a ${LOGFILE}
        exit 2;
    fi
    NAMESPACE=$1
    echo "apiVersion: v1
kind: PersistentVolumeClaim
metadata:
    name: powerstore-$NAMESPACE-nfs-pvc
spec:
    accessModes:
      - ReadWriteMany
    volumeMode: Filesystem
    resources:
        requests:
            storage: 3Gi
    storageClassName: powerstore-$NAMESPACE-nfs"> powerstore-$NAMESPACE-nfs-pvc.yaml

    echo "Going to create PVC powerstore-$NAMESPACE-nfs-pvc " | tee -a ${LOGFILE}
    #kubectl delete -f powerstore-$NAMESPACE-nfs-pvc.yaml
    deletePvcs $NAMESPACE
    echo kubectl create -f powerstore-$NAMESPACE-nfs-pvc -n $NAMESPACE| tee -a ${LOGFILE}
    kubectl create -f powerstore-$NAMESPACE-nfs-pvc.yaml -n $NAMESPACE
}

# @TODO- More clean & flexible code needs to be added here 
cleanUpNamespace(){
    echo "Going to clean namespace "| tee -a ${LOGFILE}
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        echo "Please provide namespace as an argument"| tee -a ${LOGFILE}
        exit 2;
    fi
    NAMESPACE=$1
    createDeployment $NAMESPACE 0
    waitOnRunning $NAMESPACE 0
    deletePvcs $NAMESPACE
    kubectl delete ns $NAMESPACE
}

createDeployment(){
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        echo "Please provide namespace as an argument"| tee -a ${LOGFILE}
        exit 2;
    fi
    NAMESPACE=$1
    ReplicaCount=$2
    if [[ "$2" = "" ]];
        then ReplicaCount=10
    fi
    echo "Scaling to $ReplicaCount pods"| tee -a ${LOGFILE}
    echo "apiVersion: apps/v1
kind: Deployment
metadata:
  name: dell-example
  labels:
    app: dell-wip
spec:
  selector:
    matchLabels:
      app: dell-wip
  replicas: $ReplicaCount
  template:
    metadata:
      labels:
        app: dell-wip
    spec:
      containers:
        - name: test
          image: docker.io/centos:latest
          command: [ "\"/bin/sleep\"", "\"3600\""]
          volumeMounts:
            - mountPath: "\"/data0\""
              name: pvol
      volumes:
      - name: pvol
        persistentVolumeClaim:
            claimName: powerstore-$NAMESPACE-nfs-pvc"> powerstore-$NAMESPACE-Deployment.yaml

    echo "Going to create Pods " | tee -a ${LOGFILE}
    # kubectl delete -f powerstore-$NAMESPACE-Deployment.yaml
    echo kubectl apply -f powerstore-$NAMESPACE-Deployment.yaml -n $NAMESPACE| tee -a ${LOGFILE}
    kubectl apply -f powerstore-$NAMESPACE-Deployment.yaml -n $NAMESPACE
    sleep 1
    waitOnRunning $NAMESPACE $ReplicaCount

}

waitOnRunning() {
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        echo "Please provide namespace as an argument"| tee -a ${LOGFILE}
        exit 2;
    fi
    NAMESPACE=$1
    WAITINGFOR=$2
     if [[ "$2" = "" ]];
        then WAITINGFOR=10
    fi
    RUNNING=$(kubectl get pods -n "${NAMESPACE}" | grep "Running" | wc -l)
    CREATING=$(kubectl get pods -n "${NAMESPACE}" | grep "ContainerCreating" | wc -l)
    TERMINATING=$(kubectl get pods -n "${NAMESPACE}" | grep "Terminating" | wc -l)
    
    echo "Waiting, Running, Creating & Terminating pods count is " $WAITINGFOR $RUNNING $CREATING $TERMINATING

    while [[ ${RUNNING} -ne ${WAITINGFOR} || ${CREATING} -ne 0 || ${TERMINATING} -ne 0 ]];
    do
        RUNNING=$(kubectl get pods -n "${NAMESPACE}" | grep "Running" | wc -l)
        CREATING=$(kubectl get pods -n "${NAMESPACE}" | grep "ContainerCreating" | wc -l)
        TERMINATING=$(kubectl get pods -n "${NAMESPACE}" | grep "Terminating" | wc -l)
        # PVCS=$(kubectl get pvc -n "${NAMESPACE}" --no-headers | wc -l)
        date | tee -a ${LOGFILE}
        echo running ${RUNNING} creating ${CREATING} terminating ${TERMINATING} | tee -a ${LOGFILE}
        sleep 5
    done
}

deletePvcs() {
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        echo "Please provide namespace as an argument"| tee -a ${LOGFILE}
        exit 2;
    fi
    NAMESPACE=$1
    FORCE=""
    PVCS=$(kubectl get pvc -n "${NAMESPACE}" | awk '$1 ~ /'${NAMESPACE}/ { print $1 }'')
    echo deleting... ${PVCS} | tee -a ${LOGFILE}
    for P in ${PVCS}; do
        if [[ "$FORCE" == "yes" ]]; then
            echo kubectl delete --force --grace-period=0 pvc ${P} -n "${NAMESPACE}"
            kubectl delete --force --grace-period=0 pvc ${P} -n "${NAMESPACE}"
        else
            echo kubectl delete pvc ${P} -n "${NAMESPACE}" | tee -a ${LOGFILE}
            kubectl delete pvc ${P} -n "${NAMESPACE}"
        fi
    done
}
$@