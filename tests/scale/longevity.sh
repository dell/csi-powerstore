#!/usr/bin/env bash
#
#
# Copyright © 2020-2022 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#      http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#


# longevity.sh
# This script will kick off a test designed to run forever, validating the longevity of the driver.
#
# The test will continue to run until a file named 'stop' is placed in the script directory.


TEST="volumes"
RELEASE_NAME="set1"
NAMESPACE="test"
DRIVER_NAMESPACE="default"
VOLUME_COUNT=5
REPLICAS=-1
LOGFILE="log.output"


# Usage information
function usage {
   echo
   echo "`basename ${0}`"
   echo "    -n namespace          - Namespace in which to place the test. Default is: ${NAMESPACE}"
   echo "    -d driver_namespace   - Namespace in which to place the csi driver. Default is: ${DRIVER_NAMESPACE}"
   echo "    -i release_name       - Name release and statefulset. Default is: ${RELEASE_NAME}"
   echo "    -c volume_count       - Number of volumes for each pod. Default is: ${VOLUME_COUNT}"
   echo "    -t test               - Test to run. Default is: ${TEST}. The value must point to a Helm Chart"
   echo "    -r replicas           - Number of replicas to create"
   echo
   exit 1
}

# Parse the options passed on the command line
while getopts "n:d:i:c:t:r:" opt; do
  case ${opt} in
    n)
      NAMESPACE="${OPTARG}"
      ;;
    d)
      DRIVER_NAMESPACE="${OPTARG}"
      ;;
    i)
      RELEASE_NAME="${OPTARG}"
      ;;
    c)
      VOLUME_COUNT="${OPTARG}"
      ;;
    t)
      TEST="${OPTARG}"
      ;;
    r)
      REPLICAS="${OPTARG}"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage
      ;;
  esac
done

if [[ ${REPLICAS} -eq -1 ]]; then
    echo "No value for number of replicas provided";
    usage
fi

#TARGET=$(expr ${REPLICAS} \* 3)
TARGET=${REPLICAS}
echo "Targeting replicas: $REPLICAS"
echo "Targeting pods: $TARGET"

# remove old output and stop file
rm -f stop
rm -f ${LOGFILE}


# fill an array of controller and worker node names
declare -a NODES_CONT
declare -a NODES_WORK

while read -r line; do
  P=$(echo ${line} | awk '{ print $1 }')
  NODES_CONT+=("$P")
done < <(kubectl get pods -n ${DRIVER_NAMESPACE} | grep controller)
while read -r line; do
  P=$(echo ${line} | awk '{ print $1 }')
  NODES_WORK+=("$P")
done < <(kubectl get pods -n ${DRIVER_NAMESPACE} | grep node)

deployPods() {
    echo "Deploying pods, replicas: $REPLICAS, target: $TARGET, volume count: $VOLUME_COUNT"
    helm install --set "name=$RELEASE_NAME,replicas=$REPLICAS,volumeCount=$VOLUME_COUNT,storageClass=powerstore" \
    -n ${RELEASE_NAME} --namespace "${NAMESPACE}" "${TEST}"
}

rescalePods() {
    echo "Rescaling pods, replicas: $REPLICAS, target: $TARGET"
    kubectl scale statefulset --namespace ${NAMESPACE} --replicas=$1 ${RELEASE_NAME}
}

helmDelete() {
    echo "Deleting helm charts"
    helm delete --purge ${RELEASE_NAME}
}

printVmsize() {
    for N in "${NODES_CONT[@]}"; do
        echo -n "$N " >>${LOGFILE}
        kubectl exec ${N} -n ${DRIVER_NAMESPACE} --container driver -- ps -eo cmd,vsz,rss | grep csi-powerstore | tee -a ${LOGFILE}
    done
    for N in "${NODES_WORK[@]}"; do
        echo -n "$N " >>${LOGFILE}
        kubectl exec ${N} -n ${DRIVER_NAMESPACE} --container driver -- ps -eo cmd,vsz,rss | grep csi-powerstore | tee -a ${LOGFILE}
    done
}

waitOnRunning() {
    if [[ "$1" = "" ]];
        then echo "arg: target" ;
        exit 2;
    fi
    WAITINGFOR=$1

    RUNNING=$(kubectl get pods -n "${NAMESPACE}" | grep "Running" | wc -l)
    while [[ ${RUNNING} -ne ${WAITINGFOR} ]];
    do
        RUNNING=$(kubectl get pods -n "${NAMESPACE}" | grep "Running" | wc -l)
        CREATING=$(kubectl get pods -n "${NAMESPACE}" | grep "ContainerCreating" | wc -l)
        TERMINATING=$(kubectl get pods -n "${NAMESPACE}" | grep "Terminating" | wc -l)
        PVCS=$(kubectl get pvc -n "${NAMESPACE}" --no-headers | wc -l)
        date | tee -a ${LOGFILE}
        echo running ${RUNNING} creating ${CREATING} terminating ${TERMINATING} pvcs ${PVCS} | tee -a ${LOGFILE}
        printVmsize
        sleep 15
    done
}

waitOnNoPods() {
    COUNT=$(kubectl get pods -n "${NAMESPACE}" --no-headers | wc -l)
    while [[ ${COUNT} -gt 0 ]];
    do
        echo "Waiting on all $COUNT pods to be deleted" | tee -a ${LOGFILE}
        sleep 30
        COUNT=$(kubectl get pods -n "${NAMESPACE}" --no-headers | wc -l)
        echo pods ${COUNT}
    done
}

waitOnNoVolumeAttachments() {
    COUNT=$(kubectl get volumeattachments --no-headers | wc -l)
    while [[ ${COUNT} -gt 0 ]];
    do
        echo "Waiting on all volume attachments to be deleted: $COUNT" | tee -a ${LOGFILE}
        sleep 30
        COUNT=$(kubectl get volumeattachments --no-headers | wc -l)
    done
}

deletePvcs() {
    FORCE=""
    PVCS=$(kubectl get pvc -n "${NAMESPACE}" | awk '/pvol/ { print $1; }')
    echo deleting... ${PVCS}
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


# Longevity test loop. Runs until a "stop" file is found.
ITER=1
while true;
do
    echo "Longevity test iteration $ITER replicas $REPLICAS target $TARGET $(date)" | tee -a ${LOGFILE}
    START_TIME_RUN=$SECONDS

    echo "deploying pods" >>${LOGFILE}
    deployPods
    echo "waiting on running $TARGET" >>${LOGFILE}
    waitOnRunning ${TARGET}
    ELAPSED_TIME_RUN=$(($SECONDS - $START_TIME_RUN))

    echo "rescaling pods 0" >>${LOGFILE}
    START_TIME_DELETE=$SECONDS
    rescalePods 0
    echo "waiting on running 0" >>${LOGFILE}
    waitOnRunning 0
    echo "waiting on no pods" >>${LOGFILE}
    waitOnNoPods

    waitOnNoVolumeAttachments
    deletePvcs
    helmDelete
    ELAPSED_TIME_DELETE=$(($SECONDS - $START_TIME_DELETE))
    ELAPSED_TIME_ALL=$(($SECONDS - $START_TIME_RUN))

    echo "Longevity test iteration $ITER completed $(date)" | tee -a ${LOGFILE}
    echo "Elapsed time of run: $((ELAPSED_TIME_RUN/60)) min $((ELAPSED_TIME_RUN%60)) sec" | tee -a ${LOGFILE}
    echo "Elapsed time of delete: $((ELAPSED_TIME_DELETE/60)) min $((ELAPSED_TIME_DELETE%60)) sec" | tee -a ${LOGFILE}
    echo "Elapsed time of all: $((ELAPSED_TIME_ALL/60)) min $((ELAPSED_TIME_ALL%60)) sec" | tee -a ${LOGFILE}

    if [[ -f stop ]]; then
        echo "stop detected... exiting"
        exit 0
    fi
    ITER=$(expr ${ITER} \+ 1)
done
exit 0
