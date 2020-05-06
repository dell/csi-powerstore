#!/usr/bin/env bash
kubeversion=$(kubectl version | grep 'Server Version' | sed -e 's/^.*Minor:"//' -e 's/[+"],.*//')

isiSCSI=0
isFC=0
isauto=0
if [[ $(ls | grep -c myvalues.yaml) -ne 0 ]]; then
  echo "Found myvalues.yaml"
  if [[ $(grep -c "transportProtocol:[[:blank:]]\+FC" myvalues.yaml) -ne 0 ]]; then
    isFC=1

  elif [[ $(grep -c "transportProtocol:[[:blank:]]\+ISCSI" myvalues.yaml) -ne 0 ]]; then
    isiSCSI=1

  elif [[ $(grep -c "transportProtocol:[[:blank:]]\+auto" myvalues.yaml) -ne 0 ]]; then
    isauto=1
  else
    echo "Incorrect Transport Protocol"
    exit 2
  fi
else
  echo "[ERROR] myvalues.yaml doesn't exists. You need to copy it from csi-powerstore/values.yaml and populate with proper values"
  exit 1
fi

function iscsi_verify() {
  echo "Verifying the iSCSI installation."
  fail=0
  SSH_USER=root
  for node in ${MINION_NODES}; do
    ssh ${SSH_USER}@${node} cat /etc/iscsi/initiatorname.iscsi
    rv=$?
    if [[ ${rv} -ne 0 ]]; then
      echo "*******************************************************************"
      echo "Node $node does not have the iSCSI packages installed"
      echo "*******************************************************************"
      fail=1
    fi
  done

  if [[ ${fail} -ne 0 ]]; then
    echo "YOU MUST INSTALL THE iSCSI packages ON ALL MINION (WORKER) NODES"
    exit 2
  else
    echo "Verifying the iSCSI installation was successful!"
  fi
}

function fc_verify(){
  echo "Verifying the FC configuration."
  fail=0
  SSH_USER=root
  for node in ${MINION_NODES}; do
    ssh ${SSH_USER}@${node} 'ls --hide=* /sys/class/fc_host/* 1>/dev/null'
    rv=$?
    if [[ ${rv} -ne 0 ]]; then
      echo "*******************************************************************"
      echo "Node $node does not have FC configured"
      echo "*******************************************************************"
      fail=1
    fi
  done

  if [[ ${fail} -ne 0 ]]; then
    echo "YOU MUST CONFIGURE FC ON ALL MINION (WORKER) NODES"
    exit 2
  else
    echo "Verifying the FC configuration was successful!"
  fi
}

# Determine the kubernetes version
gitversion=$(kubectl version | grep 'Server Version' | sed -e 's/^.*GitVersion:"//' -e 's/",.*//')
echo Kubernetes version ${gitversion}
# Determine the nodes
MINION_NODES=$(kubectl get nodes -o wide | grep -v -e master -e INTERNAL | awk ' { print $6; }')
MASTER_NODES=$(kubectl get nodes -o wide | awk ' /master/{ print $6; }')
echo Kubernetes master nodes: ${MASTER_NODES}
echo Kubernetes minion nodes: ${MINION_NODES}
if [[ $isiSCSI == 1 ]]; then
  iscsi_verify
fi
if [[ $isFC == 1 ]]; then
  fc_verify
fi
if [[ $isauto == 1 ]]; then
  echo "TP is set to auto. Verifying both iSCSI and FC"
  if fc_verify ; then
    echo "FC verification succeded. Skipping iSCSI Verification"
  elif iscsi_verify ; then
    echo "iSCSI verification succeded"
  else
    echo "Verification of both iSCSI and FC failed. Aborting"
  fi
fi

exit 0
