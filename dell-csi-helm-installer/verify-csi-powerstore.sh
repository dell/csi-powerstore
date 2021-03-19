#!/bin/bash
#
# Copyright (c) 2020 Dell Inc., or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0

# verify-csi-powerstore method
function verify-csi-powerstore() {
  verify_k8s_versions "1.18" "1.20"
  verify_openshift_versions "4.5" "4.7"
  verify_namespace "${NS}"
  verify_required_secrets "${RELEASE}-config"
  verify_alpha_snap_resources
  verify_snap_requirements
  verify_nfs_installation
  verify_iscsi_installation
  verify_helm_3
}

# Check if the nfs utils are installed
function verify_nfs_installation() {
  if [ ${NODE_VERIFY} -eq 0 ]; then
    return
  fi

  log smart_step "Verifying NFS installation"

  error=0
  for node in $MINION_NODES; do
    run_command ssh ${NODEUSER}@"${node}" "which mount.nfs" >/dev/null 2>&1
    rv=$?
    if [ $rv -ne 0 ]; then
      error=1
      found_warning "Either mount.nfs was not found on node: $node or not able to verify"
    fi
  done

  check_error error
}

