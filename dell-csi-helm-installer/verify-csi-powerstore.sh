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
  verify_k8s_versions "1.19" "1.21"
  verify_openshift_versions "4.6" "4.8"
  verify_namespace "${NS}"
  verify_required_secrets "${RELEASE}-config"
  verify_alpha_snap_resources
  verify_iscsi_installation
  verify_helm_3
}
