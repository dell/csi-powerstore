#!/bin/bash

# Copyright © 2020-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

echo "Make sure binary exists!"
echo "Starting driver!"

export X_CSI_POWERSTORE_CONFIG_PATH=$(pwd)/config.yaml
export X_CSI_POWERSTORE_CONFIG_PARAMS_PATH=$(pwd)/driver-config-params.yaml
export X_CSI_MODE=controller
export X_CSI_DRIVER_NAMESPACE=powerstore
export CSI_ENDPOINT=$(pwd)/controller.sock
export X_CSI_VOL_PREFIX=sanity
export X_CSI_MAX_VOLUMES_PER_NODE=0
export X_CSI_NODE_IP=REPLACE_IP
export X_CSI_NODE_NAME=REPLACE_HOSTNAME
export X_CSI_HEALTH_MONITOR_ENABLED=true
export CSI_AUTO_ROUND_OFF_FILESYSTEM_SIZE=true

#assume binary is in csi-powerstore/ dir
 ../../csi-powerstore --array-config=/root/csi-powerstore/tests/sanity/config.yaml --driver-config-params=/root/csi-powerstore/tests/sanity/driver-config-params.yaml
