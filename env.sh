#!/bin/sh
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


# HTTP endpoint of PowerStore
export X_CSI_POWERSTORE_ENDPOINT=""

# EnvUser is the name of the enviroment variable used to set the
# username when authenticating to PowerStore
export X_CSI_POWERSTORE_USER="smc"

# EnvPassword is the name of the enviroment variable used to set the
# user's password when authenticating to PowerStore
export X_CSI_POWERSTORE_PASSWORD="smc"

# EnvInsecure is the name of the enviroment variable used to specify
# that PowerStore's certificate chain and host name should not
# be verified
export X_CSI_POWERSTORE_INSECURE="true"

# EnvAutoProbe is the name of the environment variable used to specify
# that the controller service should automatically probe itself if it
# receives incoming requests before having been probed, in direct
# violation of the CSI spec
export X_CSI_POWERSTORE_AUTOPROBE="true"
