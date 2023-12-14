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

IMAGE=$1

kubectl create ns sanity
kubectl create secret generic csi-sanity-pstore-config -n sanity --from-file=config=helm/secret.yaml
# Create controller and noce driver instances
helm_command="helm install --values ./myvalues.yaml --name-template csi-sanity-pstore --namespace sanity ./helm/sanity-csi-powerstore --wait --timeout 180s"
echo "Helm install command:"
echo "  ${helm_command}"
${helm_command}

# Run tests from using csi-sanity container 
./test.sh $1

# Delete sanity test chart
helm delete --namespace sanity csi-sanity-pstore
kubectl delete ns sanity
