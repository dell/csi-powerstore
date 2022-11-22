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
kubectl run csi-sanity --image=$IMAGE --overrides='
{
  	"apiVersion": "v1",
	"spec": {
		"containers": [
			{
			"name": "csi-sanity",
			"image": "'$IMAGE'",
			"stdin": true,
			"stdinOnce": true,
			"tty": true,
			"command": ["/app/csi-sanity/csi-sanity"],
			"args": ["--ginkgo.v", "--csi.endpoint=/node.sock", "--csi.controllerendpoint=/controller.sock", "--csi.mountdir=/dev/mnt", "--csi.stagingdir=/dev/stg"],
			"volumeMounts": [{
				"name": "controller",
				"mountPath": "/controller.sock"
			},
			{
				"name": "node",
				"mountPath": "/node.sock"
			}]
			}
		],
		"volumes": [{
			"name":"controller",
			"hostPath":{
				"path": "/var/run/csi/controller-csi.sock"
			}
		},
		{
			"name":"node",
			"hostPath":{
				"path": "/var/run/csi/node-csi.sock"
			}
		}]
	}
}
' --rm -ti --attach --restart=Never