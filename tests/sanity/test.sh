#!/bin/sh
IMAGE=$1
OVERRIDE='
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
			"args": ["--ginkgo.v", "--csi.endpoint=/node.sock", "--csi.controllerendpoint=/controller.sock"],
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
				"path": "/var/run/csi/controller-csi.sock",
				"type": "File"
			}
		},
		{
			"name":"node",
			"hostPath":{
				"path": "/var/run/csi/node-csi.sock",
				"type": "File"
			}
		}]
	}
}
'

kubectl run csi-sanity --image=$IMAGE --overrides=$OVERRIDE --rm -ti --attach --restart=Never
