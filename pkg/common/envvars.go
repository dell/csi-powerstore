/*
 *
 * Copyright © 2021-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package common

const (
	// EnvDriverName is the name of the csi driver (provisioner)
	EnvDriverName = "X_CSI_DRIVER_NAME"

	// EnvNodeIDFilePath is the name of the environment variable used to
	// specify the file with the node ID
	EnvNodeIDFilePath = "X_CSI_POWERSTORE_NODE_ID_PATH"

	// EnvKubeNodeName is the name of the environment variable which stores current kubernetes
	// node name
	EnvKubeNodeName = "X_CSI_POWERSTORE_KUBE_NODE_NAME"

	// EnvKubeConfigPath indicates kubernetes configuration path that has to be used by CSI Driver
	EnvKubeConfigPath = "KUBECONFIG"

	// EnvNodeNamePrefix is the name of the environment variable which stores prefix which will be
	// used when registering node on PowerStore array
	EnvNodeNamePrefix = "X_CSI_POWERSTORE_NODE_NAME_PREFIX"

	// EnvMaxVolumesPerNode specifies maximum number of volumes that controller can publish to the node
	EnvMaxVolumesPerNode = "X_CSI_POWERSTORE_MAX_VOLUMES_PER_NODE"

	// EnvNodeChrootPath is the name of the environment variable which store path to chroot where
	// to execute iSCSI commands
	EnvNodeChrootPath = "X_CSI_POWERSTORE_NODE_CHROOT_PATH"

	// EnvCtrlRootPath is the name of the environment variable which store path to directory where
	// the host root is mounted
	EnvCtrlRootPath = "X_CSI_POWERSTORE_CTRL_ROOT_PATH"

	// EnvTmpDir is the name of the environment variable which store path to the folder which will be used
	// for csi-powerstore temporary files
	EnvTmpDir = "X_CSI_POWERSTORE_TMP_DIR" // #nosec G101

	// EnvFCPortsFilterFilePath is the name of the environment variable which store path to the file which
	// provide list of WWPN which should be used by the driver for FC connection on this node
	// example:
	// content of the file:
	//   21:00:00:29:ff:48:9f:6e,21:00:00:29:ff:48:9f:6e
	// If file not exist or empty or in invalid format, then the driver will use all available FC ports
	EnvFCPortsFilterFilePath = "X_CSI_FC_PORTS_FILTER_FILE_PATH"

	// EnvThrottlingRateLimit sets a number of concurrent requests to APi
	EnvThrottlingRateLimit = "X_CSI_POWERSTORE_THROTTLING_RATE_LIMIT"

	// EnvEnableCHAP is the flag which determines if the driver is going
	// to set the CHAP credentials in the ISCSI node database at the time
	// of node plugin boot
	EnvEnableCHAP = "X_CSI_POWERSTORE_ENABLE_CHAP"

	// EnvExternalAccess is the IP of an additional router you wish to add for nfs export
	// Used to provide NFS volumes behind NAT
	EnvExternalAccess = "X_CSI_POWERSTORE_EXTERNAL_ACCESS" // #nosec G101

	// EnvArrayConfigFilePath is filepath to powerstore arrays config file
	EnvArrayConfigFilePath = "X_CSI_POWERSTORE_CONFIG_PATH"

	// EnvConfigParamsFilePath is filepath to powerstore driver params config file
	EnvConfigParamsFilePath = "X_CSI_POWERSTORE_CONFIG_PARAMS_PATH"

	// EnvDebugEnableTracing allow to enable tracing in driver
	EnvDebugEnableTracing = "ENABLE_TRACING"

	// EnvReplicationContextPrefix enables sidecars to read required information from volume context
	EnvReplicationContextPrefix = "X_CSI_REPLICATION_CONTEXT_PREFIX"

	// EnvReplicationPrefix is used as a prefix to find out if replication is enabled
	EnvReplicationPrefix = "X_CSI_REPLICATION_PREFIX" // #nosec G101

	// EnvGOCSIDebug indicates whether to print REQUESTs and RESPONSEs of all CSI method calls(from gocsi)
	EnvGOCSIDebug = "X_CSI_DEBUG"

	// EnvIsHealthMonitorEnabled specifies if health monitor is enabled.
	EnvIsHealthMonitorEnabled = "X_CSI_HEALTH_MONITOR_ENABLED"

	// EnvNfsAcls specifies acls to be set on NFS mount directory
	EnvNfsAcls = "X_CSI_NFS_ACLS"

	// EnvK8sVisibilityAutoRegistration specifies if k8s cluster should be automatically registered to PowerStore Array
	EnvK8sVisibilityAutoRegistration = "X_CSI_K8S_VISIBILITY_AUTO_REGISTRATION"

	// EnvMetadataRetrieverEndpoint specifies the endpoint address for csi-metadata-retriever sidecar
	EnvMetadataRetrieverEndpoint = "CSI_RETRIEVER_ENDPOINT"

	// EnvAllowAutoRoundOffFilesystemSize specifies if auto round off minimum filesystem size is enabled
	EnvAllowAutoRoundOffFilesystemSize = "CSI_AUTO_ROUND_OFF_FILESYSTEM_SIZE"

	// EnvPodmonEnabled indicates that podmon is enabled
	EnvPodmonEnabled = "X_CSI_PODMON_ENABLED"

	// EnvPodmonAPIPORT indicates the port to be used for exposing podmon API health, ToDo: Rename to var EnvPodmonArrayConnectivityAPIPORT
	EnvPodmonAPIPORT = "X_CSI_PODMON_API_PORT"

	// EnvPodmonArrayConnectivityPollRate indicates the polling frequency to check array connectivity
	EnvPodmonArrayConnectivityPollRate = "X_CSI_PODMON_ARRAY_CONNECTIVITY_POLL_RATE"
)
