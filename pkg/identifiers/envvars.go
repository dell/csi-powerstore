/*
 *
 * Copyright © 2021-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package identifiers

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

	// EnvExclusiveAccess indicates whether only externalAccess entries should be added to the NFS export.
	// If true, node IP is excluded, and only IP/CIDR from externalAccess is used.
	EnvExclusiveAccess = "X_CSI_POWERSTORE_EXCLUSIVE_ACCESS"

	// EnvNfsAutoSelect enables NFS source IP auto-discovery via kernel routing query.
	// When enabled, the controller defers per-host /32 export management to the node plugin,
	// which discovers the storage-network source IP via getOutboundIP(nasIP) and manages
	// NFS export entries at NodeStage/NodeUnstage time.
	// Valid values: "true", "false". Default: "false" (disabled).
	EnvNfsAutoSelect = "X_CSI_POWERSTORE_NFS_AUTO_SELECT"

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

	// EnvIsHealthMonitorEnabled specifies if health monitor is enabled.
	EnvIsHealthMonitorEnabled = "X_CSI_HEALTH_MONITOR_ENABLED"

	// EnvNfsAcls specifies acls to be set on NFS mount directory
	EnvNfsAcls = "X_CSI_NFS_ACLS"

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

	// EnvPodmonAPIToken is the shared secret token used to authenticate requests
	// between the CSI controller and node podmon API endpoints.
	// When set, both the node HTTP server and the controller HTTP client
	// will use Bearer token authentication. If unset, authentication is skipped
	// for backward compatibility.
	EnvPodmonAPIToken = "X_CSI_PODMON_API_TOKEN" // #nosec G101

	// EnvMultiNASThreshold specifies the failure threshold used to put NAS in cooldown.
	EnvMultiNASFailureThreshold = "X_CSI_MULTI_NAS_FAILURE_THRESHOLD"

	// EnvMultiNASCooldownPeriod specifies the cooldown period for multiple NAS devices.
	EnvMultiNASCooldownPeriod = "X_CSI_MULTI_NAS_COOLDOWN_PERIOD"

	// EnvDriverNamespace is the namespace where the powerstore driver is deployed
	EnvDriverNamespace = "X_CSI_DRIVER_NAMESPACE"

	// EnvPodName is the name of the pod where the driver is running
	EnvPodName = "POD_NAME"

	// EnvCSIMode is the mode of the CSI driver (controller or node)
	EnvCSIMode = "X_CSI_MODE"

	// EnvPowerstoreAPITimeout specifies the timeout for Powerstore REST API calls
	EnvPowerstoreAPITimeout = "X_CSI_POWERSTORE_API_TIMEOUT"

	// EnvPodmonArrayConnectivityTimeout specifies the timeout for array connectivity for podmon
	EnvPodmonArrayConnectivityTimeout = "X_CSI_PODMON_ARRAY_CONNECTIVITY_TIMEOUT"

	// EnvVolumeDisconnectMaxRetries specifies the maximum number of retry attempts for volume disconnection
	EnvVolumeDisconnectMaxRetries = "X_CSI_VOLUME_DISCONNECT_MAX_RETRIES"

	// EnvVolumeDisconnectRetryInterval specifies the wait time (in seconds) between volume disconnection retries
	EnvVolumeDisconnectRetryInterval = "X_CSI_VOLUME_DISCONNECT_RETRY_INTERVAL"

	// EnvVolumeDisconnectTimeoutSeconds specifies the timeout duration (in seconds) for each volume disconnection attempt
	EnvVolumeDisconnectTimeoutSeconds = "X_CSI_VOLUME_DISCONNECT_TIMEOUT_SECONDS"

	// EnvCSMDREnabled indicates if CSM-DR is enabled
	EnvCSMDREnabled = "X_CSM_DR_ENABLED"

	// EnvCSIAddonsReplicationEnabled indicates if CSI-Addons replication is enabled
	// This enables integration with OpenShift DR (Ramen) and other CSI-Addons compliant DR orchestrators
	EnvCSIAddonsReplicationEnabled = "X_CSI_CSIADDONS_REPLICATION_ENABLED"

	// EnvFsCheckEnabled enables/disables file system check before mount
	EnvFsCheckEnabled = "X_CSI_FS_CHECK_ENABLED"

	// EnvFsCheckMode controls the file system check mode: "checkOnly" or "checkAndRepair"
	EnvFsCheckMode = "X_CSI_FS_CHECK_MODE"

	// EnvCSMDRBindPort specifies the bind port for CSM-DR controller initialization
	EnvCSMDRBindPort = "X_CSM_DR_BIND_PORT"

	// EnvSpaceReclamationEnabled enables/disables space reclamation
	EnvSpaceReclamationEnabled = "X_CSI_SPACE_RECLAMATION_ENABLED"

	// EnvSpaceReclamationSchedule is the cron schedule for space reclamation
	EnvSpaceReclamationSchedule = "X_CSI_SPACE_RECLAMATION_SCHEDULE"

	// EnvSpaceReclamationMaxConcurrent is the max concurrent reclamation operations per node
	EnvSpaceReclamationMaxConcurrent = "X_CSI_SPACE_RECLAMATION_MAX_CONCURRENT"

	// EnvSpaceReclamationTimeout is the timeout for each reclamation operation in seconds
	EnvSpaceReclamationTimeout = "X_CSI_SPACE_RECLAMATION_TIMEOUT"

	// EnvMonitorEnabled enables/disables the monitor service for PowerStore alerts
	EnvMonitorEnabled = "X_CSI_ALERT_MONITOR_ENABLED"

	// EnvMonitorPollInterval specifies the polling interval for the monitor service
	EnvMonitorPollInterval = "X_CSI_ALERT_MONITOR_POLL_INTERVAL"

	// EnvMetricsEnabled enables/disables metrics collection and server
	EnvMetricsEnabled = "X_CSI_METRICS_ENABLED"

	// EnvMetricsPort specifies the port for the metrics server
	EnvMetricsPort = "X_CSI_METRICS_PORT"

	// EnvMetricsTLSCertFile specifies the path to the TLS certificate file for metrics server
	EnvMetricsTLSCertFile = "X_CSI_METRICS_TLS_CERT_FILE"

	// EnvMetricsTLSKeyFile specifies the path to the TLS key file for metrics server
	EnvMetricsTLSKeyFile = "X_CSI_METRICS_TLS_KEY_FILE"

	// EnvMetricsPollInterval specifies the polling interval for metrics collection
	EnvMetricsPollInterval = "X_CSI_METRICS_POLL_INTERVAL"

	// EnvMetricsLeaderElectionEnabled enables/disables leader election for metrics collection
	EnvMetricsLeaderElectionEnabled = "X_CSI_METRICS_LEADER_ELECTION_ENABLED"

	// EnvMetricsLeaderElectionLeaseDuration is the duration that non-leader candidates will wait to acquire the lease
	EnvMetricsLeaderElectionLeaseDuration = "X_CSI_METRICS_LEADER_ELECTION_LEASE_DURATION"

	// EnvMetricsLeaderElectionRenewDeadline is the duration that the acting leader will retry refreshing leadership before giving up
	EnvMetricsLeaderElectionRenewDeadline = "X_CSI_METRICS_LEADER_ELECTION_RENEW_DEADLINE"

	// EnvMetricsLeaderElectionRetryPeriod is the duration the LeaderElector clients should wait between tries of actions
	EnvMetricsLeaderElectionRetryPeriod = "X_CSI_METRICS_LEADER_ELECTION_RETRY_PERIOD"

	// EnvMetricsArrayTimeout specifies the timeout for metrics API calls to PowerStore arrays
	EnvMetricsArrayTimeout = "X_CSI_METRICS_ARRAY_TIMEOUT"

	// EnvMetricsCollectionCacheTTL specifies the cache TTL for metrics collection results
	EnvMetricsCollectionCacheTTL = "X_CSI_METRICS_COLLECTION_CACHE_TTL"

	// EnvMetricsArrayRateLimit specifies the rate limit for metrics API calls
	EnvMetricsArrayRateLimit = "X_CSI_METRICS_ARRAY_RATE_LIMIT"

	// EnvMetricsArrayCBThreshold specifies the circuit breaker failure threshold
	EnvMetricsArrayCBThreshold = "X_CSI_METRICS_ARRAY_CB_THRESHOLD"

	// EnvMetricsArrayCBResetTimeout specifies the circuit breaker reset timeout
	EnvMetricsArrayCBResetTimeout = "X_CSI_METRICS_ARRAY_CB_RESET_TIMEOUT"
)
