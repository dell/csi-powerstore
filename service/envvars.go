/*
 *
 * Copyright © 2020 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package service

const (
	// EnvDriverName is the name of the csi driver (provisioner)
	EnvDriverName = "X_CSI_DRIVER_NAME"

	// EnvEndpoint is the name of the enviroment variable used to set the
	// HTTP endpoint of the PowerStore Gateway
	EnvEndpoint = "X_CSI_POWERSTORE_ENDPOINT"

	// EnvUser is the name of the enviroment variable used to set the
	// username when authenticating to the PowerStore Gateway
	EnvUser = "X_CSI_POWERSTORE_USER"

	// EnvPassword is the name of the enviroment variable used to set the
	// user's password when authenticating to the PowerStore Gateway
	EnvPassword = "X_CSI_POWERSTORE_PASSWORD" // #nosec G101

	// EnvInsecure is the name of the enviroment variable used to specify
	// that PowerStore's certificate chain and host name should not
	// be verified
	EnvInsecure = "X_CSI_POWERSTORE_INSECURE"

	// EnvAutoProbe is the name of the environment variable used to specify
	// that the controller service should automatically probe itself if it
	// receives incoming requests before having been probed, in direct
	// violation of the CSI spec
	EnvAutoProbe = "X_CSI_POWERSTORE_AUTOPROBE"

	// EnvNodeIDFilePath is the name of the environment variable used to
	// specify the file with the node ID
	EnvNodeIDFilePath = "X_CSI_POWERSTORE_NODE_ID_PATH"

	// EnvKubeNodeName is the name of the environment variable which stores current kubernetes
	// node name
	EnvKubeNodeName = "X_CSI_POWERSTORE_KUBE_NODE_NAME"

	// EnvNodeNamePrefix is the name of the environment variable which stores prefix which will be
	// used when registering node on PowerStore array
	EnvNodeNamePrefix = "X_CSI_POWERSTORE_NODE_NAME_PREFIX"

	// EnvNoProbeOnStart is the name of the environment variable used to enable
	// or disable driver probing while driver loading
	EnvNoProbeOnStart = "X_CSI_POWERSTORE_NO_PROBE_ON_START"

	// EnvNoNodeRegistration is the name of the environment variable used to enable
	// or disable auto node registration during driver boot
	EnvNoNodeRegistration = "X_CSI_POWERSTORE_NO_NODE_REGISTRATION"

	// EnvNodeChrootPath is the name of the environment variable which store path to chroot where
	// to execute iSCSI commands
	EnvNodeChrootPath = "X_CSI_POWERSTORE_NODE_CHROOT_PATH"

	// EnvTmpDir is the name of the environment variable which store path to the folder which will be used
	// for csi-powerstore temporary files
	EnvTmpDir = "X_CSI_POWERSTORE_TMP_DIR"

	// EnvEnableTracing enable tracing http points for debug purpose
	EnvEnableTracing = "X_CSI_ENABLE_TRACING"

	// EnvDebugHTTPServerListenAddress address on which to open debug http server
	EnvDebugHTTPServerListenAddress = "X_CSI_DEBUG_HTTP_LISTEN_ADDRESS"

	// EnvPreferredTransportProtocol enables you to be able to force the transport protocol.
	// Valid values are "FC" or "ISCSI" or "auto" or "". If "" or "auto", will choose FC if both are available.
	// This is mainly for testing.
	EnvPreferredTransportProtocol = "X_CSI_TRANSPORT_PROTOCOL"

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

	// EnvCHAPUserName is the the username for the ISCSI CHAP
	// authentication for the host initiator(s)
	// If set to none, then the driver will use the ISCSI IQN as the username
	EnvCHAPUserName = "X_CSI_POWERSTORE_CHAP_USERNAME"

	// EnvCHAPPassword is the the password for the ISCSI CHAP
	// authentication for the host initiator(s)
	EnvCHAPPassword = "X_CSI_POWERSTORE_CHAP_PASSWORD" // #nosec G101
)
