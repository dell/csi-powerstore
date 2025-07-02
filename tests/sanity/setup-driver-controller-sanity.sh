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
