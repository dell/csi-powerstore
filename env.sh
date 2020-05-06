#!/bin/sh

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
