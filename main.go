//go:generate go generate ./core

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

package main

import (
	"context"
	"fmt"
	"github.com/dell/csi-powerstore/provider"
	"github.com/dell/csi-powerstore/service"
	"github.com/rexray/gocsi"
	"github.com/rexray/gocsi/utils"
	log "github.com/sirupsen/logrus"
	"os"
	"sync"
	"time"
)

// main is ignored when this package is built as a go plug-in
func main() {
	rmSockFile()
	log.SetFormatter(&log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
	gocsi.Run(
		context.Background(), service.Name,
		"A PowerStore Container Storage Interface (CSI) Plugin",
		usage,
		provider.New())
}

func rmSockFile() {
	proto, addr, err := utils.GetCSIEndpoint()
	if err != nil {
		fmt.Printf("Error: failed to get CSI endpoint: %s\n", err.Error())
	}

	var rmSockFileOnce sync.Once
	rmSockFileOnce.Do(func() {
		if proto == "unix" {
			if _, err := os.Stat(addr); err == nil {
				if err = os.RemoveAll(addr); err != nil {
					fmt.Printf("Error: failed to remove socket file %s: %s\n", addr, err.Error())
				}
				fmt.Printf("removed socket file %s\n", addr)
			} else if os.IsNotExist(err) {
				return
			} else {
				fmt.Printf("Error: socket file %s may or may not exist: %s\n", addr, err.Error())
			}
		}
	})
}

const usage = `    X_CSI_POWERSTORE_ENDPOINT
        Specifies the HTTP endpoint for the POWERSTORE API. This parameter is
        required when running the Controller service.

        The default value is empty.

    X_CSI_POWERSTORE_USER
        Specifies the user name when authenticating to the POWERSTORE API.

        The default value is admin.

    X_CSI_POWERSTORE_PASSWORD
        Specifies the password of the user defined by X_CSI_POWERSTORE_USER to use
        when authenticating to the POWERSTORE API. This parameter is required
        when running the Controller service.

        The default value is empty.

    X_CSI_POWERSTORE_INSECURE
        Specifies that the PowerStore's hostname and certificate chain
        should not be verified.

        The default value is false.

`
