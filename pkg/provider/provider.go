// Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package provider

import (
	"os"
	"strings"

	"github.com/dell/csi-powerstore/v2/pkg/powerstorecommon"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identity"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	"github.com/dell/csi-powerstore/v2/pkg/service"
	"github.com/dell/csm-sharednfs/nfs"
	"github.com/dell/gocsi"
	logrus "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// Log init
var Log = logrus.New()

const namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// New returns a new gocsi Storage Plug-in Provider.
func New(controllerSvc controller.Interface, identitySvc *identity.Service, nodeSvc node.Interface, interList []grpc.UnaryServerInterceptor) *gocsi.StoragePlugin {
	svc := service.New()
	service.PutControllerService(controllerSvc)
	service.PutNodeService(nodeSvc)
	nfssvc := nfs.New(powerstorecommon.Name)
	service.PutNfsService(nfssvc)
	nfs.PutVcsiService(svc)
	nfs.DriverName = powerstorecommon.Name

	driverNamespace := os.Getenv(powerstorecommon.EnvDriverNamespace)
	if driverNamespace != "" {
		Log.Infof("Reading driver namespace from env variable %s", powerstorecommon.EnvDriverNamespace)
		nfs.DriverNamespace = driverNamespace
	} else {
		// Read the namespace associated with the service account
		namespaceData, err := os.ReadFile(namespaceFile)
		if err == nil {
			if driverNamespace = strings.TrimSpace(string(namespaceData)); len(driverNamespace) > 0 {
				Log.Infof("Driver Namespace not set, reading from the associated service account")
				nfs.DriverNamespace = driverNamespace
			}
		}
	}

	nfs.NfsExportDirectory = os.Getenv(powerstorecommon.EnvNFSExportDirectory)
	if nfs.NfsExportDirectory == "" {
		Log.Infof("NFS export directory not set. using default directory")
		nfs.NfsExportDirectory = "/var/lib/dell/nfs"
	}
	Log.Infof("Setting nfsExportDirectory to %s", nfs.NfsExportDirectory)
	return &gocsi.StoragePlugin{
		Controller:                svc,
		Identity:                  identitySvc,
		Node:                      svc,
		BeforeServe:               svc.BeforeServe,
		RegisterAdditionalServers: svc.RegisterAdditionalServers,
		Interceptors:              interList,

		EnvVars: []string{
			// Enable request validation
			gocsi.EnvVarSpecReqValidation + "=true",

			// Enable serial volume access
			gocsi.EnvVarSerialVolAccess + "=true",
		},
	}
}
