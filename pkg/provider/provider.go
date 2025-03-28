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

	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identity"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	"github.com/dell/csi-powerstore/v2/pkg/service"
	"github.com/dell/csm-hbnfs/nfs"
	"github.com/dell/gocsi"
	logrus "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// Log init
var Log = logrus.New()

// New returns a new gocsi Storage Plug-in Provider.
func New(controllerSvc controller.Interface, identitySvc *identity.Service, nodeSvc node.Interface, interList []grpc.UnaryServerInterceptor) *gocsi.StoragePlugin {
	svc := service.New()
	service.PutControllerService(controllerSvc)
	service.PutNodeService(nodeSvc)
	nfssvc := nfs.New(common.Name)
	service.PutNfsService(nfssvc)
	nfs.PutVcsiService(svc)
	nfs.DriverName = common.Name
	nfs.DriverNamespace = "powerstore"

	nfs.NfsExportDirectory = os.Getenv(common.EnvNFSExportDirectory)
	Log.Infof("Setting nfsExportDirectory env to %s", nfs.NfsExportDirectory)
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
