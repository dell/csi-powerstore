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

package provider

import (
	"context"
	"github.com/dell/csi-powerstore/service"
	"github.com/rexray/gocsi"
	"net"
)

// New returns a new Mock Storage Plug-in Provider.
func New() *CustomStoragePlugin {
	svc := service.New()
	csp := &CustomStoragePlugin{
		svc: svc,
		sp: &gocsi.StoragePlugin{
			Controller:  svc,
			Identity:    svc,
			Node:        svc,
			BeforeServe: svc.BeforeServe,

			EnvVars: []string{
				// Enable request validation.
				gocsi.EnvVarSpecReqValidation + "=true",
				// Enable serial volume access.
				gocsi.EnvVarSerialVolAccess + "=true",
			},
		}}
	return csp
}

type CustomStoragePlugin struct {
	svc service.Service
	sp  *gocsi.StoragePlugin
}

func (csp *CustomStoragePlugin) Serve(ctx context.Context, lis net.Listener) error {
	return csp.sp.Serve(ctx, lis)
}

func (csp *CustomStoragePlugin) Stop(ctx context.Context) {
	_ = csp.svc.ShutDown(ctx)
	csp.sp.Stop(ctx)
}

func (csp *CustomStoragePlugin) GracefulStop(ctx context.Context) {
	_ = csp.svc.ShutDown(ctx)
	csp.sp.GracefulStop(ctx)
}
