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
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identity"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {

	tests := []struct {
		name                string
		setEnv              func()
		unsetEnv            func()
		createNamespaceFile func()
		deleteNamespaceFile func()
	}{
		{
			name:     "X_CSI_DRIVER_NAMESPACE environment variable is not set",
			setEnv:   func() {},
			unsetEnv: func() {},
			createNamespaceFile: func() {
				err := os.MkdirAll("/var/run/secrets/kubernetes.io/serviceaccount", 0o755)
				if err != nil {
					t.Error(err)
				}
				file, err := os.Create(namespaceFile)
				if err != nil {
					t.Errorf("error creating file: %v", err)
					t.Error(err)
				}
				defer func(file *os.File) {
					err := file.Close()
					if err != nil {
						t.Error(err)
					}
				}(file)

				_, err = file.Write([]byte("powerstore"))
				if err != nil {
					t.Error(err)
				}
			},
			deleteNamespaceFile: func() {
				err := os.Remove(namespaceFile)
				if err != nil {
					t.Error(err)
				}
			},
		},
		{
			name: "X_CSI_DRIVER_NAMESPACE environment variable is set",
			setEnv: func() {
				err := os.Setenv("X_CSI_DRIVER_NAMESPACE", "powerstore")
				if err != nil {
					t.Error(err)
				}
			},
			unsetEnv: func() {
				err := os.Unsetenv("X_CSI_DRIVER_NAMESPACE")
				if err != nil {
					t.Error(err)
				}
			},
			createNamespaceFile: func() {},
			deleteNamespaceFile: func() {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controllerSvc := controller.Service{}
			identitySvc := identity.Service{}
			nodeSvc := node.Service{}
			tt.setEnv()
			tt.createNamespaceFile()
			p := New(&controllerSvc, &identitySvc, &nodeSvc, nil)
			tt.deleteNamespaceFile()
			tt.unsetEnv()
			assert.NotNil(t, p)
		})
	}
}
