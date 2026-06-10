/*
 *
 * Copyright © 2021-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/groupcontroller"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	log "github.com/dell/csmlog"
	"github.com/dell/gocsi"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestUpdateDriverName(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		expected string
	}{
		{
			name:     "Environment variable is present",
			envVar:   "test-driver",
			expected: "test-driver",
		},
		{
			name:     "Environment variable is not present",
			envVar:   "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(identifiers.EnvDriverName, tc.envVar)

			updateDriverName()

			assert.Equal(t, tc.expected, identifiers.Name)
		})
	}
}

func TestInitilizeDriverConfigParams(t *testing.T) {
	tmpDir := t.TempDir()
	content := `CSI_LOG_FORMAT: "JSON"`
	driverConfigParams := filepath.Join(tmpDir, "driver-config-params.yaml")
	writeToFile(t, driverConfigParams, content)
	t.Setenv(identifiers.EnvConfigParamsFilePath, driverConfigParams)
	initilizeDriverConfigParams()
	assert.Equal(t, log.InfoLevel, log.GetLevel())
	writeToFile(t, driverConfigParams, "CSI_LOG_LEVEL: \"info\"")
	time.Sleep(time.Second)
	assert.Equal(t, log.InfoLevel, log.GetLevel())
}

func TestMainControllerMode(t *testing.T) {
	tmpDir := t.TempDir()
	config := copyConfigFileToTmpDir(t, "../../pkg/array/testdata/one-arr.yaml", tmpDir)
	kubeconfig := createFakeKubeconfig(t, tmpDir)

	defaultK8sConfigFunc := k8sutils.InClusterConfigFunc
	defaultK8sClientsetFunc := k8sutils.NewForConfigFunc

	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewClientset(), nil
	}

	defer func() {
		k8sutils.InClusterConfigFunc = defaultK8sConfigFunc
		k8sutils.NewForConfigFunc = defaultK8sClientsetFunc
	}()

	// Set Manifest version similar to how the image would be built.
	ManifestSemver = "1.0.0"

	// Set required environment variables
	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv("CSI_ENDPOINT", "mock_endpoint")
	t.Setenv(identifiers.EnvDriverName, "test")
	t.Setenv(identifiers.EnvDebugEnableTracing, "true")
	t.Setenv("JAEGER_SERVICE_NAME", "controller-test")
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "true")
	t.Setenv("KUBECONFIG", kubeconfig)

	array2 := `  - endpoint: "https://127.0.0.2/api/rest"
    username: "admin"
    globalID: "gid2"
    password: "password"
    skipCertificateValidation: true
    blockProtocol: "auto"
    isDefault: false`

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
		require.EqualValues(t, 1, len(test.Controller.(*controller.Service).Arrays()))

		// Update the config file
		writeToFile(t, config, array2)
		time.Sleep(time.Second)

		// Assertions
		require.EqualValues(t, 2, len(test.Controller.(*controller.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainNodeMode(t *testing.T) {
	tmpDir := t.TempDir()
	config := copyConfigFileToTmpDir(t, "../../pkg/array/testdata/one-arr.yaml", tmpDir)
	kubeconfig := createFakeKubeconfig(t, tmpDir)

	defaultK8sConfigFunc := k8sutils.InClusterConfigFunc
	defaultK8sClientsetFunc := k8sutils.NewForConfigFunc

	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewClientset(), nil
	}

	defer func() {
		k8sutils.InClusterConfigFunc = defaultK8sConfigFunc
		k8sutils.NewForConfigFunc = defaultK8sClientsetFunc
	}()

	defaultInitNodeServiceFunc := initNodeServiceFunc
	initNodeServiceFunc = func(f fs.Interface, configPath string) (*node.Service, error) {
		ns := &node.Service{
			Fs: f,
		}
		if err := ns.UpdateArrays(configPath, f); err != nil {
			return nil, err
		}
		return ns, nil
	}
	defer func() { initNodeServiceFunc = defaultInitNodeServiceFunc }()

	// Set required environment variables
	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv(gocsi.EnvVarMode, "node")
	t.Setenv(identifiers.EnvDebugEnableTracing, "")
	t.Setenv(identifiers.EnvCSMDREnabled, "true")
	t.Setenv("KUBECONFIG", kubeconfig)
	tempNodeIDFile, err := os.CreateTemp(tmpDir, "node-id")
	require.NoError(t, err)
	t.Setenv("X_CSI_POWERSTORE_NODE_ID_PATH", tempNodeIDFile.Name())

	array2 := `  - endpoint: "https://127.0.0.2/api/rest"
    username: "admin"
    globalID: "gid2"
    password: "password"
    skipCertificateValidation: true
    blockProtocol: "auto"
    isDefault: false`

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.Nil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.NotNil(t, test.Node)
		require.EqualValues(t, 1, len(test.Node.(*node.Service).Arrays()))

		// Update the config file
		writeToFile(t, config, array2)
		time.Sleep(time.Second)

		// Assertions
		require.EqualValues(t, 2, len(test.Node.(*node.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func copyConfigFileToTmpDir(t *testing.T, src string, tmpDir string) string {
	t.Helper()

	srcF, err := os.Open(src)
	require.NoError(t, err)
	defer func() { _ = srcF.Close() }()

	dstF, err := os.CreateTemp(tmpDir, "config_*.yaml")
	require.NoError(t, err)
	defer func() { _ = dstF.Close() }()

	_, err = io.Copy(dstF, srcF)
	require.NoError(t, err)

	return dstF.Name()
}

func createFakeKubeconfig(t *testing.T, tmpDir string) string {
	t.Helper()

	fakeKubeconfig := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:8443
  name: fake-cluster
contexts:
- context:
    cluster: fake-cluster
    user: fake-user
  name: fake-context
current-context: fake-context
users:
- name: fake-user
`
	kubeconfigPath := filepath.Join(tmpDir, "kubeconfig")
	err := os.WriteFile(kubeconfigPath, []byte(fakeKubeconfig), 0o644)
	require.NoError(t, err)
	return kubeconfigPath
}

func writeToFile(t *testing.T, controllerConfigFile string, array2 string) {
	f, err := os.OpenFile(controllerConfigFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("failed to open confg file %s, err %v", controllerConfigFile, err)
	} else {
		defer func() { _ = f.Close() }()
		_, err = f.WriteString(array2 + "\n")
		if err != nil {
			t.Errorf("failed to update confg file %s, err %v", controllerConfigFile, err)
		}
	}
}

func TestUpdateDriverConfigParams(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetDefault("CSI_LOG_FORMAT", "text")
	v.SetDefault("CSI_LOG_LEVEL", "debug")

	viperChan := make(chan bool)
	v.WatchConfig()
	v.OnConfigChange(func(_ fsnotify.Event) {
		updateDriverConfigParams(v)
		viperChan <- true
	})

	logFormat := strings.ToLower(v.GetString("CSI_LOG_FORMAT"))
	assert.Equal(t, "text", logFormat)

	updateDriverConfigParams(v)
	level := log.GetLevel()

	assert.Equal(t, log.DebugLevel, level)

	v.Set("CSI_LOG_FORMAT", "json")
	v.Set("CSI_LOG_LEVEL", "info")
	updateDriverConfigParams(v)
	level = log.GetLevel()

	assert.Equal(t, log.InfoLevel, level)

	v.Set("CSI_LOG_LEVEL", "notalevel")
	updateDriverConfigParams(v)
	level = log.GetLevel()
	assert.Equal(t, log.InfoLevel, level)
}

func Test_initControllerService(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		init       func()
		f          func() fs.Interface
		configPath string
		want       *controller.Service
		wantErr    bool
	}{
		{
			name: "fail to update arrays",
			init: func() {},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", ".").Return([]byte{}, errors.New("read error"))
				return fs
			},
			configPath: "",
			want:       nil,
			wantErr:    true,
		},
		{
			name: "fail to initialize the controller service",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return nil, errors.New("new for config error")
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", "/some/config.yaml").Return([]byte{}, nil)
				return fs
			},
			configPath: "/some/config.yaml",
			want:       nil,
			wantErr:    true,
		},
		{
			name: "fail to create monitor service",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				callCount := 0
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					callCount++
					if callCount == 1 {
						return fake.NewClientset(), nil
					}
					return nil, errors.New("monitor k8s client error")
				}
				tempInClusterConfigFunc := k8sutils.InClusterConfigFunc
				k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
					return nil, nil
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
					k8sutils.InClusterConfigFunc = tempInClusterConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", ".").Return([]byte{}, nil)
				return fs
			},
			configPath: "",
			want:       nil,
			wantErr:    true,
		},
		{
			name: "fail to initialize the monitor service arrays",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return fake.NewClientset(), nil
				}
				tempInClusterConfigFunc := k8sutils.InClusterConfigFunc
				k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
					return nil, nil
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
					k8sutils.InClusterConfigFunc = tempInClusterConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", ".").Once().Return([]byte{}, nil)
				fs.On("ReadFile", ".").Once().Return([]byte{}, errors.New("monitor read error"))
				return fs
			},
			configPath: "",
			want:       nil,
			wantErr:    true,
		},
		{
			name: "success",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return fake.NewClientset(), nil
				}
				tempInClusterConfigFunc := k8sutils.InClusterConfigFunc
				k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
					return nil, nil
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
					k8sutils.InClusterConfigFunc = tempInClusterConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", ".").Return([]byte{}, nil)
				return fs
			},
			configPath: "",
			want: &controller.Service{
				Fs: &mocks.FsInterface{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.init()
			got, gotErr := initControllerService(tt.f(), tt.configPath)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("initControllerService() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("initControllerService() succeeded unexpectedly")
			}

			if got == nil {
				t.Error("initControllerService() expected a service struct but got nil")
			}
		})
	}
}

func Test_initNodeService(t *testing.T) {
	tests := []struct {
		name       string
		init       func()
		f          func() fs.Interface
		configPath string
		wantErr    bool
	}{
		{
			name: "fail to update arrays",
			init: func() {},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", ".").Return([]byte{}, errors.New("read error"))
				return fs
			},
			configPath: "",
			wantErr:    true,
		},
		{
			name: "fail to initialize the node service",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return nil, errors.New("k8s client error")
				}
				tempInClusterConfigFunc := k8sutils.InClusterConfigFunc
				k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
					return nil, nil
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
					k8sutils.InClusterConfigFunc = tempInClusterConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", "/some/config.yaml").Return([]byte{}, nil)
				return fs
			},
			configPath: "/some/config.yaml",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.init()
			got, gotErr := initNodeService(tt.f(), tt.configPath)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("initNodeService() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("initNodeService() succeeded unexpectedly")
			}
			if got == nil {
				t.Error("initNodeService() expected a service struct but got nil")
			}
		})
	}
}

func Test_initGroupControllerService(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		init       func()
		f          func() fs.Interface
		configPath string
		want       *groupcontroller.Service
		wantErr    bool
	}{
		{
			name: "fail to update arrays",
			init: func() {},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", ".").Return([]byte{}, errors.New("read error"))
				return fs
			},
			configPath: "",
			want:       nil,
			wantErr:    true,
		},
		{
			name: "fail to initialize the groupController service",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return nil, errors.New("new for config error")
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", "/some/config.yaml").Return([]byte{}, nil)
				return fs
			},
			configPath: "/some/config.yaml",
			want:       nil,
			wantErr:    true,
		},
		{
			name: "success",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return fake.NewClientset(), nil
				}
				tempInClusterConfigFunc := k8sutils.InClusterConfigFunc
				k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
					return nil, nil
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
					k8sutils.InClusterConfigFunc = tempInClusterConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", ".").Return([]byte{}, nil)
				return fs
			},
			configPath: "",
			want: &groupcontroller.Service{
				Fs: &mocks.FsInterface{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.init()
			got, gotErr := initGroupControllerService(tt.f(), tt.configPath)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("initGroupControllerService() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("initGroupControllerService() succeeded unexpectedly")
			}

			if got == nil {
				t.Error("initGroupControllerService() expected a service struct but got nil")
			}
		})
	}
}

func Test_validateAndSetDRBindPort(t *testing.T) {
	tests := []struct {
		name     string
		envPort  string
		expected string
	}{
		{
			name:     "Empty environment variable returns default port",
			envPort:  "",
			expected: ":8082",
		},
		{
			name:     "Valid port number returns port with colon prefix",
			envPort:  "9000",
			expected: ":9000",
		},
		{
			name:     "Valid port number 1 returns port with colon prefix",
			envPort:  "1",
			expected: ":1",
		},
		{
			name:     "Valid port number 65535 returns port with colon prefix",
			envPort:  "65535",
			expected: ":65535",
		},
		{
			name:     "Invalid non-numeric string returns default port",
			envPort:  "invalid",
			expected: ":8082",
		},
		{
			name:     "Invalid port 0 returns default port",
			envPort:  "0",
			expected: ":8082",
		},
		{
			name:     "Invalid port -1 returns default port",
			envPort:  "-1",
			expected: ":8082",
		},
		{
			name:     "Invalid port 65536 returns default port",
			envPort:  "65536",
			expected: ":8082",
		},
		{
			name:     "Invalid port 99999 returns default port",
			envPort:  "99999",
			expected: ":8082",
		},
		{
			name:     "Port with whitespace returns default port",
			envPort:  " 8080 ",
			expected: ":8082",
		},
		{
			name:     "Decimal port returns default port",
			envPort:  "8080.5",
			expected: ":8082",
		},
		{
			name:     "Empty string with spaces returns default port",
			envPort:  "   ",
			expected: ":8082",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateAndSetDRBindPort(tt.envPort)
			assert.Equal(t, tt.expected, result)
		})
	}
}
