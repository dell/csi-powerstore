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
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/collectors"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/groupcontroller"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csi-powerstore/v2/pkg/metricsruntime"
	"github.com/dell/csi-powerstore/v2/pkg/monitor"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	log "github.com/dell/csmlog"
	"github.com/dell/gocsi"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
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
	t.Setenv(identifiers.EnvCSMDREnabled, "false") // Disable CSM DR to avoid port conflicts
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
	initNodeServiceFunc = func(f fs.Interface, configPath string, metricsRegistry prometheus.Registerer) (*node.Service, error) {
		ns := &node.Service{
			Fs: f,
		}
		if err := ns.UpdateArrays(configPath, f, metricsRegistry); err != nil {
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
			name: "monitor bootstrap is no longer part of controller initialization",
			init: func() {
				tempInClusterConfigFunc := k8sutils.InClusterConfigFunc
				k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
					return &rest.Config{}, nil
				}
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return fake.NewClientset(), nil
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
			want:       &controller.Service{Fs: &mocks.FsInterface{}},
			wantErr:    false,
		},
		{
			name: "monitor service array reloads are no longer part of controller initialization",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return fake.NewClientset(), nil
				}
				tempInClusterConfigFunc := k8sutils.InClusterConfigFunc
				k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
					return &rest.Config{}, nil
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
			want:       &controller.Service{Fs: &mocks.FsInterface{}},
			wantErr:    false,
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
					return &rest.Config{}, nil
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
			got, gotErr := initControllerService(tt.f(), tt.configPath, prometheus.NewRegistry())
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
					return &rest.Config{}, nil
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
					k8sutils.InClusterConfigFunc = tempInClusterConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", "/some/config.yaml").Return([]byte{}, nil)
				fs.On("ReadFile", "").Return([]byte{}, nil)
				return fs
			},
			configPath: "/some/config.yaml",
			wantErr:    true,
		},
		{
			name: "fail to init node service - Init error",
			init: func() {
				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return fake.NewClientset(), nil
				}
				tempInClusterConfigFunc := k8sutils.InClusterConfigFunc
				k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
					return &rest.Config{}, nil
				}
				t.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
					k8sutils.InClusterConfigFunc = tempInClusterConfigFunc
				})
			},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", "/some/config.yaml").Return([]byte{}, nil)
				fs.On("ReadFile", "").Return([]byte{}, nil)
				return fs
			},
			configPath: "/some/config.yaml",
			wantErr:    true,
		},
		{
			name: "fail to init node service - UpdateArrays error with empty config",
			init: func() {},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", "").Return([]byte{}, errors.New("read error"))
				fs.On("ReadFile", ".").Return([]byte{}, errors.New("read error"))
				return fs
			},
			configPath: "",
			wantErr:    true,
		},
		{
			name: "fail to init node service - UpdateArrays error with config path",
			init: func() {},
			f: func() fs.Interface {
				fs := &mocks.FsInterface{}
				fs.On("ReadFile", "/test/config.yaml").Return([]byte{}, errors.New("read error"))
				fs.On("ReadFile", "").Return([]byte{}, errors.New("read error"))
				fs.On("ReadFile", ".").Return([]byte{}, errors.New("read error"))
				return fs
			},
			configPath: "/test/config.yaml",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.init()
			got, gotErr := initNodeService(tt.f(), tt.configPath, prometheus.NewRegistry())
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
					return &rest.Config{}, nil
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
			got, gotErr := initGroupControllerService(tt.f(), tt.configPath, prometheus.NewRegistry())
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

func Test_ensureKubeClient(t *testing.T) {
	// Save the original global variable
	originalKubeclient := k8sutils.Kubeclient
	defer func() {
		k8sutils.Kubeclient = originalKubeclient
	}()

	// Test case 1: Global Kubeclient is already set
	t.Run("returns existing global kubeclient", func(t *testing.T) {
		k8sutils.Kubeclient = &k8sutils.K8sClient{
			Clientset: fake.NewClientset(),
		}

		client, err := ensureKubeClient(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.Same(t, k8sutils.Kubeclient, client)
	})

	// Test case 2: Global Kubeclient is nil or has nil Clientset
	t.Run("creates new kubeclient when global is nil", func(t *testing.T) {
		k8sutils.Kubeclient = nil

		defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc
		defaultNewForConfigFunc := k8sutils.NewForConfigFunc

		k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
			return &rest.Config{}, nil
		}
		k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
			return fake.NewClientset(), nil
		}

		defer func() {
			k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
			k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		}()

		client, err := ensureKubeClient(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	// Test case 3: Global Kubeclient exists but Clientset is nil
	t.Run("creates new kubeclient when global clientset is nil", func(t *testing.T) {
		k8sutils.Kubeclient = &k8sutils.K8sClient{
			Clientset: nil,
		}

		defaultInClusterConfigFunc := k8sutils.InClusterConfigFunc
		defaultNewForConfigFunc := k8sutils.NewForConfigFunc

		k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
			return &rest.Config{}, nil
		}
		k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
			return fake.NewClientset(), nil
		}

		defer func() {
			k8sutils.InClusterConfigFunc = defaultInClusterConfigFunc
			k8sutils.NewForConfigFunc = defaultNewForConfigFunc
		}()

		client, err := ensureKubeClient(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestUpdateDriverConfigParams_LogFormatText(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")

	v.Set("CSI_LOG_FORMAT", "text")
	updateDriverConfigParams(v)

	// Log format should be set (we can't check the format directly, but we can verify it doesn't panic)
	assert.Equal(t, log.InfoLevel, log.GetLevel())
}

func TestUpdateDriverConfigParams_LogLevelNotSet(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")

	// Don't set CSI_LOG_LEVEL
	updateDriverConfigParams(v)

	// Log level should default to info
	assert.Equal(t, log.InfoLevel, log.GetLevel())
}

func TestUpdateDriverConfigParams_LogLevelEmpty(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")

	v.Set("CSI_LOG_LEVEL", "")
	updateDriverConfigParams(v)

	// Log level should default to info when empty
	assert.Equal(t, log.InfoLevel, log.GetLevel())
}

func TestUpdateDriverConfigParams_LogFormatInvalid(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")

	v.Set("CSI_LOG_FORMAT", "invalid")
	updateDriverConfigParams(v)

	// Log format should default to json when invalid (we can't check format directly)
	assert.Equal(t, log.InfoLevel, log.GetLevel())
}

func TestMainControllerMode_MetricsDisabled(t *testing.T) {
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
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "false") // Disable CSM DR to avoid port conflicts
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv(identifiers.EnvMetricsEnabled, "false") // Disable metrics

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
		require.EqualValues(t, 1, len(test.Controller.(*controller.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainControllerMode_TracingDisabled(t *testing.T) {
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
	t.Setenv(identifiers.EnvDebugEnableTracing, "") // Disable tracing
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "false") // Disable CSM DR to avoid port conflicts
	t.Setenv("KUBECONFIG", kubeconfig)

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
		require.EqualValues(t, 1, len(test.Controller.(*controller.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainControllerMode_CSMDRDisabled(t *testing.T) {
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
	t.Setenv(identifiers.EnvDebugEnableTracing, "")
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "false") // Disable CSM DR
	t.Setenv("KUBECONFIG", kubeconfig)

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
		require.EqualValues(t, 1, len(test.Controller.(*controller.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainNodeMode_MetricsDisabled(t *testing.T) {
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
	initNodeServiceFunc = func(f fs.Interface, configPath string, metricsRegistry prometheus.Registerer) (*node.Service, error) {
		ns := &node.Service{
			Fs: f,
		}
		if err := ns.UpdateArrays(configPath, f, metricsRegistry); err != nil {
			return nil, err
		}
		return ns, nil
	}
	defer func() { initNodeServiceFunc = defaultInitNodeServiceFunc }()

	// Set required environment variables
	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv(gocsi.EnvVarMode, "node")
	t.Setenv(identifiers.EnvDebugEnableTracing, "")
	t.Setenv(identifiers.EnvCSMDREnabled, "false")
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv(identifiers.EnvMetricsEnabled, "false") // Disable metrics
	tempNodeIDFile, err := os.CreateTemp(tmpDir, "node-id")
	require.NoError(t, err)
	t.Setenv("X_CSI_POWERSTORE_NODE_ID_PATH", tempNodeIDFile.Name())

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.Nil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.NotNil(t, test.Node)
		require.EqualValues(t, 1, len(test.Node.(*node.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainNodeMode_CSMDRDisabled(t *testing.T) {
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
	initNodeServiceFunc = func(f fs.Interface, configPath string, metricsRegistry prometheus.Registerer) (*node.Service, error) {
		ns := &node.Service{
			Fs: f,
		}
		if err := ns.UpdateArrays(configPath, f, metricsRegistry); err != nil {
			return nil, err
		}
		return ns, nil
	}
	defer func() { initNodeServiceFunc = defaultInitNodeServiceFunc }()

	// Set required environment variables
	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv(gocsi.EnvVarMode, "node")
	t.Setenv(identifiers.EnvDebugEnableTracing, "")
	t.Setenv(identifiers.EnvCSMDREnabled, "false")
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv("CSI_ENDPOINT", "mock_endpoint")
	tempNodeIDFile, err := os.CreateTemp(tmpDir, "node-id")
	require.NoError(t, err)
	t.Setenv("X_CSI_POWERSTORE_NODE_ID_PATH", tempNodeIDFile.Name())

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.Nil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.NotNil(t, test.Node)
		require.EqualValues(t, 1, len(test.Node.(*node.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainControllerMode_CSMDREnabled_DifferentPort(t *testing.T) {
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
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "true")
	t.Setenv(identifiers.EnvCSMDRBindPort, "8083") // Use different port to avoid conflicts
	t.Setenv("KUBECONFIG", kubeconfig)

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
		require.EqualValues(t, 1, len(test.Controller.(*controller.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainControllerMode_EmptyManifestSemver(t *testing.T) {
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

	// Don't set Manifest version to test empty case
	ManifestSemver = ""

	// Set required environment variables
	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv("CSI_ENDPOINT", "mock_endpoint")
	t.Setenv(identifiers.EnvDriverName, "test")
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "false") // Disable CSM DR to avoid port conflicts
	t.Setenv("KUBECONFIG", kubeconfig)

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
		require.EqualValues(t, 1, len(test.Controller.(*controller.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestHandleConfigChange_ControllerMode(t *testing.T) {
	tmpDir := t.TempDir()
	config := copyConfigFileToTmpDir(t, "../../pkg/array/testdata/one-arr.yaml", tmpDir)

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

	// Create controller service
	f := &mocks.FsInterface{}
	f.On("ReadFile", config).Return([]byte{}, nil)
	controllerService, err := initControllerService(f, config, prometheus.NewRegistry())
	require.NoError(t, err)
	require.NotNil(t, controllerService)

	// Create group controller service
	groupControllerService, err := initGroupControllerService(f, config, prometheus.NewRegistry())
	require.NoError(t, err)
	require.NotNil(t, groupControllerService)

	// Test config change handler with metrics disabled
	e := fsnotify.Event{
		Name: config,
		Op:   fsnotify.Write,
	}
	registry := prometheus.NewRegistry()
	var mu sync.Mutex
	var metricsState *metricsruntime.RuntimeState
	handleConfigChange(e, "controller", f, config, registry, false, nil, &mu, &metricsState, &collectors.SharedMetadataChecker{}, controllerService, groupControllerService, nil, nil)

	// Test with metrics enabled (but with nil metricsServer to avoid actual server startup)
	// This will cover the metricsEnabled branch
	handleConfigChange(e, "controller", f, config, registry, true, nil, &mu, &metricsState, &collectors.SharedMetadataChecker{}, controllerService, groupControllerService, nil, nil)
}

func TestHandleConfigChange_ControllerMode_WithMonitor(t *testing.T) {
	tmpDir := t.TempDir()
	config := copyConfigFileToTmpDir(t, "../../pkg/array/testdata/one-arr.yaml", tmpDir)

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

	// Create controller service
	f := &mocks.FsInterface{}
	f.On("ReadFile", config).Return([]byte{}, nil)
	controllerService, err := initControllerService(f, config, prometheus.NewRegistry())
	require.NoError(t, err)
	require.NotNil(t, controllerService)

	// Create group controller service
	groupControllerService, err := initGroupControllerService(f, config, prometheus.NewRegistry())
	require.NoError(t, err)
	require.NotNil(t, groupControllerService)

	// Create a monitor service
	monitorService := &monitor.Service{}
	monitorService.SetArrays(controllerService.Arrays())
	monitorService.SetDefaultArray(controllerService.DefaultArray())

	// Test config change handler with monitor service
	e := fsnotify.Event{
		Name: config,
		Op:   fsnotify.Write,
	}
	var metricsState *metricsruntime.RuntimeState
	var mu sync.Mutex
	handleConfigChange(e, "controller", f, config, prometheus.NewRegistry(), false, nil, &mu, &metricsState, &collectors.SharedMetadataChecker{}, controllerService, groupControllerService, nil, monitorService)
}

func TestHandleConfigChange_NodeMode(t *testing.T) {
	tmpDir := t.TempDir()
	config := copyConfigFileToTmpDir(t, "../../pkg/array/testdata/one-arr.yaml", tmpDir)

	// Create a mock node service
	nodeService := &node.Service{}
	f := &mocks.FsInterface{}
	f.On("ReadFile", config).Return([]byte{}, nil)

	// Test config change handler with metrics disabled
	e := fsnotify.Event{
		Name: config,
		Op:   fsnotify.Write,
	}
	registry := prometheus.NewRegistry()
	var metricsState *metricsruntime.RuntimeState
	var mu sync.Mutex
	handleConfigChange(e, "node", f, config, registry, false, nil, &mu, &metricsState, &collectors.SharedMetadataChecker{}, nil, nil, nodeService, nil)

	// Test with metrics enabled (but with nil metricsServer to avoid actual server startup)
	// This will cover the metricsEnabled branch
	handleConfigChange(e, "node", f, config, registry, true, nil, &mu, &metricsState, &collectors.SharedMetadataChecker{}, nil, nil, nodeService, nil)
}

func TestSetupGracefulShutdown(_ *testing.T) {
	// Test that setupGracefulShutdown doesn't panic
	// We can't easily test the actual signal handling in unit tests,
	// but we can at least verify it starts without error
	var mu sync.Mutex
	var metricsState *metricsruntime.RuntimeState
	setupGracefulShutdown("controller", &mu, &metricsState, nil)

	// Give it a moment to start the goroutine
	time.Sleep(10 * time.Millisecond)

	// Test with a non-nil metricsState
	metricsStateWithValue := &metricsruntime.RuntimeState{}
	setupGracefulShutdown("node", &mu, &metricsStateWithValue, nil)

	// Give it a moment to start the goroutine
	time.Sleep(10 * time.Millisecond)
}

// mockMonitorService is a test double for monitor.IMonitorService that captures
// whether Start was called and with what poll interval.
type mockMonitorService struct {
	monitor.Service
	startCalled  bool
	pollInterval time.Duration
	startCh      chan struct{}
}

func (m *mockMonitorService) Start(_ context.Context, pollPeriod time.Duration) {
	m.startCalled = true
	m.pollInterval = pollPeriod
	close(m.startCh)
}

// monitorTestHelper sets up common infrastructure for monitor-related main() tests.
// It returns a cleanup function and the mockMonitorService so callers can assert on it.
func monitorTestHelper(t *testing.T) (*mockMonitorService, func()) {
	t.Helper()

	defaultNewMonitorServiceFunc := newMonitorServiceFunc
	mockMon := &mockMonitorService{startCh: make(chan struct{})}
	newMonitorServiceFunc = func(_ context.Context) (monitor.IMonitorService, error) {
		return mockMon, nil
	}

	defaultK8sConfigFunc := k8sutils.InClusterConfigFunc
	defaultK8sClientsetFunc := k8sutils.NewForConfigFunc
	k8sutils.InClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
		return fake.NewClientset(), nil
	}

	ManifestSemver = "1.0.0"

	cleanup := func() {
		newMonitorServiceFunc = defaultNewMonitorServiceFunc
		k8sutils.InClusterConfigFunc = defaultK8sConfigFunc
		k8sutils.NewForConfigFunc = defaultK8sClientsetFunc
	}
	return mockMon, cleanup
}

func TestMainControllerMode_MonitorService(t *testing.T) {
	tests := []struct {
		name               string
		monitorEnabled     string
		pollInterval       string
		expectStartCalled  bool
		expectPollInterval time.Duration
	}{
		{
			name:              "disabled",
			monitorEnabled:    "false",
			pollInterval:      "",
			expectStartCalled: false,
		},
		{
			name:               "custom poll interval",
			monitorEnabled:     "true",
			pollInterval:       "10m",
			expectStartCalled:  true,
			expectPollInterval: 10 * time.Minute,
		},
		{
			name:               "invalid poll interval falls back to default",
			monitorEnabled:     "true",
			pollInterval:       "not-a-duration",
			expectStartCalled:  true,
			expectPollInterval: 5 * time.Minute,
		},
		{
			name:               "default when enabled with no interval set",
			monitorEnabled:     "true",
			pollInterval:       "",
			expectStartCalled:  true,
			expectPollInterval: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMon, cleanup := monitorTestHelper(t)
			defer cleanup()

			tmpDir := t.TempDir()
			config := copyConfigFileToTmpDir(t, "../../pkg/array/testdata/one-arr.yaml", tmpDir)
			kubeconfig := createFakeKubeconfig(t, tmpDir)

			t.Setenv(identifiers.EnvArrayConfigFilePath, config)
			t.Setenv("CSI_ENDPOINT", "mock_endpoint")
			t.Setenv(identifiers.EnvDriverName, "test")
			t.Setenv(string(gocsi.EnvVarMode), "controller")
			t.Setenv(identifiers.EnvCSMDREnabled, "false")
			t.Setenv("KUBECONFIG", kubeconfig)
			t.Setenv(identifiers.EnvMonitorEnabled, tt.monitorEnabled)
			if tt.pollInterval != "" {
				t.Setenv(identifiers.EnvMonitorPollInterval, tt.pollInterval)
			}

			runCSIPlugin = func(test *gocsi.StoragePlugin) {
				require.NotNil(t, test.Controller)
				require.NotNil(t, test.Identity)
				require.Nil(t, test.Node)
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("the code panicked with error: %v", r)
				}
			}()

			main()

			if tt.expectStartCalled {
				select {
				case <-mockMon.startCh:
				case <-time.After(2 * time.Second):
					t.Fatal("timed out waiting for monitor Start() to be called")
				}
				assert.Equal(t, tt.expectPollInterval, mockMon.pollInterval, "unexpected monitor poll interval")
			} else {
				// Give the goroutine a moment to ensure Start is NOT called
				time.Sleep(50 * time.Millisecond)
				assert.False(t, mockMon.startCalled, "monitor Start() should not be called")
			}
		})
	}
}

func TestMainControllerMode_CSMDRInvalidParseDefaultsTrue(t *testing.T) {
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

	ManifestSemver = "1.0.0"

	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv("CSI_ENDPOINT", "mock_endpoint")
	t.Setenv(identifiers.EnvDriverName, "test")
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "not-a-bool")
	t.Setenv(identifiers.EnvCSMDRBindPort, "8084")
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv(identifiers.EnvMonitorEnabled, "false")

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestSetupGracefulShutdown_SignalHandling(t *testing.T) {
	var mu sync.Mutex
	var metricsState *metricsruntime.RuntimeState
	setupGracefulShutdown("controller", &mu, &metricsState, nil)

	// Send SIGTERM to trigger the signal handler
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)

	// Give the goroutine time to set up signal.Notify
	time.Sleep(50 * time.Millisecond)

	err = p.Signal(syscall.SIGUSR1)
	// SIGUSR1 won't be caught but verifies no panic; actual SIGTERM would exit the test
	assert.NoError(t, err)
}

func TestSetupGracefulShutdown_WithMetricsState(t *testing.T) {
	var mu sync.Mutex
	metricsState := &metricsruntime.RuntimeState{}
	originalState := metricsState
	setupGracefulShutdown("node", &mu, &metricsState, nil)

	time.Sleep(50 * time.Millisecond)

	// Verify the metricsState pointer was not modified by setup (only modified on signal)
	assert.Same(t, originalState, metricsState, "metricsState should not be modified during setup")
}

func TestHandleConfigChange_UnknownMode(t *testing.T) {
	e := fsnotify.Event{
		Name: "test-config.yaml",
		Op:   fsnotify.Write,
	}
	var metricsState *metricsruntime.RuntimeState
	var mu sync.Mutex

	// handleConfigChange with an unknown mode should be a no-op:
	// it should not panic and should not modify the metricsState.
	handleConfigChange(e, "unknown", nil, "", prometheus.NewRegistry(), false, nil, &mu, &metricsState, &collectors.SharedMetadataChecker{}, nil, nil, nil, nil)

	assert.Nil(t, metricsState, "metricsState should remain nil for unknown mode (no-op)")
}

func TestMainNodeMode_MetricsEnabled(t *testing.T) {
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
	initNodeServiceFunc = func(f fs.Interface, configPath string, metricsRegistry prometheus.Registerer) (*node.Service, error) {
		ns := &node.Service{
			Fs: f,
		}
		if err := ns.UpdateArrays(configPath, f, metricsRegistry); err != nil {
			return nil, err
		}
		return ns, nil
	}
	defer func() { initNodeServiceFunc = defaultInitNodeServiceFunc }()

	// Set required environment variables
	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv(gocsi.EnvVarMode, "node")
	t.Setenv(identifiers.EnvDebugEnableTracing, "")
	t.Setenv(identifiers.EnvCSMDREnabled, "false")
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv("CSI_ENDPOINT", "mock_endpoint")
	t.Setenv(identifiers.EnvMetricsEnabled, "true")
	tempNodeIDFile, err := os.CreateTemp(tmpDir, "node-id")
	require.NoError(t, err)
	t.Setenv("X_CSI_POWERSTORE_NODE_ID_PATH", tempNodeIDFile.Name())

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		// Assertions
		require.Nil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.NotNil(t, test.Node)
		require.EqualValues(t, 1, len(test.Node.(*node.Service).Arrays()))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainControllerMode_CSIAddonsReplicationEnabled(t *testing.T) {
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

	ManifestSemver = "1.0.0"

	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv("CSI_ENDPOINT", "mock_endpoint")
	t.Setenv(identifiers.EnvDriverName, "test")
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "false")
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv(identifiers.EnvMonitorEnabled, "false")

	// Enable CSI Addons
	t.Setenv(identifiers.EnvCSIAddonsReplicationEnabled, "true")

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}

func TestMainControllerMode_CSIAddonsReplicationParseErr(t *testing.T) {
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

	ManifestSemver = "1.0.0"

	t.Setenv(identifiers.EnvArrayConfigFilePath, config)
	t.Setenv("CSI_ENDPOINT", "mock_endpoint")
	t.Setenv(identifiers.EnvDriverName, "test")
	t.Setenv(string(gocsi.EnvVarMode), "controller")
	t.Setenv(identifiers.EnvCSMDREnabled, "false")
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv(identifiers.EnvMonitorEnabled, "false")

	// Error parsing
	t.Setenv(identifiers.EnvCSIAddonsReplicationEnabled, "not_bool")

	runCSIPlugin = func(test *gocsi.StoragePlugin) {
		require.NotNil(t, test.Controller)
		require.NotNil(t, test.Identity)
		require.Nil(t, test.Node)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the code panicked with error: %v", r)
		}
	}()

	main()
}
