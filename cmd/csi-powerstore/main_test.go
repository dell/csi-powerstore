/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	"github.com/dell/gocsi"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			err := os.Setenv(common.EnvDriverName, tc.envVar)
			if err != nil {
				t.Fatalf("Failed to set environment variable: %v", err)
			}

			updateDriverName()

			assert.Equal(t, tc.expected, common.Name)
		})
	}
}

func TestInitilizeDriverConfigParams(t *testing.T) {
	tmpDir := t.TempDir()
	content := `CSI_LOG_FORMAT: "JSON"`
	driverConfigParams := filepath.Join(tmpDir, "driver-config-params.yaml")
	writeToFile(t, driverConfigParams, content)
	os.Setenv(common.EnvConfigParamsFilePath, driverConfigParams)
	initilizeDriverConfigParams()
	assert.Equal(t, log.DebugLevel, log.GetLevel())
	writeToFile(t, driverConfigParams, "CSI_LOG_LEVEL: \"info\"")
	time.Sleep(time.Second)
	assert.Equal(t, log.InfoLevel, log.GetLevel())
}

func TestMainControllerMode(t *testing.T) {
	tmpDir := t.TempDir()
	config := copyConfigFileToTmpDir(t, "../../pkg/array/testdata/one-arr.yaml", tmpDir)

	// Set required environment variables
	os.Setenv(common.EnvArrayConfigFilePath, config)
	os.Setenv("CSI_ENDPOINT", "mock_endpoint")
	os.Setenv(common.EnvDriverName, "test")
	os.Setenv(common.EnvDebugEnableTracing, "true")
	os.Setenv("JAEGER_SERVICE_NAME", "controller-test")
	os.Setenv(string(gocsi.EnvVarMode), "controller")

	array2 := `  - endpoint: "https://127.0.0.2/api/rest"
    username: "admin"
    globalID: "gid2"
    password: "password"
    skipCertificateValidation: true
    blockProtocol: "auto"
    isDefault: false`

	_ = func(test *gocsi.StoragePlugin) {
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

	// Set required environment variables
	os.Setenv(common.EnvArrayConfigFilePath, config)
	os.Setenv(gocsi.EnvVarMode, "node")
	os.Setenv(common.EnvDebugEnableTracing, "")
	tempNodeIDFile, err := os.CreateTemp("", "node-id")
	require.NoError(t, err)
	defer os.Remove(tempNodeIDFile.Name())
	os.Setenv("X_CSI_POWERSTORE_NODE_ID_PATH", tempNodeIDFile.Name())

	array2 := `  - endpoint: "https://127.0.0.2/api/rest"
    username: "admin"
    globalID: "gid2"
    password: "password"
    skipCertificateValidation: true
    blockProtocol: "auto"
    isDefault: false`

	_ = func(test *gocsi.StoragePlugin) {
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
	defer srcF.Close()

	dstF, err := os.CreateTemp(tmpDir, "config_*.yaml")
	require.NoError(t, err)
	defer dstF.Close()

	_, err = io.Copy(dstF, srcF)
	require.NoError(t, err)

	return dstF.Name()
}

func writeToFile(t *testing.T, controllerConfigFile string, array2 string) {
	f, err := os.OpenFile(controllerConfigFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("failed to open confg file %s, err %v", controllerConfigFile, err)
	} else {
		defer f.Close()
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
	logFormatter, ok := log.StandardLogger().Formatter.(*log.JSONFormatter)
	assert.True(t, ok)
	assert.Equal(t, time.RFC3339Nano, logFormatter.TimestampFormat)

	v.Set("CSI_LOG_LEVEL", "notalevel")
	updateDriverConfigParams(v)
	level = log.GetLevel()
	assert.Equal(t, log.DebugLevel, level)
}
