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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/gocsi"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(t *testing.T) {
	// Set required environment variables
	os.Setenv("X_CSI_POWERSTORE_CONFIG_PATH", "../../pkg/array/testdata/one-arr.yaml")
	os.Setenv("CSI_ENDPOINT", "mock_endpoint")
	os.Setenv(common.EnvDebugEnableTracing, "true")
	os.Setenv("JAEGER_SERVICE_NAME", "controller-test")
	os.Setenv(common.EnvDriverName, "test")

	t.Run("ControllerMode", func(t *testing.T) {
		os.Setenv(string(gocsi.EnvVarMode), "controller")

		runCSIPlugin = func(test *gocsi.StoragePlugin) {
			// Assertions
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
	})

	t.Run("NodeMode", func(t *testing.T) {
		os.Setenv(gocsi.EnvVarMode, "node")
		os.Setenv(common.EnvDebugEnableTracing, "")
		tempNodeIDFile, err := os.CreateTemp("", "node-id")
		require.NoError(t, err)
		defer os.Remove(tempNodeIDFile.Name())
		os.Setenv("X_CSI_POWERSTORE_NODE_ID_PATH", tempNodeIDFile.Name())

		runCSIPlugin = func(test *gocsi.StoragePlugin) {
			// Assertions
			require.Nil(t, test.Controller)
			require.NotNil(t, test.Identity)
			require.NotNil(t, test.Node)
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the code panicked with error: %v", r)
			}
		}()

		main()
	})

}

func TestUpdateDriverConfigParams(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetDefault("CSI_LOG_FORMAT", "text")
	v.SetDefault("CSI_LOG_LEVEL", "debug")

	viperChan := make(chan bool)
	v.WatchConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
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
