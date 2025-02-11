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
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)


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