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

package service

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	nfsmock "github.com/dell/csm-sharednfs/nfs/mocks"
	"github.com/dell/gocsi"
	csictx "github.com/dell/gocsi/context"
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
)

func TestNew(t *testing.T) {
	assert.NotNil(t, New())
}

func TestVolumeIDToArrayID(t *testing.T) {
	t.Run("empty volume id", func(t *testing.T) {
		resp := New().VolumeIDToArrayID("")
		assert.Empty(t, resp)
	})

	t.Run("normal volume id", func(t *testing.T) {
		resp := New().VolumeIDToArrayID("123-456")
		assert.Equal(t, "123", resp)
	})
}

func TestRegisterAdditionalServers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockController := new(mocks.ControllerInterface)
	mockController.On("RegisterAdditionalServers", mock.Anything).Return()
	svc := New()
	PutControllerService(mockController)
	server := grpc.Server{}
	svc.RegisterAdditionalServers(&server)
}

func TestBeforeServe(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("no node name", func(t *testing.T) {
		mockNfs := nfsmock.NewMockService(ctrl)
		mockNfs.EXPECT().BeforeServe(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(fmt.Errorf("no node name"))
		PutNfsService(mockNfs)

		err := New().BeforeServe(context.Background(), &gocsi.StoragePlugin{}, nil)
		assert.Nil(t, err)
	})

	t.Run("X_CSI_POWERSTORE_NODE_CHROOT_PATH", func(t *testing.T) {
		os.Setenv("X_CSI_NODE_NAME", "test")
		ctx := context.Background()
		csictx.Setenv(ctx, gocsi.EnvVarMode, "node")

		err := New().BeforeServe(context.Background(), &gocsi.StoragePlugin{}, nil)
		assert.Error(t, err, fmt.Errorf("X_CSI_POWERSTORE_NODE_CHROOT_PATH environment variable not set"))
	})

	t.Run("success", func(t *testing.T) {
		os.Setenv("X_CSI_NODE_NAME", "test")
		ctx := context.Background()
		csictx.Setenv(ctx, gocsi.EnvVarMode, "node")
		os.Setenv(identifiers.EnvNodeChrootPath, "test-path")
		mockNfs := nfsmock.NewMockService(ctrl)
		mockNfs.EXPECT().BeforeServe(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
		PutNfsService(mockNfs)
		assert.Nil(t, New().BeforeServe(ctx, &gocsi.StoragePlugin{}, nil))
	})
}

func TestProcessMapSecretChange(t *testing.T) {
	err := New().ProcessMapSecretChange()
	assert.Nil(t, err)
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

	assert.Equal(t, logrus.DebugLevel, level)

	v.Set("CSI_LOG_FORMAT", "json")
	v.Set("CSI_LOG_LEVEL", "info")
	updateDriverConfigParams(v)
	level = log.GetLevel()
	assert.Equal(t, logrus.InfoLevel, level)

	v.Set("CSI_LOG_LEVEL", "notalevel")
	updateDriverConfigParams(v)
	level = log.GetLevel()
	assert.Equal(t, logrus.DebugLevel, level)
}
