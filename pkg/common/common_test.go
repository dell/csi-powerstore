/*
 *
 * Copyright © 2021 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package common_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/dell/csi-powerstore/mocks"
	"github.com/dell/csi-powerstore/pkg/common"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gocsi/utils"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCustomLogger(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	lg := &common.CustomLogger{}
	ctx := context.Background()
	lg.Info(ctx, "foo")
	lg.Debug(ctx, "bar")
	lg.Error(ctx, "spam")
}

func TestRmSockFile(t *testing.T) {
	sockPath := "unix:///var/run/csi/csi.sock"
	trimmedSockPath := "/var/run/csi/csi.sock"
	_ = os.Setenv(utils.CSIEndpoint, sockPath)

	t.Run("removed socket", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, nil)
		fsMock.On("RemoveAll", trimmedSockPath).Return(nil)

		common.RmSockFile(fsMock)
	})

	t.Run("failed to remove socket", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, nil)
		fsMock.On("RemoveAll", trimmedSockPath).Return(fmt.Errorf("some error"))

		common.RmSockFile(fsMock)
	})

	t.Run("not found", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, os.ErrNotExist)

		common.RmSockFile(fsMock)
	})

	t.Run("may or may not exist", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("Stat", trimmedSockPath).Return(&mocks.FileInfo{}, fmt.Errorf("some other error"))

		common.RmSockFile(fsMock)
	})

	t.Run("no endpoint set", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		_ = os.Setenv(utils.CSIEndpoint, "")

		common.RmSockFile(fsMock)
	})

}

func TestSetLogFields(t *testing.T) {
	t.Run("empty context", func(t *testing.T) {
		common.SetLogFields(nil, log.Fields{})
	})
}

func TestGetLogFields(t *testing.T) {
	t.Run("empty context", func(t *testing.T) {
		fields := common.GetLogFields(nil)
		assert.Equal(t, log.Fields{}, fields)
	})

	t.Run("req id", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), csictx.RequestIDKey, "1")
		fields := common.GetLogFields(ctx)
		assert.Equal(t, log.Fields{"RequestID": "1"}, fields)
	})
}

func TestGetFCTargetsInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetFCPorts", context.Background()).Return([]gopowerstore.FcPort{}, e)
		_, err := common.GetFCTargetsInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})
}

func TestGetNVMEFCTargetInfoFromStorage(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		e := errors.New("some error")
		clientMock := new(gopowerstoremock.Client)
		clientMock.On("GetCluster", context.Background()).Return(gopowerstore.Cluster{}, e)
		clientMock.On("GetFCPorts", context.Background()).Return([]gopowerstore.FcPort{}, e)
		_, err := common.GetNVMEFCTargetInfoFromStorage(clientMock, "A1")
		assert.EqualError(t, err, e.Error())
	})
}
