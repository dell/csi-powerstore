// +build test

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

package service

import (
	"context"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gopowerstore/mock"
	"github.com/golang/mock/gomock"
	csictx "github.com/rexray/gocsi/context"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMock(t *testing.T) {
	c := gomock.NewController(t)
	var ifaceINT internalServiceAPI
	var ifaceEXT Service
	var ifaceFsLib wrapperFsLib
	var ifaceMountLib mountLib
	ifaceINT = NewMockinternalServiceAPI(c)
	ifaceEXT = NewMockService(c)
	ifaceFsLib = NewMockwrapperFsLib(c)
	ifaceMountLib = NewMockmountLib(c)
	assert.NotNil(t, ifaceEXT)
	assert.NotNil(t, ifaceINT)
	assert.NotNil(t, ifaceFsLib)
	assert.NotNil(t, ifaceMountLib)
}

func TestVolumeSize(t *testing.T) {
	tests := []struct {
		min int64
		max int64
		err error
	}{
		{
			-1,
			-1,
			status.Errorf(
				codes.OutOfRange,
				"bad capacity: volume size bytes -1 and limit size bytes: -1 must not be negative"),
		},
		{
			236364574767,
			235345345,
			status.Errorf(
				codes.OutOfRange,
				"bad capacity: max size bytes 235345345 can't be less than minimum size bytes 236364574767"),
		},
		{
			8192,
			MaxVolumeSizeBytes + 1,
			status.Errorf(
				codes.OutOfRange,
				"bad capacity: max size bytes %d can't be more than maximum size bytes %d",
				MaxVolumeSizeBytes+1, MaxVolumeSizeBytes),
		},
		{
			8192,
			MaxVolumeSizeBytes - 1,
			nil,
		},
	}

	for _, test := range tests {
		test := test
		t.Run("", func(st *testing.T) {
			st.Parallel()
			result := volumeSizeValidation(test.min, test.max)

			assert.Equal(t, result, test.err)
		})
	}
}

func TestVolumeName(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"IsOkName", nil},
		{"", status.Errorf(codes.InvalidArgument, "Name cannot be empty")},
		{strings.Repeat("N", MaxVolumeNameLength+1),
			status.Errorf(codes.InvalidArgument, "Name must contain %d or fewer printable Unicode characters", MaxVolumeNameLength)},
	}

	for _, test := range tests {
		test := test
		t.Run("", func(st *testing.T) {
			st.Parallel()
			result := volumeNameValidation(test.name)

			assert.Equal(t, result, test.err)
		})
	}
}

func TestGetVolumeSize(t *testing.T) {
	tests := []struct {
		cr         *csi.CapacityRange
		resultSize int64
		err        error
	}{
		{
			&csi.CapacityRange{
				RequiredBytes: 0,
				LimitBytes:    1099511627776,
			},
			MinVolumeSizeBytes,
			nil,
		},
		{
			&csi.CapacityRange{
				RequiredBytes: 236364578816,
				LimitBytes:    235345345,
			},
			0,
			status.Errorf(
				codes.OutOfRange,
				"bad capacity: max size bytes 235345345 can't be less than minimum size bytes 236364578816"),
		},
		{
			&csi.CapacityRange{
				RequiredBytes: VolumeSizeMultiple*30 - 5,
				LimitBytes:    1099511627776,
			},
			VolumeSizeMultiple * 30,
			nil,
		},
	}

	for _, test := range tests {
		test := test
		t.Run("", func(st *testing.T) {
			st.Parallel()
			size, err := getVolumeSize(test.cr)

			assert.Equal(t, test.resultSize, size)
			assert.Equal(t, test.err, err)
		})
	}
}

func TestSemaphore(t *testing.T) {
	f := func(sec int, ctx context.Context, ts timeoutSemaphore) error {
		if err := ts.Acquire(ctx); err != nil {
			return err
		}
		time.Sleep(time.Duration(sec) * time.Second)
		ts.Release(ctx)

		return nil
	}

	// long running function
	ts := newTimeoutSemaphore(1, 1)
	go f(3, context.Background(), ts)
	// wait for run long function
	time.Sleep(1 * time.Second)
	err := f(1, context.Background(), ts)
	assert.NotNil(t, err)

	// fast running function
	ts = newTimeoutSemaphore(3, 1)
	go f(1, context.Background(), ts)
	err = f(2, context.Background(), ts)
	assert.Nil(t, err)
}

func getAdminClient(t *testing.T) (*mock.MockClient, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	c := mock.NewMockClient(ctrl)
	return c, ctrl
}

func getNodeFSLibMock(t *testing.T) (*MockwrapperFsLib, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	c := NewMockwrapperFsLib(ctrl)
	return c, ctrl
}

func getServiceIMPLMock(t *testing.T) (*MockinternalServiceAPI, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	c := NewMockinternalServiceAPI(ctrl)
	return c, ctrl
}

func getFileReaderMock(t *testing.T) (*MockfileReader, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	c := NewMockfileReader(ctrl)
	return c, ctrl
}

func getGracefulStopperMock(t *testing.T) (*MockgracefulStopper, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	c := NewMockgracefulStopper(ctrl)
	return c, ctrl
}

func getFilePathMock(t *testing.T) (*MockfilePath, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	c := NewMockfilePath(ctrl)
	return c, ctrl
}

func getFileOpenerMock(t *testing.T) (*MocklimitedOSIFace, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	c := NewMocklimitedOSIFace(ctrl)
	return c, ctrl
}

func getLimiterdFileIFaceMock(t *testing.T) (*MocklimitedFileIFace, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	c := NewMocklimitedFileIFace(ctrl)
	return c, ctrl
}

func getIMPLWitIMPLMock(t *testing.T) (serviceIMPL, *MockinternalServiceAPI, *gomock.Controller) {
	svc := service{}
	implMock, ctrl := getServiceIMPLMock(t)
	svc.impl = implMock
	impl := serviceIMPL{&svc, implMock}
	return impl, implMock, ctrl
}

func TestService_getLogFields(t *testing.T) {
	testValue := "test val"
	// nil
	fields := getLogFields(nil)
	assert.Empty(t, fields)
	// no log fields in context
	ctx := context.Background()
	fields = getLogFields(ctx)
	assert.Empty(t, fields)
	// only request id
	ctx = context.Background()
	ctx = context.WithValue(ctx, csictx.RequestIDKey, testValue)
	fields = getLogFields(ctx)
	assert.Equal(t, testValue, fields["RequestID"])
	// fields without request id
	ctx = context.Background()
	initialFields := log.Fields{"Test": "test"}
	ctx = context.WithValue(ctx, contextLogFieldsKey, initialFields)
	fields = getLogFields(ctx)
	assert.Equal(t, "test", fields["Test"])
	assert.NotContains(t, fields, "RequestID")
	// fields and request id
	ctx = context.WithValue(ctx, csictx.RequestIDKey, testValue)
	fields = getLogFields(ctx)
	assert.Equal(t, "test", fields["Test"])
	assert.Contains(t, fields, "RequestID")
}

func TestService_setLogFields(t *testing.T) {
	// nil context
	testFields := log.Fields{"test": "test"}
	ctx := setLogFields(nil, testFields)
	assert.NotNil(t, ctx)
	assert.Contains(t, ctx.Value(contextLogFieldsKey).(log.Fields), "test")

	// context with already set fields
	ctx = context.Background()
	initialFields := log.Fields{"foo": "bar"}
	ctx = context.WithValue(ctx, "contextLogFieldsKey", initialFields)
	ctx = setLogFields(ctx, testFields)
	assert.NotNil(t, ctx)
	assert.Contains(t, ctx.Value(contextLogFieldsKey).(log.Fields), "test")
	assert.NotContains(t, ctx.Value(contextLogFieldsKey).(log.Fields), "foo")
}

func TestService_traceFuncCall(t *testing.T) {
	tracer := trace.New("Foo", "bar")
	defer tracer.Finish()
	ctx := trace.NewContext(context.Background(), tracer)
	// check for panic
	traceFuncCall(ctx, "foobar")
	traceFuncCall(context.Background(), "foobar")
}

func TestService_serviceIMPL_runDebugHTTPServer(t *testing.T) {
	svc := New().(*service)
	httpServerAddress := "127.0.0.1:8080"
	svc.opts.DebugHTTPServerListenAddress = httpServerAddress
	impl := svc.impl.(*serviceIMPL)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	gs := NewMockgracefulStopper(ctrl)
	gs.EXPECT().GracefulStop(gomock.Any())
	go impl.runDebugHTTPServer(context.Background(), gs)

	// check server available
	time.Sleep(time.Second * 2)
	_, err := http.Get(
		fmt.Sprintf("http://%s/debug/requests", httpServerAddress))
	assert.Nil(t, err)
	err = svc.debugHTTPServer.Shutdown(context.Background())
	assert.Nil(t, err)
	time.Sleep(time.Second * 2)
}

func TestService_getTransportProtocolFromEnv(t *testing.T) {
	assert.Nil(t, os.Unsetenv(EnvPreferredTransportProtocol))
	assert.Equal(t, getTransportProtocolFromEnv(), autoDetectTransport)
	assert.Nil(t, os.Setenv(EnvPreferredTransportProtocol, "FC"))
	assert.Equal(t, getTransportProtocolFromEnv(), fcTransport)
	assert.Nil(t, os.Setenv(EnvPreferredTransportProtocol, "iSCSI"))
	assert.Equal(t, getTransportProtocolFromEnv(), iSCSITransport)
	assert.Nil(t, os.Setenv(EnvPreferredTransportProtocol, "foobar"))
	assert.Equal(t, getTransportProtocolFromEnv(), autoDetectTransport)
}

func TestService_customLogger(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	lg := &customLogger{}
	ctx := context.Background()
	lg.Info(ctx, "foo")
	lg.Debug(ctx, "bar")
	lg.Error(ctx, "spam")
}
