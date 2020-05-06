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
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"sync"
	"testing"
	"time"

	csictx "github.com/rexray/gocsi/context"
)

const testID = "111"

func testHandler(ctx context.Context, _ interface{}) (interface{}, error) {
	return ctx, nil
}

func TestRewriteRequestIDInterceptor_RequestIDExist(t *testing.T) {
	handleInterceptor := NewRewriteRequestIDInterceptor()
	ctx := new(context.Context)
	md := metadata.Pairs()
	*ctx = metadata.NewIncomingContext(*ctx, md)
	md[csictx.RequestIDKey] = []string{testID}

	newCtx, _ := handleInterceptor(*ctx, nil, nil, testHandler)
	requestID, ok := newCtx.(context.Context).Value(csictx.RequestIDKey).(string)

	assert.Equal(t, ok, true)
	assert.Equal(t, requestID, fmt.Sprintf("%s-%s", csictx.RequestIDKey, testID))
}

func getSleepHandler(millisec int) grpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		fmt.Println("start sleep")
		time.Sleep(time.Duration(millisec) * time.Millisecond)
		fmt.Println("stop sleep")
		return nil, nil
	}
}

func TestNewCustomSerialLock(t *testing.T) {
	ctx := context.Background()
	serialLock := NewCustomSerialLock()

	runTest := func(req1 interface{}, req2 interface{}) error {
		wg := sync.WaitGroup{}
		h := getSleepHandler(300)
		wg.Add(1)
		go func() {
			serialLock(ctx, req1, nil, h)
			wg.Done()
		}()
		time.Sleep(time.Millisecond * 100)
		_, err := serialLock(ctx, req2, nil, h)
		wg.Wait()
		return err

	}
	t.Run("NodeStage for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.NodeStageVolumeRequest{VolumeId: validVolumeID},
			&csi.NodeStageVolumeRequest{VolumeId: validVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})

	t.Run("NodeUnstage for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.NodeUnstageVolumeRequest{VolumeId: validVolumeID},
			&csi.NodeUnstageVolumeRequest{VolumeId: validVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})

	t.Run("NodeUnstage for different volumes", func(t *testing.T) {
		err := runTest(&csi.NodeUnstageVolumeRequest{VolumeId: validVolumeID},
			&csi.NodeUnstageVolumeRequest{VolumeId: validVolumeID2})
		assert.Nil(t, err)
	})

	t.Run("NodeStage for different volumes", func(t *testing.T) {
		err := runTest(&csi.NodeStageVolumeRequest{VolumeId: validVolumeID},
			&csi.NodeStageVolumeRequest{VolumeId: validVolumeID2})
		assert.Nil(t, err)
	})

	t.Run("NodePublish for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.NodePublishVolumeRequest{VolumeId: validVolumeID},
			&csi.NodePublishVolumeRequest{VolumeId: validVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})

	t.Run("NodePublish and NodeStage for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.NodeStageVolumeRequest{VolumeId: validVolumeID},
			&csi.NodePublishVolumeRequest{VolumeId: validVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})

	t.Run("CreateVolume for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.CreateVolumeRequest{Name: validVolumeID},
			&csi.CreateVolumeRequest{Name: validVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})
	t.Run("CreateVolume for different volumes", func(t *testing.T) {
		err := runTest(&csi.CreateVolumeRequest{Name: validVolumeID},
			&csi.CreateVolumeRequest{Name: validVolumeID2})
		assert.Nil(t, err)
	})
}

func Test_tracingInterceptor_handleServe(t *testing.T) {
	h := NewTracingInterceptor()
	info := grpc.UnaryServerInfo{FullMethod: "FooBar"}
	d, err := h(context.Background(), nil, &info, func(ctx context.Context, req interface{}) (i interface{}, e error) {
		_, ok := trace.FromContext(ctx)
		assert.True(t, ok)
		return nil, nil
	})
	assert.Nil(t, d)
	assert.Nil(t, err)
}
