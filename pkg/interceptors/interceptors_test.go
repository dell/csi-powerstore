/*
 *
 * Copyright © 2021-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package interceptors

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/akutz/gosync"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-metadata-retriever/retriever"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	controller "github.com/dell/csi-powerstore/v2/pkg/controller"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gocsi/middleware/serialvolume/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	validBlockVolumeID = "39bb1b5f-5624-490d-9ece-18f7b28a904e/192.168.0.1/scsi"
	validNfsVolumeID   = "39bb1b5f-5624-490d-9ece-18f7b28a904e/192.168.0.2/nfs"
	testID             = "111"
)

func getSleepHandler(millisec int) grpc.UnaryHandler {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		fmt.Println("start sleep")
		time.Sleep(time.Duration(millisec) * time.Millisecond)
		fmt.Println("stop sleep")
		return nil, nil
	}
}

func testHandler(ctx context.Context, _ interface{}) (interface{}, error) {
	return ctx, nil
}

func TestRewriteRequestIDInterceptor_RequestIDExist(t *testing.T) {
	handleInterceptor := NewRewriteRequestIDInterceptor()
	md := metadata.Pairs()
	ctx := metadata.NewIncomingContext(context.Background(), md)
	md[csictx.RequestIDKey] = []string{testID}

	newCtx, _ := handleInterceptor(ctx, nil, nil, testHandler)
	requestID, ok := newCtx.(context.Context).Value(csictx.RequestIDKey).(string)

	assert.Equal(t, ok, true)
	assert.Equal(t, requestID, fmt.Sprintf("%s-%s", csictx.RequestIDKey, testID))
}

func TestNewCustomSerialLock(t *testing.T) {
	ctx := context.Background()
	serialLock := NewCustomSerialLock("controller")

	runTest := func(req1 interface{}, req2 interface{}) error {
		wg := sync.WaitGroup{}
		h := getSleepHandler(300)
		wg.Add(1)
		go func() {
			_, _ = serialLock(ctx, req1, nil, h)
			wg.Done()
		}()
		time.Sleep(time.Millisecond * 100)
		_, err := serialLock(ctx, req2, nil, h)
		wg.Wait()
		return err
	}
	t.Run("NodeStage for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.NodeStageVolumeRequest{VolumeId: validBlockVolumeID},
			&csi.NodeStageVolumeRequest{VolumeId: validBlockVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})

	t.Run("NodeUnstage for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.NodeUnstageVolumeRequest{VolumeId: validBlockVolumeID},
			&csi.NodeUnstageVolumeRequest{VolumeId: validBlockVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})

	t.Run("NodeUnstage for different volumes", func(t *testing.T) {
		err := runTest(&csi.NodeUnstageVolumeRequest{VolumeId: validBlockVolumeID},
			&csi.NodeUnstageVolumeRequest{VolumeId: validNfsVolumeID})
		assert.Nil(t, err)
	})

	t.Run("NodeStage for different volumes", func(t *testing.T) {
		err := runTest(&csi.NodeStageVolumeRequest{VolumeId: validBlockVolumeID},
			&csi.NodeStageVolumeRequest{VolumeId: validNfsVolumeID})
		assert.Nil(t, err)
	})

	t.Run("NodePublish for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.NodePublishVolumeRequest{VolumeId: validBlockVolumeID},
			&csi.NodePublishVolumeRequest{VolumeId: validBlockVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})

	t.Run("NodePublish and NodeStage for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.NodeStageVolumeRequest{VolumeId: validBlockVolumeID},
			&csi.NodePublishVolumeRequest{VolumeId: validBlockVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})

	t.Run("CreateVolume for same volume concurrent call", func(t *testing.T) {
		err := runTest(&csi.CreateVolumeRequest{Name: validBlockVolumeID},
			&csi.CreateVolumeRequest{Name: validBlockVolumeID})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "pending")
	})
	t.Run("CreateVolume for different volumes", func(t *testing.T) {
		err := runTest(&csi.CreateVolumeRequest{Name: validBlockVolumeID},
			&csi.CreateVolumeRequest{Name: validNfsVolumeID})
		assert.Nil(t, err)
	})
}

func TestGetLockWithName(t *testing.T) {
	// Test case: Requesting a lock for a name that doesn't exist
	i := &lockProvider{
		volNameLocks: map[string]gosync.TryLocker{},
	}
	lock, err := i.GetLockWithName(context.Background(), "test")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if lock == nil {
		t.Error("Expected a lock, got nil")
	}

	// Test case: Requesting a lock for a name that already exists
	lock2, err := i.GetLockWithName(context.Background(), "test")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if lock2 != lock {
		t.Error("Expected the same lock, got a different lock")
	}
}

func TestGetLockWithID(t *testing.T) {
	// Test case: Get lock for an ID that doesn't exist
	i := &lockProvider{
		volIDLocks: map[string]gosync.TryLocker{},
	}
	lock, err := i.GetLockWithID(context.Background(), "test")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if lock == nil {
		t.Error("Expected a lock, got nil")
	}

	// Test case: Get lock for an ID that already exists
	lock2, err := i.GetLockWithID(context.Background(), "test")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if lock2 != lock {
		t.Error("Expected the same lock, got a different lock")
	}
}

func TestCreateMetadataRetrieverClient(t *testing.T) {
	// Create a new interceptor
	i := &interceptor{
		opts: opts{
			MetadataSidecarClient: nil,
		},
	}

	// Create a new context with the environment variable set
	ctx := context.WithValue(context.Background(), csictx.RequestIDKey, "requestID")
	ctx = csictx.WithEnviron(ctx, []string{fmt.Sprintf("%s=%s", common.EnvMetadataRetrieverEndpoint, "endpoint")})

	// Call the function
	i.createMetadataRetrieverClient(ctx)

	// Check if the client was created
	if i.opts.MetadataSidecarClient == nil {
		t.Error("Expected MetadataSidecarClient to be set, but it was nil")
	}
}

// Define the options struct
type options struct {
	locker                types.VolumeLockerProvider
	MetadataSidecarClient MetadataSidecarClient
	timeout               time.Duration
}

// Define the Locker interface
type Locker interface {
	GetLockWithID(ctx context.Context, id string) (gosync.TryLocker, error)
}

// Define the MetadataSidecarClient interface
type MetadataSidecarClient interface {
	GetPVCLabels(ctx context.Context, req *retriever.GetPVCLabelsRequest) (*retriever.GetPVCLabelsResponse, error)
}

// Mock implementations for dependencies
type MockLocker struct {
	mock.Mock
}

func (m *MockLocker) GetLockWithID(ctx context.Context, id string) (gosync.TryLocker, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(gosync.TryLocker), args.Error(1)
}

func (m *MockLocker) GetLockWithName(ctx context.Context, name string) (gosync.TryLocker, error) {
	args := m.Called(ctx, name)
	return args.Get(0).(gosync.TryLocker), args.Error(1)
}

type MockLock struct {
	mock.Mock
}

func (m *MockLock) TryLock(timeout time.Duration) bool {
	args := m.Called(timeout)
	return args.Bool(0)
}

func (m *MockLock) Unlock() {
	m.Called()
}

func (m *MockLock) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Add the Lock method to satisfy the gosync.TryLocker interface
func (m *MockLock) Lock() {
	m.Called()
}

type MockMetadataSidecarClient struct {
	mock.Mock
}

func (m *MockMetadataSidecarClient) GetPVCLabels(ctx context.Context, req *retriever.GetPVCLabelsRequest) (*retriever.GetPVCLabelsResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*retriever.GetPVCLabelsResponse), args.Error(1)
}

func TestCreateVolume(t *testing.T) {
	ctx := context.Background()
	req := &csi.CreateVolumeRequest{
		Name: "test-volume",
		Parameters: map[string]string{
			controller.KeyCSIPVCName:      "test-pvc",
			controller.KeyCSIPVCNamespace: "default",
		},
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "success", nil
	}

	mockLocker := new(MockLocker)
	mockLock := new(MockLock)
	mockMetadataClient := new(MockMetadataSidecarClient)

	interceptor := &interceptor{
		opts: opts{
			locker:                mockLocker,
			MetadataSidecarClient: mockMetadataClient,
			timeout:               5 * time.Second,
		},
	}

	t.Run("successful volume creation", func(t *testing.T) {
		mockLocker.On("GetLockWithID", ctx, req.Name).Return(mockLock, nil)
		mockLock.On("TryLock", interceptor.opts.timeout).Return(true)
		mockLock.On("Unlock").Return()
		mockLock.On("Close").Return(nil)
		mockMetadataClient.On("GetPVCLabels", ctx, mock.Anything).Return(&retriever.GetPVCLabelsResponse{
			Parameters: map[string]string{"label1": "value1"},
		}, nil)

		res, err := interceptor.createVolume(ctx, req, nil, handler)
		assert.NoError(t, err)
		assert.Equal(t, "success", res)
	})

	t.Run("metadata retrieval failure", func(t *testing.T) {
		mockLocker.On("GetLockWithID", ctx, req.Name).Return(mockLock, nil)
		mockLock.On("TryLock", interceptor.opts.timeout).Return(true)
		mockLock.On("Unlock").Return()
		mockLock.On("Close").Return(nil)
		mockMetadataClient.On("GetPVCLabels", ctx, mock.Anything).Return(nil, errors.New("metadata error"))

		res, err := interceptor.createVolume(ctx, req, nil, handler)
		assert.NoError(t, err)
		assert.Equal(t, "success", res)
	})
}
