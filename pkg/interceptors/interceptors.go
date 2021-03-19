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

// Package interceptors contains custom unary gRPC interceptors.
package interceptors

import (
	"context"
	"fmt"
	"github.com/akutz/gosync"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/rexray/gocsi/middleware/serialvolume"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"sync"
	"time"

	csictx "github.com/rexray/gocsi/context"
	mwtypes "github.com/rexray/gocsi/middleware/serialvolume/types"
	xctx "golang.org/x/net/context"
)

type rewriteRequestIDInterceptor struct{}

func (r *rewriteRequestIDInterceptor) handleServer(ctx context.Context, req interface{},
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Retrieve the gRPC metadata from the incoming context.
	md, mdOK := metadata.FromIncomingContext(ctx)

	// Check the metadata from the request ID.
	if mdOK {
		ID, IDOK := md[csictx.RequestIDKey]
		if IDOK {
			newIDValue := fmt.Sprintf("%s-%s", csictx.RequestIDKey, ID[0])
			ctx = context.WithValue(ctx, csictx.RequestIDKey, newIDValue)
		}
	}

	return handler(ctx, req)
}

// NewRewriteRequestIDInterceptor creates new unary interceptor that rewrites request IDs
func NewRewriteRequestIDInterceptor() grpc.UnaryServerInterceptor {
	interceptor := &rewriteRequestIDInterceptor{}
	return interceptor.handleServer
}

type lockProvider struct {
	volIDLocksL   sync.Mutex
	volNameLocksL sync.Mutex
	volIDLocks    map[string]gosync.TryLocker
	volNameLocks  map[string]gosync.TryLocker
}

func (i *lockProvider) GetLockWithID(ctx context.Context, id string) (gosync.TryLocker, error) {
	i.volIDLocksL.Lock()
	defer i.volIDLocksL.Unlock()

	lock := i.volIDLocks[id]
	if lock == nil {
		lock = &gosync.TryMutex{}
		i.volIDLocks[id] = lock
	}

	return lock, nil
}

func (i *lockProvider) GetLockWithName(ctx context.Context, name string) (gosync.TryLocker, error) {
	i.volNameLocksL.Lock()
	defer i.volNameLocksL.Unlock()

	lock := i.volNameLocks[name]
	if lock == nil {
		lock = &gosync.TryMutex{}
		i.volNameLocks[name] = lock
	}

	return lock, nil
}

type opts struct {
	timeout time.Duration
	locker  mwtypes.VolumeLockerProvider
}

type interceptor struct {
	opts opts
}

// NewCustomSerialLock creates new unary interceptor that locks gRPC requests
func NewCustomSerialLock() grpc.UnaryServerInterceptor {
	locker := &lockProvider{
		volIDLocks:   map[string]gosync.TryLocker{},
		volNameLocks: map[string]gosync.TryLocker{},
	}

	gocsiSerializer := serialvolume.New(serialvolume.WithLockProvider(locker))

	i := &interceptor{opts{locker: locker, timeout: 0}}

	handle := func(ctx xctx.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		switch t := req.(type) {
		case *csi.NodeStageVolumeRequest:
			return i.nodeStageVolume(ctx, t, info, handler)
		case *csi.NodeUnstageVolumeRequest:
			return i.nodeUnstageVolume(ctx, t, info, handler)
		default:
			return gocsiSerializer(ctx, req, info, handler)
		}
	}
	return handle
}

const pending = "pending"

func (i *interceptor) nodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest,
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (res interface{}, resErr error) {
	lock, err := i.opts.locker.GetLockWithID(ctx, req.VolumeId)
	if err != nil {
		return nil, err
	}

	if closer, ok := lock.(io.Closer); ok {
		defer closer.Close()
	}

	if !lock.TryLock(i.opts.timeout) {
		return nil, status.Error(codes.Aborted, pending)
	}
	defer lock.Unlock()

	return handler(ctx, req)
}

func (i *interceptor) nodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest,
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (res interface{}, resErr error) {
	lock, err := i.opts.locker.GetLockWithID(ctx, req.VolumeId)
	if err != nil {
		return nil, err
	}

	if closer, ok := lock.(io.Closer); ok {
		defer closer.Close()
	}

	if !lock.TryLock(i.opts.timeout) {
		return nil, status.Error(codes.Aborted, pending)
	}
	defer lock.Unlock()

	return handler(ctx, req)
}
