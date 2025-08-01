/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"io"
	"sync"
	"time"

	"github.com/akutz/gosync"
	"github.com/container-storage-interface/spec/lib/go/csi"
	controller "github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gocsi/middleware/serialvolume"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	csictx "github.com/dell/gocsi/context"
	mwtypes "github.com/dell/gocsi/middleware/serialvolume/lockprovider"
	log "github.com/sirupsen/logrus"
	xctx "golang.org/x/net/context"

	"github.com/dell/csi-metadata-retriever/retriever"
	"github.com/kubernetes-csi/csi-lib-utils/connection"
	"github.com/kubernetes-csi/csi-lib-utils/metrics"
)

type rewriteRequestIDInterceptor struct{}

func (r *rewriteRequestIDInterceptor) handleServer(ctx context.Context, req interface{},
	_ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (interface{}, error) {
	// Retrieve the gRPC metadata from the incoming context.
	md, mdOK := metadata.FromIncomingContext(ctx)

	// Check the metadata from the request ID.
	if mdOK {
		ID, IDOK := md[csictx.RequestIDKey]
		if IDOK {
			newIDValue := fmt.Sprintf("%s-%s", csictx.RequestIDKey, ID[0])
			ctx = context.WithValue(ctx, interface{}(csictx.RequestIDKey), newIDValue)
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

func (i *lockProvider) GetLockWithID(_ context.Context, id string) (gosync.TryLocker, error) {
	i.volIDLocksL.Lock()
	defer i.volIDLocksL.Unlock()

	lock := i.volIDLocks[id]
	if lock == nil {
		lock = &gosync.TryMutex{}
		i.volIDLocks[id] = lock
	}

	return lock, nil
}

func (i *lockProvider) GetLockWithName(_ context.Context, name string) (gosync.TryLocker, error) {
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
	timeout               time.Duration
	locker                mwtypes.VolumeLockerProvider
	MetadataSidecarClient retriever.MetadataRetrieverClient
}

type interceptor struct {
	opts opts
}

// NewCustomSerialLock creates new unary interceptor that locks gRPC requests
func NewCustomSerialLock(mode string) grpc.UnaryServerInterceptor {
	locker := &lockProvider{
		volIDLocks:   map[string]gosync.TryLocker{},
		volNameLocks: map[string]gosync.TryLocker{},
	}

	gocsiSerializer := serialvolume.New(serialvolume.WithLockProvider(locker))

	i := &interceptor{opts{locker: locker, timeout: 0}}
	// To avoid unnecessary call, we can add a conditional check to prevent this logic from being called unnecessarily in node pods.
	if mode == "controller" {
		i.createMetadataRetrieverClient(context.Background())
	}
	handle := func(ctx xctx.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		switch t := req.(type) {
		case *csi.CreateVolumeRequest:
			return i.createVolume(ctx, t, info, handler)
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

func (i *interceptor) createMetadataRetrieverClient(ctx context.Context) {
	metricsManager := metrics.NewCSIMetricsManagerWithOptions("csi-metadata-retriever",
		metrics.WithProcessStartTime(false),
		metrics.WithSubsystem(metrics.SubsystemSidecar))
	if retrieverAddress, ok := csictx.LookupEnv(ctx, identifiers.EnvMetadataRetrieverEndpoint); ok {
		rpcConn, err := connection.Connect(retrieverAddress, metricsManager, connection.OnConnectionLoss(connection.ExitOnConnectionLoss()))
		if err != nil {
			log.Error(err.Error())
		}

		retrieverClient := retriever.NewMetadataRetrieverClient(rpcConn, 100*time.Second)
		if retrieverClient == nil {
			log.Error("Cannot get csi-metadata-retriever client")
		}

		i.opts.MetadataSidecarClient = retrieverClient
	} else {
		log.Warn("env var not found: ", identifiers.EnvMetadataRetrieverEndpoint)
	}
}

const pending = "pending"

func (i *interceptor) nodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest,
	_ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (res interface{}, resErr error) {
	lock, err := i.opts.locker.GetLockWithID(ctx, req.VolumeId)
	if err != nil {
		return nil, err
	}

	if closer, ok := lock.(io.Closer); ok {
		defer closer.Close() // #nosec G307
	}

	if !lock.TryLock(i.opts.timeout) {
		return nil, status.Error(codes.Aborted, pending)
	}
	defer lock.Unlock()

	return handler(ctx, req)
}

func (i *interceptor) nodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest,
	_ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (res interface{}, resErr error) {
	lock, err := i.opts.locker.GetLockWithID(ctx, req.VolumeId)
	if err != nil {
		return nil, err
	}
	if closer, ok := lock.(io.Closer); ok {
		defer closer.Close() // #nosec G307
	}
	if !lock.TryLock(i.opts.timeout) {
		return nil, status.Error(codes.Aborted, pending)
	}
	defer lock.Unlock()

	return handler(ctx, req)
}

func (i *interceptor) createVolume(ctx context.Context, req *csi.CreateVolumeRequest,
	_ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (res interface{}, resErr error) {
	lock, err := i.opts.locker.GetLockWithID(ctx, req.Name)
	if err != nil {
		return nil, err
	}

	if closer, ok := lock.(io.Closer); ok {
		defer closer.Close() // #nosec G307
	}

	if !lock.TryLock(i.opts.timeout) {
		return nil, status.Error(codes.Aborted, pending)
	}
	defer lock.Unlock()

	metadataReq := &retriever.GetPVCLabelsRequest{
		Name:      req.Parameters[controller.KeyCSIPVCName],
		NameSpace: req.Parameters[controller.KeyCSIPVCNamespace],
	}

	if i.opts.MetadataSidecarClient != nil {
		metadataRes, err := i.opts.MetadataSidecarClient.GetPVCLabels(ctx, metadataReq)
		if err != nil {
			log.Errorf("Cannot retrieve labels for PVC %s in namespace: %s, error: %v",
				controller.KeyCSIPVCName,
				controller.KeyCSIPVCNamespace,
				err.Error())
		}

		if metadataRes != nil {
			for k, v := range metadataRes.Parameters {
				req.Parameters[k] = v
			}
		} else {
			log.Warnf("Metadata retrieved is nil for PVC %s in namespace: %s",
				controller.KeyCSIPVCName,
				controller.KeyCSIPVCNamespace)
		}
	}

	return handler(ctx, req)
}
