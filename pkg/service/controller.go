/*
 *
 * Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package service provides CSI specification compatible controller service.
package service

import (
	"context"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csm-hbnfs/nfs"
	commonext "github.com/dell/dell-csi-extensions/common"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	CsiNfsParameter = "csi-nfs"
	KeyNasName      = "nasName"
)

// CreateVolume creates either FileSystem or Volume on storage array.
func (s *service) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	params := req.GetParameters()
	if params[CsiNfsParameter] != "" {
		params[CsiNfsParameter] = "RWX"
	}
	if nfs.IsNFSStorageClass(params) {
		return nfssvc.CreateVolume(ctx, req)
	}
	return controllerSvc.CreateVolume(ctx, req)
}

// DeleteVolume deletes either FileSystem or Volume from storage array.
func (s *service) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	if nfs.IsNFSVolumeID(req.VolumeId) {
		req.VolumeId = nfs.ToArrayVolumeID(req.VolumeId)
	}
	return controllerSvc.DeleteVolume(ctx, req)
}

// ControllerPublishVolume prepares Volume/FileSystem to be consumed by node by attaching/allowing access to the host.
func (s *service) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	log := getLogger(ctx)
	volumeContext := req.GetVolumeContext()
	if volumeContext != nil {
		log.Debugf("VolumeContext:")
		for key, value := range volumeContext {
			log.Debugf("    [%s]=%s", key, value)
		}
	}

	// create publish context
	publishContext := make(map[string]string)
	publishContext[KeyNasName] = volumeContext[KeyNasName]

	csiVolID := req.GetVolumeId()
	publishContext["volumeContextId"] = csiVolID

	if csiVolID == "" {
		return nil, status.Error(codes.InvalidArgument,
			"volume ID is required")
	}

	if nfs.IsNFSVolumeID(csiVolID) {
		log.Infof("csi-nfs: RWX calling nfssvc.ControllerPublishVolume")
		return nfssvc.ControllerPublishVolume(ctx, req)
	}
	return controllerSvc.ControllerPublishVolume(ctx, req)
}

// ControllerUnpublishVolume prepares Volume/FileSystem to be deleted by unattaching/disabling access to the host.
func (s *service) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	log := getLogger(ctx)
	if nfs.IsNFSVolumeID(req.GetVolumeId()) {
		log.Info("csi-nfs: calling nfssrv.Controller.UnpublishVolume")
		return nfssvc.ControllerUnpublishVolume(ctx, req)
	}
	return controllerSvc.ControllerUnpublishVolume(ctx, req)
}

// ValidateVolumeCapabilities checks if capabilities found in request are supported by driver.
func (s *service) ValidateVolumeCapabilities(ctx context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	if nfs.IsNFSVolumeID(req.VolumeId) {
		req.VolumeId = nfs.ToArrayVolumeID(req.VolumeId)
	}
	return controllerSvc.ValidateVolumeCapabilities(ctx, req)
}

// ListVolumes returns all accessible volumes from the storage array.
func (s *service) ListVolumes(ctx context.Context, req *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error) {
	return controllerSvc.ListVolumes(ctx, req)
}

// GetCapacity returns available capacity for a storage array.
func (s *service) GetCapacity(ctx context.Context, req *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error) {
	return controllerSvc.GetCapacity(ctx, req)
}

// ControllerGetCapabilities returns list of capabilities that are supported by the driver.
func (s *service) ControllerGetCapabilities(ctx context.Context, req *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	return controllerSvc.ControllerGetCapabilities(ctx, req)
}

// CreateSnapshot creates a snapshot of the Volume or FileSystem.
func (s *service) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	if nfs.IsNFSVolumeID(req.SourceVolumeId) {
		req.SourceVolumeId = nfs.ToArrayVolumeID(req.SourceVolumeId)
	}
	return controllerSvc.CreateSnapshot(ctx, req)
}

// DeleteSnapshot deletes a snapshot of the Volume or FileSystem.
func (s *service) DeleteSnapshot(ctx context.Context, req *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	return controllerSvc.DeleteSnapshot(ctx, req)
}

// ListSnapshots list all accessible snapshots from the storage array.
func (s *service) ListSnapshots(ctx context.Context, req *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	if nfs.IsNFSVolumeID(req.SourceVolumeId) {
		req.SourceVolumeId = nfs.ToArrayVolumeID(req.SourceVolumeId)
	}
	return controllerSvc.ListSnapshots(ctx, req)
}

// ControllerExpandVolume resizes Volume or FileSystem by increasing available volume capacity in the storage array.
func (s *service) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	if nfs.IsNFSVolumeID(req.GetVolumeId()) {
		req.VolumeId = nfs.ToArrayVolumeID(req.GetVolumeId())
	}
	return controllerSvc.ControllerExpandVolume(ctx, req)
}

// ControllerGetVolume fetch current information about a volume
func (s *service) ControllerGetVolume(ctx context.Context, req *csi.ControllerGetVolumeRequest) (*csi.ControllerGetVolumeResponse, error) {
	if nfs.IsNFSVolumeID(req.VolumeId) {
		req.VolumeId = nfs.ToArrayVolumeID(req.VolumeId)
	}
	return controllerSvc.ControllerGetVolume(ctx, req)
}

// ProbeController probes the controller service
func (s *service) ProbeController(ctx context.Context, req *commonext.ProbeControllerRequest) (*commonext.ProbeControllerResponse, error) {
	return controllerSvc.ProbeController(ctx, req)
}

func getLogger(ctx context.Context) *logrus.Entry {
	fields := logrus.Fields{}
	headers, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if req, ok := headers["csi.requestid"]; ok && len(req) > 0 {
			fields["request_id"] = req[0]
		}
	} else {
		if ctx.Value("request_id") != nil {
			fields["request_id"] = ctx.Value("request_id").(string)
		}
	}
	return logrus.WithFields(fields)
}
