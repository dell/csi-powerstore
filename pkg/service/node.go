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

// Package node provides CSI specification compatible node service.
package service

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"syscall"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csm-sharednfs/nfs"
)

var (
	osRemove   = os.RemoveAll
	sysUnmount = syscall.Unmount
)

// NodeStageVolume prepares volume to be consumed by node publish by connecting volume to the node
func (s *service) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	if nfs.IsNFSVolumeID(req.GetVolumeId()) {
		return nfssvc.NodeStageVolume(ctx, req)
	}
	return nodeSvc.NodeStageVolume(ctx, req)
}

// NodeUnstageVolume reverses steps done in NodeStage by disconnecting volume from the node
func (s *service) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	if nfs.IsNFSVolumeID(req.GetVolumeId()) {
		return nfssvc.NodeUnstageVolume(ctx, req)
	}
	return nodeSvc.NodeUnstageVolume(ctx, req)
}

// NodePublishVolume publishes volume to the node by mounting it to the target path
func (s *service) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	if nfs.IsNFSVolumeID(req.GetVolumeId()) {
		log.Infof("shared-nfs: RWX calling nfssvc.NodePublishVolume")
		return nfssvc.NodePublishVolume(ctx, req)
	}
	return nodeSvc.NodePublishVolume(ctx, req)
}

// NodeUnpublishVolume unpublishes volume from the node by unmounting it from the target path
func (s *service) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	if nfs.IsNFSVolumeID(req.GetVolumeId()) {
		log.Infof("shared-nfs: RWX calling nfssvc.NodeUnpublishVolume")
		return nfssvc.NodeUnpublishVolume(ctx, req)
	}

	return nodeSvc.NodeUnpublishVolume(ctx, req)
}

// NodeGetVolumeStats returns volume usage stats
func (s *service) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	if nfs.IsNFSVolumeID(req.VolumeId) {
		req.VolumeId = nfs.ToArrayVolumeID(req.VolumeId)
	}
	return nodeSvc.NodeGetVolumeStats(ctx, req)
}

// NodeExpandVolume expands the volume by re-scanning and resizes filesystem if needed
func (s *service) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	log.Infof("NodeExpandVolume called req %v", req)
	return nodeSvc.NodeExpandVolume(ctx, req)
}

// NodeGetCapabilities returns supported features by the node service
func (s *service) NodeGetCapabilities(ctx context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return nodeSvc.NodeGetCapabilities(ctx, req)
}

// NodeGetInfo returns id of the node and topology constraints
func (s *service) NodeGetInfo(ctx context.Context, _ *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return nodeSvc.NodeGetInfo(ctx, nil)
}

func (s *service) MountVolume(ctx context.Context, volumeID, fsType, nfsExportDirectory string, publishContext map[string]string) (string, error) {
	log.Infof("MountVolume called volumeId %s", volumeID)
	if volumeID == "" {
		return "", fmt.Errorf("MountVolume: volumeId was empty")
	}

	if nfsExportDirectory == "" {
		nfsExportDirectory = nfs.NfsExportDirectory
	}
	// the Stage volume will create a file and mount the device directly to the file
	staging := path.Join(nfsExportDirectory, publishContext[nfs.ServiceName]+"-dev")
	target := path.Join(nfsExportDirectory, publishContext[nfs.ServiceName])

	nodeStageReq := &csi.NodeStageVolumeRequest{
		VolumeId: volumeID,
		VolumeCapability: &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Mount{
				Mount: &csi.VolumeCapability_MountVolume{
					MountFlags: []string{"rw"},
				},
			},
			AccessMode: &csi.VolumeCapability_AccessMode{
				Mode: csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER,
			},
		},
		StagingTargetPath: staging,
		PublishContext:    publishContext,
	}

	log.Infof("MountVolume calling NodeStageVolume:  %+v", nodeStageReq)
	_, err := nodeSvc.NodeStageVolume(ctx, nodeStageReq)
	if err != nil {
		return "", fmt.Errorf("MountVolume: could not stage volume volumeId %s: %s", volumeID, err)
	}

	nodePubReq := &csi.NodePublishVolumeRequest{
		VolumeId: volumeID,
		VolumeCapability: &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Mount{
				Mount: &csi.VolumeCapability_MountVolume{
					MountFlags: []string{"rw"},
					FsType:     fsType,
				},
			},
			AccessMode: &csi.VolumeCapability_AccessMode{
				Mode: csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER,
			},
		},
		PublishContext:    publishContext,
		StagingTargetPath: staging,
		TargetPath:        target,
		Readonly:          false,
	}

	log.Infof("MountVolume calling NodePublishVolume %+v", nodePubReq)
	_, err = nodeSvc.NodePublishVolume(ctx, nodePubReq)
	if err != nil {
		return "", fmt.Errorf("MountVolume: could not publish volume volumeId %s", volumeID)
	}
	log.Infof("MountVolume ALL GOOD volume %s mounted to target %s", volumeID, target)
	return target, nil
}

func (s *service) UnmountVolume(ctx context.Context, volumeID, exportPath string, publishContext map[string]string) error {
	staging := path.Join(exportPath, publishContext[nfs.ServiceName]+"-dev")
	target := path.Join(exportPath, publishContext[nfs.ServiceName])

	target = filepath.Clean(target)
	staging = filepath.Clean(staging)

	nodeUnpublishReq := &csi.NodeUnpublishVolumeRequest{
		VolumeId:   volumeID,
		TargetPath: target,
	}

	log.Infof("[UnmountVolume] Target: %s", target)
	// Unpublish the target directory for sharedNFS first. This will properly clean up and /dev/sdX entries associated to the mount.
	_, err := nodeSvc.NodeUnpublishVolume(ctx, nodeUnpublishReq)
	if err != nil {
		return fmt.Errorf("[UnmountVolume] unpublish failed for %s: %e", target, err)
	}

	nodeUnstageReq := &csi.NodeUnstageVolumeRequest{
		VolumeId:          volumeID,
		StagingTargetPath: staging,
	}

	// Unmount the staging directory for sharedNFS (-dev) to clean up anything related to the mount.
	log.Infof("[UnmountVolume] Staging: %s", staging)
	_, err = nodeSvc.NodeUnstageVolume(ctx, nodeUnstageReq)
	if err != nil {
		return fmt.Errorf("[UnmountVolume] unstage failed for %s: %e", staging, err)
	}

	// After successfully unmounting/unstaging both target and staging, remove both.
	err = osRemove(target)
	if err != nil && !os.IsNotExist(err) {
		log.Errorf("[UnmountVolume] could not remove target path %s: %s", target, err.Error())
		return err
	}

	err = osRemove(staging)
	if err != nil && !os.IsNotExist(err) {
		log.Errorf("[UnmountVolume] could not remove staging path %s: %s", staging, err.Error())
		return err
	}

	log.Infof("[UnmountVolume] Successfully unmounted volume %s", volumeID)
	return nil
}
