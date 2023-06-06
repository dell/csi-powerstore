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

package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/container-storage-interface/spec/lib/go/csi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func parseSize(size string) (int64, error) {
	pattern := `(\d*) ?Gi$`
	pathMetadata := regexp.MustCompile(pattern)

	matches := pathMetadata.FindStringSubmatch(size)
	for i, match := range matches {
		if i != 0 {
			bytes, err := strconv.ParseInt(match, 10, 64)
			if err != nil {
				return 0, status.Error(codes.Internal, "Failed to parse size")
			}
			return bytes * 1073741824, nil
		}
	}
	return 0, errors.New("failed to parse bytes")
}

func (s *Service) ephemeralNodePublish(
	ctx context.Context,
	req *csi.NodePublishVolumeRequest) (
	*csi.NodePublishVolumeResponse, error) {
	if _, err := s.Fs.Stat(ephemeralStagingMountPath); os.IsNotExist(err) {
		log.Debug("path does not exists")
		err = s.Fs.MkdirAll(ephemeralStagingMountPath, 0750)
		if err != nil {
			log.Errorf("NodestageErrorEph %s", err.Error())
			return nil, status.Error(codes.Internal, "Unable to create directory for mounting ephemeral volumes")
		}
	}

	volID := req.VolumeId
	volName := fmt.Sprintf("ephemeral-%s", volID)
	volSize, err := parseSize(req.VolumeContext["size"])
	if err != nil {
		log.Errorf("Parse size failed %s", err.Error())
		return nil, status.Error(codes.Internal, "inline ephemeral parse size failed")
	}

	crvolresp, err := s.ctrlSvc.CreateVolume(ctx, &csi.CreateVolumeRequest{
		Name: volName,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: volSize,
			LimitBytes:    volSize,
		},
		VolumeCapabilities: []*csi.VolumeCapability{req.VolumeCapability},
		Parameters:         req.VolumeContext,
		Secrets:            req.Secrets,
	})
	if err != nil {
		log.Errorf("CreateVolume Ephemeral %s", err.Error())
		return nil, status.Error(codes.Internal, "inline ephemeral create volume failed")
	}

	errLock := s.Fs.MkdirAll(ephemeralStagingMountPath+volID, 0750)
	if errLock != nil {
		return nil, errLock
	}
	f, errLock := s.Fs.Create(ephemeralStagingMountPath + volID + "/id")
	if errLock != nil {
		return nil, errLock
	}
	defer f.Close() //#nosec
	_, errLock = s.Fs.WriteString(f, crvolresp.Volume.VolumeId)
	if errLock != nil {
		return nil, errLock
	}

	cpubresp, err := s.ctrlSvc.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
		VolumeId:         crvolresp.Volume.VolumeId,
		NodeId:           s.nodeID,
		VolumeCapability: req.VolumeCapability,
		Readonly:         req.Readonly,
		Secrets:          req.Secrets,
		VolumeContext:    crvolresp.Volume.VolumeContext,
	})
	if err != nil {
		log.Infof("Rolling back and calling unpublish ephemeral volumes with VolId %s", crvolresp.Volume.VolumeId)
		_, _ = s.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{
			VolumeId:   volID,
			TargetPath: req.TargetPath,
		})
		return nil, status.Error(codes.Internal, "inline ephemeral controller publish failed")
	}

	_, err = s.NodeStageVolume(ctx, &csi.NodeStageVolumeRequest{
		VolumeId:          crvolresp.Volume.VolumeId,
		PublishContext:    cpubresp.PublishContext,
		StagingTargetPath: ephemeralStagingMountPath,
		VolumeCapability:  req.VolumeCapability,
		Secrets:           req.Secrets,
		VolumeContext:     crvolresp.Volume.VolumeContext,
	})
	if err != nil {
		log.Errorf("NodeStageErrEph %s", err.Error())
		log.Infof("Rolling back and calling unpublish ephemeral volumes with VolId %s", crvolresp.Volume.VolumeId)
		_, _ = s.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{
			VolumeId:   volID,
			TargetPath: req.TargetPath,
		})
		return nil, status.Error(codes.Internal, "inline ephemeral node stage failed")

	}
	delete(crvolresp.Volume.VolumeContext, "csi.storage.k8s.io/ephemeral")
	_, err = s.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{
		VolumeId:          crvolresp.Volume.VolumeId,
		PublishContext:    cpubresp.PublishContext,
		StagingTargetPath: ephemeralStagingMountPath,
		TargetPath:        req.TargetPath,
		VolumeCapability:  req.VolumeCapability,
		Readonly:          req.Readonly,
		Secrets:           req.Secrets,
		VolumeContext:     crvolresp.Volume.VolumeContext,
	})
	if err != nil {
		log.Errorf("NodePublishErrEph %s", err.Error())
		_, _ = s.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{
			VolumeId:   volID,
			TargetPath: req.TargetPath,
		})
		return nil, status.Error(codes.Internal, "inline ephemeral node publish failed")
	}

	return &csi.NodePublishVolumeResponse{}, nil

}

func (s *Service) ephemeralNodeUnpublish(
	ctx context.Context,
	req *csi.NodeUnpublishVolumeRequest) error {
	volID := req.GetVolumeId()
	if volID == "" {
		return status.Error(codes.InvalidArgument, "volume ID is required")
	}

	stagingPath := ephemeralStagingMountPath
	lockFile := ephemeralStagingMountPath + volID + "/id"
	dat, err := s.Fs.ReadFile(lockFile)
	if os.IsNotExist(err) {
		return status.Error(codes.Internal, "Inline ephemeral. Was unable to read lockfile")
	}
	goodVolid := string(dat)
	_, err = s.NodeUnstageVolume(ctx, &csi.NodeUnstageVolumeRequest{
		VolumeId:          goodVolid,
		StagingTargetPath: stagingPath,
	})
	if err != nil {
		log.Info(err)
		return status.Error(codes.Internal, "Inline ephemeral node unstage unpublish failed")
	}
	log.Info("Calling unpublish")
	_, err = s.ctrlSvc.ControllerUnpublishVolume(ctx, &csi.ControllerUnpublishVolumeRequest{
		VolumeId: goodVolid,
		NodeId:   s.nodeID,
	})
	if err != nil {
		return status.Error(codes.Internal, "Inline ephemeral controller unpublish unpublish failed")
	}
	_, err = s.ctrlSvc.DeleteVolume(ctx, &csi.DeleteVolumeRequest{
		VolumeId: goodVolid,
	})
	if err != nil {
		return err
	}
	err = os.RemoveAll(ephemeralStagingMountPath + volID)
	if err != nil {
		return status.Error(codes.Internal, "Failed to cleanup lockfiles")
	}
	return nil
}
