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
	"errors"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"regexp"
	"strconv"
)

const (
	ephemeralStagingMountPath = "/var/lib/kubelet/plugins/kubernetes.io/csi/pv/ephemeral/"
)

func (s *service) fileExists(filename string) bool {
	_, err := s.os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func (s *service) initEphemeralApiThrottle() {

	if s.opts.ThrottlingRateLimit < 1 {
		s.opts.ThrottlingRateLimit = defaultThrottlingRateLimit
	}
	if s.opts.ThrottlingTimeoutSeconds < 1 {
		s.opts.ThrottlingTimeoutSeconds = defaultThrottlingTimeoutSeconds
	}

	if s.apiThrottle == nil {
		s.apiThrottle = newTimeoutSemaphore(
			s.opts.ThrottlingTimeoutSeconds,
			s.opts.ThrottlingRateLimit,
		)
	}
}

func parseSize(size string) (int64, error) {
	pattern := `(\d*) ?Gi$`
	pathMetadata := regexp.MustCompile(pattern)

	matches := pathMetadata.FindStringSubmatch(size)
	for i, match := range matches {
		if i != 0 {
			bytes, err := strconv.ParseInt(match, 10, 64)
			if err != nil {
				return 0, errors.New("Failed to parse bytes")
			}
			return bytes * 1073741824, nil
		}
	}
	return 0, errors.New("failed to parse bytes")
}

func (s *service) ephemeralNodePublish(
	ctx context.Context,
	req *csi.NodePublishVolumeRequest) (
	*csi.NodePublishVolumeResponse, error) {
	log.Info("initialization of api throttle")
	s.initEphemeralApiThrottle()
	if _, err := s.os.Stat(ephemeralStagingMountPath); os.IsNotExist(err) {
		log.Debug("path does not exists")
		err = s.os.MkdirAll(ephemeralStagingMountPath, 0750)
		if err != nil {
			log.Errorf("NodestageErrorEph %s", err.Error())
			return nil, status.Error(codes.Internal, "Unable to create directory for mounting ephemeral volumes")
		}
	}
	volID := req.GetVolumeId()
	volName := fmt.Sprintf("ephemeral-%s", volID)
	volSize, err := parseSize(req.VolumeContext["size"])
	if err != nil {
		log.Errorf("Parse size failed %s", err.Error())
		return nil, status.Error(codes.Internal, "inline ephemeral parse size failed")
	}

	crvolresp, err := s.CreateVolume(ctx, &csi.CreateVolumeRequest{
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

	errLock := s.os.MkdirAll(ephemeralStagingMountPath+volID, 0750)
	if errLock != nil {
		return nil, errLock
	}
	f, errLock := s.os.Create(ephemeralStagingMountPath + volID + "/id")
	if errLock != nil {
		return nil, errLock
	}
	defer f.Close() //#nosec
	_, errLock = s.os.WriteString(f, crvolresp.Volume.VolumeId)
	if errLock != nil {
		return nil, errLock
	}

	cpubresp, err := s.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
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

func (s *service) ephemeralNodeUnpublish(
	ctx context.Context,
	req *csi.NodeUnpublishVolumeRequest) error {
	log.Info("initialization of api throttle")
	s.initEphemeralApiThrottle()
	volID := req.GetVolumeId()
	if volID == "" {
		return status.Error(codes.InvalidArgument, "volume ID is required")
	}

	stagingPath := ephemeralStagingMountPath
	lockFile := ephemeralStagingMountPath + volID + "/id"
	dat, err := s.os.ReadFile(lockFile)
	if os.IsNotExist(err) {
		return status.Error(codes.Internal, "Inline ephemeral. Was unable to read lockfile")
	}
	goodVolid := string(dat)
	_, err = s.NodeUnstageVolume(ctx, &csi.NodeUnstageVolumeRequest{
		VolumeId:          goodVolid,
		StagingTargetPath: stagingPath,
	})
	if err != nil {
		return errors.New("Inline ephemeral node unstage failed")
	}
	_, err = s.ControllerUnpublishVolume(ctx, &csi.ControllerUnpublishVolumeRequest{
		VolumeId: goodVolid,
		NodeId:   s.nodeID,
	})
	if err != nil {
		return errors.New("Inline ephemeral controller unpublish failed")
	}
	_, err = s.DeleteVolume(ctx, &csi.DeleteVolumeRequest{
		VolumeId: goodVolid,
	})
	if err != nil {
		return err
	}
	err = os.RemoveAll(ephemeralStagingMountPath + volID)
	if err != nil {
		return errors.New("failed to cleanup lock files")
	}
	return nil
}
