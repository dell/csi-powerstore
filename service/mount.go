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
	"bytes"
	"context"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gofsutil"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path"
)

const (
	procMountsPath    = "/proc/self/mountinfo"
	procMountsRetries = 15
)

type mount struct{}

// StageVolume stage volume to required node path
func (m *mount) StageVolume(ctx context.Context,
	req *csi.NodeStageVolumeRequest, device string) error {
	return m.getStageVolumeIMPL().stage(ctx, req, device)
}

// StageVolumeNFS stages nfs volume to required node path
func (m *mount) StageVolumeNFS(ctx context.Context,
	req *csi.NodeStageVolumeRequest, path string) error {
	return m.getStageVolumeIMPL().stageNFS(ctx, req, path)
}

// UnstageVolume unstage volume from required node path
func (m *mount) UnstageVolume(ctx context.Context,
	req *csi.NodeUnstageVolumeRequest) (string, error) {
	return m.getUnstageVolumeIMPL().unstage(ctx, req)
}

// PublishVolume mount volume to required node path
func (m *mount) PublishVolume(ctx context.Context,
	req *csi.NodePublishVolumeRequest) error {
	return m.getPublishVolumeIMPL().publish(ctx, req)
}

// PublishVolumeNFS mount nfs volume to required node path
func (m *mount) PublishVolumeNFS(ctx context.Context,
	req *csi.NodePublishVolumeRequest) error {
	return m.getPublishVolumeIMPL().publishNFS(ctx, req)
}

// UnpublishVolume unmount volume from required node path
func (m *mount) UnpublishVolume(ctx context.Context,
	req *csi.NodeUnpublishVolumeRequest) error {
	return m.getUnpublishVolumeIMPL().unpublish(ctx, req)
}

// GetStagingPath returns path for volume staging
func (m *mount) GetStagingPath(ctx context.Context, req commonReqGetters) string {
	rh := &reqHelpersIMPL{}
	return rh.getStagingPath(ctx, req)
}

// GetMountsByDev returns all mounts for dev
func (m *mount) GetMountsByDev(ctx context.Context, device string) ([]gofsutil.Info, error) {
	return m.getMountIMPLGetMounts().getMountsByDev(ctx, device)
}

// GetTargetMount returns mount object for target path
func (m *mount) GetTargetMount(ctx context.Context, target string) (gofsutil.Info, bool, error) {
	return m.getMountIMPLGetMounts().getTargetMount(ctx, target)
}

// IsReadyToPublish check volume is ready to be published
func (m *mount) IsReadyToPublish(ctx context.Context, device string) (bool, bool, error) {
	return m.getPublishCheckIMPL().isReadyToPublish(ctx, device)
}

// IsReadyToPublishNFS check if nfs volume is ready to be published
func (m *mount) IsReadyToPublishNFS(ctx context.Context, device string) (bool, error) {
	return m.getPublishCheckIMPL().isReadyToPublishNFS(ctx, device)
}

func (m *mount) getStageVolumeIMPL() *mountLibStageIMPL {
	return newMountLibStageIMPL(
		newMkfile(&osWrapper{}),
		newMkdir(&osWrapper{}),
		&reqHelpersIMPL{},
		&gofsutilWrapper{},
		newMountLibStageCheckIMPL(
			&reqHelpersIMPL{},
			newMountLibMountsReaderIMPL(
				&ioutilWrapper{},
				newConsistentReadIMPL(&ioutilWrapper{}),
				&gofsutilWrapper{})))
}

func (m *mount) getUnstageVolumeIMPL() *mountLibUnstageIMPL {
	return newMountLibUnstageIMPL(
		&osWrapper{},
		&reqHelpersIMPL{},
		&gofsutilWrapper{},
		newMountLibStageCheckIMPL(
			&reqHelpersIMPL{},
			newMountLibMountsReaderIMPL(
				&ioutilWrapper{},
				newConsistentReadIMPL(&ioutilWrapper{}),
				&gofsutilWrapper{})),
	)
}

func (m *mount) getPublishVolumeIMPL() *mountLibPublishIMPL {
	return newMountLibPublishIMPL(
		newMountLibPublishCheckIMPL(
			newMountLibMountsReaderIMPL(
				&ioutilWrapper{},
				newConsistentReadIMPL(&ioutilWrapper{}),
				&gofsutilWrapper{}),
			&gofsutilWrapper{}),
		&reqHelpersIMPL{},
		newMountLibPublishBlockIMPL(
			newMkfile(&osWrapper{}),
			&reqHelpersIMPL{},
			&gofsutilWrapper{}),
		newMountLibPublishMountIMPL(
			newMkdir(&osWrapper{}),
			&reqHelpersIMPL{},
			&gofsutilWrapper{},
			newMkFS(&osWrapper{})),
		newMkdir(&osWrapper{}),
		&gofsutilWrapper{},
	)
}

func (m *mount) getPublishCheckIMPL() *mountLibPublishCheckIMPL {
	return newMountLibPublishCheckIMPL(
		newMountLibMountsReaderIMPL(
			&ioutilWrapper{},
			newConsistentReadIMPL(&ioutilWrapper{}),
			&gofsutilWrapper{}),
		&gofsutilWrapper{})
}

func (m *mount) getUnpublishVolumeIMPL() *mountLibUnpublishIMPL {
	return newMountLibUnpublishIMPL(
		newMountLibMountsReaderIMPL(
			&ioutilWrapper{},
			newConsistentReadIMPL(&ioutilWrapper{}),
			&gofsutilWrapper{}),
		&gofsutilWrapper{},
		&osWrapper{})
}

func (m *mount) getMountIMPLGetMounts() *mountLibMountsReaderIMPL {
	return newMountLibMountsReaderIMPL(
		&ioutilWrapper{},
		newConsistentReadIMPL(&ioutilWrapper{}),
		&gofsutilWrapper{})
}

func newMountLibMountsReaderIMPL(fileReader fileReader,
	consistentReader consistentReader,
	fsLib wrapperFsLib) *mountLibMountsReaderIMPL {
	return &mountLibMountsReaderIMPL{
		fileReader:       fileReader,
		consistentReader: consistentReader,
		fsLib:            fsLib}
}

type mountLibMountsReaderIMPL struct {
	fileReader       fileReader
	consistentReader consistentReader
	fsLib            wrapperFsLib
}

func (mr *mountLibMountsReaderIMPL) getMountsByDev(
	ctx context.Context, device string) ([]gofsutil.Info, error) {

	logFields := getLogFields(ctx)
	mnts, err := mr.getMounts(ctx)
	if err != nil {
		log.WithFields(logFields).Error(err)
		return mnts, status.Error(codes.Internal,
			"could not reliably determine mount status for device")
	}
	var result []gofsutil.Info
	for _, m := range mnts {
		if m.Device == device || (m.Device == "devtmpfs" && m.Source == device) {
			result = append(result, m)
		}
	}
	return result, nil
}

func (mr *mountLibMountsReaderIMPL) getTargetMount(
	ctx context.Context, target string) (gofsutil.Info, bool, error) {

	logFields := getLogFields(ctx)
	var targetMount gofsutil.Info
	var found bool
	mounts, err := mr.getMounts(ctx)
	if err != nil {
		log.Error("could not reliably determine existing mount status")
		return targetMount, false, status.Error(codes.Internal,
			"could not reliably determine existing mount status")
	}
	for _, mount := range mounts {
		if mount.Path == target {
			targetMount = mount
			log.WithFields(logFields).Infof("matching targetMount %s target %s",
				target, mount.Path)
			found = true
			break
		}
	}
	return targetMount, found, nil
}

func (mr *mountLibMountsReaderIMPL) getMounts(ctx context.Context) ([]gofsutil.Info, error) {
	data, err := mr.consistentReader.consistentRead(procMountsPath, procMountsRetries)
	if err != nil {
		return []gofsutil.Info{}, err
	}
	info, err := mr.fsLib.ParseProcMounts(context.Background(),
		bytes.NewReader(data))
	if err != nil {
		return []gofsutil.Info{}, err
	}
	return info, nil
}

type mkdir struct {
	os limitedOSIFace
}

func newMkdir(os limitedOSIFace) *mkdir {
	return &mkdir{os: os}
}

func (m *mkdir) mkDir(path string) (bool, error) {
	st, err := m.os.Stat(path)
	if m.os.IsNotExist(err) {
		if err := m.os.Mkdir(path, 0750); err != nil {
			log.WithField("dir", path).WithError(
				err).Error("Unable to create dir")
			return false, err
		}
		log.WithField("path", path).Debug("created directory")
		return true, nil
	}
	if !st.IsDir() {
		return false, fmt.Errorf("existing path is not a directory")
	}
	return false, nil
}

type mkdirall struct {
	os limitedOSIFace
}

func newMkdirAll(os limitedOSIFace) *mkdirall {
	return &mkdirall{os: os}
}

func (m *mkdirall) mkDirAll(path string) (bool, error) {
	st, err := m.os.Stat(path)
	if m.os.IsNotExist(err) {
		if err := m.os.MkdirAll(path, 0750); err != nil {
			log.WithField("dir", path).WithError(
				err).Error("Unable to create dir")
			return false, err
		}
		log.WithField("path", path).Debug("created directory")
		return true, nil
	}
	if !st.IsDir() {
		return false, fmt.Errorf("existing path is not a directory")
	}
	return false, nil
}

func newMkfile(os limitedOSIFace) *mkfile {
	return &mkfile{os: os}
}

type mkfile struct {
	os limitedOSIFace
}

func (m *mkfile) mkFile(path string) (bool, error) {
	st, err := m.os.Stat(path)
	if m.os.IsNotExist(err) {
		file, err := m.os.OpenFile(path, os.O_CREATE, 0600)
		if err != nil {
			log.WithField("path", path).WithError(
				err).Error("Unable to create file")
			return false, err
		}
		if err = file.Close(); err != nil {
			return false, fmt.Errorf("could not close file")
		}
		log.WithField("path", path).Debug("created file")
		return true, nil
	}
	if st.IsDir() {
		return false, fmt.Errorf("existing path is a directory")
	}
	return false, nil
}

func newMkFS(os limitedOSIFace) *mkfs {
	return &mkfs{os: os}
}

type mkfs struct {
	os limitedOSIFace
}

func (m *mkfs) format(ctx context.Context,
	source, fsType string,
	opts ...string) error {

	f := log.Fields{
		"source":  source,
		"fsType":  fsType,
		"options": opts,
	}

	// Use 'xfs' as the default
	if fsType == "" {
		fsType = "xfs"
	}

	mkfsCmd := fmt.Sprintf("mkfs.%s", fsType)
	mkfsArgs := []string{"-E", "nodiscard", "-F", source}

	if fsType == "xfs" {
		mkfsArgs = []string{"-K", source}
	}
	mkfsArgs = append(mkfsArgs, opts...)

	log.WithFields(f).Infof("formatting with command: %s %v", mkfsCmd, mkfsArgs)
	out, err := m.os.ExecCommand(mkfsCmd, mkfsArgs...)
	if err != nil {
		log.WithFields(f).WithError(err).Errorf("formatting disk failed, output: %q", string(out))
		return err
	}

	return nil
}

func contains(list []string, item string) bool {
	for _, x := range list {
		if x == item {
			return true
		}
	}
	return false
}

func newConsistentReadIMPL(fileReader fileReader) *consistentReadIMPL {
	return &consistentReadIMPL{fileReader}
}

type consistentReadIMPL struct {
	fileReader fileReader
}

func (cr *consistentReadIMPL) consistentRead(filename string, retry int) ([]byte, error) {
	oldContent, err := cr.fileReader.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	for i := 0; i < retry; i++ {
		newContent, err := cr.fileReader.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		if bytes.Compare(oldContent, newContent) == 0 {
			log.Infof("successfully read mount file snapshot retry count: %d", i)
			return newContent, nil
		}
		// Files are different, continue reading
		oldContent = newContent
	}
	return nil, fmt.Errorf("could not get consistent content of %s after %d attempts", filename, retry)
}

type reqHelpersIMPL struct{}

func (rh *reqHelpersIMPL) isBlock(req volumeCapabilityGetter) bool {
	_, isBlock := req.GetVolumeCapability().GetAccessType().(*csi.VolumeCapability_Block)
	return isBlock
}

func (rh *reqHelpersIMPL) getStagingPath(ctx context.Context, req commonReqGetters) string {
	logFields := getLogFields(ctx)
	sp := req.GetStagingTargetPath()
	volID := req.GetVolumeId()
	if sp == "" || volID == "" {
		return ""
	}
	stagingPath := path.Join(sp, volID)
	log.WithFields(logFields).Infof("staging path is: %s", stagingPath)
	return path.Join(sp, volID)
}

type commonReqGetters interface {
	GetStagingTargetPath() string
	GetVolumeId() string
}
