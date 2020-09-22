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
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gofsutil"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestMount_getStageVolumeIMPL(t *testing.T) {
	m := mount{}
	assert.NotNil(t, m.getStageVolumeIMPL())
}

func TestMount_getUnstageVolumeIMPL(t *testing.T) {
	m := mount{}
	assert.NotNil(t, m.getUnstageVolumeIMPL())
}

func TestMount_getPublishVolumeIMPL(t *testing.T) {
	m := mount{}
	assert.NotNil(t, m.getPublishVolumeIMPL())
}

func TestMount_getUnpublishVolumeIMPL(t *testing.T) {
	m := mount{}
	assert.NotNil(t, m.getUnpublishVolumeIMPL())
}

func TestMount_getMountIMPLGetMounts(t *testing.T) {
	m := mount{}
	assert.NotNil(t, m.getMountIMPLGetMounts())
}

func TestMount_getPublishCheckIMPL(t *testing.T) {
	m := mount{}
	assert.NotNil(t, m.getPublishCheckIMPL())
}

type mountLibMountsReaderIMPLMocks struct {
	fileReaderMock       *MockfileReader
	consistentReaderMock *MockconsistentReader
	fsLibMock            *MockwrapperFsLib
	getMountsOK          func()
	getMountsError       func()
}

func initMountLibMountsReaderMocks(t *testing.T) (
	mountLibMountsReaderIMPLMocks,
	*mountLibMountsReaderIMPL,
	*gomock.Controller) {

	ctrl := gomock.NewController(t)
	mocks := mountLibMountsReaderIMPLMocks{}
	mocks.fileReaderMock = NewMockfileReader(ctrl)
	mocks.consistentReaderMock = NewMockconsistentReader(ctrl)
	mocks.fsLibMock = NewMockwrapperFsLib(ctrl)

	mocks.getMountsOK = func() {
		mocks.consistentReaderMock.EXPECT().
			consistentRead(gomock.Any(), gomock.Any()).Return([]byte{}, nil)
		mocks.fsLibMock.EXPECT().ParseProcMounts(gomock.Any(), gomock.Any()).
			Return([]gofsutil.Info{getValidGofsutilOtherDevInfo(),
				getValidGofsutilTargetDevInfo()}, nil)
	}

	mocks.getMountsError = func() {
		mocks.consistentReaderMock.EXPECT().
			consistentRead(gomock.Any(), gomock.Any()).
			Return([]byte{}, errors.New(testErrMsg))
	}

	impl := newMountLibMountsReaderIMPL(
		mocks.fileReaderMock,
		mocks.consistentReaderMock,
		mocks.fsLibMock)
	return mocks, impl, ctrl
}

func TestMount_mountLibMountsReaderIMPL_getMountsByDev(t *testing.T) {
	mocks, impl, ctrl := initMountLibMountsReaderMocks(t)
	defer ctrl.Finish()
	ctx := context.Background()

	funcUnderTest := func() ([]gofsutil.Info, error) {
		return impl.getMountsByDev(ctx, validDevPath)
	}

	t.Run("getMounts error", func(t *testing.T) {
		mocks.getMountsError()
		_, err := funcUnderTest()
		assert.EqualError(t, err, "rpc error: code = Internal"+
			" desc = could not reliably determine mount status for device")
	})

	t.Run("success", func(t *testing.T) {
		mocks.getMountsOK()
		data, err := funcUnderTest()
		assert.Nil(t, err)
		assert.Len(t, data, 1)
		assert.Equal(t, validDevPath, data[0].Device)
	})
}

func TestMount_mountLibMountsReaderIMPL_getTargetMount(t *testing.T) {
	mocks, impl, ctrl := initMountLibMountsReaderMocks(t)
	defer ctrl.Finish()
	ctx := context.Background()

	funcUnderTest := func() (gofsutil.Info, bool, error) {
		return impl.getTargetMount(ctx, validTargetPath)
	}

	t.Run("getMounts error", func(t *testing.T) {
		mocks.getMountsError()
		_, found, err := funcUnderTest()
		assert.False(t, found)
		assert.EqualError(t, err, "rpc error: code = Internal"+
			" desc = could not reliably determine existing mount status")
	})

	t.Run("success", func(t *testing.T) {
		mocks.getMountsOK()
		data, found, err := funcUnderTest()
		assert.True(t, found)
		assert.Nil(t, err)
		assert.Equal(t, validDevPath, data.Device)
	})
}

func TestMount_mountLibMountsReaderIMPL_getMounts(t *testing.T) {
	mocks, impl, ctrl := initMountLibMountsReaderMocks(t)
	defer ctrl.Finish()
	ctx := context.Background()

	funcUnderTest := func() ([]gofsutil.Info, error) {
		return impl.getMounts(ctx)
	}
	consistentReadMock := func() *gomock.Call {
		return mocks.consistentReaderMock.EXPECT().
			consistentRead(gomock.Any(), gomock.Any())
	}
	consistentReadMockError := func() {
		consistentReadMock().Return([]byte{}, errors.New(testErrMsg))
	}
	consistentReadMockOK := func() {
		consistentReadMock().Return([]byte{}, nil)
	}

	parseProcMountsMock := func() *gomock.Call {
		return mocks.fsLibMock.EXPECT().ParseProcMounts(gomock.Any(), gomock.Any())
	}
	parseProcMountsMockOK := func() {
		parseProcMountsMock().
			Return([]gofsutil.Info{getValidGofsutilOtherDevInfo(),
				getValidGofsutilTargetDevInfo()}, nil)
	}
	parseProcMountsMockError := func() {
		parseProcMountsMock().
			Return([]gofsutil.Info{}, errors.New(testErrMsg))
	}

	t.Run("consistentRead error", func(t *testing.T) {
		consistentReadMockError()
		_, err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("ParseProcMounts error", func(t *testing.T) {
		consistentReadMockOK()
		parseProcMountsMockError()
		_, err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("success", func(t *testing.T) {
		consistentReadMockOK()
		parseProcMountsMockOK()
		data, err := funcUnderTest()
		assert.Nil(t, err)
		assert.Len(t, data, 2)
	})
}

func TestMkDir(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	osMock := NewMocklimitedOSIFace(ctrl)
	fileInfoMock := NewMocklimitedFileInfoIFace(ctrl)

	mkdir := newMkdir(osMock)

	// already exist
	osMock.EXPECT().Stat(validTargetPath).Return(fileInfoMock, nil)
	osMock.EXPECT().IsNotExist(gomock.Nil()).Return(false)
	fileInfoMock.EXPECT().IsDir().Return(true)
	created, err := mkdir.mkDir(validTargetPath)
	assert.Nil(t, err)
	assert.False(t, created)

	// not a dir
	osMock.EXPECT().Stat(validTargetPath).Return(fileInfoMock, nil)
	osMock.EXPECT().IsNotExist(gomock.Nil()).Return(false)
	fileInfoMock.EXPECT().IsDir().Return(false)
	created, err = mkdir.mkDir(validTargetPath)
	assert.EqualError(t, err, "existing path is not a directory")

	// created
	err = errors.New(testErrMsg)
	osMock.EXPECT().Stat(validTargetPath).Return(fileInfoMock, err)
	osMock.EXPECT().IsNotExist(err).Return(true)
	osMock.EXPECT().Mkdir(validTargetPath, gomock.Any()).Return(nil)
	created, err = mkdir.mkDir(validTargetPath)
	assert.Nil(t, err)
	assert.True(t, created)

	// failed to create
	errMsg2 := "test err2"
	osMock.EXPECT().Stat(validTargetPath).Return(fileInfoMock, err)
	osMock.EXPECT().IsNotExist(err).Return(true)
	osMock.EXPECT().Mkdir(validTargetPath, gomock.Any()).Return(errors.New(errMsg2))
	created, err = mkdir.mkDir(validTargetPath)
	assert.EqualError(t, err, errMsg2)
}

func TestMkFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	osMock := NewMocklimitedOSIFace(ctrl)
	fileInfoMock := NewMocklimitedFileInfoIFace(ctrl)
	fileMock := NewMocklimitedFileIFace(ctrl)

	mkfile := newMkfile(osMock)

	// already exist
	osMock.EXPECT().Stat(validTargetPath).Return(fileInfoMock, nil)
	osMock.EXPECT().IsNotExist(gomock.Nil()).Return(false)
	fileInfoMock.EXPECT().IsDir().Return(false)
	created, err := mkfile.mkFile(validTargetPath)
	assert.Nil(t, err)
	assert.False(t, created)

	// is dir
	osMock.EXPECT().Stat(validTargetPath).Return(fileInfoMock, nil)
	osMock.EXPECT().IsNotExist(gomock.Nil()).Return(false)
	fileInfoMock.EXPECT().IsDir().Return(true)
	created, err = mkfile.mkFile(validTargetPath)
	assert.EqualError(t, err, "existing path is a directory")

	err = errors.New("not exist")

	osMock.EXPECT().Stat(validTargetPath).Return(fileInfoMock, err).AnyTimes()
	osMock.EXPECT().IsNotExist(err).Return(true).AnyTimes()

	// open error
	osMock.EXPECT().OpenFile(validTargetPath, os.O_CREATE, gomock.Any()).
		Return(fileMock, errors.New(testErrMsg))
	created, err = mkfile.mkFile(validTargetPath)
	assert.EqualError(t, err, testErrMsg)

	// close error
	osMock.EXPECT().OpenFile(validTargetPath, os.O_CREATE, gomock.Any()).
		Return(fileMock, nil)
	fileMock.EXPECT().Close().Return(errors.New(testErrMsg))
	created, err = mkfile.mkFile(validTargetPath)
	assert.EqualError(t, err, "could not close file")

	// created
	osMock.EXPECT().OpenFile(validTargetPath, os.O_CREATE, gomock.Any()).
		Return(fileMock, nil)
	fileMock.EXPECT().Close().Return(nil)
	created, err = mkfile.mkFile(validTargetPath)
	assert.Nil(t, err)
	assert.True(t, created)
}

func TestMkFS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	osMock := NewMocklimitedOSIFace(ctrl)

	mkFS := newMkFS(osMock)
	// error
	osMock.EXPECT().ExecCommand(gomock.Eq("mkfs.ext4"), gomock.Any()).
		Return(nil, errors.New(testErrMsg))
	err := mkFS.format(nil, validTargetPath, "ext4")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), testErrMsg)

	// success
	osMock.EXPECT().ExecCommand(gomock.Eq("mkfs.ext4"), gomock.Any()).
		Return([]byte("\n"), nil)
	err = mkFS.format(nil, validTargetPath, "ext4")
	assert.Nil(t, err)

	// xfs on default
	osMock.EXPECT().ExecCommand(gomock.Eq("mkfs.xfs"), gomock.Any()).
		Return([]byte("\n"), nil)
	err = mkFS.format(nil, validTargetPath, "")
	assert.Nil(t, err)
}

func TestMount_contains(t *testing.T) {
	testData := []string{"foo", "bar", "ro", "spam", "rw"}
	assert.True(t, contains(testData, "rw"))
	assert.True(t, contains(testData, "ro"))
	assert.False(t, contains(testData, "test"))
}

func TestMount_consistentReadIMPL_consistentRead(t *testing.T) {
	ctrl := gomock.NewController(t)
	fileReaderMock := NewMockfileReader(ctrl)

	retryCount := 5
	testByteArr := []byte("foobar")

	cri := newConsistentReadIMPL(fileReaderMock)

	funcUnderTest := func() ([]byte, error) {
		return cri.consistentRead(procMountsPath, retryCount)
	}

	t.Run("error reading first time", func(t *testing.T) {
		fileReaderMock.EXPECT().ReadFile(procMountsPath).Return([]byte{}, errors.New(testErrMsg))
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("error reading second time", func(t *testing.T) {
		fileReaderMock.EXPECT().ReadFile(procMountsPath).Return(testByteArr, nil)
		fileReaderMock.EXPECT().ReadFile(procMountsPath).Return([]byte{}, errors.New(testErrMsg))
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("success without retry", func(t *testing.T) {
		fileReaderMock.EXPECT().ReadFile(procMountsPath).Return(testByteArr, nil).Times(2)
		data, err := funcUnderTest()
		assert.Equal(t, testByteArr, data)
		assert.Nil(t, err)
	})

	t.Run("success with retry", func(t *testing.T) {
		fileReaderMock.EXPECT().ReadFile(procMountsPath).Return([]byte("foo"), nil)
		fileReaderMock.EXPECT().ReadFile(procMountsPath).Return(testByteArr, nil)
		fileReaderMock.EXPECT().ReadFile(procMountsPath).Return(testByteArr, nil)
		data, err := funcUnderTest()
		assert.Equal(t, testByteArr, data)
		assert.Nil(t, err)
	})

	t.Run("failed", func(t *testing.T) {
		fileReaderMock.EXPECT().ReadFile(procMountsPath).DoAndReturn(func(key string) ([]byte, error) {
			resp := make([]byte, 10)
			_, err := rand.Read(resp)
			if err != nil {
				t.FailNow()
			}
			return resp, nil
		}).Times(retryCount * 2)
		data, err := funcUnderTest()
		assert.Empty(t, data)
		assert.EqualError(t, err, fmt.Sprintf("could not get consistent content"+
			" of %s after %d attempts", procMountsPath, retryCount))
	})
}

func TestMount_reqHelpersIMPL_isBlock(t *testing.T) {
	req := getNodePublishValidRequest()
	volCap := getCapabilityWithVoltypeAccessFstype("block", "single-writer", "")
	req.VolumeCapability = volCap
	rh := reqHelpersIMPL{}
	assert.True(t, rh.isBlock(req))

	volCap = getCapabilityWithVoltypeAccessFstype("mount", "single-writer", "")
	req.VolumeCapability = volCap
	assert.False(t, rh.isBlock(req))
}

func TestMount_reqHelpersIMPL_getStagingPath(t *testing.T) {
	req := getNodePublishValidRequest()
	rh := reqHelpersIMPL{}
	ctx := context.Background()
	assert.NotEmpty(t, rh.getStagingPath(ctx, req))

	req.StagingTargetPath = ""
	assert.Empty(t, rh.getStagingPath(ctx, req))
	req.StagingTargetPath = validStagingPath

	req.VolumeId = ""
	assert.Empty(t, rh.getStagingPath(ctx, req))
	req.VolumeId = validVolumeID
}

func TestMount_mountLibStageIMPL_stage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mkfile := NewMockfileCreator(ctrl)
	mkdir := NewMockdirCreator(ctrl)
	reqHelper := NewMockreqHelpers(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)
	stageCheck := NewMockmountLibStageCheck(ctrl)

	ctx := context.Background()

	impl := newMountLibStageIMPL(mkfile, mkdir, reqHelper, fsLib, stageCheck)

	funcUnderTest := func() error {
		return impl.stage(ctx, getNodeStageValidRequest(), validDevPath)
	}

	getStagingPathMockOK := func() {
		reqHelper.EXPECT().getStagingPath(gomock.Any(), gomock.Any()).
			Return(validStagingPath)
	}
	mkFileMock := func() *gomock.Call {
		return mkfile.EXPECT().mkFile(validStagingPath)
	}
	mkFileMockError := func() {
		mkFileMock().Return(false, errors.New(testErrMsg))
	}
	mkFileMockCreated := func() {
		mkFileMock().Return(true, nil)
	}
	bindMountMock := func() *gomock.Call {
		return fsLib.EXPECT().
			BindMount(gomock.Any(), validDevPath, validStagingPath)
	}
	bindMountError := func() {
		bindMountMock().Return(errors.New(testErrMsg))
	}
	bindMountOK := func() {
		bindMountMock().Return(nil)
	}

	t.Run("can't create target file", func(t *testing.T) {
		getStagingPathMockOK()
		mkFileMockError()
		err := funcUnderTest()
		assert.EqualError(t, err,
			fmt.Sprintf("rpc error: code = Internal"+
				" desc = can't create target file %s: %s",
				validStagingPath, testErrMsg))
	})

	t.Run("bind error", func(t *testing.T) {
		getStagingPathMockOK()
		mkFileMockCreated()
		bindMountError()
		err := funcUnderTest()
		assert.EqualError(t, err,
			fmt.Sprintf("rpc error: code = Internal "+
				"desc = error bind disk %s to target path: %s",
				validDevPath, testErrMsg))
	})

	t.Run("success", func(t *testing.T) {
		getStagingPathMockOK()
		mkFileMockCreated()
		bindMountOK()
		err := funcUnderTest()
		assert.Nil(t, err)
	})
}

func TestMount_mountLibStageIMPL_stageNFS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mkfile := NewMockfileCreator(ctrl)
	mkdir := NewMockdirCreator(ctrl)
	reqHelper := NewMockreqHelpers(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)
	stageCheck := NewMockmountLibStageCheck(ctrl)

	ctx := context.Background()

	impl := newMountLibStageIMPL(mkfile, mkdir, reqHelper, fsLib, stageCheck)

	funcUnderTest := func() error {
		return impl.stageNFS(ctx, getNodeStageValidRequest(), validDevPath)
	}

	getStagingPathMockOK := func() {
		reqHelper.EXPECT().getStagingPath(gomock.Any(), gomock.Any()).
			Return(validStagingPath)
	}
	mkDirMock := func() *gomock.Call {
		return mkdir.EXPECT().mkDir(validStagingPath)
	}
	mkDirMockError := func() {
		mkDirMock().Return(false, errors.New(testErrMsg))
	}
	mkDirMockCreated := func() {
		mkDirMock().Return(true, nil)
	}
	mountMock := func() *gomock.Call {
		return fsLib.EXPECT().
			Mount(gomock.Any(), validDevPath, validStagingPath, "")
	}
	mountError := func() {
		mountMock().Return(errors.New(testErrMsg))
	}
	mountOK := func() {
		mountMock().Return(nil)
	}

	t.Run("can't create target folder", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockError()
		err := funcUnderTest()
		assert.EqualError(t, err,
			fmt.Sprintf("rpc error: code = Internal"+
				" desc = can't create target folder %s: %s",
				validStagingPath, testErrMsg))
	})

	t.Run("mount error", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockCreated()
		mountError()
		err := funcUnderTest()
		assert.EqualError(t, err,
			fmt.Sprintf("rpc error: code = Internal "+
				"desc = error mount nfs share %s to target path: %s",
				validDevPath, testErrMsg))
	})

	t.Run("success", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockCreated()
		mountOK()
		err := funcUnderTest()
		assert.Nil(t, err)
	})
}

func TestMount_mountLibUnstageIMPL_unstage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	osLib := NewMocklimitedOSIFace(ctrl)
	reqHelper := NewMockreqHelpers(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)
	stageCheck := NewMockmountLibStageCheck(ctrl)

	ctx := context.Background()

	impl := newMountLibUnstageIMPL(osLib, reqHelper, fsLib, stageCheck)

	funcUnderTest := func() (string, error) {
		return impl.unstage(ctx, getNodeUnstageValidRequest())
	}
	getStagingPathMockOK := func() {
		reqHelper.EXPECT().getStagingPath(gomock.Any(), gomock.Any()).
			Return(validStagingPath)
	}
	getStagedDevMock := func() *gomock.Call {
		return stageCheck.EXPECT().getStagedDev(gomock.Any(), validStagingPath)
	}
	getStagedDevMockError := func() {
		getStagedDevMock().Return("", errors.New(testErrMsg))
	}
	getStagedDevMockEmpty := func() {
		getStagedDevMock().Return("", nil)
	}
	getStagedDevMockFound := func() {
		getStagedDevMock().Return(validDevPath, nil)
	}
	unmountMock := func() *gomock.Call {
		return fsLib.EXPECT().Unmount(gomock.Any(), gomock.Any())
	}
	unmountMockError := func() {
		unmountMock().Return(errors.New(testErrMsg))
	}
	unmountMockOK := func() {
		unmountMock().Return(nil)
	}
	removeMock := func() *gomock.Call {
		return osLib.EXPECT().Remove(validStagingPath)
	}
	removeMockError := func() {
		osLib.EXPECT().IsNotExist(gomock.Any()).Return(false)
		removeMock().Return(errors.New(testErrMsg))
	}
	removeMockOK := func() {
		removeMock().Return(nil)
	}
	removeMockNotFound := func() {
		removeMock().Return(errors.New(testErrMsg))
		osLib.EXPECT().IsNotExist(gomock.Any()).Return(true)
	}

	t.Run("getStagedDev error", func(t *testing.T) {
		getStagingPathMockOK()
		getStagedDevMockError()
		_, err := funcUnderTest()
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal desc"+
			" = could not reliably determine existing mount for path %s: %s",
			validStagingPath, testErrMsg))
	})

	t.Run("device already unstaged", func(t *testing.T) {
		getStagingPathMockOK()
		getStagedDevMockEmpty()
		removeMockOK()
		device, err := funcUnderTest()
		assert.Nil(t, err)
		assert.Empty(t, device)
	})
	t.Run("unmount error", func(t *testing.T) {
		getStagingPathMockOK()
		getStagedDevMockFound()
		unmountMockError()
		device, err := funcUnderTest()
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal "+
			"desc = could not unmount dev %s: %s",
			validDevName, testErrMsg))
		assert.Empty(t, device)
	})
	t.Run("remove mount point error", func(t *testing.T) {
		getStagingPathMockOK()
		getStagedDevMockFound()
		unmountMockOK()
		removeMockError()
		device, err := funcUnderTest()
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal"+
			" desc = failed to delete mount path %s: %s",
			validStagingPath, testErrMsg))
		assert.Empty(t, device)
	})
	t.Run("mount point not found while remove", func(t *testing.T) {
		getStagingPathMockOK()
		getStagedDevMockFound()
		unmountMockOK()
		removeMockNotFound()
		device, err := funcUnderTest()
		assert.Nil(t, err)
		assert.Equal(t, validDevName, device)
	})
	t.Run("mount point remove ok", func(t *testing.T) {
		getStagingPathMockOK()
		getStagedDevMockFound()
		unmountMockOK()
		removeMockOK()
		device, err := funcUnderTest()
		assert.Nil(t, err)
		assert.Equal(t, validDevName, device)
	})
}

func TestMount_mountLibStageCheckIMPL_getStagedDev(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	getMounts := NewMockmountLibMountsReader(ctrl)
	reqHelper := NewMockreqHelpers(ctrl)

	ctx := context.Background()

	impl := newMountLibStageCheckIMPL(reqHelper, getMounts)

	funcUnderTest := func() (string, error) {
		return impl.getStagedDev(ctx, validStagingPath)
	}
	getTargetMountMock := func() *gomock.Call {
		return getMounts.EXPECT().getTargetMount(gomock.Any(), validStagingPath)
	}
	getTargetMountMockError := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, errors.New(testErrMsg))
	}
	getTargetMountMockFoundBind := func() {
		device := getValidGofsutilTargetDevInfo()
		device.Device = "devtmpfs"
		getTargetMountMock().Return(device, true, nil)
	}
	getTargetMountMockNotFound := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, nil)
	}
	t.Run("getTargetMount error", func(t *testing.T) {
		getTargetMountMockError()
		device, err := funcUnderTest()
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal "+
			"desc = can't check mounts for path %s: %s",
			validStagingPath, testErrMsg))
		assert.Empty(t, device)
	})
	t.Run("getTargetMount not found", func(t *testing.T) {
		getTargetMountMockNotFound()
		device, err := funcUnderTest()
		assert.Nil(t, err)
		assert.Empty(t, device)
	})

	t.Run("success", func(t *testing.T) {
		getTargetMountMockFoundBind()
		device, err := funcUnderTest()
		assert.Nil(t, err)
		assert.Equal(t, device, getValidGofsutilTargetDevInfo().Device)
	})
}

func TestMount_mountLibPublishIMPL_publish(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	publishCheck := NewMockmountLibPublishCheck(ctrl)
	reqHelper := NewMockreqHelpers(ctrl)
	mountBlock := NewMockmountLibPublishBlock(ctrl)
	mountMount := NewMockmountLibPublishMount(ctrl)
	mkdir := NewMockdirCreator(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)

	ctx := context.Background()

	impl := newMountLibPublishIMPL(publishCheck, reqHelper, mountBlock, mountMount, mkdir, fsLib)

	funcUnderTest := func() error {
		return impl.publish(ctx, getNodePublishValidRequest())
	}
	isAlreadyPublishedMock := func() *gomock.Call {
		return publishCheck.EXPECT().isAlreadyPublished(
			gomock.Any(), gomock.Any(), gomock.Any())
	}
	isAlreadyPublishedMockError := func() {
		isAlreadyPublishedMock().Return(false, errors.New(testErrMsg))
	}
	isAlreadyPublishedMockTrue := func() {
		isAlreadyPublishedMock().Return(true, nil)
	}
	isAlreadyPublishedMockFalse := func() {
		isAlreadyPublishedMock().Return(false, nil)
	}
	isBlockMock := func() *gomock.Call {
		return reqHelper.EXPECT().isBlock(gomock.Any())
	}
	isBlockMockTrue := func() {
		isBlockMock().Return(true)
	}
	isBlockMockFalse := func() {
		isBlockMock().Return(false)
	}
	publishBlockMock := func() *gomock.Call {
		return mountBlock.EXPECT().publishBlock(gomock.Any(), gomock.Any())
	}
	publishBlockMockOK := func() {
		publishBlockMock().Return(nil)
	}
	publishBlockMockError := func() {
		publishBlockMock().Return(errors.New(testErrMsg))
	}
	publishMountMock := func() *gomock.Call {
		return mountMount.EXPECT().publishMount(gomock.Any(), gomock.Any())
	}
	publishMountMockOK := func() {
		publishMountMock().Return(nil)
	}
	publishMountMockError := func() {
		publishMountMock().Return(errors.New(testErrMsg))
	}

	t.Run("isAlreadyPublished error", func(t *testing.T) {
		isAlreadyPublishedMockError()
		err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("isAlreadyPublished true", func(t *testing.T) {
		isAlreadyPublishedMockTrue()
		err := funcUnderTest()
		assert.Nil(t, err)
	})

	t.Run("publish block error", func(t *testing.T) {
		isAlreadyPublishedMockFalse()
		isBlockMockTrue()
		publishBlockMockError()
		err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})
	t.Run("publish block ok", func(t *testing.T) {
		isAlreadyPublishedMockFalse()
		isBlockMockTrue()
		publishBlockMockOK()
		err := funcUnderTest()
		assert.Nil(t, err)
	})
	t.Run("publish mount error", func(t *testing.T) {
		isAlreadyPublishedMockFalse()
		isBlockMockFalse()
		publishMountMockError()
		err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})
	t.Run("publish block ok", func(t *testing.T) {
		isAlreadyPublishedMockFalse()
		isBlockMockFalse()
		publishMountMockOK()
		err := funcUnderTest()
		assert.Nil(t, err)
	})
}

func TestMount_mountLibPublishIMPL_publishNFS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	publishCheck := NewMockmountLibPublishCheck(ctrl)
	reqHelper := NewMockreqHelpers(ctrl)
	mountBlock := NewMockmountLibPublishBlock(ctrl)
	mountMount := NewMockmountLibPublishMount(ctrl)
	mkdir := NewMockdirCreator(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)

	ctx := context.Background()

	impl := newMountLibPublishIMPL(publishCheck, reqHelper, mountBlock, mountMount, mkdir, fsLib)

	funcUnderTest := func() error {
		return impl.publishNFS(ctx, getNodePublishValidRequest())
	}

	getStagingPathMockOK := func() {
		reqHelper.EXPECT().getStagingPath(gomock.Any(), gomock.Any()).
			Return(validStagingPath)
	}

	isAlreadyPublishedMock := func() *gomock.Call {
		return publishCheck.EXPECT().isAlreadyPublished(
			gomock.Any(), gomock.Any(), gomock.Any())
	}
	isAlreadyPublishedMockError := func() {
		isAlreadyPublishedMock().Return(false, errors.New(testErrMsg))
	}
	isAlreadyPublishedMockTrue := func() {
		isAlreadyPublishedMock().Return(true, nil)
	}
	isAlreadyPublishedMockFalse := func() {
		isAlreadyPublishedMock().Return(false, nil)
	}

	mkDirMock := func() *gomock.Call {
		return mkdir.EXPECT().mkDir(gomock.Any())
	}
	mkDirMockError := func() {
		mkDirMock().Return(false, errors.New(testErrMsg))
	}
	mkDirMockCreated := func() {
		mkDirMock().Return(true, nil)
	}

	publishNfsMock := func() *gomock.Call {
		return fsLib.EXPECT().BindMount(gomock.Any(), gomock.Any(), gomock.Any())
	}
	publishNfsMockOK := func() {
		publishNfsMock().Return(nil)
	}
	publishNfsMockError := func() {
		publishNfsMock().Return(errors.New(testErrMsg))
	}

	t.Run("isAlreadyPublished error", func(t *testing.T) {
		getStagingPathMockOK()
		isAlreadyPublishedMockError()
		err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
	})

	t.Run("isAlreadyPublished true", func(t *testing.T) {
		getStagingPathMockOK()
		isAlreadyPublishedMockTrue()
		err := funcUnderTest()
		assert.Nil(t, err)
	})

	t.Run("can't create target folder", func(t *testing.T) {
		getStagingPathMockOK()
		isAlreadyPublishedMockFalse()
		mkDirMockError()
		err := funcUnderTest()
		assert.EqualError(t, err,
			fmt.Sprintf("rpc error: code = Internal"+
				" desc = can't create target folder %s: %s",
				validStagingPath, testErrMsg))
	})

	t.Run("publish error", func(t *testing.T) {
		getStagingPathMockOK()
		isAlreadyPublishedMockFalse()
		mkDirMockCreated()
		publishNfsMockError()
		err := funcUnderTest()
		assert.EqualError(t, err,
			fmt.Sprintf("rpc error: code = Internal "+
				"desc = error bind disk %s to target path: %s",
				validStagingPath, testErrMsg))
	})

	t.Run("success", func(t *testing.T) {
		getStagingPathMockOK()
		isAlreadyPublishedMockFalse()
		mkDirMockCreated()
		publishNfsMockOK()
		err := funcUnderTest()
		assert.Nil(t, err)
	})
}

func TestMount_mountLibUnpublishIMPL_unpuplish(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	osLib := NewMocklimitedOSIFace(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)
	mountReader := NewMockmountLibMountsReader(ctrl)

	ctx := context.Background()

	impl := newMountLibUnpublishIMPL(mountReader, fsLib, osLib)

	funcUnderTest := func() error {
		return impl.unpublish(ctx, getNodeUnpublishValidRequest())
	}

	getTargetMountMock := func() *gomock.Call {
		return mountReader.EXPECT().getTargetMount(gomock.Any(), validTargetPath)
	}
	getTargetMountMockError := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, errors.New(testErrMsg))
	}
	getTargetMountMockFound := func() {
		getTargetMountMock().Return(getValidGofsutilTargetDevInfo(), true, nil)
	}
	getTargetMountMockNotFound := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, nil)
	}
	unmountMock := func() *gomock.Call {
		return fsLib.EXPECT().Unmount(gomock.Any(), validTargetPath)
	}
	unmountMockError := func() {
		unmountMock().Return(errors.New(testErrMsg))
	}
	unmountMockOK := func() {
		unmountMock().Return(nil)
	}
	t.Run("getTargetMount error", func(t *testing.T) {
		getTargetMountMockError()
		err := funcUnderTest()
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal"+
			" desc = could not reliably determine "+
			"existing mount status for path %s: %s", validTargetPath, testErrMsg))
	})

	t.Run("getTargetMount not found", func(t *testing.T) {
		getTargetMountMockNotFound()
		err := funcUnderTest()
		assert.Nil(t, err)
	})

	t.Run("unmount error", func(t *testing.T) {
		getTargetMountMockFound()
		unmountMockError()
		err := funcUnderTest()
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal"+
			" desc = could not unmount dev %s: %s", validTargetPath, testErrMsg))
	})
	t.Run("success", func(t *testing.T) {
		getTargetMountMockFound()
		unmountMockOK()
		err := funcUnderTest()
		assert.Nil(t, err)
	})
}

func TestMount_getRWModeString(t *testing.T) {
	assert.Equal(t, "ro", getRWModeString(true))
	assert.Equal(t, "rw", getRWModeString(false))
}

func TestMount_mountLibPublishCheckIMPL_isAlreadyPublished(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mountReader := NewMockmountLibMountsReader(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)

	ctx := context.Background()
	impl := newMountLibPublishCheckIMPL(mountReader, fsLib)

	funcUnderTest := func() (bool, error) {
		return impl.isAlreadyPublished(ctx, validTargetPath, "rw")
	}
	getTargetMountMock := func() *gomock.Call {
		return mountReader.EXPECT().getTargetMount(gomock.Any(), validTargetPath)
	}
	getTargetMountMockError := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, errors.New(testErrMsg))
	}
	getTargetMountMockFound := func() {
		getTargetMountMock().Return(getValidGofsutilTargetDevInfo(), true, nil)
	}
	getTargetMountMockNotFound := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, nil)
	}
	t.Run("getTargetMount error", func(t *testing.T) {
		getTargetMountMockError()
		_, err := funcUnderTest()
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal"+
			" desc = can't check mounts for path %s: %s", validTargetPath, testErrMsg))
	})
	t.Run("getTargetMount not found", func(t *testing.T) {
		getTargetMountMockNotFound()
		published, err := funcUnderTest()
		assert.False(t, published)
		assert.Nil(t, err)
	})
	t.Run("getTargetMount found bad mode", func(t *testing.T) {
		getTargetMountMockFound()
		published, err := impl.isAlreadyPublished(ctx, validTargetPath, "ro")
		assert.False(t, published)
		assert.EqualError(t, err, "rpc error: code = FailedPrecondition "+
			"desc = volume already mounted"+
			" but with different capabilities: [rw realtime]")
	})
	t.Run("published", func(t *testing.T) {
		getTargetMountMockFound()
		published, err := funcUnderTest()
		assert.True(t, published)
		assert.Nil(t, err)
	})
}

func TestMount_mountLibPublishCheckIMPL_isReadyToPublish(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mountReader := NewMockmountLibMountsReader(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)

	ctx := context.Background()
	impl := newMountLibPublishCheckIMPL(mountReader, fsLib)

	funcUnderTest := func() (bool, bool, error) {
		return impl.isReadyToPublish(ctx, validStagingPath)
	}
	getTargetMountMock := func() *gomock.Call {
		return mountReader.EXPECT().getTargetMount(gomock.Any(), validStagingPath)
	}
	getTargetMountMockError := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, errors.New(testErrMsg))
	}
	getTargetMountMockFound := func() {
		getTargetMountMock().Return(getValidGofsutilTargetDevInfo(), true, nil)
	}
	getTargetMountMockNotFound := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, nil)
	}

	getTargetMountMockFoundWithDeleted := func() {
		getTargetMountMock().Return(gofsutil.Info{Source: "/dev/sdb/deleted"}, true, nil)
	}

	fsLibGetDiskFormatMock := func() *gomock.Call {
		return fsLib.EXPECT().GetDiskFormat(ctx, validStagingPath)
	}

	fsLibGetDiskFormatMockErr := func() *gomock.Call {
		return fsLibGetDiskFormatMock().Return("", errors.New(testErrMsg))
	}

	fsLibGetDiskFormatMockIsMpathMember := func() *gomock.Call {
		return fsLibGetDiskFormatMock().Return("mpath_member", nil)
	}

	fsLibGetDiskFormatMockEXT4 := func() *gomock.Call {
		return fsLibGetDiskFormatMock().Return("ext4", nil)
	}

	t.Run("getTargetMount error", func(t *testing.T) {
		getTargetMountMockError()
		found, ready, err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
		assert.False(t, ready)
		assert.False(t, found)
	})

	t.Run("getTargetMount not found", func(t *testing.T) {
		getTargetMountMockNotFound()
		found, ready, err := funcUnderTest()
		assert.Nil(t, err)
		assert.False(t, ready)
		assert.False(t, found)
	})

	t.Run("device has deleted suffix", func(t *testing.T) {
		getTargetMountMockFoundWithDeleted()
		found, ready, err := funcUnderTest()
		assert.Nil(t, err)
		assert.False(t, ready)
		assert.True(t, found)
	})

	t.Run("GetDiskFormat error", func(t *testing.T) {
		getTargetMountMockFound()
		fsLibGetDiskFormatMockErr()
		found, ready, err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
		assert.False(t, ready)
		assert.True(t, found)
	})

	t.Run("GetDiskFormat is mpath_member", func(t *testing.T) {
		getTargetMountMockFound()
		fsLibGetDiskFormatMockIsMpathMember()
		found, ready, err := funcUnderTest()
		assert.Nil(t, err)
		assert.False(t, ready)
		assert.True(t, found)
	})

	t.Run("ready", func(t *testing.T) {
		getTargetMountMockFound()
		fsLibGetDiskFormatMockEXT4()
		found, ready, err := funcUnderTest()
		assert.Nil(t, err)
		assert.True(t, ready)
		assert.True(t, found)
	})

}

func TestMount_mountLibPublishCheckIMPL_isReadyToPublishNFS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mountReader := NewMockmountLibMountsReader(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)

	ctx := context.Background()
	impl := newMountLibPublishCheckIMPL(mountReader, fsLib)

	funcUnderTest := func() (bool, error) {
		return impl.isReadyToPublishNFS(ctx, validStagingPath)
	}
	getTargetMountMock := func() *gomock.Call {
		return mountReader.EXPECT().getTargetMount(gomock.Any(), validStagingPath)
	}
	getTargetMountMockError := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, errors.New(testErrMsg))
	}
	getTargetMountMockFound := func() {
		getTargetMountMock().Return(getValidGofsutilTargetDevInfo(), true, nil)
	}
	getTargetMountMockNotFound := func() {
		getTargetMountMock().Return(gofsutil.Info{}, false, nil)
	}
	getTargetMountMockFoundWithDeleted := func() {
		getTargetMountMock().Return(gofsutil.Info{Source: "/dev/sdb/deleted"}, true, nil)
	}

	t.Run("getTargetMount error", func(t *testing.T) {
		getTargetMountMockError()
		found, err := funcUnderTest()
		assert.EqualError(t, err, testErrMsg)
		assert.False(t, found)
	})

	t.Run("getTargetMount not found", func(t *testing.T) {
		getTargetMountMockNotFound()
		found, err := funcUnderTest()
		assert.Nil(t, err)
		assert.False(t, found)
	})

	t.Run("device has deleted suffix", func(t *testing.T) {
		getTargetMountMockFoundWithDeleted()
		found, err := funcUnderTest()
		assert.Nil(t, err)
		assert.True(t, found)
	})

	t.Run("ready", func(t *testing.T) {
		getTargetMountMockFound()
		found, err := funcUnderTest()
		assert.Nil(t, err)
		assert.True(t, found)
	})

}

func TestMount_mountLibPublishBlockIMPL_publishBlock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	reqHelpers := NewMockreqHelpers(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)
	mkfile := NewMockfileCreator(ctrl)

	ctx := context.Background()
	impl := newMountLibPublishBlockIMPL(mkfile, reqHelpers, fsLib)

	funcUnderTest := func(req *csi.NodePublishVolumeRequest) error {
		if req == nil {
			req = getNodePublishValidRequest()
		}
		return impl.publishBlock(ctx, req)
	}
	getStagingPathMockOK := func() {
		reqHelpers.EXPECT().getStagingPath(gomock.Any(), gomock.Any()).
			Return(validStagingPath)
	}
	mkFileMock := func() *gomock.Call {
		return mkfile.EXPECT().mkFile(validTargetPath)
	}
	mkFileMockError := func() {
		mkFileMock().Return(false, errors.New(testErrMsg))
	}
	mkFileMockOK := func() {
		mkFileMock().Return(true, nil)
	}
	bindMountMock := func() *gomock.Call {
		return fsLib.EXPECT().BindMount(gomock.Any(), validStagingPath, validTargetPath)
	}
	bindMountMockError := func() {
		bindMountMock().Return(errors.New(testErrMsg))
	}
	bindMountMockOK := func() {
		bindMountMock().Return(nil)
	}
	t.Run("isRO validation", func(t *testing.T) {
		getStagingPathMockOK()
		req := getNodePublishValidRequest()
		req.VolumeCapability = getCapabilityWithVoltypeAccessFstype(
			"block", "single-reader", "")
		req.Readonly = true
		err := funcUnderTest(req)
		assert.EqualError(t, err, "rpc error: code = InvalidArgument"+
			" desc = read only not supported for Block Volume")
	})
	t.Run("mkfile error", func(t *testing.T) {
		getStagingPathMockOK()
		mkFileMockError()
		err := funcUnderTest(nil)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal"+
			" desc = can't create target file %s: %s", validTargetPath, testErrMsg))
	})

	t.Run("bind error", func(t *testing.T) {
		getStagingPathMockOK()
		mkFileMockOK()
		bindMountMockError()
		err := funcUnderTest(nil)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal"+
			" desc = error bind disk %s to target path: %s", validStagingPath, testErrMsg))
	})
	t.Run("success", func(t *testing.T) {
		getStagingPathMockOK()
		mkFileMockOK()
		bindMountMockOK()
		err := funcUnderTest(nil)
		assert.Nil(t, err)
	})
}

func TestMount_mountLibPublishMountIMPL_publishMount(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	reqHelpers := NewMockreqHelpers(ctrl)
	fsLib := NewMockwrapperFsLib(ctrl)
	mkfs := NewMockfsCreator(ctrl)
	mkdir := NewMockdirCreator(ctrl)

	ctx := context.Background()
	impl := newMountLibPublishMountIMPL(mkdir, reqHelpers, fsLib, mkfs)

	funcUnderTest := func(req *csi.NodePublishVolumeRequest) error {
		if req == nil {
			req = getNodePublishValidRequest()
		}
		return impl.publishMount(ctx, req)
	}
	getStagingPathMockOK := func() {
		reqHelpers.EXPECT().getStagingPath(gomock.Any(), gomock.Any()).
			Return(validStagingPath)
	}
	mkDirMock := func() *gomock.Call {
		return mkdir.EXPECT().mkDir(validTargetPath)
	}
	mkDirMockError := func() {
		mkDirMock().Return(false, errors.New(testErrMsg))
	}
	mkDirMockOK := func() {
		mkDirMock().Return(true, nil)
	}
	getDiskFormatMock := func() *gomock.Call {
		return fsLib.EXPECT().GetDiskFormat(gomock.Any(), validStagingPath)
	}
	getDiskFormatMockError := func() {
		getDiskFormatMock().Return("", errors.New(testErrMsg))
	}
	getDiskFormatMockNotFound := func() {
		getDiskFormatMock().Return("", nil)
	}
	getDiskFormatMockFound := func(fs string) {
		if fs == "" {
			fs = "ext4"
		}
		getDiskFormatMock().Return(fs, nil)
	}
	formatMock := func() *gomock.Call {
		return mkfs.EXPECT().
			format(gomock.Any(), validStagingPath, gomock.Any(), gomock.Any())
	}
	formatMockError := func() {
		formatMock().Return(errors.New(testErrMsg))
	}
	formatMockOK := func() {
		formatMock().Return(nil)
	}
	mountMock := func() *gomock.Call {
		return fsLib.EXPECT().Mount(gomock.Any(),
			validStagingPath,
			validTargetPath,
			gomock.Any(), gomock.Any())
	}
	mountMockError := func() {
		mountMock().Return(errors.New(testErrMsg))
	}
	mountMockOK := func() {
		mountMock().Return(nil)
	}
	t.Run("multi node write validation", func(t *testing.T) {
		req := getNodePublishValidRequest()
		req.VolumeCapability = getCapabilityWithVoltypeAccessFstype(
			"mount", "multiple-writer", "")
		req.Readonly = false
		err := funcUnderTest(req)
		assert.EqualError(t, err, "rpc error: code = Unimplemented"+
			" desc = Mount volumes do not support AccessMode MULTI_NODE_MULTI_WRITER")
	})
	t.Run("can't create mount dir", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockError()
		err := funcUnderTest(nil)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal"+
			" desc = can't create target dir %s: %s", validTargetPath, testErrMsg))
	})
	t.Run("can't get disk fs", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockOK()
		getDiskFormatMockError()
		err := funcUnderTest(nil)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal"+
			" desc = error while trying to detect"+
			" fs for staging path %s: %s", validStagingPath, testErrMsg))
	})
	t.Run("curFS != targetFS", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockOK()
		getDiskFormatMockFound("xfs")
		req := getNodePublishValidRequest()
		req.VolumeCapability = getCapabilityWithVoltypeAccessFstype(
			"mount", "single-writer", "ext4")
		err := funcUnderTest(req)
		assert.EqualError(t, err, "rpc error: code = FailedPrecondition"+
			" desc = filesystem mismatch. Target device"+
			" already formatted to xfs mount spec require ext4")
	})
	t.Run("no FS and disk is RO", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockOK()
		getDiskFormatMockNotFound()
		req := getNodePublishValidRequest()
		req.Readonly = true
		err := funcUnderTest(req)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = FailedPrecondition "+
			"desc = RO mount required but no fs detected"+
			" on staged volume %s", validStagingPath))
	})
	t.Run("failed to create FS", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockOK()
		getDiskFormatMockNotFound()
		formatMockError()
		err := funcUnderTest(nil)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = "+
			"Internal desc = can't format"+
			" staged device %s: %s", validStagingPath, testErrMsg))
	})
	t.Run("mount error", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockOK()
		getDiskFormatMockNotFound()
		formatMockOK()
		mountMockError()
		req := getNodePublishValidRequest()
		req.VolumeCapability = getCapabilityWithVoltypeAccessFstype(
			"mount", "single-writer", "ext4")
		err := funcUnderTest(req)
		assert.EqualError(t, err, fmt.Sprintf("rpc error: code = Internal "+
			"desc = error performing mount for staging path %s: %s", validStagingPath, testErrMsg))
	})
	t.Run("mount ok", func(t *testing.T) {
		getStagingPathMockOK()
		mkDirMockOK()
		getDiskFormatMockFound("")
		mountMockOK()
		req := getNodePublishValidRequest()
		req.Readonly = true
		err := funcUnderTest(req)
		assert.Nil(t, err)
	})
}
