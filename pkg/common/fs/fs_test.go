/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package fs

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/dell/gofsutil"
	"github.com/stretchr/testify/suite"
)

type FsTestSuite struct {
	suite.Suite
	fs  Interface
	tmp string
}

func (suite *FsTestSuite) SetupSuite() {
	suite.fs = &Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}
	suite.tmp = "./tmp"
	err := os.Mkdir(suite.tmp, 0o750)
	if err != nil {
		suite.T().Error("couldn't create the tmp folder")
	}
}

func (suite *FsTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tmp)
	if err != nil {
		suite.T().Error("couldn't remove the tmp folder")
	}
}

func (suite *FsTestSuite) TestCreate() {
	file, err := suite.fs.Create(suite.tmp + "/create")
	suite.Assert().NoError(err)

	_, err = suite.fs.Stat(suite.tmp + "/create")
	suite.Assert().NoError(err)

	_, err = suite.fs.WriteString(file, "random string")
	suite.Assert().NoError(err)

	bytes, err := suite.fs.ReadFile(suite.tmp + "/create")
	suite.Assert().NoError(err)
	suite.Assert().Equal(string(bytes), "random string")

	err = suite.fs.Remove(suite.tmp + "/create")
	suite.Assert().NoError(err)
	suite.Assert().NoFileExists(suite.tmp + "/create")

	_, err = suite.fs.ReadFile(suite.tmp + "/create")
	suite.Assert().Error(err)
	suite.fs.IsNotExist(err)
}

func (suite *FsTestSuite) TestWriteFile() {
	str := "random string \n hello"
	data := []byte(str)
	err := suite.fs.WriteFile(suite.tmp+"/create", data, 0o640)
	suite.Assert().NoError(err)

	bytes, err := suite.fs.ReadFile(suite.tmp + "/create")
	suite.Assert().NoError(err)
	suite.Assert().Equal(bytes, data)
}

func (suite *FsTestSuite) TestOpenFile() {
	file, err := suite.fs.OpenFile(suite.tmp+"/file", os.O_CREATE, 0o600)
	suite.Assert().NoError(err)

	err = suite.fs.Chmod(suite.tmp+"/file", os.ModeSticky)
	suite.Assert().NoError(err)

	err = file.Close()
	suite.Assert().NoError(err)
}

func (suite *FsTestSuite) TestMkDir() {
	err := suite.fs.Mkdir(suite.tmp+"/dir", 0o750)
	suite.Assert().NoError(err)
	suite.Assert().DirExists(suite.tmp + "/dir")

	err = suite.fs.MkdirAll(suite.tmp+"/1/2/3", 0o750)
	suite.Assert().NoError(err)
	suite.Assert().DirExists(suite.tmp + "/1/2")

	err = suite.fs.RemoveAll(suite.tmp + "/1")
	suite.Assert().NoError(err)
	suite.Assert().NoDirExists(suite.tmp + "/1")
}

func (suite *FsTestSuite) TestMkFileIdempotent() {
	created, err := suite.fs.MkFileIdempotent(suite.tmp + "/myfile")
	suite.Assert().NoError(err)
	suite.Assert().Equal(true, created)

	err = suite.fs.Mkdir(suite.tmp+"/mydir", 0o750)
	suite.Assert().NoError(err)
	_, err = suite.fs.MkFileIdempotent(suite.tmp + "/mydir")
	suite.Assert().EqualError(err, "existing path is a directory")

	created, err = suite.fs.MkFileIdempotent(suite.tmp + "/myfile")
	suite.Assert().NoError(err)
	suite.Assert().Equal(false, created)
}

func (suite *FsTestSuite) TestExecCommand() {
	out, err := suite.fs.ExecCommand("find")
	suite.Assert().NoError(err)
	suite.Assert().NotEmpty(out)

	out, err = suite.fs.ExecCommandOutput("find")
	suite.Assert().NoError(err)
	suite.Assert().NotEmpty(out)
}

func (suite *FsTestSuite) TestIsDeviceOrResourceBusy() {
	err := suite.fs.Remove(suite.tmp + "/busy")
	res := suite.fs.IsDeviceOrResourceBusy(err)
	suite.Assert().False(res)
}

func (suite *FsTestSuite) TestParseProcMounts() {
	input := `17 60 0:16 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw,seclabel
		18 60 0:3 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
		19 60 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,seclabel,size=1930460k,nr_inodes=482615,mode=755
		20 17 0:15 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:7 - securityfs securityfs rw
		21 19 0:17 / /dev/shm rw,nosuid,nodev shared:3 - tmpfs tmpfs rw,seclabel
		22 19 0:11 / /dev/pts rw,nosuid,noexec,relatime shared:4 - devpts devpts rw,seclabel,gid=5,mode=620,ptmxmode=000
		23 60 0:18 / /run rw,nosuid,nodev shared:23 - tmpfs tmpfs rw,seclabel,mode=755
		24 17 0:19 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:8 - tmpfs tmpfs ro,seclabel,mode=755`
	mounts, err := suite.fs.ParseProcMounts(context.Background(), strings.NewReader(input))
	suite.Assert().NoError(err)
	suite.Assert().NotEmpty(mounts)
}

func (suite *FsTestSuite) TestNetDial() {
	conn, err := suite.fs.NetDial("localhost")
	suite.Assert().NoError(err)
	conn.Close()
}

func (suite *FsTestSuite) TestGetUtil() {
	util := suite.fs.GetUtil()
	suite.Assert().NotNil(util)
}

func TestFsTestSuite(t *testing.T) {
	suite.Run(t, new(FsTestSuite))
}
