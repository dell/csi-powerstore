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

package fs

import (
	"os"
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
	suite.fs = &Fs{Util: &gofsutil.FS{}}
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

func (suite *FsTestSuite) TestGetUtil() {
	util := suite.fs.GetUtil()
	suite.Assert().NotNil(util)
}

func TestFsTestSuite(t *testing.T) {
	suite.Run(t, new(FsTestSuite))
}
