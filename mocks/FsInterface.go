/*
 *
 * Copyright © 2021-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Code generated by mockery. DO NOT EDIT.

package mocks

import (
	context "context"

	commonfs "github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"

	fs "io/fs"

	gofsutil "github.com/dell/gofsutil"

	io "io"

	mock "github.com/stretchr/testify/mock"

	net "net"

	os "os"
)

// FsInterface is an autogenerated mock type for the FsInterface type
type FsInterface struct {
	mock.Mock
}

// Chmod provides a mock function with given fields: name, perm
func (_m *FsInterface) Chmod(name string, perm fs.FileMode) error {
	ret := _m.Called(name, perm)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, fs.FileMode) error); ok {
		r0 = rf(name, perm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Create provides a mock function with given fields: name
func (_m *FsInterface) Create(name string) (*os.File, error) {
	ret := _m.Called(name)

	var r0 *os.File
	if rf, ok := ret.Get(0).(func(string) *os.File); ok {
		r0 = rf(name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*os.File)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ExecCommand provides a mock function with given fields: name, args
func (_m *FsInterface) ExecCommand(name string, args ...string) ([]byte, error) {
	_va := make([]interface{}, len(args))
	for _i := range args {
		_va[_i] = args[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, name)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string, ...string) []byte); ok {
		r0 = rf(name, args...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, ...string) error); ok {
		r1 = rf(name, args...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ExecCommandOutput provides a mock function with given fields: name, args
func (_m *FsInterface) ExecCommandOutput(name string, args ...string) ([]byte, error) {
	_va := make([]interface{}, len(args))
	for _i := range args {
		_va[_i] = args[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, name)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string, ...string) []byte); ok {
		r0 = rf(name, args...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, ...string) error); ok {
		r1 = rf(name, args...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUtil provides a mock function with given fields:
func (_m *FsInterface) GetUtil() commonfs.UtilInterface {
	ret := _m.Called()

	var r0 commonfs.UtilInterface
	if rf, ok := ret.Get(0).(func() commonfs.UtilInterface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(commonfs.UtilInterface)
		}
	}

	return r0
}

// IsNotExist provides a mock function with given fields: err
func (_m *FsInterface) IsNotExist(err error) bool {
	ret := _m.Called(err)

	var r0 bool
	if rf, ok := ret.Get(0).(func(error) bool); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IsDeviceOrResourceBusy provides a mock function with given fields: err
func (_m *FsInterface) IsDeviceOrResourceBusy(err error) bool {
	ret := _m.Called(err)

	var r0 bool
	if rf, ok := ret.Get(0).(func(error) bool); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// MkFileIdempotent provides a mock function with given fields: path
func (_m *FsInterface) MkFileIdempotent(path string) (bool, error) {
	ret := _m.Called(path)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(path)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(path)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mkdir provides a mock function with given fields: name, perm
func (_m *FsInterface) Mkdir(name string, perm fs.FileMode) error {
	ret := _m.Called(name, perm)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, fs.FileMode) error); ok {
		r0 = rf(name, perm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MkdirAll provides a mock function with given fields: name, perm
func (_m *FsInterface) MkdirAll(name string, perm fs.FileMode) error {
	ret := _m.Called(name, perm)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, fs.FileMode) error); ok {
		r0 = rf(name, perm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NetDial provides a mock function with given fields: endpoint
func (_m *FsInterface) NetDial(endpoint string) (net.Conn, error) {
	ret := _m.Called(endpoint)

	var r0 net.Conn
	if rf, ok := ret.Get(0).(func(string) net.Conn); ok {
		r0 = rf(endpoint)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(net.Conn)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(endpoint)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// OpenFile provides a mock function with given fields: name, flag, perm
func (_m *FsInterface) OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	ret := _m.Called(name, flag, perm)

	var r0 *os.File
	if rf, ok := ret.Get(0).(func(string, int, fs.FileMode) *os.File); ok {
		r0 = rf(name, flag, perm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*os.File)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, int, fs.FileMode) error); ok {
		r1 = rf(name, flag, perm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseProcMounts provides a mock function with given fields: ctx, content
func (_m *FsInterface) ParseProcMounts(ctx context.Context, content io.Reader) ([]gofsutil.Info, error) {
	ret := _m.Called(ctx, content)

	var r0 []gofsutil.Info
	if rf, ok := ret.Get(0).(func(context.Context, io.Reader) []gofsutil.Info); ok {
		r0 = rf(ctx, content)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]gofsutil.Info)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, io.Reader) error); ok {
		r1 = rf(ctx, content)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ReadFile provides a mock function with given fields: name
func (_m *FsInterface) ReadFile(name string) ([]byte, error) {
	ret := _m.Called(name)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string) []byte); ok {
		r0 = rf(name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Remove provides a mock function with given fields: name
func (_m *FsInterface) Remove(name string) error {
	ret := _m.Called(name)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveAll provides a mock function with given fields: name
func (_m *FsInterface) RemoveAll(name string) error {
	ret := _m.Called(name)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Stat provides a mock function with given fields: name
func (_m *FsInterface) Stat(name string) (commonfs.FileInfo, error) {
	ret := _m.Called(name)

	var r0 commonfs.FileInfo
	if rf, ok := ret.Get(0).(func(string) commonfs.FileInfo); ok {
		r0 = rf(name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(commonfs.FileInfo)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WriteFile provides a mock function with given fields: filename, data, perm
func (_m *FsInterface) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	ret := _m.Called(filename, data, perm)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, []byte, fs.FileMode) error); ok {
		r0 = rf(filename, data, perm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// WriteString provides a mock function with given fields: file, str
func (_m *FsInterface) WriteString(file *os.File, str string) (int, error) {
	ret := _m.Called(file, str)

	var r0 int
	if rf, ok := ret.Get(0).(func(*os.File, string) int); ok {
		r0 = rf(file, str)
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*os.File, string) error); ok {
		r1 = rf(file, str)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
