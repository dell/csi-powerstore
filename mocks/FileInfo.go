// Code generated by mockery. DO NOT EDIT.

package mocks

import (
	iofs "io/fs"
	time "time"

	mock "github.com/stretchr/testify/mock"
)

// FileInfo is an autogenerated mock type for the FileInfo type
type FileInfo struct {
	mock.Mock
}

// IsDir provides a mock function with given fields:
func (_m *FileInfo) IsDir() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// ModTime provides a mock function with given fields:
func (_m *FileInfo) ModTime() time.Time {
	ret := _m.Called()

	var r0 time.Time
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	return r0
}

// Mode provides a mock function with given fields:
func (_m *FileInfo) Mode() iofs.FileMode {
	ret := _m.Called()

	var r0 iofs.FileMode
	if rf, ok := ret.Get(0).(func() iofs.FileMode); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(iofs.FileMode)
	}

	return r0
}

// Name provides a mock function with given fields:
func (_m *FileInfo) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Size provides a mock function with given fields:
func (_m *FileInfo) Size() int64 {
	ret := _m.Called()

	var r0 int64
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	return r0
}

// Sys provides a mock function with given fields:
func (_m *FileInfo) Sys() interface{} {
	ret := _m.Called()

	var r0 interface{}
	if rf, ok := ret.Get(0).(func() interface{}); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	return r0
}
