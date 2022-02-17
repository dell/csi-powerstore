// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	context "context"

	gobrick "github.com/dell/gobrick"
	mock "github.com/stretchr/testify/mock"
)

// NVMETCPConnector is an autogenerated mock type for the NVMETCPConnector type
type NVMETCPConnector struct {
	mock.Mock
}

// ConnectVolume provides a mock function with given fields: ctx, info
func (_m *NVMETCPConnector) ConnectVolume(ctx context.Context, info gobrick.NVMeTCPVolumeInfo) (gobrick.Device, error) {
	ret := _m.Called(ctx, info)

	var r0 gobrick.Device
	if rf, ok := ret.Get(0).(func(context.Context, gobrick.NVMeTCPVolumeInfo) gobrick.Device); ok {
		r0 = rf(ctx, info)
	} else {
		r0 = ret.Get(0).(gobrick.Device)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, gobrick.NVMeTCPVolumeInfo) error); ok {
		r1 = rf(ctx, info)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DisconnectVolumeByDeviceName provides a mock function with given fields: ctx, name
func (_m *NVMETCPConnector) DisconnectVolumeByDeviceName(ctx context.Context, name string) error {
	ret := _m.Called(ctx, name)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetInitiatorName provides a mock function with given fields: ctx
func (_m *NVMETCPConnector) GetInitiatorName(ctx context.Context) ([]string, error) {
	ret := _m.Called(ctx)

	var r0 []string
	if rf, ok := ret.Get(0).(func(context.Context) []string); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
