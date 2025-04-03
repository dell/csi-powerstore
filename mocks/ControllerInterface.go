/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	array "github.com/dell/csi-powerstore/v2/pkg/array"
	common "github.com/dell/dell-csi-extensions/common"

	context "context"

	csi "github.com/container-storage-interface/spec/lib/go/csi"

	fs "github.com/dell/csi-powerstore/v2/pkg/common/fs"

	grpc "google.golang.org/grpc"

	mock "github.com/stretchr/testify/mock"
)

// ControllerInterface is an autogenerated mock type for the ControllerInterface type
type ControllerInterface struct {
	mock.Mock
}

// Arrays provides a mock function with no fields
func (_m *ControllerInterface) Arrays() map[string]*array.PowerStoreArray {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Arrays")
	}

	var r0 map[string]*array.PowerStoreArray
	if rf, ok := ret.Get(0).(func() map[string]*array.PowerStoreArray); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]*array.PowerStoreArray)
		}
	}

	return r0
}

// ControllerExpandVolume provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ControllerExpandVolume(_a0 context.Context, _a1 *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ControllerExpandVolume")
	}

	var r0 *csi.ControllerExpandVolumeResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerExpandVolumeRequest) *csi.ControllerExpandVolumeResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.ControllerExpandVolumeResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.ControllerExpandVolumeRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ControllerGetCapabilities provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ControllerGetCapabilities(_a0 context.Context, _a1 *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ControllerGetCapabilities")
	}

	var r0 *csi.ControllerGetCapabilitiesResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerGetCapabilitiesRequest) *csi.ControllerGetCapabilitiesResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.ControllerGetCapabilitiesResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.ControllerGetCapabilitiesRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ControllerGetVolume provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ControllerGetVolume(_a0 context.Context, _a1 *csi.ControllerGetVolumeRequest) (*csi.ControllerGetVolumeResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ControllerGetVolume")
	}

	var r0 *csi.ControllerGetVolumeResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerGetVolumeRequest) (*csi.ControllerGetVolumeResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerGetVolumeRequest) *csi.ControllerGetVolumeResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.ControllerGetVolumeResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.ControllerGetVolumeRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ControllerPublishVolume provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ControllerPublishVolume(_a0 context.Context, _a1 *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ControllerPublishVolume")
	}

	var r0 *csi.ControllerPublishVolumeResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerPublishVolumeRequest) *csi.ControllerPublishVolumeResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.ControllerPublishVolumeResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.ControllerPublishVolumeRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ControllerUnpublishVolume provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ControllerUnpublishVolume(_a0 context.Context, _a1 *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ControllerUnpublishVolume")
	}

	var r0 *csi.ControllerUnpublishVolumeResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ControllerUnpublishVolumeRequest) *csi.ControllerUnpublishVolumeResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.ControllerUnpublishVolumeResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.ControllerUnpublishVolumeRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateSnapshot provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) CreateSnapshot(_a0 context.Context, _a1 *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for CreateSnapshot")
	}

	var r0 *csi.CreateSnapshotResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.CreateSnapshotRequest) *csi.CreateSnapshotResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.CreateSnapshotResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.CreateSnapshotRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateVolume provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) CreateVolume(_a0 context.Context, _a1 *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for CreateVolume")
	}

	var r0 *csi.CreateVolumeResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.CreateVolumeRequest) *csi.CreateVolumeResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.CreateVolumeResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.CreateVolumeRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DefaultArray provides a mock function with no fields
func (_m *ControllerInterface) DefaultArray() *array.PowerStoreArray {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for DefaultArray")
	}

	var r0 *array.PowerStoreArray
	if rf, ok := ret.Get(0).(func() *array.PowerStoreArray); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*array.PowerStoreArray)
		}
	}

	return r0
}

// DeleteSnapshot provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) DeleteSnapshot(_a0 context.Context, _a1 *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for DeleteSnapshot")
	}

	var r0 *csi.DeleteSnapshotResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.DeleteSnapshotRequest) *csi.DeleteSnapshotResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.DeleteSnapshotResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.DeleteSnapshotRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteVolume provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) DeleteVolume(_a0 context.Context, _a1 *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for DeleteVolume")
	}

	var r0 *csi.DeleteVolumeResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.DeleteVolumeRequest) *csi.DeleteVolumeResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.DeleteVolumeResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.DeleteVolumeRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetCapacity provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) GetCapacity(_a0 context.Context, _a1 *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetCapacity")
	}

	var r0 *csi.GetCapacityResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.GetCapacityRequest) *csi.GetCapacityResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.GetCapacityResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.GetCapacityRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListSnapshots provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ListSnapshots(_a0 context.Context, _a1 *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ListSnapshots")
	}

	var r0 *csi.ListSnapshotsResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ListSnapshotsRequest) *csi.ListSnapshotsResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.ListSnapshotsResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.ListSnapshotsRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListVolumes provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ListVolumes(_a0 context.Context, _a1 *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ListVolumes")
	}

	var r0 *csi.ListVolumesResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ListVolumesRequest) *csi.ListVolumesResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.ListVolumesResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.ListVolumesRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProbeController provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ProbeController(_a0 context.Context, _a1 *common.ProbeControllerRequest) (*common.ProbeControllerResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ProbeController")
	}

	var r0 *common.ProbeControllerResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *common.ProbeControllerRequest) (*common.ProbeControllerResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *common.ProbeControllerRequest) *common.ProbeControllerResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*common.ProbeControllerResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *common.ProbeControllerRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegisterAdditionalServers provides a mock function with given fields: _a0
func (_m *ControllerInterface) RegisterAdditionalServers(_a0 *grpc.Server) {
	_m.Called(_a0)
}

// SetArrays provides a mock function with given fields: _a0
func (_m *ControllerInterface) SetArrays(_a0 map[string]*array.PowerStoreArray) {
	_m.Called(_a0)
}

// SetDefaultArray provides a mock function with given fields: _a0
func (_m *ControllerInterface) SetDefaultArray(_a0 *array.PowerStoreArray) {
	_m.Called(_a0)
}

// UpdateArrays provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) UpdateArrays(_a0 string, _a1 fs.Interface) error {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for UpdateArrays")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, fs.Interface) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateVolumeCapabilities provides a mock function with given fields: _a0, _a1
func (_m *ControllerInterface) ValidateVolumeCapabilities(_a0 context.Context, _a1 *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ValidateVolumeCapabilities")
	}

	var r0 *csi.ValidateVolumeCapabilitiesResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *csi.ValidateVolumeCapabilitiesRequest) *csi.ValidateVolumeCapabilitiesResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.ValidateVolumeCapabilitiesResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *csi.ValidateVolumeCapabilitiesRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewControllerInterface creates a new instance of ControllerInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewControllerInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *ControllerInterface {
	mock := &ControllerInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
