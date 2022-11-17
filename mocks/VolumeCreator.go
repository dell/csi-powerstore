/*
 *
 * Copyright © 2021-2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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

	csi "github.com/container-storage-interface/spec/lib/go/csi"

	gopowerstore "github.com/dell/gopowerstore"

	mock "github.com/stretchr/testify/mock"
)

// VolumeCreator is an autogenerated mock type for the VolumeCreator type
type VolumeCreator struct {
	mock.Mock
}

// CheckIfAlreadyExists provides a mock function with given fields: ctx, name, sizeInBytes, client
func (_m *VolumeCreator) CheckIfAlreadyExists(ctx context.Context, name string, sizeInBytes int64, client gopowerstore.Client) (*csi.Volume, error) {
	ret := _m.Called(ctx, name, sizeInBytes, client)

	var r0 *csi.Volume
	if rf, ok := ret.Get(0).(func(context.Context, string, int64, gopowerstore.Client) *csi.Volume); ok {
		r0 = rf(ctx, name, sizeInBytes, client)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.Volume)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, int64, gopowerstore.Client) error); ok {
		r1 = rf(ctx, name, sizeInBytes, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CheckName provides a mock function with given fields: ctx, name
func (_m *VolumeCreator) CheckName(ctx context.Context, name string) error {
	ret := _m.Called(ctx, name)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CheckSize provides a mock function with given fields: ctx, cr
func (_m *VolumeCreator) CheckSize(ctx context.Context, cr *csi.CapacityRange) (int64, error) {
	ret := _m.Called(ctx, cr)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context, *csi.CapacityRange) int64); ok {
		r0 = rf(ctx, cr)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *csi.CapacityRange) error); ok {
		r1 = rf(ctx, cr)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Clone provides a mock function with given fields: ctx, volumeSource, volumeName, sizeInBytes, parameters, client
func (_m *VolumeCreator) Clone(ctx context.Context, volumeSource *csi.VolumeContentSource_VolumeSource, volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.Volume, error) {
	ret := _m.Called(ctx, volumeSource, volumeName, sizeInBytes, parameters, client)

	var r0 *csi.Volume
	if rf, ok := ret.Get(0).(func(context.Context, *csi.VolumeContentSource_VolumeSource, string, int64, map[string]string, gopowerstore.Client) *csi.Volume); ok {
		r0 = rf(ctx, volumeSource, volumeName, sizeInBytes, parameters, client)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.Volume)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *csi.VolumeContentSource_VolumeSource, string, int64, map[string]string, gopowerstore.Client) error); ok {
		r1 = rf(ctx, volumeSource, volumeName, sizeInBytes, parameters, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Create provides a mock function with given fields: ctx, req, sizeInBytes, client
func (_m *VolumeCreator) Create(ctx context.Context, req *csi.CreateVolumeRequest, sizeInBytes int64, client gopowerstore.Client) (gopowerstore.CreateResponse, error) {
	ret := _m.Called(ctx, req, sizeInBytes, client)

	var r0 gopowerstore.CreateResponse
	if rf, ok := ret.Get(0).(func(context.Context, *csi.CreateVolumeRequest, int64, gopowerstore.Client) gopowerstore.CreateResponse); ok {
		r0 = rf(ctx, req, sizeInBytes, client)
	} else {
		r0 = ret.Get(0).(gopowerstore.CreateResponse)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *csi.CreateVolumeRequest, int64, gopowerstore.Client) error); ok {
		r1 = rf(ctx, req, sizeInBytes, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateVolumeFromSnapshot provides a mock function with given fields: ctx, snapshotSource, volumeName, sizeInBytes, parameters, client
func (_m *VolumeCreator) CreateVolumeFromSnapshot(ctx context.Context, snapshotSource *csi.VolumeContentSource_SnapshotSource, volumeName string, sizeInBytes int64, parameters map[string]string, client gopowerstore.Client) (*csi.Volume, error) {
	ret := _m.Called(ctx, snapshotSource, volumeName, sizeInBytes, parameters, client)

	var r0 *csi.Volume
	if rf, ok := ret.Get(0).(func(context.Context, *csi.VolumeContentSource_SnapshotSource, string, int64, map[string]string, gopowerstore.Client) *csi.Volume); ok {
		r0 = rf(ctx, snapshotSource, volumeName, sizeInBytes, parameters, client)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*csi.Volume)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *csi.VolumeContentSource_SnapshotSource, string, int64, map[string]string, gopowerstore.Client) error); ok {
		r1 = rf(ctx, snapshotSource, volumeName, sizeInBytes, parameters, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
