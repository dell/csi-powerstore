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

	gobrick "github.com/dell/gobrick"
	mock "github.com/stretchr/testify/mock"
)

// FcConnector is an autogenerated mock type for the FcConnector type
type FcConnector struct {
	mock.Mock
}

// ConnectVolume provides a mock function with given fields: ctx, info
func (_m *FcConnector) ConnectVolume(ctx context.Context, info gobrick.FCVolumeInfo) (gobrick.Device, error) {
	ret := _m.Called(ctx, info)

	var r0 gobrick.Device
	if rf, ok := ret.Get(0).(func(context.Context, gobrick.FCVolumeInfo) gobrick.Device); ok {
		r0 = rf(ctx, info)
	} else {
		r0 = ret.Get(0).(gobrick.Device)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, gobrick.FCVolumeInfo) error); ok {
		r1 = rf(ctx, info)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DisconnectVolumeByDeviceName provides a mock function with given fields: ctx, name
func (_m *FcConnector) DisconnectVolumeByDeviceName(ctx context.Context, name string) error {
	ret := _m.Called(ctx, name)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetInitiatorPorts provides a mock function with given fields: ctx
func (_m *FcConnector) GetInitiatorPorts(ctx context.Context) ([]string, error) {
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
