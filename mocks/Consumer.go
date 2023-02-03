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

// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import array "github.com/dell/csi-powerstore/v2/pkg/array"
import fs "github.com/dell/csi-powerstore/v2/pkg/common/fs"
import mock "github.com/stretchr/testify/mock"

// Consumer is an autogenerated mock type for the Consumer type
type Consumer struct {
	mock.Mock
}

// Arrays provides a mock function with given fields:
func (_m *Consumer) Arrays() map[string]*array.PowerStoreArray {
	ret := _m.Called()

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

// DefaultArray provides a mock function with given fields:
func (_m *Consumer) DefaultArray() *array.PowerStoreArray {
	ret := _m.Called()

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

// RegisterK8sCluster provides a mock function with given fields: _a0
func (_m *Consumer) RegisterK8sCluster(_a0 fs.Interface) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(fs.Interface) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetArrays provides a mock function with given fields: _a0
func (_m *Consumer) SetArrays(_a0 map[string]*array.PowerStoreArray) {
	_m.Called(_a0)
}

// SetDefaultArray provides a mock function with given fields: _a0
func (_m *Consumer) SetDefaultArray(_a0 *array.PowerStoreArray) {
	_m.Called(_a0)
}

// UpdateArrays provides a mock function with given fields: _a0, _a1
func (_m *Consumer) UpdateArrays(_a0 string, _a1 fs.Interface) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, fs.Interface) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
