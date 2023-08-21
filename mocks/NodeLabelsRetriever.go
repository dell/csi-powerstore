/*
 Copyright (c) 2023 Dell Inc, or its subsidiaries.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

// Code generated by mockery. DO NOT EDIT.

package mocks

import (
	context "context"

	kubernetes "k8s.io/client-go/kubernetes"

	mock "github.com/stretchr/testify/mock"

	rest "k8s.io/client-go/rest"
)

// NodeLabelsRetrieverInterface is an autogenerated mock type for the NodeLabelsRetrieverInterface type
type NodeLabelsRetrieverInterface struct {
	mock.Mock
}

// BuildConfigFromFlags provides a mock function with given fields: masterURL, kubeconfig
func (_m *NodeLabelsRetrieverInterface) BuildConfigFromFlags(masterURL string, kubeconfig string) (*rest.Config, error) {
	ret := _m.Called(masterURL, kubeconfig)

	var r0 *rest.Config
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string) (*rest.Config, error)); ok {
		return rf(masterURL, kubeconfig)
	}
	if rf, ok := ret.Get(0).(func(string, string) *rest.Config); ok {
		r0 = rf(masterURL, kubeconfig)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*rest.Config)
		}
	}

	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(masterURL, kubeconfig)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNodeLabels provides a mock function with given fields: ctx, k8sclientset, kubeNodeName
func (_m *NodeLabelsRetrieverInterface) GetNodeLabels(ctx context.Context, k8sclientset *kubernetes.Clientset, kubeNodeName string) (map[string]string, error) {
	ret := _m.Called(k8sclientset, ctx, kubeNodeName)

	var r0 map[string]string
	var r1 error
	if rf, ok := ret.Get(0).(func(*kubernetes.Clientset, context.Context, string) (map[string]string, error)); ok {
		return rf(k8sclientset, ctx, kubeNodeName)
	}
	if rf, ok := ret.Get(0).(func(*kubernetes.Clientset, context.Context, string) map[string]string); ok {
		r0 = rf(k8sclientset, ctx, kubeNodeName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]string)
		}
	}

	if rf, ok := ret.Get(1).(func(*kubernetes.Clientset, context.Context, string) error); ok {
		r1 = rf(k8sclientset, ctx, kubeNodeName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InClusterConfig provides a mock function with given fields:
func (_m *NodeLabelsRetrieverInterface) InClusterConfig() (*rest.Config, error) {
	ret := _m.Called()

	var r0 *rest.Config
	var r1 error
	if rf, ok := ret.Get(0).(func() (*rest.Config, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *rest.Config); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*rest.Config)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewForConfig provides a mock function with given fields: config
func (_m *NodeLabelsRetrieverInterface) NewForConfig(config *rest.Config) (*kubernetes.Clientset, error) {
	ret := _m.Called(config)

	var r0 *kubernetes.Clientset
	var r1 error
	if rf, ok := ret.Get(0).(func(*rest.Config) (*kubernetes.Clientset, error)); ok {
		return rf(config)
	}
	if rf, ok := ret.Get(0).(func(*rest.Config) *kubernetes.Clientset); ok {
		r0 = rf(config)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*kubernetes.Clientset)
		}
	}

	if rf, ok := ret.Get(1).(func(*rest.Config) error); ok {
		r1 = rf(config)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewNodeLabelsRetrieverInterface creates a new instance of NodeLabelsRetrieverInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewNodeLabelsRetrieverInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *NodeLabelsRetrieverInterface {
	mock := &NodeLabelsRetrieverInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}