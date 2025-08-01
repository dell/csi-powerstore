// Code generated by mockery. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// NASCooldownTracker is an autogenerated mock type for the NASCooldownTracker type
type NASCooldownTracker struct {
	mock.Mock
}

// FallbackRetry provides a mock function with given fields: nasList
func (_m *NASCooldownTracker) FallbackRetry(nasList []string) string {
	ret := _m.Called(nasList)

	if len(ret) == 0 {
		panic("no return value specified for FallbackRetry")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func([]string) string); ok {
		r0 = rf(nasList)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// IsInCooldown provides a mock function with given fields: nas
func (_m *NASCooldownTracker) IsInCooldown(nas string) bool {
	ret := _m.Called(nas)

	if len(ret) == 0 {
		panic("no return value specified for IsInCooldown")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(nas)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// MarkFailure provides a mock function with given fields: nas
func (_m *NASCooldownTracker) MarkFailure(nas string) {
	_m.Called(nas)
}

// ResetFailure provides a mock function with given fields: nas
func (_m *NASCooldownTracker) ResetFailure(nas string) {
	_m.Called(nas)
}

// NewNASCooldownTracker creates a new instance of NASCooldownTracker. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewNASCooldownTracker(t interface {
	mock.TestingT
	Cleanup(func())
}) *NASCooldownTracker {
	mock := &NASCooldownTracker{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
