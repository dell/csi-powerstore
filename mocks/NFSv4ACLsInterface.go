// Code generated by mockery v1.0.0. DO NOT EDIT.
  
package mocks

import mock "github.com/stretchr/testify/mock"

// NFSv4ACLsInterface is an autogenerated mock type for the NFSv4ACLsInterface type
type NFSv4ACLsInterface struct {
        mock.Mock
}

// SetNfsv4Acls provides a mock function with given fields: acls, dir
func (_m *NFSv4ACLsInterface) SetNfsv4Acls(acls string, dir string) error {
        ret := _m.Called(acls, dir)

        var r0 error
        if rf, ok := ret.Get(0).(func(string, string) error); ok {
                r0 = rf(acls, dir)
        } else {
                r0 = ret.Error(0)
        }

        return r0
}
