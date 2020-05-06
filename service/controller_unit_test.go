// +build test

/*
 *
 * Copyright © 2020 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

const (
	anotherHostID  = "b0ec603a-cebd-4a5c-a0e1-b2e88c0a81cc"
	k8sNodeID      = "k8s-node1"
	validVolumeID  = "e997a58a-b017-4bf0-8958-ac7faef3eca9"
	validVolumeID2 = "d6e8d0fe-7fad-4441-94f1-0b11687900dd"
)

func getClientAndService(t *testing.T) (*mock.MockClient, *service, *gomock.Controller) {
	svc := initService()

	ctrl := gomock.NewController(t)
	c := mock.NewMockClient(ctrl)
	svc.adminClient = c
	svc.impl.initApiThrottle()
	return c, svc, ctrl
}

func getVolumeCapability() *csi.VolumeCapability {
	accessMode := new(csi.VolumeCapability_AccessMode)
	accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
	capability := new(csi.VolumeCapability)
	capability.AccessMode = accessMode
	return capability
}

func Test_ControllerCreateVolume_FailApiThrottleAcquire(t *testing.T) {
	_, svc, ctrl := getClientAndService(t)
	apiThrottleMock := NewMocktimeoutSemaphore(ctrl)
	svc.apiThrottle = apiThrottleMock
	defer ctrl.Finish()

	ctx := context.Background()
	req := getTypicalCreateVolumeRequest("volume1", 1024*1024*1024)

	apiThrottleMock.EXPECT().Acquire(gomock.Eq(ctx)).
		Return(&TimeoutSemaphoreError{"Lock is acquire failed, timeout expired"}).
		Times(1)

	_, err := svc.CreateVolume(ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Lock is acquire failed, timeout expired")
}

func Test_ControllerDeleteVolume_FailApiThrottleAcquire(t *testing.T) {
	_, svc, ctrl := getClientAndService(t)
	apiThrottleMock := NewMocktimeoutSemaphore(ctrl)
	svc.apiThrottle = apiThrottleMock
	defer ctrl.Finish()

	ctx := context.Background()
	req := &csi.DeleteVolumeRequest{VolumeId: GoodVolumeID}

	apiThrottleMock.EXPECT().Acquire(gomock.Eq(ctx)).
		Return(&TimeoutSemaphoreError{"Lock is acquire failed, timeout expired"}).
		Times(1)

	_, err := svc.DeleteVolume(ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Lock is acquire failed, timeout expired")
}

func Test_ControllerPublishVolume_WithoutVolumeCapability(t *testing.T) {
	_, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{}

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "volume capability is required")
}

func Test_ControllerPublishVolume_WithoutAccessMode(t *testing.T) {
	_, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	capability := new(csi.VolumeCapability)
	req := &csi.ControllerPublishVolumeRequest{}
	req.VolumeCapability = capability

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "access mode is required")
}

func Test_ControllerPublishVolume_UnknownAccessMode(t *testing.T) {
	_, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	accessMode := new(csi.VolumeCapability_AccessMode)
	accessMode.Mode = csi.VolumeCapability_AccessMode_UNKNOWN
	capability := new(csi.VolumeCapability)
	capability.AccessMode = accessMode
	req := &csi.ControllerPublishVolumeRequest{}
	req.VolumeCapability = capability

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "access mode cannot be UNKNOWN")
}

func Test_ControllerPublishVolume_WithoutVolumeID(t *testing.T) {
	_, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{}
	req.VolumeCapability = getVolumeCapability()

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "volume ID is required")
}

func Test_ControllerPublishVolume_VolumeIsNotExist(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{VolumeId: GoodVolumeID}
	req.VolumeCapability = getVolumeCapability()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, *apiError)

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("volume with ID '%s' not found", GoodVolumeID))
}

func Test_ControllerPublishVolume_FailureVolumeStatus(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{VolumeId: GoodVolumeID}
	req.VolumeCapability = getVolumeCapability()

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, gopowerstore.NewAPIError())

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failure checking volume status for volume publishing")
}

func Test_ControllerPublishVolume_WithoutNodeID(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{VolumeId: GoodVolumeID}
	req.VolumeCapability = getVolumeCapability()

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "node ID is required")
}

func Test_ControllerPublishVolume_NodeNotFound(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}
	req.VolumeCapability = getVolumeCapability()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.NoHostObjectFoundCode
	apiError.StatusCode = http.StatusBadRequest

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{}, *apiError)

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("host with k8s node ID '%s' not found", k8sNodeID))
}

func Test_ControllerPublishVolume_FailureHostStatus(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}
	req.VolumeCapability = getVolumeCapability()

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{}, gopowerstore.NewAPIError())

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(),
		fmt.Sprintf("failure checking host '%s' status for volume publishing", k8sNodeID))
}

func Test_ControllerPublishVolume_FailGetMapping(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}
	req.VolumeCapability = getVolumeCapability()

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{ID: GoodHostID}, nil)
	adminClient.EXPECT().GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Any()).
		Return([]gopowerstore.HostVolumeMapping{}, gopowerstore.NewAPIError())

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(),
		fmt.Sprintf("failed to get mapping for volume with ID '%s'", GoodVolumeID))
}

func Test_ControllerPublishVolume_ManyMappingForSingleNode(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerPublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}
	req.VolumeCapability = getVolumeCapability()

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{ID: GoodHostID}, nil)
	adminClient.EXPECT().GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Any()).
		Return([]gopowerstore.HostVolumeMapping{
			{HostID: anotherHostID, LogicalUnitNumber: 1},
			{HostID: anotherHostID, LogicalUnitNumber: 1}},
			nil)
	registerGetStorageISCSITargetAddressesMock(adminClient)

	_, err := svc.ControllerPublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(),
		fmt.Sprintf("volume already present in a different lun mapping on node '%s'", anotherHostID))
}

func Test_ControllerPublishVolume_FailApiThrottleAcquire(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	apiThrottleMock := NewMocktimeoutSemaphore(ctrl)
	svc.apiThrottle = apiThrottleMock
	defer ctrl.Finish()

	ctx := context.Background()
	req := &csi.ControllerPublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}
	req.VolumeCapability = getVolumeCapability()

	apiThrottleMock.EXPECT().Acquire(gomock.Eq(ctx)).
		Return(&TimeoutSemaphoreError{"Lock is acquire failed, timeout expired"}).
		Times(1)

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{ID: GoodHostID}, nil)
	adminClient.EXPECT().GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Any()).
		Return([]gopowerstore.HostVolumeMapping{}, nil)
	registerGetStorageISCSITargetAddressesMock(adminClient)

	_, err := svc.ControllerPublishVolume(ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Lock is acquire failed, timeout expired")
}

func Test_ControllerPublishVolume_FailAttach(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	req := &csi.ControllerPublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}
	req.VolumeCapability = getVolumeCapability()

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{ID: GoodHostID}, nil)
	adminClient.EXPECT().GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Any()).
		Return([]gopowerstore.HostVolumeMapping{}, nil)
	adminClient.EXPECT().AttachVolumeToHost(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(gopowerstore.EmptyResponse(""), gopowerstore.NewAPIError())
	registerGetStorageISCSITargetAddressesMock(adminClient)

	_, err := svc.ControllerPublishVolume(context.Background(), req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(),
		fmt.Sprintf("failed to attach volume with ID '%s' to host with ID '%s':", GoodVolumeID, GoodHostID))
}

func Test_ControllerPublishVolume_FailGetMappingAfterAttach(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	req := &csi.ControllerPublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}
	req.VolumeCapability = getVolumeCapability()

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{ID: GoodHostID}, nil)
	adminClient.EXPECT().GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Any()).
		Return([]gopowerstore.HostVolumeMapping{}, nil)
	adminClient.EXPECT().AttachVolumeToHost(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(gopowerstore.EmptyResponse(""), nil)
	adminClient.EXPECT().GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Any()).
		Return([]gopowerstore.HostVolumeMapping{}, gopowerstore.NewAPIError())
	registerGetStorageISCSITargetAddressesMock(adminClient)
	_, err := svc.ControllerPublishVolume(context.Background(), req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(),
		fmt.Sprintf("failed to get mapping for volume with ID '%s' after attaching:", GoodVolumeID))
}

func Test_ControllerUnpublishVolume_WithoutVolumeID(t *testing.T) {
	_, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerUnpublishVolumeRequest{}

	_, err := svc.ControllerUnpublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "volume ID is required")
}

func Test_ControllerUnpublishVolume_VolumeIsNotExist(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerUnpublishVolumeRequest{VolumeId: GoodVolumeID}

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, *apiError)

	_, err := svc.ControllerUnpublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("volume with ID '%s' not found", GoodVolumeID))
}

func Test_ControllerUnpublishVolume_FailureVolumeStatus(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerUnpublishVolumeRequest{VolumeId: GoodVolumeID}

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, gopowerstore.NewAPIError())

	_, err := svc.ControllerUnpublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failure checking volume status for volume unpublishing")
}

func Test_ControllerUnpublishVolume_WithoutNodeID(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerUnpublishVolumeRequest{VolumeId: GoodVolumeID}

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)

	_, err := svc.ControllerUnpublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "node ID is required")
}

func Test_ControllerUnpublishVolume_NodeNotFound(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerUnpublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.NoHostObjectFoundCode
	apiError.StatusCode = http.StatusBadRequest

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{}, *apiError)

	_, err := svc.ControllerUnpublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("host with k8s node ID '%s' not found", k8sNodeID))
}

func Test_ControllerUnpublishVolume_FailureHostStatus(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerUnpublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{}, gopowerstore.NewAPIError())

	_, err := svc.ControllerUnpublishVolume(*ctx, req)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(),
		fmt.Sprintf("failure checking host '%s' status for volume unpublishing", k8sNodeID))
}

func Test_ControllerUnpublishVolume_FailDetach(t *testing.T) {
	adminClient, svc, ctrl := getClientAndService(t)
	defer ctrl.Finish()

	ctx := new(context.Context)
	req := &csi.ControllerUnpublishVolumeRequest{
		VolumeId: GoodVolumeID,
		NodeId:   k8sNodeID,
	}

	adminClient.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil)
	adminClient.EXPECT().GetHostByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Host{ID: GoodHostID}, nil)
	adminClient.EXPECT().DetachVolumeFromHost(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(gopowerstore.EmptyResponse(""), gopowerstore.NewAPIError())

	_, err := svc.ControllerUnpublishVolume(*ctx, req)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(),
		fmt.Sprintf("failed to detach volume '%s' from host:", GoodVolumeID))
}

func registerGetStorageISCSITargetAddressesMock(c *mock.MockClient) {
	c.EXPECT().GetStorageISCSITargetAddresses(gomock.Any()).
		Return([]gopowerstore.IPPoolAddress{
			{IPPort: gopowerstore.IPPortInstance{TargetIqn: "iqn.1998-01.com.foo.iscsi:name1"},
				Address: "192.168.1.1"},
			{IPPort: gopowerstore.IPPortInstance{TargetIqn: "iqn.1998-01.com.foo.iscsi:name2"},
				Address: "192.168.1.2"},
		}, nil)
	c.EXPECT().GetFCPorts(gomock.Any()).
		Return([]gopowerstore.FcPort{
			{Wwn: "58:cc:f0:93:48:a0:03:a3"},
			{Wwn: "58:cc:f0:92:48:a0:03:a3"},
		}, nil)
}

func TestDetachVolumeFromAllHosts(t *testing.T) {
	impl, implMock, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	adminClientMock, ctrl := getAdminClient(t)
	defer ctrl.Finish()
	impl.service.adminClient = adminClientMock

	funcUnderTest := func() error {
		return impl.detachVolumeFromAllHosts(nil, validVolumeID)
	}
	getHostVolumeMappingByVolumeIDMock := func() *gomock.Call {
		return adminClientMock.EXPECT().GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Any())
	}
	detachVolumeFromHostMock := func() *gomock.Call {
		return implMock.EXPECT().detachVolumeFromHost(gomock.Any(), validHostID, validVolumeID)
	}

	mapping := []gopowerstore.HostVolumeMapping{{HostID: validHostID, VolumeID: validVolumeID}}
	// get mapping error
	getHostVolumeMappingByVolumeIDMock().Return([]gopowerstore.HostVolumeMapping{}, errors.New(testErrMsg))
	assert.EqualError(t, funcUnderTest(), testErrMsg)
	// pass
	getHostVolumeMappingByVolumeIDMock().Return(mapping, nil)
	detachVolumeFromHostMock().Return(nil)
	assert.Nil(t, funcUnderTest())
	// detach vol err
	getHostVolumeMappingByVolumeIDMock().Return(mapping, nil)
	detachVolumeFromHostMock().Return(errors.New(testErrMsg))
	assert.EqualError(t, funcUnderTest(), testErrMsg)
}

func TestDetachVolumeFromHost(t *testing.T) {
	impl, _, ctrl := getIMPLWitIMPLMock(t)
	defer ctrl.Finish()
	adminClientMock, ctrl := getAdminClient(t)
	defer ctrl.Finish()
	impl.service.adminClient = adminClientMock

	funcUnderTest := func() error {
		return impl.detachVolumeFromHost(nil, validHostID, validVolumeID)
	}

	detachVolumeFromHostMock := func() *gomock.Call {
		return adminClientMock.EXPECT().DetachVolumeFromHost(gomock.Any(), validHostID, gomock.Any())
	}

	emptyResp := gopowerstore.EmptyResponse("")

	// pass
	detachVolumeFromHostMock().Return(emptyResp, nil)
	assert.Nil(t, funcUnderTest())

	// already detached
	detachVolumeFromHostMock().Return(emptyResp, gopowerstore.NewHostIsNotAttachedToVolume())
	assert.Nil(t, funcUnderTest())

	// random err
	detachVolumeFromHostMock().Return(emptyResp, errors.New(testErrMsg))
	assert.EqualError(t, funcUnderTest(),
		fmt.Sprintf("rpc error: code = Unknown desc = failed to detach volume '%s' from host: %s",
			validVolumeID, testErrMsg))

	// host not exist
	detachVolumeFromHostMock().Return(emptyResp, gopowerstore.NewHostIsNotExistError())
	assert.EqualError(t, funcUnderTest(),
		fmt.Sprintf("rpc error: code = NotFound desc = host with ID '%s' not found",
			validHostID))
}
