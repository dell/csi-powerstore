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
	"github.com/DATA-DOG/godog"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/gofsutil"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/mock"
	"github.com/golang/mock/gomock"
	"github.com/joho/godotenv"
	"github.com/rexray/gocsi"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strconv"
	"strings"
)

const (
	EnvVarsFile = "./features/envvars.sh"

	GoodVolumeID = "39bb1b5f-5624-490d-9ece-18f7b28a904e"
	GoodHostID   = "24aefac2-a796-47dc-886a-c73ff8c1a671"
)

type feature struct {
	nGoRoutines                          int
	server                               *httptest.Server
	service                              *service
	err                                  error // return from the preceding call
	adminClient                          gopowerstore.Client
	getPluginInfoResponse                *csi.GetPluginInfoResponse
	getPluginCapabilitiesResponse        *csi.GetPluginCapabilitiesResponse
	probeResponse                        *csi.ProbeResponse
	createVolumeResponse                 *csi.CreateVolumeResponse
	publishVolumeResponse                *csi.ControllerPublishVolumeResponse
	unpublishVolumeResponse              *csi.ControllerUnpublishVolumeResponse
	expanvolumeRequest                   *csi.ControllerExpandVolumeRequest
	expanvolumeResponse                  *csi.ControllerExpandVolumeResponse
	nodeGetInfoResponse                  *csi.NodeGetInfoResponse
	nodeGetCapabilitiesResponse          *csi.NodeGetCapabilitiesResponse
	deleteVolumeResponse                 *csi.DeleteVolumeResponse
	getCapacityResponse                  *csi.GetCapacityResponse
	controllerGetCapabilitiesResponse    *csi.ControllerGetCapabilitiesResponse
	validateVolumeCapabilitiesResponse   *csi.ValidateVolumeCapabilitiesResponse
	createSnapshotRequest                *csi.CreateSnapshotRequest
	createSnapshotResponse               *csi.CreateSnapshotResponse
	deleteSnapshotRequest                *csi.DeleteSnapshotRequest
	deleteSnapshotResponse               *csi.DeleteSnapshotResponse
	listSnapshotsRequest                 *csi.ListSnapshotsRequest
	listSnapshotsResponse                *csi.ListSnapshotsResponse
	createVolumeRequest                  *csi.CreateVolumeRequest
	publishVolumeRequest                 *csi.ControllerPublishVolumeRequest
	unpublishVolumeRequest               *csi.ControllerUnpublishVolumeRequest
	deleteVolumeRequest                  *csi.DeleteVolumeRequest
	listVolumesRequest                   *csi.ListVolumesRequest
	listVolumesResponse                  *csi.ListVolumesResponse
	invalidVolumeID                      bool
	wrongCapacity                        bool
	useAccessTypeMount                   bool
	omitAccessMode, omitVolumeCapability bool
	capability                           *csi.VolumeCapability
	capabilities                         []*csi.VolumeCapability
	nodePublishVolumeRequest             *csi.NodePublishVolumeRequest
}

func (f *feature) aPowerStoreService(mode string) error {
	f.checkGoRoutines("start aPowerStoreService")
	// Save off the admin client
	f.service = f.getService()
	// Let the real code initialize it the first time, we reset the cache each test
	f.err = nil
	f.getPluginInfoResponse = nil
	f.getPluginCapabilitiesResponse = nil
	f.probeResponse = nil
	f.createVolumeResponse = nil
	f.nodeGetInfoResponse = nil
	f.nodeGetCapabilitiesResponse = nil
	f.getCapacityResponse = nil
	f.controllerGetCapabilitiesResponse = nil
	f.validateVolumeCapabilitiesResponse = nil
	f.createVolumeRequest = nil
	f.publishVolumeRequest = nil
	f.unpublishVolumeRequest = nil
	f.invalidVolumeID = false
	f.omitAccessMode = false
	f.omitVolumeCapability = false
	f.useAccessTypeMount = false
	f.wrongCapacity = false
	f.deleteVolumeRequest = nil
	f.deleteVolumeResponse = nil
	f.listVolumesRequest = nil
	f.listVolumesResponse = nil
	f.capability = nil
	f.capabilities = make([]*csi.VolumeCapability, 0)
	f.nodePublishVolumeRequest = nil
	f.createSnapshotResponse = nil
	f.createSnapshotRequest = nil
	f.deleteSnapshotRequest = nil
	f.deleteSnapshotResponse = nil
	f.listSnapshotsRequest = nil
	f.listSnapshotsResponse = nil

	// configure gofsutil; we use a mock interface
	gofsutil.UseMockFS()
	gofsutil.GOFSMock.InduceBindMountError = false
	gofsutil.GOFSMock.InduceMountError = false
	gofsutil.GOFSMock.InduceGetMountsError = false
	gofsutil.GOFSMock.InduceDevMountsError = false
	gofsutil.GOFSMock.InduceUnmountError = false
	gofsutil.GOFSMock.InduceFormatError = false
	gofsutil.GOFSMock.InduceGetDiskFormatError = false
	gofsutil.GOFSMock.InduceGetDiskFormatType = ""
	gofsutil.GOFSMockMounts = gofsutil.GOFSMockMounts[:0]

	// Get or reuse the cached service
	f.service.mode = mode
	if f.service.mode == "node" {
		_, err := f.service.impl.nodeProbe(nil)
		if err != nil {
			return err
		}
	}

	f.checkGoRoutines("end aPowerStoreService")
	err := f.service.ShutDown(context.Background())
	if err != nil {
		return err
	}
	return nil
}

func (f *feature) getService() *service {
	svc := initService()
	if f.adminClient != nil {
		svc.adminClient = f.adminClient
	}
	err := godotenv.Load(EnvVarsFile)
	if err != nil {
		log.Printf("%s file not found.", EnvVarsFile)
	}

	sp := &gocsi.StoragePlugin{}

	f.err = svc.BeforeServe(context.Background(), sp, nil)
	return svc
}

func (f *feature) iResetPowerStoreClient() error {
	f.service.adminClient = nil
	return nil
}

func (f *feature) iRewritePowerStoreServiceOption(name, value string) error {
	v := reflect.ValueOf(&f.service.opts).Elem().FieldByName(name)

	switch v.Kind() {
	case reflect.String:
		v.SetString(value)
	case reflect.Int:
		i, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(i)
	case reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		v.SetBool(b)
	}
	return nil
}

func (f *feature) checkGoRoutines(tag string) {
	goroutines := runtime.NumGoroutine()
	fmt.Printf("goroutines %s new %d old groutines %d\n", tag, goroutines, f.nGoRoutines)
	f.nGoRoutines = goroutines
}

func (f *feature) iCallGetPluginInfo() error {
	ctx := new(context.Context)
	req := new(csi.GetPluginInfoRequest)
	f.getPluginInfoResponse, f.err = f.service.GetPluginInfo(*ctx, req)
	if f.err != nil {
		return f.err
	}
	return nil
}

func (f *feature) aValidGetPluginInfoResponseIsReturned() error {
	rep := f.getPluginInfoResponse
	url := rep.GetManifest()["url"]
	if rep.GetName() == "" || rep.GetVendorVersion() == "" || url == "" {
		return errors.New("expected GetPluginInfo to return name and version")
	}
	log.Printf("Name %s Version %s URL %s", rep.GetName(), rep.GetVendorVersion(), url)
	return nil
}

func (f *feature) iCallGetPluginCapabilities() error {
	ctx := new(context.Context)
	req := new(csi.GetPluginCapabilitiesRequest)
	f.getPluginCapabilitiesResponse, f.err = f.service.GetPluginCapabilities(*ctx, req)
	if f.err != nil {
		return f.err
	}
	return nil
}

func (f *feature) aValidGetPluginCapabilitiesResponseIsReturned() error {
	rep := f.getPluginCapabilitiesResponse
	capabilities := rep.GetCapabilities()
	for _, capability := range capabilities {
		if capability.GetService().GetType() != csi.PluginCapability_Service_CONTROLLER_SERVICE {
			continue
		} else {
			return nil
		}

	}
	return errors.New("expected PluginCapabilitiesResponse to contain CONTROLLER_SERVICE")

}

func (f *feature) iCallNodeGetCapabilities() error {
	ctx := new(context.Context)
	req := new(csi.NodeGetCapabilitiesRequest)
	f.nodeGetCapabilitiesResponse, f.err = f.service.NodeGetCapabilities(*ctx, req)
	if f.err != nil {
		return f.err
	}
	return nil
}

func (f *feature) aValidNodeGetCapabilitiesResponseIsReturned() error {
	rep := f.nodeGetCapabilitiesResponse
	capabilities := rep.GetCapabilities()
	for _, capability := range capabilities {
		if capability.GetRpc().GetType() != csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME {
			continue
		} else {
			return nil
		}
	}
	return errors.New("expected nodeGetCapabilitiesResponse to contain STAGE_UNSTAGE_VOLUME")
}

func (f *feature) iCallControllerGetCapabilities() error {
	ctx := new(context.Context)
	req := new(csi.ControllerGetCapabilitiesRequest)
	f.controllerGetCapabilitiesResponse, f.err = f.service.ControllerGetCapabilities(*ctx, req)
	if f.err != nil {
		return f.err
	}
	return nil
}

func (f *feature) aValidControllerGetCapabilitiesResponseIsReturned() error {
	rep := f.controllerGetCapabilitiesResponse

	capabilities := rep.GetCapabilities()
	for _, capability := range capabilities {
		switch capability.GetRpc().GetType() {
		case
			csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
			csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME,
			csi.ControllerServiceCapability_RPC_LIST_VOLUMES,
			csi.ControllerServiceCapability_RPC_GET_CAPACITY,
			csi.ControllerServiceCapability_RPC_CLONE_VOLUME,
			csi.ControllerServiceCapability_RPC_CREATE_DELETE_SNAPSHOT,
			csi.ControllerServiceCapability_RPC_EXPAND_VOLUME,
			csi.ControllerServiceCapability_RPC_LIST_SNAPSHOTS:
			continue
		default:
			return fmt.Errorf("expected controllerGetCapabilitiesResponse to contain %s",
				capability.GetRpc().String())
		}
	}
	return nil
}

func getVolumeCapabilities(voltype, access string) []*csi.VolumeCapability {
	capability := new(csi.VolumeCapability)

	switch voltype {
	case "block":
		block := new(csi.VolumeCapability_BlockVolume)
		accessType := new(csi.VolumeCapability_Block)
		accessType.Block = block
		capability.AccessType = accessType
	case "mount":
		mount := new(csi.VolumeCapability_MountVolume)
		accessType := new(csi.VolumeCapability_Mount)
		accessType.Mount = mount
		capability.AccessType = accessType
	}

	accessMode := new(csi.VolumeCapability_AccessMode)
	switch access {
	case "single-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
	case "single-reader":
		accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY
	case "multi-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
	case "multi-reader":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY
	case "multi-node-single-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER
	}
	capability.AccessMode = accessMode

	capabilities := make([]*csi.VolumeCapability, 0)
	capabilities = append(capabilities, capability)
	return capabilities
}

func (f *feature) iCallValidateVolumeCapabilitiesWithVoltypeAccess(voltype, access string) error {
	ctx := new(context.Context)
	req := new(csi.ValidateVolumeCapabilitiesRequest)
	req.VolumeId = GoodVolumeID

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil).
		Times(1)
	f.service.adminClient = c

	req.VolumeCapabilities = getVolumeCapabilities(voltype, access)

	log.Printf("Calling ValidateVolumeCapabilities")
	f.validateVolumeCapabilitiesResponse, f.err = f.service.ValidateVolumeCapabilities(*ctx, req)
	if f.err != nil || f.validateVolumeCapabilitiesResponse == nil {
		return nil
	}
	if f.validateVolumeCapabilitiesResponse.Message != "" {
		f.err = errors.New(f.validateVolumeCapabilitiesResponse.Message)
	} else {
		// Validate we get a Confirmed structure with VolumeCapabilities
		if f.validateVolumeCapabilitiesResponse.Confirmed == nil {
			return errors.New("expected ValidateVolumeCapabilities to have a Confirmed structure but it did not")
		}
		confirmed := f.validateVolumeCapabilitiesResponse.Confirmed
		if len(confirmed.VolumeCapabilities) <= 0 {
			return errors.New("expected ValidateVolumeCapabilities to return the confirmed VolumeCapabilities but it did not")
		}
	}
	return nil
}

func (f *feature) iCallValidateVolumeCapabilitiesWithNotExistVolume() error {
	ctx := new(context.Context)
	req := new(csi.ValidateVolumeCapabilitiesRequest)
	req.VolumeId = GoodVolumeID

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{}, *apiError).
		Times(1)

	f.service.adminClient = c

	f.validateVolumeCapabilitiesResponse, f.err = f.service.ValidateVolumeCapabilities(*ctx, req)

	return nil
}

func (f *feature) iCallValidateVolumeCapabilitiesWithFailure() error {
	ctx := new(context.Context)
	req := new(csi.ValidateVolumeCapabilitiesRequest)
	req.VolumeId = GoodVolumeID

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{}, gopowerstore.NewAPIError()).
		Times(1)

	f.service.adminClient = c

	f.validateVolumeCapabilitiesResponse, f.err = f.service.ValidateVolumeCapabilities(*ctx, req)

	return nil
}

func (f *feature) iCallProbe() error {
	ctx := new(context.Context)
	req := new(csi.ProbeRequest)
	f.checkGoRoutines("before probe")
	f.probeResponse, f.err = f.service.Probe(*ctx, req)
	f.checkGoRoutines("after probe")
	return nil
}

func (f *feature) aValidProbeResponseIsReturned() error {
	if !f.probeResponse.GetReady().GetValue() {
		return errors.New("probe returned Ready false")
	}
	return nil
}

func (f *feature) theErrorContains(arg1 string) error {
	f.checkGoRoutines("theErrorContains")
	// If arg1 is none, we expect no error, any error received is unexpected
	if arg1 == "none" {
		if f.err == nil {
			return nil
		}
		return fmt.Errorf("unexpected error: %s", f.err)
	}
	// We expected an error... unless there is a none clause
	if f.err == nil {
		// Check to see if no error is allowed as alternative
		possibleMatches := strings.Split(arg1, "@@")
		for _, possibleMatch := range possibleMatches {
			if possibleMatch == "none" {
				return nil
			}
		}
		return fmt.Errorf("expected error to contain %s but no error", arg1)
	}
	// Allow for multiple possible matches, separated by @@. This was necessary
	// because Windows and Linux sometimes return different error strings for
	// gofsutil operations. Note @@ was used instead of || because the Gherkin
	// parser is not smart enough to ignore vertical braces within a quoted string,
	// so if || is used it thinks the row's cell count is wrong.
	possibleMatches := strings.Split(arg1, "@@")
	for _, possibleMatch := range possibleMatches {
		if strings.Contains(f.err.Error(), possibleMatch) {
			return nil
		}
	}
	return fmt.Errorf("expected error to contain %s but it was %s", arg1, f.err.Error())
}

func getTypicalCreateVolumeRequest(name string, size int64) *csi.CreateVolumeRequest {
	req := new(csi.CreateVolumeRequest)
	params := make(map[string]string)
	req.Parameters = params
	req.Name = name
	capacityRange := new(csi.CapacityRange)
	capacityRange.RequiredBytes = size
	capacityRange.LimitBytes = size * 2
	req.CapacityRange = capacityRange
	block := new(csi.VolumeCapability_BlockVolume)
	capability := new(csi.VolumeCapability)
	accessType := new(csi.VolumeCapability_Block)
	accessType.Block = block
	capability.AccessType = accessType
	accessMode := new(csi.VolumeCapability_AccessMode)
	accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
	capability.AccessMode = accessMode
	capabilities := make([]*csi.VolumeCapability, 0)
	capabilities = append(capabilities, capability)
	req.VolumeCapabilities = capabilities

	return req
}
func getTypicalCreateVolumeNFSRequest(name string, size int64) *csi.CreateVolumeRequest {
	req := new(csi.CreateVolumeRequest)
	params := make(map[string]string)
	req.Parameters = params
	req.Name = name

	capacityRange := new(csi.CapacityRange)
	capacityRange.RequiredBytes = size
	capacityRange.LimitBytes = size * 2
	req.CapacityRange = capacityRange

	mount := new(csi.VolumeCapability_MountVolume)
	capability := new(csi.VolumeCapability)
	accessType := new(csi.VolumeCapability_Mount)
	accessType.Mount = mount
	capability.AccessType = accessType

	accessMode := new(csi.VolumeCapability_AccessMode)
	accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
	capability.AccessMode = accessMode

	capabilities := make([]*csi.VolumeCapability, 0)
	capabilities = append(capabilities, capability)
	req.VolumeCapabilities = capabilities
	params["FsType"] = "nfs"
	params["nasName"] = "AnyAnanasName"
	return req
}

func (f *feature) iCallCreateVolume(name string, size int64) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	volID := GoodVolumeID

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateVolume(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeCreate{})).
		Return(gopowerstore.CreateResponse{ID: volID}, nil).
		Times(1)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Any()).Times(0)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest(name, size*1024*1024*1024)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateNFSVolume(name string, size int64) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	volID := GoodVolumeID

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.CreateResponse{ID: volID}, nil).
		Times(1)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq(volID)).
		Return(gopowerstore.FileSystem{}, nil).Times(0)
	c.EXPECT().GetNASByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.NAS{}, nil).Times(1)
	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest(name, size*1024*1024*1024)

	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateVolumeWithError(name string, size int64) error {
	req := getTypicalCreateVolumeRequest(name, size*1024*1024*1024)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) aValidCreateVolumeResponseIsReturned() error {
	if f.err != nil {
		return f.err
	}
	if f.createVolumeResponse == nil || f.createVolumeResponse.Volume == nil {
		return errors.New("expected a valid createVolumeResponse")
	}
	if f.createVolumeResponse.Volume.GetCapacityBytes() != f.createVolumeRequest.CapacityRange.RequiredBytes {
		return errors.New("invalid volume capacity")
	}
	return nil
}

func getTypicalCreateSnapshotRequest(name, volid string) *csi.CreateSnapshotRequest {
	params := make(map[string]string)

	return &csi.CreateSnapshotRequest{
		SourceVolumeId: volid,
		Name:           name,
		Parameters:     params,
	}
}

func (f *feature) iCallCreateSnapshot(name, volID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	snapID := "64bed1b4f-5221-382e-9ece-18fbc25a924e"

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateSnapshot(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.SnapshotCreate{}), volID).
		Return(gopowerstore.CreateResponse{ID: snapID}, nil).
		Times(1)

	c.EXPECT().GetVolumeByName(gomock.Any(), name).
		Return(gopowerstore.Volume{}, errors.New("doesn't exist")).
		Times(1)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{Size: 3000}, nil).Times(1)

	f.service.adminClient = c

	req := getTypicalCreateSnapshotRequest(name, volID)
	f.createSnapshotRequest = req
	f.createSnapshotResponse, f.err = f.service.CreateSnapshot(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateSnapshot called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("snap id %s\n", f.createSnapshotResponse.GetSnapshot().SnapshotId)
	}
	return nil
}

func (f *feature) iCallCreateNfsSnapshot(name, volID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	snapID := "64bed1b4f-5221-382e-9ece-18fbc25a924e"

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, errors.New("doesn't exist")).Times(1)

	c.EXPECT().GetFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{SizeTotal: 3000}, nil).Times(1)

	c.EXPECT().GetFSByName(gomock.Any(), name).
		Return(gopowerstore.FileSystem{}, errors.New("doesn't exist")).
		Times(1)

	c.EXPECT().
		CreateFsSnapshot(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.SnapshotFSCreate{}), volID).
		Return(gopowerstore.CreateResponse{ID: snapID}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateSnapshotRequest(name, volID)
	f.createSnapshotRequest = req
	f.createSnapshotResponse, f.err = f.service.CreateSnapshot(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateSnapshot called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("snap id %s\n", f.createSnapshotResponse.GetSnapshot().SnapshotId)
	}
	return nil
}

func (f *feature) aValidCreateSnapshotResponseIsReturned() error {
	if f.err != nil {
		return f.err
	}
	if f.createSnapshotResponse == nil || f.createSnapshotResponse.Snapshot == nil {
		return errors.New("expected a valid createSnapshotResponse")
	}
	return nil
}

func (f *feature) iCallCreateSnapshotWithError(name, volid string) error {
	req := getTypicalCreateSnapshotRequest(name, volid)
	f.createSnapshotRequest = req

	f.createSnapshotResponse, f.err = f.service.CreateSnapshot(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateSnapshot called failed: %s\n", f.err.Error())
	}
	if f.createSnapshotResponse != nil {
		log.Printf("snap id %s\n", f.createSnapshotResponse.GetSnapshot().SnapshotId)
	}
	return nil
}

func (f *feature) iCallCreateExistingSnapshot(name, volID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.SnapshotNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusBadRequest

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{
			ID:   "0",
			Name: "vol1",
			Size: 8162,
		}, nil).Times(1)

	c.EXPECT().GetVolumeByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{
			ID:   "1",
			Name: "snap1",
			ProtectionData: gopowerstore.ProtectionData{
				SourceID: "39bb1b5f",
			},
		}, nil).Times(1)

	f.service.adminClient = c

	req := getTypicalCreateSnapshotRequest(name, volID)
	f.createSnapshotRequest = req
	f.createSnapshotResponse, f.err = f.service.CreateSnapshot(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateSnapshot called failed: %s\n", f.err.Error())
	}
	if f.createSnapshotResponse != nil {
		log.Printf("snap id %s\n", f.createSnapshotResponse.GetSnapshot().SnapshotId)
	}
	return nil
}

func (f *feature) iCallCreateExistingNfsSnapshot(name, volID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.SnapshotNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusBadRequest

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, errors.New("doesn't exist")).Times(1)

	c.EXPECT().GetFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{SizeTotal: 3000}, nil).Times(1)

	c.EXPECT().GetFSByName(gomock.Any(), name).
		Return(gopowerstore.FileSystem{
			ID:        "0",
			Name:      "fs1",
			SizeTotal: 8162,
			ParentId:  "39bb1b5f",
		}, nil).Times(1)

	f.service.adminClient = c

	req := getTypicalCreateSnapshotRequest(name, volID)
	f.createSnapshotRequest = req
	f.createSnapshotResponse, f.err = f.service.CreateSnapshot(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateSnapshot called failed: %s\n", f.err.Error())
	}
	if f.createSnapshotResponse != nil {
		log.Printf("snap id %s\n", f.createSnapshotResponse.GetSnapshot().SnapshotId)
	}
	return nil
}

func (f *feature) iCallCreateExistingSnapshotIncompatible(name, volID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.SnapshotNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusBadRequest

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{
			ID:   "0",
			Name: "vol1",
			Size: 8162,
		}, nil).Times(1)
	c.EXPECT().GetVolumeByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{
			ID:   "1",
			Name: "snap1",
			ProtectionData: gopowerstore.ProtectionData{
				SourceID: "39bb1b5f",
			},
		}, nil).Times(1)

	f.service.adminClient = c

	req := getTypicalCreateSnapshotRequest(name, volID)
	f.createSnapshotRequest = req
	f.createSnapshotResponse, f.err = f.service.CreateSnapshot(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateSnapshot called failed: %s\n", f.err.Error())
	}
	if f.createSnapshotResponse != nil {
		log.Printf("snap id %s\n", f.createSnapshotResponse.GetSnapshot().SnapshotId)
	}
	return nil
}

func (f *feature) iCallCreateExistingSnapshotError(name, volID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.SnapshotNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusBadRequest

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{
			ID:   "0",
			Name: "vol1",
			Size: 8162,
		}, nil).Times(1)

	c.EXPECT().
		CreateSnapshot(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.SnapshotCreate{}), volID).
		Return(gopowerstore.CreateResponse{}, *apiError).Times(1)

	c.EXPECT().GetVolumeByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, errors.New("err")).Times(2)

	f.service.adminClient = c

	req := getTypicalCreateSnapshotRequest(name, volID)
	f.createSnapshotRequest = req
	f.createSnapshotResponse, f.err = f.service.CreateSnapshot(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateSnapshot called failed: %s\n", f.err.Error())
	}
	if f.createSnapshotResponse != nil {
		log.Printf("snap id %s\n", f.createSnapshotResponse.GetSnapshot().SnapshotId)
	}
	return nil
}

func (f *feature) iCallFailureCreateSnapshot(name, volID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.Message = "Unknown error"

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{
			ID:   "0",
			Name: "vol1",
			Size: 8162,
		}, nil).Times(1)

	c.EXPECT().GetVolumeByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, gopowerstore.NewAPIError()).Times(1)

	c.EXPECT().
		CreateSnapshot(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.SnapshotCreate{}), volID).
		Return(gopowerstore.CreateResponse{}, *apiError).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateSnapshotRequest(name, volID)
	f.createSnapshotRequest = req
	f.createSnapshotResponse, f.err = f.service.CreateSnapshot(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateSnapshot called failed: %s\n", f.err.Error())
	}
	if f.createSnapshotResponse != nil {
		log.Printf("snap id %s\n", f.createSnapshotResponse.GetSnapshot().SnapshotId)
	}
	return nil
}

func (f *feature) aValidDeleteSnapshotResponseIsReturned() error {
	if f.err != nil {
		return f.err
	}
	if f.deleteSnapshotResponse == nil {
		return errors.New("expected a valid deleteSnapshotResponse")
	}
	return nil
}

func (f *feature) iCallDeleteSnapshot(snapID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetSnapshot(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: "1"}, nil)

	c.EXPECT().DeleteSnapshot(gomock.Any(), gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.EmptyResponse(""), nil).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteSnapshotRequest{SnapshotId: snapID}
	f.deleteSnapshotResponse, f.err = f.service.DeleteSnapshot(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteNfsSnapshot(snapID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetSnapshot(gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.Volume{}, errors.New("doesn't exist"))

	c.EXPECT().GetFsSnapshot(gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.FileSystem{ID: snapID}, nil)

	c.EXPECT().DeleteFsSnapshot(gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.EmptyResponse(""), nil).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteSnapshotRequest{SnapshotId: snapID}
	f.deleteSnapshotResponse, f.err = f.service.DeleteSnapshot(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteSnapshotWithError(snapID string) error {
	req := &csi.DeleteSnapshotRequest{SnapshotId: snapID}
	f.deleteSnapshotResponse, f.err = f.service.DeleteSnapshot(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteNonExistingSnapshot(snapID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetSnapshot(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: "1"}, nil)

	c.EXPECT().DeleteSnapshot(gomock.Any(), gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.EmptyResponse(""), *apiError).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteSnapshotRequest{SnapshotId: snapID}
	f.deleteSnapshotResponse, f.err = f.service.DeleteSnapshot(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteNonExistingNfsSnapshot(snapID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetSnapshot(gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.Volume{}, errors.New("doesn't exist"))

	c.EXPECT().GetFsSnapshot(gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.FileSystem{ID: snapID}, nil)

	c.EXPECT().DeleteFsSnapshot(gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.EmptyResponse(""), *apiError).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteSnapshotRequest{SnapshotId: snapID}
	f.deleteSnapshotResponse, f.err = f.service.DeleteSnapshot(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteSnapshotButNoneFound(snapID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetSnapshot(gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.Volume{}, *apiError)

	c.EXPECT().GetFsSnapshot(gomock.Any(), gomock.Eq(snapID)).
		Return(gopowerstore.FileSystem{}, *apiError)

	f.service.adminClient = c

	req := &csi.DeleteSnapshotRequest{SnapshotId: snapID}
	f.deleteSnapshotResponse, f.err = f.service.DeleteSnapshot(context.Background(), req)
	return nil
}

func (f *feature) aValidListSnapshotsResponseIsReturned() error {
	if f.err != nil {
		return f.err
	}
	if f.listSnapshotsResponse == nil {
		return errors.New("received null response to ListSnapshots")
	}
	fmt.Printf("NextToken: %s, Entries: %v\n", f.listSnapshotsResponse.NextToken, f.listSnapshotsResponse.Entries)
	return nil
}

func (f *feature) iCallListSnapshots(snapID, srcID string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetSnapshot(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: GoodVolumeID, Size: 8162}, nil).Times(1)
	f.service.adminClient = c

	ctx := new(context.Context)
	req := &csi.ListSnapshotsRequest{
		StartingToken:  "1",
		SourceVolumeId: srcID,
		SnapshotId:     snapID,
	}

	f.listSnapshotsResponse, f.err = f.service.ListSnapshots(*ctx, req)
	if f.err != nil {
		log.Printf("ListSnapshots call failed: %s\n", f.err.Error())
		return nil
	}
	return nil
}

func (f *feature) iCallListSnapshotsError(startToken string) error {
	ctx := new(context.Context)
	req := &csi.ListSnapshotsRequest{StartingToken: startToken}

	f.listSnapshotsResponse, f.err = f.service.ListSnapshots(*ctx, req)
	if f.err != nil {
		log.Printf("ListSnapshots call failed: %s\n", f.err.Error())
		return nil
	}
	return nil
}

func (f *feature) iCallListSnapshotsWithStartToken(startToken string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	req := &csi.ListSnapshotsRequest{StartingToken: startToken}
	c.EXPECT().
		GetSnapshots(gomock.Any()).
		Return([]gopowerstore.Volume{
			{
				ID:   GoodVolumeID,
				Size: 8162,
			},
		}, nil).Times(1)
	f.service.adminClient = c

	f.listSnapshotsResponse, f.err = f.service.ListSnapshots(context.Background(), req)
	if f.err != nil {
		log.Printf("ListSnapshots call failed: %s\n", f.err.Error())
		return nil
	}
	return nil
}

func (f *feature) iCallFailureListSnapshots() error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetSnapshots(gomock.Any()).
		Return([]gopowerstore.Volume{}, gopowerstore.NewAPIError()).
		Times(1)
	f.service.adminClient = c

	ctx := new(context.Context)
	req := new(csi.ListSnapshotsRequest)

	f.listSnapshotsResponse, f.err = f.service.ListSnapshots(*ctx, req)
	return nil
}

func (f *feature) iCallCreateVolumeFromSnapshot(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	volID := GoodVolumeID

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateVolumeFromSnapshot(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeClone{}), "39bb1b5f").
		Return(gopowerstore.CreateResponse{ID: volID}, nil).
		Times(1)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.Volume{
			ID:   "39bb1b5f",
			Size: volSize,
		}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest("vol1", volSize)
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
		Snapshot: &csi.VolumeContentSource_SnapshotSource{
			SnapshotId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateVolumeFromSnapshotIncompatible(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.Volume{
			ID:   "39bb1b5f",
			Size: 16 * 1024 * 1024,
		}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest("vol1", volSize)
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
		Snapshot: &csi.VolumeContentSource_SnapshotSource{
			SnapshotId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateVolumeFromSnapshotError(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.Volume{}, gopowerstore.NewAPIError()).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest("vol1", volSize)
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
		Snapshot: &csi.VolumeContentSource_SnapshotSource{
			SnapshotId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallFailureCreateVolumeFromSnapshot(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateVolumeFromSnapshot(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeClone{}), "39bb1b5f").
		Return(gopowerstore.CreateResponse{}, gopowerstore.NewAPIError()).
		Times(1)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.Volume{
			ID:   "39bb1b5f",
			Size: volSize,
		}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest("vol1", volSize)
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
		Snapshot: &csi.VolumeContentSource_SnapshotSource{
			SnapshotId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateCloneVolume(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	volID := GoodVolumeID

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CloneVolume(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeClone{}), "39bb1b5f").
		Return(gopowerstore.CreateResponse{ID: volID}, nil).
		Times(1)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.Volume{
			ID:   "39bb1b5f",
			Size: volSize,
		}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest("vol1", volSize)
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{
			VolumeId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateCloneVolumeIncompatible(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.Volume{
			ID:   "39bb1b5f",
			Size: 16 * 1024 * 1024,
		}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest("vol1", volSize)
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{
			VolumeId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateCloneVolumeError(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.Volume{}, gopowerstore.NewAPIError()).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest("vol1", volSize)
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{
			VolumeId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallFailureCreateCloneVolume(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CloneVolume(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeClone{}), "39bb1b5f").
		Return(gopowerstore.CreateResponse{}, gopowerstore.NewAPIError()).
		Times(1)

	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.Volume{
			ID:   "39bb1b5f",
			Size: volSize,
		}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest("vol1", volSize)
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{
			VolumeId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateNfsFromSnapshot(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	volID := GoodVolumeID

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.FileSystem{
			ID:        "39bb1b5f",
			SizeTotal: volSize + ReservedSize,
		}, nil).
		Times(1)
	c.EXPECT().
		CreateFsFromSnapshot(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.FsClone{}), "39bb1b5f").
		Return(gopowerstore.CreateResponse{ID: volID}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest("vol1", volSize)

	params := make(map[string]string, 1)
	params[keyFsType] = "nfs"
	req.Parameters = params
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
		Snapshot: &csi.VolumeContentSource_SnapshotSource{
			SnapshotId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateNfsFromSnapshotIncompatible(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{
			ID:        "39bb1b5f",
			SizeTotal: 16 * 1024 * 1024,
		}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest("vol1", volSize)

	params := make(map[string]string, 1)
	params[keyFsType] = "nfs"
	req.Parameters = params
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
		Snapshot: &csi.VolumeContentSource_SnapshotSource{
			SnapshotId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateNfsFromSnapshotError(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.FileSystem{}, gopowerstore.NewAPIError()).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest("vol1", volSize)

	params := make(map[string]string, 1)
	params[keyFsType] = "nfs"
	req.Parameters = params

	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
		Snapshot: &csi.VolumeContentSource_SnapshotSource{
			SnapshotId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallFailureCreateNfsFromSnapshot(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.FileSystem{
			ID:        "39bb1b5f",
			SizeTotal: volSize + ReservedSize,
		}, nil).
		Times(1)
	c.EXPECT().
		CreateFsFromSnapshot(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.FsClone{}), "39bb1b5f").
		Return(gopowerstore.CreateResponse{}, gopowerstore.NewAPIError()).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest("vol1", volSize)

	params := make(map[string]string, 1)
	params[keyFsType] = "nfs"
	req.Parameters = params

	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
		Snapshot: &csi.VolumeContentSource_SnapshotSource{
			SnapshotId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateCloneFs(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	volID := GoodVolumeID

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.FileSystem{
			ID:        "39bb1b5f",
			SizeTotal: volSize + ReservedSize,
		}, nil).
		Times(1)
	c.EXPECT().
		CloneFS(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.FsClone{}), "39bb1b5f").
		Return(gopowerstore.CreateResponse{ID: volID}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest("vol1", volSize)

	params := make(map[string]string, 1)
	params[keyFsType] = "nfs"
	req.Parameters = params
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{
			VolumeId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateCloneFsIncompatible(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{
			ID:        "39bb1b5f",
			SizeTotal: 16 * 1024 * 1024,
		}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest("vol1", volSize)

	params := make(map[string]string, 1)
	params[keyFsType] = "nfs"
	req.Parameters = params
	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{
			VolumeId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateCloneFsError(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.FileSystem{}, gopowerstore.NewAPIError()).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest("vol1", volSize)

	params := make(map[string]string, 1)
	params[keyFsType] = "nfs"
	req.Parameters = params

	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{
			VolumeId: "39bb1b5f",
		},
	}}
	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallFailureCreateCloneFs(size int) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	volSize := int64(size * 1024 * 1024)

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq("39bb1b5f")).
		Return(gopowerstore.FileSystem{
			ID:        "39bb1b5f",
			SizeTotal: volSize + ReservedSize,
		}, nil).
		Times(1)
	c.EXPECT().
		CloneFS(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.FsClone{}), "39bb1b5f").
		Return(gopowerstore.CreateResponse{}, gopowerstore.NewAPIError()).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest("vol1", volSize)

	params := make(map[string]string, 1)
	params[keyFsType] = "nfs"
	req.Parameters = params

	req.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{
			VolumeId: "39bb1b5f",
		},
	}}

	f.createVolumeRequest = req
	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume call failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallNodeGetInfo() error {
	ctx := new(context.Context)
	req := new(csi.NodeGetInfoRequest)
	f.service.nodeID = ""
	f.nodeGetInfoResponse, f.err = f.service.NodeGetInfo(*ctx, req)
	return nil
}

func (f *feature) aValidNodeGetInfoResponseIsReturned() error {
	if f.err != nil {
		return f.err
	}
	if f.nodeGetInfoResponse.NodeId == "" {
		return errors.New("expected NodeGetInfoResponse to contain NodeID but it was null")
	}
	if f.nodeGetInfoResponse.MaxVolumesPerNode != 0 {
		return errors.New("expected NodeGetInfoResponse MaxVolumesPerNode to be 0")
	}
	fmt.Printf("NodeID %s\n", f.nodeGetInfoResponse.NodeId)
	return nil
}

func (f *feature) iCallCreateExistVolume(name string, size int64) error {
	sizeInBytes := size * 1024 * 1024 * 1024

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	volID := GoodVolumeID
	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.VolumeNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusUnprocessableEntity

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateVolume(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeCreate{})).
		Return(gopowerstore.CreateResponse{}, *apiError).
		Times(1)

	c.EXPECT().GetVolumeByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: volID, Name: name, Size: sizeInBytes}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest(name, sizeInBytes)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateExistingNfsVolume(name string, size int64) error {
	sizeInBytes := size * 1024 * 1024 * 1024

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.VolumeNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusUnprocessableEntity

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetNASByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.NAS{
			ID:   "nasId",
			Name: "nasName",
		}, nil).Times(1)
	c.EXPECT().
		CreateFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.CreateResponse{}, *apiError).
		Times(1)

	c.EXPECT().GetFSByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{
			ID:             "somefsid",
			Name:           "fsname",
			NasServerID:    "nas-server",
			FilesystemType: "nfs4",
			SizeTotal:      sizeInBytes,
		}, nil).Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest(name, sizeInBytes)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateExistingNfsVolumeError(name string, size int64) error {
	sizeInBytes := size * 1024 * 1024 * 1024

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.VolumeNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusUnprocessableEntity

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetNASByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.NAS{
			ID:   "nasId",
			Name: "nasName",
		}, nil).Times(1)
	c.EXPECT().
		CreateFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.CreateResponse{}, *apiError).
		Times(1)

	c.EXPECT().GetFSByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{}, gopowerstore.NewAPIError()).Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest(name, sizeInBytes)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateExistingNfsVolumeIncompatibleSize(name string, size int64) error {
	sizeInBytes := size * 1024 * 1024 * 1024

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.VolumeNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusUnprocessableEntity

	c := mock.NewMockClient(ctrl)

	c.EXPECT().GetNASByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.NAS{
			ID:   "nasId",
			Name: "nasName",
		}, nil).Times(1)
	c.EXPECT().CreateFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.CreateResponse{}, *apiError).
		Times(1)
	c.EXPECT().GetFSByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{
			ID:             "somefsid",
			Name:           "fsname",
			NasServerID:    "nas-server",
			FilesystemType: "nfs4",
			SizeTotal:      sizeInBytes,
		}, nil).Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeNFSRequest(name, sizeInBytes+1024)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateExistVolumeIncompatible(name string, size int64) error {
	sizeInBytes := size * 1024 * 1024

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	volID := GoodVolumeID
	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.VolumeNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusUnprocessableEntity

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateVolume(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeCreate{})).
		Return(gopowerstore.CreateResponse{}, *apiError).
		Times(1)

	c.EXPECT().GetVolumeByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: volID, Name: name, Size: sizeInBytes}, nil).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest(name, sizeInBytes+1024)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallCreateExistVolumeError(name string, size int64) error {
	sizeInBytes := size * 1024 * 1024

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.VolumeNameAlreadyUseErrorCode
	apiError.StatusCode = http.StatusUnprocessableEntity

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateVolume(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeCreate{})).
		Return(gopowerstore.CreateResponse{}, *apiError).
		Times(1)

	c.EXPECT().GetVolumeByName(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{}, gopowerstore.NewAPIError()).
		Times(1)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest(name, sizeInBytes+1024)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallFailureCreateVolume(name string, size int64) error {
	sizeInBytes := size * 1024 * 1024

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.Message = "Unknown error"

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		CreateVolume(gomock.Any(), gomock.AssignableToTypeOf(&gopowerstore.VolumeCreate{})).
		Return(gopowerstore.CreateResponse{}, *apiError).
		Times(1)

	c.EXPECT().GetVolumes(gomock.Any()).
		Times(0)

	f.service.adminClient = c

	req := getTypicalCreateVolumeRequest(name, sizeInBytes+1024)
	f.createVolumeRequest = req

	f.createVolumeResponse, f.err = f.service.CreateVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("CreateVolume called failed: %s\n", f.err.Error())
	}
	if f.createVolumeResponse != nil {
		log.Printf("vol id %s\n", f.createVolumeResponse.GetVolume().VolumeId)
	}
	return nil
}

func (f *feature) iCallDeleteVolume(name string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.Volume{ID: GoodVolumeID}, nil).
		Times(1)
	c.EXPECT().
		GetSnapshotsByVolumeID(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return([]gopowerstore.Volume{}, nil).
		Times(1)
	c.EXPECT().DeleteVolume(gomock.Any(), gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.EmptyResponse(""), nil).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteVolumeRequest{VolumeId: GoodVolumeID}
	f.deleteVolumeResponse, f.err = f.service.DeleteVolume(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteVolumeSnapError(name string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.Volume{ID: GoodVolumeID}, nil).
		Times(1)
	c.EXPECT().
		GetSnapshotsByVolumeID(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return([]gopowerstore.Volume{{ID: GoodVolumeID}}, nil).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteVolumeRequest{VolumeId: GoodVolumeID}
	f.deleteVolumeResponse, f.err = f.service.DeleteVolume(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteNFSVolumeSnapError(name string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.Volume{}, errors.New("NFS")).
		Times(1)
	c.EXPECT().
		GetFS(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.FileSystem{ID: GoodVolumeID}, nil).
		Times(1)
	c.EXPECT().
		GetFsSnapshotsByVolumeID(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return([]gopowerstore.FileSystem{{ID: GoodVolumeID}}, nil).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteVolumeRequest{VolumeId: GoodVolumeID}
	f.deleteVolumeResponse, f.err = f.service.DeleteVolume(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteNFSVolume(name string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.Volume{}, errors.New("NFS")).
		Times(1)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.FileSystem{
			ID: GoodVolumeID,
		}, nil)
	c.EXPECT().
		GetFsSnapshotsByVolumeID(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return([]gopowerstore.FileSystem{}, nil).
		Times(1)
	c.EXPECT().DeleteFS(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.EmptyResponse(""), nil).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteVolumeRequest{VolumeId: GoodVolumeID}
	f.deleteVolumeResponse, f.err = f.service.DeleteVolume(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteNonExistingNfsVolume(name string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.Volume{}, errors.New("NFS")).
		Times(1)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.FileSystem{
			ID: GoodVolumeID,
		}, nil)

	c.EXPECT().
		GetFsSnapshotsByVolumeID(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return([]gopowerstore.FileSystem{}, nil).
		Times(1)

	c.EXPECT().DeleteFS(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.EmptyResponse(""), *apiError).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteVolumeRequest{VolumeId: GoodVolumeID}
	f.deleteVolumeResponse, f.err = f.service.DeleteVolume(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteNonExistVolume(arg1 string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.Volume{ID: GoodVolumeID}, nil).
		Times(1)
	c.EXPECT().
		GetSnapshotsByVolumeID(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return([]gopowerstore.Volume{}, nil).
		Times(1)
	c.EXPECT().DeleteVolume(gomock.Any(), gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.EmptyResponse(""), *apiError).
		Times(1)

	f.service.adminClient = c

	req := &csi.DeleteVolumeRequest{VolumeId: GoodVolumeID}
	f.deleteVolumeResponse, f.err = f.service.DeleteVolume(context.Background(), req)
	return nil
}

func (f *feature) iCallDeleteVolumeError(name string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.Volume{}, errors.New("NFS")).
		Times(1)

	c.EXPECT().GetFS(gomock.Any(), gomock.Eq(GoodVolumeID)).
		Return(gopowerstore.FileSystem{}, gopowerstore.NewAPIError())

	f.service.adminClient = c

	req := &csi.DeleteVolumeRequest{VolumeId: GoodVolumeID}
	f.deleteVolumeResponse, f.err = f.service.DeleteVolume(context.Background(), req)
	return nil
}

func (f *feature) aValidDeleteVolumeResponseIsReturned() error {
	if f.err != nil {
		return f.err
	}
	if f.deleteVolumeResponse == nil {
		return errors.New("expected a valid deleteVolumeResponse")
	}
	return nil
}

func (f *feature) iCallGetCapacity() error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	var capacity int64 = 8162

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetCapacity(gomock.Any()).
		Return(capacity, nil).
		Times(1)
	f.service.adminClient = c

	ctx := new(context.Context)
	req := new(csi.GetCapacityRequest)

	f.getCapacityResponse, f.err = f.service.GetCapacity(*ctx, req)
	if f.err != nil {
		log.Printf("GetCapacity call failed: %s\n", f.err.Error())
		return nil
	}
	return nil
}

func (f *feature) aValidGetCapacityResponseIsReturned() error {
	if f.err != nil {
		return f.err
	}
	if f.getCapacityResponse == nil {
		return errors.New("received null response to GetCapacity")
	}
	if f.getCapacityResponse.AvailableCapacity <= 0 {
		return errors.New("expected AvailableCapacity to be positive")
	}
	fmt.Printf("Available capacity: %d\n", f.getCapacityResponse.AvailableCapacity)
	return nil
}

func (f *feature) iCallGetCapacityWithProbeError() error {
	ctx := new(context.Context)
	req := new(csi.GetCapacityRequest)

	f.getCapacityResponse, f.err = f.service.GetCapacity(*ctx, req)
	if f.err != nil {
		log.Printf("GetCapacity call failed: %s\n", f.err.Error())
		return nil
	}
	return nil
}

func (f *feature) iCallFailureGetCapacity() error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	var capacity int64

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetCapacity(gomock.Any()).
		Return(capacity, gopowerstore.NewAPIError()).
		Times(1)
	f.service.adminClient = c

	ctx := new(context.Context)
	req := new(csi.GetCapacityRequest)

	f.getCapacityResponse, f.err = f.service.GetCapacity(*ctx, req)
	return nil
}

func (f *feature) iCallGetCapacityWithVolumeCapabilitiesVoltypeAccess(voltype, access string) error {
	ctx := new(context.Context)
	req := new(csi.GetCapacityRequest)
	req.VolumeCapabilities = getVolumeCapabilities(voltype, access)

	f.getCapacityResponse, f.err = f.service.GetCapacity(*ctx, req)
	if f.err != nil {
		log.Printf("GetCapacity call failed: %s\n", f.err.Error())
		return nil
	}
	return nil
}

func (f *feature) iCallListVolumes() error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolumes(gomock.Any()).
		Return([]gopowerstore.Volume{{ID: GoodVolumeID, Size: 8162}, {ID: GoodVolumeID, Size: 8162}}, nil).
		Times(1)
	f.service.adminClient = c

	ctx := new(context.Context)
	req := &csi.ListVolumesRequest{StartingToken: "1"}

	f.listVolumesResponse, f.err = f.service.ListVolumes(*ctx, req)
	if f.err != nil {
		log.Printf("ListVolumes call failed: %s\n", f.err.Error())
		return nil
	}
	return nil
}

func (f *feature) aValidListVolumesResponseIsReturned() error {
	if f.err != nil {
		return f.err
	}
	if f.listVolumesResponse == nil {
		return errors.New("received null response to ListVolumes")
	}
	fmt.Printf("NextToken: %s, Entries: %v\n", f.listVolumesResponse.NextToken, f.listVolumesResponse.Entries)
	return nil
}

func (f *feature) iCallListVolumesWithCacheAndStartToken(startToken string) error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	ctx := new(context.Context)
	req := &csi.ListVolumesRequest{StartingToken: startToken}

	_, err := strconv.ParseInt(startToken, 10, 32)
	if err == nil {
		c := mock.NewMockClient(ctrl)
		c.EXPECT().
			GetVolumes(gomock.Any()).
			Return([]gopowerstore.Volume{
				{
					ID:   GoodVolumeID,
					Size: 8162,
				},
			}, nil).Times(1)
		f.service.adminClient = c
	}

	f.listVolumesResponse, f.err = f.service.ListVolumes(*ctx, req)
	if f.err != nil {
		log.Printf("ListVolumes call failed: %s\n", f.err.Error())
		return nil
	}
	return nil
}

func (f *feature) iCallFailureListVolumes() error {
	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolumes(gomock.Any()).
		Return([]gopowerstore.Volume{}, gopowerstore.NewAPIError()).
		Times(1)
	f.service.adminClient = c

	ctx := new(context.Context)
	req := new(csi.ListVolumesRequest)

	f.listVolumesResponse, f.err = f.service.ListVolumes(*ctx, req)
	return nil
}

func (f *feature) getControllerPublishVolumeRequest(access, nodeID string) *csi.ControllerPublishVolumeRequest {
	capability := new(csi.VolumeCapability)
	accessMode := new(csi.VolumeCapability_AccessMode)
	switch access {
	case "single-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
		break
	case "multiple-reader":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY
		break
	case "multiple-writer":
		accessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
		break
	case "unknown":
		accessMode.Mode = csi.VolumeCapability_AccessMode_UNKNOWN
		break
	}
	capability.AccessMode = accessMode

	block := new(csi.VolumeCapability_BlockVolume)
	accessType := new(csi.VolumeCapability_Block)
	accessType.Block = block
	capability.AccessType = accessType

	fmt.Printf("capability.AccessType %v\n", capability.AccessType)
	fmt.Printf("capability.AccessMode %v\n", capability.AccessMode)

	req := new(csi.ControllerPublishVolumeRequest)
	req.VolumeId = GoodVolumeID
	req.NodeId = nodeID
	req.Readonly = false
	req.VolumeCapability = capability
	return req
}

func (f *feature) iCallPublishVolumeWithTo(accessMode, nodeID string) error {
	req := f.getControllerPublishVolumeRequest(accessMode, nodeID)
	req.VolumeContext = map[string]string{keyFsType: "xfs"}
	f.publishVolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{ID: req.VolumeId, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil).
		Times(1)
	c.EXPECT().GetHostByName(gomock.Any(), gomock.Eq(req.NodeId)).
		Return(gopowerstore.Host{ID: GoodHostID}, nil).
		Times(1)
	c.EXPECT().
		GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return([]gopowerstore.HostVolumeMapping{}, nil).
		Times(1)
	c.EXPECT().
		AttachVolumeToHost(gomock.Any(), gomock.Eq(GoodHostID), gomock.AssignableToTypeOf(&gopowerstore.HostVolumeAttach{})).
		Return(gopowerstore.EmptyResponse(""), nil).
		Times(1)
	c.EXPECT().
		GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return([]gopowerstore.HostVolumeMapping{{HostID: GoodHostID, LogicalUnitNumber: 1}}, nil).
		Times(1)
	c.EXPECT().
		GetStorageISCSITargetAddresses(gomock.Any()).
		Return([]gopowerstore.IPPoolAddress{
			{Address: "192.168.1.1", IPPort: gopowerstore.IPPortInstance{TargetIqn: "iqn"}}}, nil).
		Times(1)
	c.EXPECT().
		GetFCPorts(gomock.Any()).
		Return([]gopowerstore.FcPort{
			{Wwn: "58:cc:f0:93:48:a0:03:a3"}}, nil).
		Times(1)

	f.service.adminClient = c

	f.publishVolumeResponse, f.err = f.service.ControllerPublishVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("PublishVolume call failed: %s\n", f.err.Error())
	}
	f.publishVolumeRequest = nil
	return nil
}

func (f *feature) iCallPublishNFSVolumeWithTo(accessMode, nodeID string) error {
	req := f.getControllerPublishVolumeRequest(accessMode, nodeID)
	req.VolumeContext = make(map[string]string)
	req.VolumeContext["FsType"] = "nfs"
	req.VolumeContext["nasName"] = "NASName"
	f.publishVolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()
	fsName := "testFS"
	nfsID := "1ae5edac1-a796-886a-47dc-c72a3j8clw031"
	nasID := "some-nas-id"

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetFS(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.FileSystem{
			ID:          req.VolumeId,
			Name:        fsName,
			NasServerID: nasID,
		}, nil).Times(2)

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.UnknownVolumeErrorCode
	apiError.StatusCode = http.StatusNotFound

	c.EXPECT().GetNFSExportByFileSystemID(gomock.Any(), gomock.Any()).
		Return(gopowerstore.NFSExport{
			ID: nfsID,
		}, *apiError).Times(1)

	nfsExportCreate := &gopowerstore.NFSExportCreate{
		Name:         fsName,
		FileSystemID: req.VolumeId,
		Path:         "/" + fsName,
	}

	c.EXPECT().CreateNFSExport(gomock.Any(), nfsExportCreate).
		Return(gopowerstore.CreateResponse{ID: nfsID}, nil).
		Times(1)

	c.EXPECT().ModifyNFSExport(gomock.Any(), gomock.Any(), nfsID).
		Return(gopowerstore.CreateResponse{}, nil).
		Times(1)

	interfaceID := "215as1223-d124-ss1h-njh4-c72a3j8clw031"

	c.EXPECT().GetNAS(gomock.Any(), nasID).
		Return(gopowerstore.NAS{
			CurrentPreferredIPv4InterfaceId: interfaceID,
		}, nil).Times(1)

	c.EXPECT().GetFileInterface(gomock.Any(), interfaceID).
		Return(gopowerstore.FileInterface{IpAddress: "192.168.1.2"}, nil).
		Times(1)

	f.service.adminClient = c

	f.publishVolumeResponse, f.err = f.service.ControllerPublishVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("PublishNFSVolume call failed: %s\n", f.err.Error())
	}
	f.publishVolumeRequest = nil
	return nil
}

func (f *feature) aValidControllerPublishVolumeResponseIsReturned() error {
	if f.err != nil {
		return errors.New("PublishVolume returned error: " + f.err.Error())
	}
	if f.publishVolumeResponse == nil {
		return errors.New("no PublishVolumeResponse returned")
	}
	for key, value := range f.publishVolumeResponse.PublishContext {
		fmt.Printf("PublishContext %s: %s", key, value)
	}
	return nil
}

func (f *feature) iCallPublishVolumeWithAlreadyMappedVolume() error {
	ctx := new(context.Context)
	req := f.getControllerPublishVolumeRequest("single-writer", "node1")
	req.VolumeContext = map[string]string{keyFsType: "xfs"}
	f.publishVolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{ID: req.VolumeId, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil).
		Times(1)
	c.EXPECT().GetHostByName(gomock.Any(), gomock.Eq(req.NodeId)).
		Return(gopowerstore.Host{ID: GoodHostID}, nil).
		Times(1)
	c.EXPECT().
		GetHostVolumeMappingByVolumeID(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return([]gopowerstore.HostVolumeMapping{{HostID: GoodHostID, LogicalUnitNumber: 1}}, nil).
		Times(1)
	c.EXPECT().
		AttachVolumeToHost(gomock.Any(), gomock.Eq(GoodHostID), gomock.AssignableToTypeOf(&gopowerstore.HostVolumeAttach{})).
		Times(0)
	c.EXPECT().
		GetStorageISCSITargetAddresses(gomock.Any()).
		Return([]gopowerstore.IPPoolAddress{
			{Address: "192.168.1.1", IPPort: gopowerstore.IPPortInstance{TargetIqn: "iqn"}}}, nil).
		Times(1)
	c.EXPECT().
		GetFCPorts(gomock.Any()).
		Return([]gopowerstore.FcPort{
			{Wwn: "58:cc:f0:93:48:a0:03:a3"}}, nil).
		Times(1)

	f.service.adminClient = c

	f.publishVolumeResponse, f.err = f.service.ControllerPublishVolume(*ctx, req)
	if f.err != nil {
		log.Printf("PublishVolume call failed: %s\n", f.err.Error())
	}
	f.publishVolumeRequest = nil
	return nil
}

func (f *feature) iCallUnpublishVolume(nodeID string) error {
	req := &csi.ControllerUnpublishVolumeRequest{VolumeId: GoodVolumeID, NodeId: nodeID}
	f.unpublishVolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil).
		Times(1)
	c.EXPECT().
		GetHostByName(gomock.Any(), gomock.Eq(req.NodeId)).
		Return(gopowerstore.Host{ID: GoodHostID}, nil).
		Times(1)
	c.EXPECT().
		DetachVolumeFromHost(gomock.Any(), GoodHostID, gomock.AssignableToTypeOf(&gopowerstore.HostVolumeDetach{})).
		Return(gopowerstore.EmptyResponse(""), nil).
		Times(1)
	f.service.adminClient = c

	f.unpublishVolumeResponse, f.err = f.service.ControllerUnpublishVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("UnpublishVolume call failed: %s\n", f.err.Error())
	}
	return nil
}

func (f *feature) iCallUnpublishNFSVolume(nodeID string) error {
	req := &csi.ControllerUnpublishVolumeRequest{VolumeId: GoodVolumeID, NodeId: "csi-node-test-127.0.0.1"}
	f.unpublishVolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{}, errors.New("NFS")).
		Times(1)

	c.EXPECT().GetFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{}, nil)

	c.EXPECT().
		GetNFSExportByFileSystemID(gomock.Any(), gomock.Any()).
		Return(gopowerstore.NFSExport{
			ID: "Some",
		}, nil).
		Times(1)
	c.EXPECT().
		ModifyNFSExport(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(gopowerstore.CreateResponse{}, nil).
		Times(1)

	f.service.adminClient = c

	f.unpublishVolumeResponse, f.err = f.service.ControllerUnpublishVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("UnpublishVolume call failed: %s\n", f.err.Error())
	}
	return nil
}

func (f *feature) aValidControllerUnpublishVolumeResponseIsReturned() error {
	if f.unpublishVolumeResponse == nil {
		return errors.New("expected unpublishVolumeResponse (with no contents)but did not get one")
	}
	return nil
}

func (f *feature) aValidExpandVolumeResponseIsReturned() error {
	if f.unpublishVolumeResponse == nil {
		return errors.New("expected expandVolumeResponse (with no contents)but did not get one")
	}
	return nil
}

func (f *feature) iCallControllerExpandVolume() error {
	var expandto int64 = MaxVolumeSizeBytes / 200
	req := &csi.ControllerExpandVolumeRequest{
		VolumeId: GoodVolumeID,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: expandto,
			LimitBytes:    MaxVolumeSizeBytes,
		},
	}
	f.expanvolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil).
		Times(1)
	c.EXPECT().
		ModifyVolume(gomock.Any(), gomock.Any(), GoodVolumeID).
		Return(gopowerstore.EmptyResponse(""), nil).
		Times(1)
	f.service.adminClient = c

	f.expanvolumeResponse, f.err = f.service.ControllerExpandVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("Controller Expand call failed: %s\n", f.err.Error())
	}
	return nil
}
func (f *feature) iCallControllerExpandVolumeSizeExceedLimit() error {
	var expandto int64 = MaxVolumeSizeBytes * 2
	req := &csi.ControllerExpandVolumeRequest{
		VolumeId: GoodVolumeID,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: expandto,
			LimitBytes:    MaxVolumeSizeBytes,
		},
	}
	f.expanvolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)

	f.service.adminClient = c

	f.expanvolumeResponse, f.err = f.service.ControllerExpandVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("Controller Expand call failed: %s\n", f.err.Error())
	}
	return nil
}

func (f *feature) iCallControllerExpandNFSVolumeSizeExceedLimit() error {
	var expandto int64 = MaxVolumeSizeBytes * 2
	req := &csi.ControllerExpandVolumeRequest{
		VolumeId: GoodVolumeID,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: expandto,
			LimitBytes:    MaxVolumeSizeBytes,
		},
	}
	f.expanvolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)

	f.service.adminClient = c

	f.expanvolumeResponse, f.err = f.service.ControllerExpandVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("Controller Expand call failed: %s\n", f.err.Error())
	}
	return nil
}

func (f *feature) iCallControllerExpandNFSVolumeShrink() error {
	var expandto int64 = MaxVolumeSizeBytes / 10000
	req := &csi.ControllerExpandVolumeRequest{
		VolumeId: GoodVolumeID,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: expandto,
			LimitBytes:    MaxVolumeSizeBytes,
		},
	}
	f.expanvolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{
			ID: req.VolumeId,
		}, errors.New("Gimme NFS")).
		Times(1)
	c.EXPECT().GetFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{SizeTotal: MaxVolumeSizeBytes / 1000}, nil)
	f.service.adminClient = c

	f.expanvolumeResponse, f.err = f.service.ControllerExpandVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("Controller Expand call failed: %s\n", f.err.Error())
	}
	return nil
}

func (f *feature) iCallControllerExpandVolumeShrink() error {
	var expandto int64 = MaxVolumeSizeBytes / 10000
	req := &csi.ControllerExpandVolumeRequest{
		VolumeId: GoodVolumeID,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: expandto,
			LimitBytes:    MaxVolumeSizeBytes,
		},
	}
	f.expanvolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{ID: req.VolumeId, Size: MaxVolumeSizeBytes / 100}, nil).
		Times(1)
	f.service.adminClient = c

	f.expanvolumeResponse, f.err = f.service.ControllerExpandVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("Controller Expand call failed: %s\n", f.err.Error())
	}
	return nil
}

func (f *feature) iCallControllerExpandNFSVolume() error {
	var expandto int64 = MaxVolumeSizeBytes / 200
	req := &csi.ControllerExpandVolumeRequest{
		VolumeId: GoodVolumeID,
		CapacityRange: &csi.CapacityRange{
			RequiredBytes: expandto,
			LimitBytes:    MaxVolumeSizeBytes,
		},
	}
	f.expanvolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	c := mock.NewMockClient(ctrl)
	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Eq(req.VolumeId)).
		Return(gopowerstore.Volume{ID: req.VolumeId}, errors.New("I want NFS")).
		Times(1)
	c.EXPECT().GetFS(gomock.Any(), gomock.Any()).
		Return(gopowerstore.FileSystem{}, nil)
	c.EXPECT().
		ModifyFS(gomock.Any(), gomock.Any(), GoodVolumeID).
		Return(gopowerstore.EmptyResponse(""), nil).
		Times(1)
	f.service.adminClient = c

	f.expanvolumeResponse, f.err = f.service.ControllerExpandVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("Controller Expand call failed: %s\n", f.err.Error())
	}
	return nil
}
func (f *feature) iCallUnpublishVolumeWithNotFoundHost() error {
	req := &csi.ControllerUnpublishVolumeRequest{VolumeId: GoodVolumeID, NodeId: "node1"}
	f.unpublishVolumeRequest = req

	ctrl := gomock.NewController(nil)
	defer ctrl.Finish()

	apiError := gopowerstore.NewAPIError()
	apiError.ErrorCode = gopowerstore.NoHostObjectFoundCode
	apiError.StatusCode = http.StatusBadRequest

	c := mock.NewMockClient(ctrl)

	c.EXPECT().
		GetVolume(gomock.Any(), gomock.Any()).
		Return(gopowerstore.Volume{ID: req.VolumeId}, nil).
		Times(1)
	c.EXPECT().
		GetHostByName(gomock.Any(), gomock.Eq(req.NodeId)).
		Return(gopowerstore.Host{ID: GoodHostID}, nil).
		Times(1)
	c.EXPECT().
		DetachVolumeFromHost(gomock.Any(), GoodHostID, gomock.AssignableToTypeOf(&gopowerstore.HostVolumeDetach{})).
		Return(gopowerstore.EmptyResponse(""), *apiError).
		Times(1)

	f.service.adminClient = c

	f.unpublishVolumeResponse, f.err = f.service.ControllerUnpublishVolume(context.Background(), req)
	if f.err != nil {
		log.Printf("UnpublishVolume call failed: %s\n", f.err.Error())
	}
	return nil
}

func FeatureContext(s *godog.Suite) {
	f := &feature{}
	s.Step(`^a PowerStore service on "([^"]*)"$`, f.aPowerStoreService)
	s.Step(`^I reset PowerStore client$`, f.iResetPowerStoreClient)
	s.Step(`^I call GetPluginInfo$`, f.iCallGetPluginInfo)
	s.Step(`^a valid GetPluginInfoResponse is returned$`, f.aValidGetPluginInfoResponseIsReturned)
	s.Step(`^I call GetPluginCapabilities$`, f.iCallGetPluginCapabilities)
	s.Step(`^a valid GetPluginCapabilitiesResponse is returned$`, f.aValidGetPluginCapabilitiesResponseIsReturned)
	s.Step(`^I call NodeGetCapabilities$`, f.iCallNodeGetCapabilities)
	s.Step(`^a valid NodeGetCapabilitiesResponse is returned$`, f.aValidNodeGetCapabilitiesResponseIsReturned)
	s.Step(`^I call ControllerGetCapabilities$`, f.iCallControllerGetCapabilities)
	s.Step(`^a valid ControllerGetCapabilitiesResponse is returned$`, f.aValidControllerGetCapabilitiesResponseIsReturned)
	s.Step(`^I call ValidateVolumeCapabilities with voltype "([^"]*)" access "([^"]*)"$`, f.iCallValidateVolumeCapabilitiesWithVoltypeAccess)
	s.Step(`^I call ValidateVolumeCapabilities with not exist volume$`, f.iCallValidateVolumeCapabilitiesWithNotExistVolume)
	s.Step(`^I call ValidateVolumeCapabilities with failure$`, f.iCallValidateVolumeCapabilitiesWithFailure)
	s.Step(`^I call Probe$`, f.iCallProbe)
	s.Step(`^I rewrite PowerStore service option "([^"]*)" "([^"]*)"$`, f.iRewritePowerStoreServiceOption)
	s.Step(`^a valid ProbeResponse is returned$`, f.aValidProbeResponseIsReturned)
	s.Step(`^the error contains "([^"]*)"$`, f.theErrorContains)
	s.Step(`^I call CreateVolume "([^"]*)" "(\d+)"$`, f.iCallCreateVolume)
	s.Step(`^I call CreateNFSVolume "([^"]*)" "(\d+)"$`, f.iCallCreateNFSVolume)
	s.Step(`^I call CreateVolume "([^"]*)" "(\d+)" with error$`, f.iCallCreateVolumeWithError)
	s.Step(`^a valid CreateVolumeResponse is returned$`, f.aValidCreateVolumeResponseIsReturned)
	s.Step(`^I call NodeGetInfo$`, f.iCallNodeGetInfo)
	s.Step(`^a valid NodeGetInfoResponse is returned$`, f.aValidNodeGetInfoResponseIsReturned)
	s.Step(`^I call CreateExistVolume "([^"]*)" "(\d+)"$`, f.iCallCreateExistVolume)
	s.Step(`^I call CreateExistVolumeIncompatible "([^"]*)" "(\d+)"$`, f.iCallCreateExistVolumeIncompatible)
	s.Step(`^I call CreateExistingNfsVolumeIncompatibleSize "([^"]*)" "(\d+)"$`, f.iCallCreateExistingNfsVolumeIncompatibleSize)
	s.Step(`^I call CreateExistVolumeError "([^"]*)" "(\d+)"$`, f.iCallCreateExistVolumeError)
	s.Step(`^I call CreateExistingNfsVolumeError "([^"]*)" "(\d+)"$`, f.iCallCreateExistingNfsVolumeError)
	s.Step(`^I call DeleteVolumeError "([^"]*)"$`, f.iCallDeleteVolumeError)
	s.Step(`^I call failure CreateVolume "([^"]*)" "(\d+)"$`, f.iCallFailureCreateVolume)
	s.Step(`^I call CreateExistingNfsVolume "([^"]*)" "(\d+)"$`, f.iCallCreateExistingNfsVolume)
	s.Step(`^I call DeleteVolume "([^"]*)"$`, f.iCallDeleteVolume)
	s.Step(`^I call DeleteVolumeSnapError "([^"]*)"$`, f.iCallDeleteVolumeSnapError)
	s.Step(`^I call DeleteNFSVolumeSnapError "([^"]*)"$`, f.iCallDeleteNFSVolumeSnapError)
	s.Step(`^I call DeleteNFSVolume "([^"]*)"$`, f.iCallDeleteNFSVolume)
	s.Step(`^a valid DeleteVolumeResponse is returned$`, f.aValidDeleteVolumeResponseIsReturned)
	s.Step(`^I call DeleteNonExistVolume "([^"]*)"$`, f.iCallDeleteNonExistVolume)
	s.Step(`^I call DeleteNonExistingNfsVolume "([^"]*)"$`, f.iCallDeleteNonExistingNfsVolume)
	s.Step(`^I call GetCapacity$`, f.iCallGetCapacity)
	s.Step(`^a valid GetCapacityResponse is returned$`, f.aValidGetCapacityResponseIsReturned)
	s.Step(`^I call GetCapacity with Probe error$`, f.iCallGetCapacityWithProbeError)
	s.Step(`^I call failure GetCapacity$`, f.iCallFailureGetCapacity)
	s.Step(`^I call GetCapacity with volume capabilities voltype "([^"]*)" access "([^"]*)"$`, f.iCallGetCapacityWithVolumeCapabilitiesVoltypeAccess)
	s.Step(`^I call ListVolumes$`, f.iCallListVolumes)
	s.Step(`^a valid ListVolumesResponse is returned$`, f.aValidListVolumesResponseIsReturned)
	s.Step(`^I call ListVolumes with cache and start token "([^"]*)"$`, f.iCallListVolumesWithCacheAndStartToken)
	s.Step(`^I call failure ListVolumes$`, f.iCallFailureListVolumes)
	s.Step(`^I call PublishVolume with "([^"]*)" to "([^"]*)"$`, f.iCallPublishVolumeWithTo)
	s.Step(`^I call PublishNFSVolume with "([^"]*)" to "([^"]*)"$`, f.iCallPublishNFSVolumeWithTo)
	s.Step(`^a valid ControllerPublishVolumeResponse is returned$`, f.aValidControllerPublishVolumeResponseIsReturned)
	s.Step(`^I call PublishVolume with already mapped volume$`, f.iCallPublishVolumeWithAlreadyMappedVolume)
	s.Step(`^I call UnpublishVolume from "([^"]*)"$`, f.iCallUnpublishVolume)
	s.Step(`^I call UnpublishNFSVolume from "([^"]*)"$`, f.iCallUnpublishNFSVolume)
	s.Step(`^a valid ControllerUnpublishVolumeResponse is returned$`, f.aValidControllerUnpublishVolumeResponseIsReturned)
	s.Step(`^I call UnpublishVolume with not found host$`, f.iCallUnpublishVolumeWithNotFoundHost)
	s.Step(`^I call CreateSnapshot "([^"]*)" "([^"]*)"$`, f.iCallCreateSnapshot)
	s.Step(`^I call CreateNfsSnapshot "([^"]*)" "([^"]*)"$`, f.iCallCreateNfsSnapshot)
	s.Step(`^a valid CreateSnapshotResponse is returned$`, f.aValidCreateSnapshotResponseIsReturned)
	s.Step(`^I call CreateSnapshot "([^"]*)" "([^"]*)" with error$`, f.iCallCreateSnapshotWithError)
	s.Step(`^I call CreateExistingSnapshot "([^"]*)" "([^"]*)"$`, f.iCallCreateExistingSnapshot)
	s.Step(`^I call CreateExistingNfsSnapshot "([^"]*)" "([^"]*)"$`, f.iCallCreateExistingNfsSnapshot)
	s.Step(`^I call CreateExistingSnapshotIncompatible "([^"]*)" "([^"]*)" with error$`, f.iCallCreateExistingSnapshotIncompatible)
	s.Step(`^I call CreateExistingSnapshotError "([^"]*)" "([^"]*)"$`, f.iCallCreateExistingSnapshotError)
	s.Step(`^I call failure CreateSnapshot "([^"]*)" "([^"]*)"$`, f.iCallFailureCreateSnapshot)
	s.Step(`^I call DeleteSnapshot "([^"]*)"$`, f.iCallDeleteSnapshot)
	s.Step(`^I call DeleteNfsSnapshot "([^"]*)"$`, f.iCallDeleteNfsSnapshot)
	s.Step(`^I call DeleteSnapshot "([^"]*)" with error$`, f.iCallDeleteSnapshotWithError)
	s.Step(`^a valid DeleteSnapshotResponse is returned$`, f.aValidDeleteSnapshotResponseIsReturned)
	s.Step(`^I call DeleteNonExistingSnapshot "([^"]*)"$`, f.iCallDeleteNonExistingSnapshot)
	s.Step(`^I call DeleteNonExistingNfsSnapshot "([^"]*)"$`, f.iCallDeleteNonExistingNfsSnapshot)
	s.Step(`^I call DeleteSnapshotButNoneFound "([^"]*)"$`, f.iCallDeleteSnapshotButNoneFound)
	s.Step(`^I call ListSnapshots "([^"]*)" "([^"]*)"$`, f.iCallListSnapshots)
	s.Step(`^a valid ListSnapshotsResponse is returned$`, f.aValidListSnapshotsResponseIsReturned)
	s.Step(`^I call ListSnapshotsError "([^"]*)"$`, f.iCallListSnapshotsError)
	s.Step(`^I call ListSnapshotsWithStartToken "([^"]*)"$`, f.iCallListSnapshotsWithStartToken)
	s.Step(`^I call failure ListSnapshots`, f.iCallFailureListSnapshots)
	s.Step(`^I call CreateVolumeFromSnapshot "(\d+)"$`, f.iCallCreateVolumeFromSnapshot)
	s.Step(`^I call CreateNfsFromSnapshot "(\d+)"$`, f.iCallCreateNfsFromSnapshot)
	s.Step(`^I call CreateVolumeFromSnapshotIncompatible "(\d+)"$`, f.iCallCreateVolumeFromSnapshotIncompatible)
	s.Step(`^I call CreateNfsFromSnapshotIncompatible "(\d+)"$`, f.iCallCreateNfsFromSnapshotIncompatible)
	s.Step(`^I call CreateVolumeFromSnapshotError "(\d+)"$`, f.iCallCreateVolumeFromSnapshotError)
	s.Step(`^I call CreateNfsFromSnapshotError "(\d+)"$`, f.iCallCreateNfsFromSnapshotError)
	s.Step(`^I call failure CreateVolumeFromSnapshot "(\d+)"`, f.iCallFailureCreateVolumeFromSnapshot)
	s.Step(`^I call failure CreateNfsFromSnapshot "(\d+)"`, f.iCallFailureCreateNfsFromSnapshot)
	s.Step(`^I call CreateCloneFs "(\d+)"$`, f.iCallCreateCloneFs)
	s.Step(`^I call CreateCloneFsIncompatible "(\d+)"$`, f.iCallCreateCloneFsIncompatible)
	s.Step(`^I call CreateCloneFsError "(\d+)"$`, f.iCallCreateCloneFsError)
	s.Step(`^I call failure CreateCloneFs "(\d+)"`, f.iCallFailureCreateCloneFs)
	s.Step(`^I call CreateCloneVolume "(\d+)"$`, f.iCallCreateCloneVolume)
	s.Step(`^I call CreateCloneVolumeIncompatible "(\d+)"$`, f.iCallCreateCloneVolumeIncompatible)
	s.Step(`^I call CreateCloneVolumeError "(\d+)"$`, f.iCallCreateCloneVolumeError)
	s.Step(`^I call failure CreateCloneVolume "(\d+)"`, f.iCallFailureCreateCloneVolume)
	s.Step(`^I call ExpandVolumeSize$`, f.iCallControllerExpandVolume)
	s.Step(`^I call ExpandNFSVolumeSize$`, f.iCallControllerExpandNFSVolume)
	s.Step(`^I call ExpandVolumeSizeExceedlimit$`, f.iCallControllerExpandVolumeSizeExceedLimit)
	s.Step(`^I call ExpandNFSVolumeSizeExceedlimit$`, f.iCallControllerExpandNFSVolumeSizeExceedLimit)
	s.Step(`^I call ExpandVolumeSizeShrink$`, f.iCallControllerExpandVolumeShrink)
	s.Step(`^I call ExpandNFSVolumeSizeShrink$`, f.iCallControllerExpandNFSVolumeShrink)
	s.Step(`^a valid ExpandVolumeResponse is returned$`, f.aValidExpandVolumeResponseIsReturned)
}
