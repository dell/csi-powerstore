/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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
package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	"github.com/dell/gopowerstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestVolumePublisher_Publish(t *testing.T) {
	t.Run("scsi publisher", func(t *testing.T) {
		sp := &SCSIPublisher{}
		getVolumeOK := func(clientMock *mocks.Client) {
			clientMock.On("GetVolume", mock.Anything, validBaseVolID).
				Return(gopowerstore.Volume{ID: validBaseVolID, Wwn: "naa.68ccf098003ceb5e4577a20be6d11bf9"}, nil)
		}

		getHostByNameOK := func(clientMock *mocks.Client) {
			clientMock.On("GetHostByName", mock.Anything, validNodeID).Return(gopowerstore.Host{ID: validHostID}, nil)
		}

		t.Run("getVolume failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{}, errors.New("error"))
			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure checking volume status for volume publishing")
		})

		t.Run("no volume found", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetVolume", context.Background(), validBaseVolID).
				Return(gopowerstore.Volume{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				})
			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("volume with ID '%s' not found", validBaseVolID))
		})

		t.Run("can't find ip in node id", func(t *testing.T) {
			nodeID := "some-random-text"
			clientMock := new(mocks.Client)

			getVolumeOK(clientMock)

			clientMock.On("GetHostByName", mock.Anything, nodeID).
				Return(gopowerstore.Host{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				}).Once()

			_, err := sp.Publish(context.Background(), nil, nil, clientMock, nodeID, validBaseVolID, true)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't find IP in node ID")
		})

		t.Run("host unknown api error", func(t *testing.T) {
			e := errors.New("random-api-error")

			clientMock := new(mocks.Client)

			getVolumeOK(clientMock)

			clientMock.On("GetHostByName", mock.Anything, validNodeID).
				Return(gopowerstore.Host{}, e).Once()

			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(),
				fmt.Sprintf("failure checking host '%s' status for volume publishing: %s", validNodeID, e.Error()))
		})

		t.Run("failed to get mapping", func(t *testing.T) {
			e := errors.New("random-api-error")

			clientMock := new(mocks.Client)

			getVolumeOK(clientMock)
			getHostByNameOK(clientMock)

			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{}, e).Once()

			_, err := sp.Publish(context.Background(), nil, nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(),
				fmt.Sprintf("failed to get mapping for volume with ID '%s': %s", validBaseVolID, e.Error()))
		})

		t.Run("failed to get iscsiTargets", func(t *testing.T) {
			e := errors.New("unable to get targets for any protocol")

			clientMock := new(mocks.Client)

			getVolumeOK(clientMock)
			getHostByNameOK(clientMock)

			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{}, nil).Once()
			clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
				Return([]gopowerstore.IPPoolAddress{}, e)
			clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
				Return([]gopowerstore.IPPoolAddress{}, e)
			clientMock.On("GetFCPorts", mock.Anything).
				Return([]gopowerstore.FcPort{}, nil)
			clientMock.On("GetCluster", mock.Anything).
				Return(gopowerstore.Cluster{Name: validClusterName, NVMeNQN: "nqn"}, nil)
			clientMock.On("AttachVolumeToHost", mock.Anything, validHostID, mock.Anything).
				Return(gopowerstore.EmptyResponse(""), nil)
			clientMock.On("GetHostVolumeMappingByVolumeID", mock.Anything, validBaseVolID).
				Return([]gopowerstore.HostVolumeMapping{{HostID: validHostID, LogicalUnitNumber: 1}}, nil).Once()

			_, err := sp.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), e.Error())
		})
	})

	t.Run("nfs publisher", func(t *testing.T) {
		np := &NfsPublisher{}

		getFSOK := func(clientMock *mocks.Client) {
			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)
		}

		getExportOK := func(clientMock *mocks.Client, times int) {
			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, validBaseVolID).
				Return(gopowerstore.NFSExport{ID: "some-export-id"}, nil).Times(times)
		}

		t.Run("getFS failure", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{}, errors.New("error"))
			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure checking volume status for volume publishing")
		})

		t.Run("no volume found", func(t *testing.T) {
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", context.Background(), validBaseVolID).
				Return(gopowerstore.FileSystem{}, gopowerstore.APIError{
					ErrorMsg: &api.ErrorMsg{
						StatusCode: http.StatusNotFound,
					},
				})
			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("volume with ID '%s' not found", validBaseVolID))
		})

		t.Run("can't find ip in node id", func(t *testing.T) {
			nodeID := "some-random-text"
			clientMock := new(mocks.Client)
			clientMock.On("GetFS", mock.Anything, validBaseVolID).
				Return(gopowerstore.FileSystem{ID: validBaseVolID}, nil)

			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, nodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "can't find IP in node ID")
		})

		t.Run("can't check nfs export status", func(t *testing.T) {
			e := errors.New("random-api-error")
			clientMock := new(mocks.Client)

			getFSOK(clientMock)

			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
				Return(gopowerstore.NFSExport{}, e).Once()

			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure checking nfs export status for volume publishing")
		})

		t.Run("failed to get existing nfs export", func(t *testing.T) {
			e := errors.New("random-api-error")
			clientMock := new(mocks.Client)

			getFSOK(clientMock)
			getExportOK(clientMock, 1)

			clientMock.On("GetNFSExportByFileSystemID", mock.Anything, mock.Anything).
				Return(gopowerstore.NFSExport{}, e).Once()

			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure getting nfs export")
		})

		t.Run("failed to add hosts", func(t *testing.T) {
			e := errors.New("random-api-error")
			clientMock := new(mocks.Client)

			getFSOK(clientMock)
			getExportOK(clientMock, 2)

			clientMock.On("ModifyNFSExport", mock.Anything, mock.Anything, mock.Anything).
				Return(gopowerstore.CreateResponse{}, e).Once()

			_, err := np.Publish(context.Background(), make(map[string]string), nil, clientMock, validNodeID, validBaseVolID, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failure when adding new host to nfs export")
		})
	})
}
