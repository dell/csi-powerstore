/*
 *
 * Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package array

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	drv1 "github.com/dell/csm-dr/api/v1"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsMetroFractured(t *testing.T) {
	volumeHandle := VolumeHandle{
		LocalUUID: uuid.New().String(),
	}
	replicationSessionID := uuid.New().String()

	tests := []struct {
		name         string
		client       gopowerstore.Client
		before       func(*gopowerstoremock.Client)
		wantResponse *MetroFracturedResponse
		wantErr      error
	}{
		{
			name:   "IsMetroFractured - Not Replication Session ID",
			client: new(gopowerstoremock.Client),
			before: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, mock.Anything).Return(
					gopowerstore.Volume{
						ID:                        uuid.New().String(),
						Name:                      "myVolume",
						MetroReplicationSessionID: "",
					}, nil,
				)
			},
			wantResponse: &MetroFracturedResponse{IsFractured: false, VolumeName: "myVolume", State: ""},
			wantErr:      nil,
		},
		{
			name:   "IsMetroFractured - Replication Session is OK",
			client: new(gopowerstoremock.Client),
			before: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, mock.Anything).Return(
					gopowerstore.Volume{
						ID:                        uuid.New().String(),
						Name:                      "myVolume",
						MetroReplicationSessionID: replicationSessionID,
					}, nil,
				)

				client.On("GetReplicationSessionByID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{
						ID:    replicationSessionID,
						State: "OK",
					}, nil,
				)
			},
			wantResponse: &MetroFracturedResponse{IsFractured: false, VolumeName: "myVolume", State: ""},
			wantErr:      nil,
		},
		{
			name:   "IsMetroFractured - Replication Session is Fractured",
			client: new(gopowerstoremock.Client),
			before: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, mock.Anything).Return(
					gopowerstore.Volume{
						ID:                        uuid.New().String(),
						Name:                      "myVolume",
						MetroReplicationSessionID: replicationSessionID,
					}, nil,
				)

				client.On("GetReplicationSessionByID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{
						ID:                 replicationSessionID,
						State:              "Fractured",
						LocalResourceState: "Promoted",
					}, nil,
				)
			},
			wantResponse: &MetroFracturedResponse{IsFractured: true, VolumeName: "myVolume", State: "Promoted"},
			wantErr:      nil,
		},
		{
			name:   "IsMetroFractured - error: unable to get volume",
			client: new(gopowerstoremock.Client),
			before: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, mock.Anything).Return(
					gopowerstore.Volume{}, errors.New("unable to get volume"),
				)
			},
			wantResponse: nil,
			wantErr:      errors.New("unable to get volume"),
		},
		{
			name:   "IsMetroFractured - error: unable to get replication session by ID",
			client: new(gopowerstoremock.Client),
			before: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, mock.Anything).Return(
					gopowerstore.Volume{
						ID:                        uuid.New().String(),
						Name:                      "myVolume",
						MetroReplicationSessionID: replicationSessionID,
					}, nil,
				)

				client.On("GetReplicationSessionByID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, errors.New("unable to get replication session by ID"),
				)
			},
			wantResponse: nil,
			wantErr:      errors.New("unable to get replication session by ID"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.before != nil {
				tt.before(tt.client.(*gopowerstoremock.Client))
			}

			response, err := IsMetroFractured(t.Context(), tt.client, volumeHandle.LocalUUID)
			if err != nil {
				if errors.Is(err, tt.wantErr) {
					t.Errorf("IsMetroFractured() received unexpected error: got %v, want %v", err, tt.wantErr)
				}
			}

			if tt.wantResponse != nil {
				if tt.wantResponse.IsFractured != response.IsFractured || tt.wantResponse.VolumeName != response.VolumeName || tt.wantResponse.State != response.State {
					t.Errorf("IsMetroFractured() received unexpected response: got %v, want %v", response, tt.wantResponse)
				}
			}
		})
	}
}

func TestCheckMetroState(t *testing.T) {
	tests := []struct {
		name             string
		volumeHandle     VolumeHandle
		localClient      gopowerstore.Client
		remoteClient     gopowerstore.Client
		wantResponse     *MetroFracturedResponse
		wantLocalDemoted bool
		wantErr          error
		beforeLocal      func(*gopowerstoremock.Client)
		beforeRemote     func(*gopowerstoremock.Client)
	}{
		{
			name: "CheckMetroState - Local volume is demoted",
			volumeHandle: VolumeHandle{
				LocalUUID:  "local-uuid",
				RemoteUUID: "remote-uuid",
			},
			localClient:  new(gopowerstoremock.Client),
			remoteClient: new(gopowerstoremock.Client),
			wantResponse: &MetroFracturedResponse{
				IsFractured: true,
				VolumeName:  "volume-name",
				State:       "Demoted",
			},
			wantLocalDemoted: true,
			wantErr:          nil,
			beforeLocal: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "local-uuid").Return(gopowerstore.Volume{
					ID:                        "local-uuid",
					Name:                      "volume-name",
					MetroReplicationSessionID: "replication-session-id",
				}, nil)
				client.On("GetReplicationSessionByID", mock.Anything, "replication-session-id").Return(gopowerstore.ReplicationSession{
					ID:                 "replication-session-id",
					State:              "Fractured",
					LocalResourceState: "Demoted",
				}, nil)
			},
			beforeRemote: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "remote-uuid").Once().Return(gopowerstore.Volume{
					ID:                        "remote-uuid",
					Name:                      "volume-name",
					MetroReplicationSessionID: "remote-replication-session-id",
				}, nil).After(100 * time.Millisecond) // delay the response to simulate offline
				client.On("GetReplicationSessionByID", mock.Anything, "remote-replication-session-id").Maybe().Return(gopowerstore.ReplicationSession{
					ID:                 "remote-replication-session-id",
					State:              "Fractured",
					LocalResourceState: "Promoted",
				}, nil)
			},
		},
		{
			name: "CheckMetroState - Local volume is promoted",
			volumeHandle: VolumeHandle{
				LocalUUID:  "local-uuid",
				RemoteUUID: "remote-uuid",
			},
			localClient:  new(gopowerstoremock.Client),
			remoteClient: new(gopowerstoremock.Client),
			wantResponse: &MetroFracturedResponse{
				IsFractured: true,
				VolumeName:  "volume-name",
				State:       "Promoted",
			},
			wantLocalDemoted: false,
			wantErr:          nil,
			beforeLocal: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "local-uuid").Return(gopowerstore.Volume{
					ID:                        "local-uuid",
					Name:                      "volume-name",
					MetroReplicationSessionID: "replication-session-id",
				}, nil)
				client.On("GetReplicationSessionByID", mock.Anything, "replication-session-id").Return(gopowerstore.ReplicationSession{
					ID:                 "replication-session-id",
					State:              "Fractured",
					LocalResourceState: "Promoted",
				}, nil)
			},
			beforeRemote: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "remote-uuid").Once().Return(gopowerstore.Volume{
					ID:                        "remote-uuid",
					Name:                      "volume-name",
					MetroReplicationSessionID: "remote-replication-session-id",
				}, nil)
				client.On("GetReplicationSessionByID", mock.Anything, "remote-replication-session-id").Once().Return(gopowerstore.ReplicationSession{
					ID:                 "remote-replication-session-id",
					State:              "Fracture",
					LocalResourceState: "Demoted",
				}, nil)
			},
		},
		{
			name: "CheckMetroState - Error getting local volume, remote volume promoted",
			volumeHandle: VolumeHandle{
				LocalUUID:  "local-uuid",
				RemoteUUID: "remote-uuid",
			},
			localClient:  new(gopowerstoremock.Client),
			remoteClient: new(gopowerstoremock.Client),
			wantResponse: &MetroFracturedResponse{
				IsFractured: true,
				VolumeName:  "volume-name",
				State:       "Promoted",
			},
			wantLocalDemoted: true,
			wantErr:          nil,
			beforeLocal: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "local-uuid").Return(gopowerstore.Volume{}, fmt.Errorf("error getting local volume"))
			},
			beforeRemote: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "remote-uuid").Return(gopowerstore.Volume{
					ID:                        "remote-uuid",
					Name:                      "volume-name",
					MetroReplicationSessionID: "replication-session-id",
				}, nil)
				client.On("GetReplicationSessionByID", mock.Anything, "replication-session-id").Return(gopowerstore.ReplicationSession{
					ID:                 "replication-session-id",
					State:              "Fractured",
					LocalResourceState: "Promoted",
				}, nil)
			},
		},
		{
			name: "CheckMetroState - Error getting local volume, remote volume Demoted",
			volumeHandle: VolumeHandle{
				LocalUUID:  "local-uuid",
				RemoteUUID: "remote-uuid",
			},
			localClient:  new(gopowerstoremock.Client),
			remoteClient: new(gopowerstoremock.Client),
			wantResponse: &MetroFracturedResponse{
				IsFractured: true,
				VolumeName:  "volume-name",
				State:       "Demoted",
			},
			wantLocalDemoted: false,
			wantErr:          nil,
			beforeLocal: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "local-uuid").Return(gopowerstore.Volume{}, fmt.Errorf("error getting local volume"))
			},
			beforeRemote: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "remote-uuid").Return(gopowerstore.Volume{
					ID:                        "remote-uuid",
					Name:                      "volume-name",
					MetroReplicationSessionID: "replication-session-id",
				}, nil)
				client.On("GetReplicationSessionByID", mock.Anything, "replication-session-id").Return(gopowerstore.ReplicationSession{
					ID:                 "replication-session-id",
					State:              "Fractured",
					LocalResourceState: "Demoted",
				}, nil)
			},
		},
		{
			name: "CheckMetroState - Error getting local volume and remote volume",
			volumeHandle: VolumeHandle{
				LocalUUID:  "local-uuid",
				RemoteUUID: "remote-uuid",
			},
			localClient:      new(gopowerstoremock.Client),
			remoteClient:     new(gopowerstoremock.Client),
			wantResponse:     nil,
			wantLocalDemoted: false,
			wantErr:          fmt.Errorf("error getting remote volume"),
			beforeLocal: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "local-uuid").Return(gopowerstore.Volume{}, fmt.Errorf("error getting local volume"))
			},
			beforeRemote: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "remote-uuid").Return(gopowerstore.Volume{}, fmt.Errorf("error getting remote volume"))
			},
		},
		{
			name: "CheckMetroState - Local not found, remote different error",
			volumeHandle: VolumeHandle{
				LocalUUID:  "local-uuid",
				RemoteUUID: "remote-uuid",
			},
			localClient:      new(gopowerstoremock.Client),
			remoteClient:     new(gopowerstoremock.Client),
			wantResponse:     nil,
			wantLocalDemoted: false,
			wantErr:          fmt.Errorf("metro session not found on local array, error checking remote array: error getting remote volume"),
			beforeLocal: func(client *gopowerstoremock.Client) {
				// Simulate a not found error from local array
				client.On("GetVolume", mock.Anything, "local-uuid").Return(gopowerstore.Volume{}, gopowerstore.NewNotFoundError())
			},
			beforeRemote: func(client *gopowerstoremock.Client) {
				// Simulate a different error from remote array
				client.On("GetVolume", mock.Anything, "remote-uuid").Return(gopowerstore.Volume{}, fmt.Errorf("error getting remote volume"))
			},
		},
		{
			name: "CheckMetroState - Local volume not fractured, remote error",
			volumeHandle: VolumeHandle{
				LocalUUID:  "local-uuid",
				RemoteUUID: "remote-uuid",
			},
			localClient:  new(gopowerstoremock.Client),
			remoteClient: new(gopowerstoremock.Client),
			wantResponse: &MetroFracturedResponse{
				IsFractured: false,
				VolumeName:  "volume-name",
				State:       "",
			},
			wantLocalDemoted: false,
			wantErr:          nil,
			beforeLocal: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "local-uuid").Return(gopowerstore.Volume{
					ID:                        "local-uuid",
					Name:                      "volume-name",
					MetroReplicationSessionID: "replication-session-id",
				}, nil)
				client.On("GetReplicationSessionByID", mock.Anything, "replication-session-id").Return(gopowerstore.ReplicationSession{
					ID:                 "replication-session-id",
					State:              "OK",
					LocalResourceState: "",
				}, nil)
			},
			beforeRemote: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "remote-uuid").Return(gopowerstore.Volume{}, fmt.Errorf("error getting remote volume"))
			},
		},
		{
			name: "CheckMetroState - Remote volume not fractured, local error",
			volumeHandle: VolumeHandle{
				LocalUUID:  "local-uuid",
				RemoteUUID: "remote-uuid",
			},
			localClient:  new(gopowerstoremock.Client),
			remoteClient: new(gopowerstoremock.Client),
			wantResponse: &MetroFracturedResponse{
				IsFractured: false,
				VolumeName:  "volume-name",
				State:       "",
			},
			wantLocalDemoted: false,
			wantErr:          nil,
			beforeLocal: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "local-uuid").Return(gopowerstore.Volume{}, fmt.Errorf("error getting local volume"))
			},
			beforeRemote: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, "remote-uuid").Return(gopowerstore.Volume{
					ID:                        "remote-uuid",
					Name:                      "volume-name",
					MetroReplicationSessionID: "replication-session-id",
				}, nil)
				client.On("GetReplicationSessionByID", mock.Anything, "replication-session-id").Return(gopowerstore.ReplicationSession{
					ID:                 "replication-session-id",
					State:              "OK",
					LocalResourceState: "",
				}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.beforeLocal(tt.localClient.(*gopowerstoremock.Client))
			tt.beforeRemote(tt.remoteClient.(*gopowerstoremock.Client))

			response, localDemoted, err := CheckMetroState(context.Background(), tt.volumeHandle, tt.localClient, tt.remoteClient)

			if tt.wantResponse != nil {
				if tt.wantResponse.IsFractured != response.IsFractured || tt.wantResponse.VolumeName != response.VolumeName || tt.wantResponse.State != response.State {
					t.Errorf("CheckMetroState() response = %v, want %v", response, tt.wantResponse)
				}
			}

			if localDemoted != tt.wantLocalDemoted {
				t.Errorf("CheckMetroState() localDemoted = %v, want %v", localDemoted, tt.wantLocalDemoted)
			}

			if (tt.wantErr != nil && err == nil) || (tt.wantErr == nil && err != nil) {
				t.Errorf("CheckMetroState() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatchSessionForClone(t *testing.T) {
	tests := []struct {
		name        string
		session     gopowerstore.ReplicationSession
		asPreferred bool
		want        bool
	}{
		{
			name: "Preferred with Active_Active DataTransferState - online",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				DataTransferState:  gopowerstore.RSDataTransferStateActiveActive,
				LocalResourceState: "",
			},
			asPreferred: true,
			want:        true,
		},
		{
			name: "Non-Preferred with Active_Active DataTransferState - online",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Non_Preferred",
				DataTransferState:  gopowerstore.RSDataTransferStateActiveActive,
				LocalResourceState: "",
			},
			asPreferred: false,
			want:        true,
		},
		{
			name: "Preferred Promoted - online",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				DataTransferState:  "", // Empty DataTransferState, should rely on LocalResourceState
				LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
			},
			asPreferred: true,
			want:        true,
		},
		{
			name: "Non-Preferred Promoted - online",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Non_Preferred",
				DataTransferState:  "", // Empty DataTransferState, should rely on LocalResourceState
				LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
			},
			asPreferred: false,
			want:        true,
		},
		{
			name: "Preferred System_Promoted - online",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				DataTransferState:  "", // Empty DataTransferState, should rely on LocalResourceState
				LocalResourceState: string(gopowerstore.ReplicationResourceStateSystemPromoted),
			},
			asPreferred: true,
			want:        true,
		},
		{
			name: "Non-Preferred System_Promoted - online",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Non_Preferred",
				DataTransferState:  "", // Empty DataTransferState, should rely on LocalResourceState
				LocalResourceState: string(gopowerstore.ReplicationResourceStateSystemPromoted),
			},
			asPreferred: false,
			want:        true,
		},
		{
			name: "Preferred Demoted - offline",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				DataTransferState:  "", // Empty DataTransferState, should rely on LocalResourceState
				LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
			},
			asPreferred: true,
			want:        false,
		},
		{
			name: "Non-Preferred Demoted - offline",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Non_Preferred",
				DataTransferState:  "", // Empty DataTransferState, should rely on LocalResourceState
				LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
			},
			asPreferred: false,
			want:        false,
		},
		{
			name: "Preferred with Active_Active DataTransferState but wrong role - offline",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Non_Preferred",
				DataTransferState:  gopowerstore.RSDataTransferStateActiveActive,
				LocalResourceState: "",
			},
			asPreferred: true,
			want:        false,
		},
		{
			name: "Non-Preferred with Active_Active DataTransferState but wrong role - offline",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				DataTransferState:  gopowerstore.RSDataTransferStateActiveActive,
				LocalResourceState: "",
			},
			asPreferred: false,
			want:        false,
		},
		{
			name: "Preferred with different DataTransferState - offline",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				DataTransferState:  gopowerstore.RSDataTransferStateSynchronous,
				LocalResourceState: "",
			},
			asPreferred: true,
			want:        false,
		},
		{
			name: "Error state - offline",
			session: gopowerstore.ReplicationSession{
				DataTransferState:  "", // Empty DataTransferState
				LocalResourceState: "",
			},
			asPreferred: true,
			want:        false,
		},
	}

	// nil session must always return false
	tests = append(tests, struct {
		name        string
		session     gopowerstore.ReplicationSession
		asPreferred bool
		want        bool
	}{name: "nil session - offline", asPreferred: true, want: false})

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sp *gopowerstore.ReplicationSession
			if i < len(tests)-1 { // all except the nil case
				sp = &tt.session
			}
			got := matchSessionForClone(sp, tt.asPreferred)
			if got != tt.want {
				t.Errorf("matchSessionForClone() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSelectMetroArrayForClone(t *testing.T) {
	metroSessionID := "metro-session-123"

	tests := []struct {
		name           string
		beforeLocal    func(*gopowerstoremock.Client)
		beforeRemote   func(*gopowerstoremock.Client)
		wantVolID      string
		wantErr        bool
		wantErrContain string
	}{
		{
			name: "Preferred array online (local=preferred) - selects preferred",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "local-vol-id",
						RemoteResourceID:   "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "remote-vol-id",
						RemoteResourceID:   "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantVolID: "local-vol-id",
			wantErr:   false,
		},
		{
			name: "Preferred array online (local=non-preferred) - selects remote as preferred",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantVolID: "remote-vol-id",
			wantErr:   false,
		},
		{
			name: "Preferred fractured/demoted, non-preferred promoted - selects non-preferred",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantVolID: "remote-vol-id",
			wantErr:   false,
		},
		{
			name: "Both arrays demoted - returns error",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
					}, nil,
				)
			},
			wantErr:        true,
			wantErrContain: "neither local nor remote array has a healthy Metro session",
		},
		{
			name: "Both API calls fail - returns error",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{}, errors.New("local API error"),
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{}, errors.New("remote API error"),
				)
			},
			wantErr:        true,
			wantErrContain: "unable to get replication session from either local or remote array",
		},
		{
			name:        "localArray nil (local unreachable), remote preferred online - selects remote",
			beforeLocal: func(_ *gopowerstoremock.Client) {},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantVolID: "remote-vol-id",
			wantErr:   false,
		},
		{
			name: "Local API fails, remote preferred online - selects remote",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{}, errors.New("local API error"),
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantVolID: "remote-vol-id",
			wantErr:   false,
		},
		{
			name: "Preferred arrays unavailable, local non-preferred available - selects local as non-preferred",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
					}, nil,
				)
			},
			wantVolID: "local-vol-id",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localMock := new(gopowerstoremock.Client)
			remoteMock := new(gopowerstoremock.Client)
			tt.beforeLocal(localMock)
			tt.beforeRemote(remoteMock)

			localArray := &PowerStoreArray{
				GlobalID: "PS-local",
				Client:   localMock,
			}

			remoteArray := &PowerStoreArray{
				GlobalID: "PS-remote",
				Client:   remoteMock,
			}

			localArr := localArray
			if tt.name == "localArray nil (local unreachable), remote preferred online - selects remote" {
				localArr = nil
			}
			selectedArr, selectedSession, err := SelectMetroArrayForClone(t.Context(), metroSessionID, localArr, remoteArray)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("SelectMetroArrayForClone() expected error, got nil")
				}
				if tt.wantErrContain != "" {
					if !contains(err.Error(), tt.wantErrContain) {
						t.Errorf("SelectMetroArrayForClone() error = %v, want containing %q", err, tt.wantErrContain)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("SelectMetroArrayForClone() unexpected error: %v", err)
			}
			if selectedArr == nil {
				t.Fatal("SelectMetroArrayForClone() returned nil array")
			}
			if selectedSession.LocalResourceID != tt.wantVolID {
				t.Errorf("SelectMetroArrayForClone() selectedSession.LocalResourceID = %q, want %q", selectedSession.LocalResourceID, tt.wantVolID)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDetermineIfArrayCanClone(t *testing.T) {
	metroSessionID := "metro-session-456"

	tests := []struct {
		name           string
		before         func(*gopowerstoremock.Client)
		wantErr        bool
		wantErrContain string
		wantVolID      string
	}{
		{
			name: "session Promoted - array can clone",
			before: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantErr:   false,
			wantVolID: "local-vol-id",
		},
		{
			name: "session SystemPromoted - array can clone",
			before: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateSystemPromoted),
					}, nil,
				)
			},
			wantErr:   false,
			wantVolID: "local-vol-id",
		},
		{
			name: "session DataTransferState Active_Active - array can clone",
			before: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                metroSessionID,
						LocalResourceID:   "local-vol-id",
						DataTransferState: gopowerstore.RSDataTransferStateActiveActive,
					}, nil,
				)
			},
			wantErr:   false,
			wantVolID: "local-vol-id",
		},
		{
			name: "session Demoted - array cannot clone",
			before: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
					}, nil,
				)
			},
			wantErr:        true,
			wantErrContain: "array selected for cloning is not in correct state",
		},
		{
			name: "GetReplicationSessionByID fails - session nil - cannot clone",
			before: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{}, errors.New("API error"),
				)
			},
			wantErr:        true,
			wantErrContain: "unable to get replication session from array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(gopowerstoremock.Client)
			tt.before(mockClient)

			arr := &PowerStoreArray{
				GlobalID: "PS-test",
				Client:   mockClient,
			}

			session, err := DetermineIfArrayCanClone(t.Context(), metroSessionID, arr)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("DetermineIfArrayCanClone() expected error, got nil")
				}
				if tt.wantErrContain != "" && !containsSubstring(err.Error(), tt.wantErrContain) {
					t.Errorf("DetermineIfArrayCanClone() error = %v, want containing %q", err, tt.wantErrContain)
				}
				return
			}

			if err != nil {
				t.Fatalf("DetermineIfArrayCanClone() unexpected error: %v", err)
			}
			if session == nil {
				t.Fatal("DetermineIfArrayCanClone() returned nil session")
			}
			if session.LocalResourceID != tt.wantVolID {
				t.Errorf("DetermineIfArrayCanClone() session.LocalResourceID = %q, want %q", session.LocalResourceID, tt.wantVolID)
			}
		})
	}
}

func TestMatchSessionForExpansion(t *testing.T) {
	tests := []struct {
		name    string
		session gopowerstore.ReplicationSession
		want    bool
	}{
		{
			name: "Preferred + Active_Active - eligible",
			session: gopowerstore.ReplicationSession{
				Role:              "Metro_Preferred",
				DataTransferState: gopowerstore.RSDataTransferStateActiveActive,
			},
			want: true,
		},
		{
			name: "Preferred + Promoted - eligible",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
			},
			want: true,
		},
		{
			name: "Preferred + System_Promoted - eligible",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				LocalResourceState: string(gopowerstore.ReplicationResourceStateSystemPromoted),
			},
			want: true,
		},
		{
			name: "Preferred + Demoted - not eligible",
			session: gopowerstore.ReplicationSession{
				Role:               "Metro_Preferred",
				LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
			},
			want: false,
		},
		{
			name: "Non-Preferred + Active_Active - not eligible for expansion",
			session: gopowerstore.ReplicationSession{
				Role:              "Metro_Non_Preferred",
				DataTransferState: gopowerstore.RSDataTransferStateActiveActive,
			},
			want: false,
		},
		{
			name: "Preferred + Synchronous DataTransferState - not eligible",
			session: gopowerstore.ReplicationSession{
				Role:              "Metro_Preferred",
				DataTransferState: gopowerstore.RSDataTransferStateSynchronous,
			},
			want: false,
		},
		{
			name: "Empty role - not eligible",
			session: gopowerstore.ReplicationSession{
				DataTransferState: gopowerstore.RSDataTransferStateActiveActive,
			},
			want: false,
		},
	}

	// nil session must always return false
	tests = append(tests, struct {
		name    string
		session gopowerstore.ReplicationSession
		want    bool
	}{name: "nil session - not eligible", want: false})

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sp *gopowerstore.ReplicationSession
			if i < len(tests)-1 { // all except the nil case
				sp = &tt.session
			}
			got := matchSessionForExpansion(sp)
			if got != tt.want {
				t.Errorf("matchSessionForExpansion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSelectMetroArrayForExpansion(t *testing.T) {
	metroSessionID := "metro-session-expand-123"

	tests := []struct {
		name           string
		localArrayNil  bool
		remoteArrayNil bool
		beforeLocal    func(*gopowerstoremock.Client)
		beforeRemote   func(*gopowerstoremock.Client)
		wantArrayID    string
		wantErr        bool
		wantErrContain string
	}{
		{
			name: "Local is preferred + online - selects local",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                metroSessionID,
						Role:              "Metro_Preferred",
						State:             gopowerstore.RsStateOk,
						LocalResourceID:   "local-vol-id",
						DataTransferState: gopowerstore.RSDataTransferStateActiveActive,
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:              metroSessionID,
						Role:            "Metro_Non_Preferred",
						State:           gopowerstore.RsStateOk,
						LocalResourceID: "remote-vol-id",
					}, nil,
				)
			},
			wantArrayID: "PS-local",
			wantErr:     false,
		},
		{
			name: "Remote is preferred + online - selects remote",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:              metroSessionID,
						Role:            "Metro_Non_Preferred",
						State:           gopowerstore.RsStateOk,
						LocalResourceID: "local-vol-id",
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantArrayID: "PS-remote",
			wantErr:     false,
		},
		{
			name: "Local preferred + Promoted - selects local",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:              metroSessionID,
						Role:            "Metro_Non_Preferred",
						LocalResourceID: "remote-vol-id",
					}, nil,
				)
			},
			wantArrayID: "PS-local",
			wantErr:     false,
		},
		{
			name: "Remote preferred + System_Promoted - selects remote",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:              metroSessionID,
						Role:            "Metro_Non_Preferred",
						LocalResourceID: "local-vol-id",
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateSystemPromoted),
					}, nil,
				)
			},
			wantArrayID: "PS-remote",
			wantErr:     false,
		},
		{
			name: "Local API fails, remote preferred online - selects remote",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{}, errors.New("local API error"),
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                metroSessionID,
						Role:              "Metro_Preferred",
						State:             gopowerstore.RsStateOk,
						LocalResourceID:   "remote-vol-id",
						DataTransferState: gopowerstore.RSDataTransferStateActiveActive,
					}, nil,
				)
			},
			wantArrayID: "PS-remote",
			wantErr:     false,
		},
		{
			name: "Remote API fails, local preferred online - selects local",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                metroSessionID,
						Role:              "Metro_Preferred",
						State:             gopowerstore.RsStateOk,
						LocalResourceID:   "local-vol-id",
						DataTransferState: gopowerstore.RSDataTransferStateActiveActive,
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{}, errors.New("remote API error"),
				)
			},
			wantArrayID: "PS-local",
			wantErr:     false,
		},
		{
			name: "Both API calls fail - error both unavailable",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{}, errors.New("local API error"),
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{}, errors.New("remote API error"),
				)
			},
			wantErr:        true,
			wantErrContain: "PS-local and PS-remote are unavailable",
		},
		{
			name: "Both reachable but preferred is demoted on both - error",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
					}, nil,
				)
			},
			wantErr:        true,
			wantErrContain: "unable to find Metro_Preferred site online for volume expansion",
		},
		{
			name: "Non-preferred is online but preferred is not - error (expansion only uses preferred)",
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "local-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStateDemoted),
					}, nil,
				)
			},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateFractured,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantErr:        true,
			wantErrContain: "unable to find Metro_Preferred site online for volume expansion",
		},
		{
			name:          "Local array nil (unreachable), remote preferred online - selects remote",
			localArrayNil: true,
			beforeLocal:   func(_ *gopowerstoremock.Client) {},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantArrayID: "PS-remote",
			wantErr:     false,
		},
		{
			name:           "Remote array nil (unreachable), local preferred online - selects local",
			remoteArrayNil: true,
			beforeLocal: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                metroSessionID,
						Role:              "Metro_Preferred",
						State:             gopowerstore.RsStateOk,
						LocalResourceID:   "local-vol-id",
						DataTransferState: gopowerstore.RSDataTransferStateActiveActive,
					}, nil,
				)
			},
			beforeRemote: func(_ *gopowerstoremock.Client) {},
			wantArrayID:  "PS-local",
			wantErr:      false,
		},
		{
			name:          "Local nil, remote non-preferred online - error (only preferred eligible)",
			localArrayNil: true,
			beforeLocal:   func(_ *gopowerstoremock.Client) {},
			beforeRemote: func(c *gopowerstoremock.Client) {
				c.On("GetReplicationSessionByID", mock.Anything, metroSessionID).Return(
					gopowerstore.ReplicationSession{
						ID:                 metroSessionID,
						Role:               "Metro_Non_Preferred",
						State:              gopowerstore.RsStateOk,
						LocalResourceID:    "remote-vol-id",
						LocalResourceState: string(gopowerstore.ReplicationResourceStatePromoted),
					}, nil,
				)
			},
			wantErr:        true,
			wantErrContain: "unable to verify Preferred site for volume expansion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localMock := new(gopowerstoremock.Client)
			remoteMock := new(gopowerstoremock.Client)
			tt.beforeLocal(localMock)
			tt.beforeRemote(remoteMock)

			localArray := &PowerStoreArray{
				GlobalID: "PS-local",
				Client:   localMock,
			}
			remoteArray := &PowerStoreArray{
				GlobalID: "PS-remote",
				Client:   remoteMock,
			}

			var localArr, remoteArr *PowerStoreArray
			if !tt.localArrayNil {
				localArr = localArray
			}
			if !tt.remoteArrayNil {
				remoteArr = remoteArray
			}

			selectedArr, _, err := SelectMetroArrayForExpansion(t.Context(), metroSessionID, localArr, remoteArr)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("SelectMetroArrayForExpansion() expected error, got nil")
				}
				if tt.wantErrContain != "" {
					if !contains(err.Error(), tt.wantErrContain) {
						t.Errorf("SelectMetroArrayForExpansion() error = %v, want containing %q", err, tt.wantErrContain)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("SelectMetroArrayForExpansion() unexpected error: %v", err)
			}
			if selectedArr == nil {
				t.Fatal("SelectMetroArrayForExpansion() returned nil array")
			}
			if selectedArr.GetGlobalID() != tt.wantArrayID {
				t.Errorf("SelectMetroArrayForExpansion() selected array = %q, want %q", selectedArr.GetGlobalID(), tt.wantArrayID)
			}
		})
	}
}

func TestCreateOrUpdateJournalEntry(t *testing.T) {
	defaultGetClientFunc := GetDRClientFunc

	volumeName := "my-volume"
	volumeHandle := VolumeHandle{
		LocalUUID: uuid.New().String(),
	}
	nodeName := "myNode"
	tests := []struct {
		name      string
		operation string
		wantErr   error
		init      func(myClient client.Client)
		before    func(operation string) ([]byte, client.Client)
	}{
		{
			name:      "CreateOrUpdateJournalEntry - Success: Creation of Journal",
			operation: "NodeStageVolume",
			init: func(myClient client.Client) {
				GetDRClientFunc = func(_ context.Context) (client.Client, error) {
					return myClient, nil
				}
			},
			before: func(_ string) ([]byte, client.Client) {
				req := &csi.NodeStageVolumeRequest{
					VolumeId: uuid.NewString(),
				}

				deferredRequest, err := proto.Marshal(req)
				if err != nil {
					return nil, nil
				}

				volumeJournal := drv1.VolumeJournal{}
				scheme := setupDrScheme()
				client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&volumeJournal).Build()

				return deferredRequest, client
			},
			wantErr: nil,
		},
		{
			name:      "CreateOrUpdateJournalEntry - Success: Update of Journal (found)",
			operation: "NodeStageVolume",
			init: func(myClient client.Client) {
				GetDRClientFunc = func(_ context.Context) (client.Client, error) {
					return myClient, nil
				}
			},
			before: func(operation string) ([]byte, client.Client) {
				req := &csi.NodeStageVolumeRequest{
					VolumeId: uuid.NewString(),
				}

				deferredRequest, err := proto.Marshal(req)
				if err != nil {
					return nil, nil
				}

				volumeJournal := drv1.VolumeJournal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "journal-" + volumeName,
					},
					Spec: drv1.VolumeJournalSpec{
						JournalEntries: []drv1.JournalEntry{
							{
								Operation: operation,
								Status:    "pending-reconciliation",
								Host:      nodeName,
							},
						},
					},
				}
				scheme := setupDrScheme()
				client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&volumeJournal).Build()

				return deferredRequest, client
			},
			wantErr: nil,
		},
		{
			name:      "CreateOrUpdateJournalEntry - Success: Update of Journal (not found)",
			operation: "NodeStageVolume",
			init: func(myClient client.Client) {
				GetDRClientFunc = func(_ context.Context) (client.Client, error) {
					return myClient, nil
				}
			},
			before: func(_ string) ([]byte, client.Client) {
				req := &csi.NodeStageVolumeRequest{
					VolumeId: uuid.NewString(),
				}

				deferredRequest, err := proto.Marshal(req)
				if err != nil {
					return nil, nil
				}

				volumeJournal := drv1.VolumeJournal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "journal-" + volumeName,
					},
					Spec: drv1.VolumeJournalSpec{
						JournalEntries: []drv1.JournalEntry{
							{
								Operation: "ControllerPublishVolume",
								Status:    "pending-reconciliation",
							},
						},
					},
				}
				scheme := setupDrScheme()
				client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&volumeJournal).Build()

				return deferredRequest, client
			},
			wantErr: nil,
		},
		{
			name:      "CreateOrUpdateJournalEntry - Error: Unable to get client",
			operation: "NodeStageVolume",
			init: func(_ client.Client) {
				GetDRClientFunc = func(_ context.Context) (client.Client, error) {
					return nil, errors.New("unable to get dr client")
				}
			},
			before: func(_ string) ([]byte, client.Client) {
				volumeJournal := drv1.VolumeJournal{}
				scheme := setupDrScheme()
				client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&volumeJournal).Build()

				return nil, client
			},
			wantErr: errors.New("unable to get dr client"),
		},
		{
			name:      "CreateOrUpdateJournalEntry - Error: CSMDR not registered",
			operation: "NodeStageVolume",
			init: func(myClient client.Client) {
				GetDRClientFunc = func(_ context.Context) (client.Client, error) {
					return myClient, nil
				}
			},
			before: func(_ string) ([]byte, client.Client) {
				client := fake.NewClientBuilder().Build()

				return nil, client
			},
			wantErr: errors.New("not registered"),
		},
		{
			name:      "CreateOrUpdateJournalEntry - Error: Creation of Journal",
			operation: "NodeStageVolume",
			init: func(myClient client.Client) {
				GetDRClientFunc = func(_ context.Context) (client.Client, error) {
					return myClient, nil
				}
			},
			before: func(_ string) ([]byte, client.Client) {
				req := &csi.NodeStageVolumeRequest{
					VolumeId: uuid.NewString(),
				}

				deferredRequest, err := proto.Marshal(req)
				if err != nil {
					return nil, nil
				}

				volumeJournal := drv1.VolumeJournal{}
				scheme := setupDrScheme()
				client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&volumeJournal).Build()

				testClient := &failingClient{Client: client, failOperator: map[string]bool{"create": true}}

				return deferredRequest, testClient
			},
		},
		{
			name:      "CreateOrUpdateJournalEntry - Error: Update of Journal",
			operation: "NodeStageVolume",
			init: func(myClient client.Client) {
				GetDRClientFunc = func(_ context.Context) (client.Client, error) {
					return myClient, nil
				}
			},
			before: func(operation string) ([]byte, client.Client) {
				req := &csi.NodeStageVolumeRequest{
					VolumeId: uuid.NewString(),
				}

				deferredRequest, err := proto.Marshal(req)
				if err != nil {
					return nil, nil
				}

				volumeJournal := drv1.VolumeJournal{
					ObjectMeta: metav1.ObjectMeta{
						Name: "journal-" + volumeName,
					},
					Spec: drv1.VolumeJournalSpec{
						JournalEntries: []drv1.JournalEntry{
							{
								Operation: operation,
								Status:    "pending-reconciliation",
							},
						},
					},
				}
				scheme := setupDrScheme()
				client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&volumeJournal).Build()

				testClient := &failingClient{Client: client, failOperator: map[string]bool{"update": true}}

				return deferredRequest, testClient
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, client := tt.before(tt.operation)
			t.Cleanup(func() {
				GetDRClientFunc = defaultGetClientFunc
			})

			tt.init(client)

			err := CreateOrUpdateJournalEntry(t.Context(), volumeName, volumeHandle, volumeHandle.LocalArrayGlobalID, nodeName, tt.operation, request)
			if err != nil {
				if errors.Is(err, tt.wantErr) {
					t.Errorf("IsMetroFractured() received unexpected error: got %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

func setupDrScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = drv1.AddToScheme(scheme)
	return scheme
}

// failingClient is a client that fails on create and update
type failingClient struct {
	client.Client
	failOperator map[string]bool
}

func (f *failingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if !f.failOperator["create"] {
		return f.Client.Create(ctx, obj, opts...)
	}

	return fmt.Errorf("simulated create failure")
}

func (f *failingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if !f.failOperator["update"] {
		return f.Client.Update(ctx, obj, opts...)
	}

	return fmt.Errorf("simulated create failure")
}
