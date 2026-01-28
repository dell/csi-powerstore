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

	drv1 "github.com/dell/csm-dr/api/v1"
	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
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
					}, nil)
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
					}, nil)

				client.On("GetReplicationSessionByID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{
						ID:    replicationSessionID,
						State: "OK",
					}, nil)
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
					}, nil)

				client.On("GetReplicationSessionByID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{
						ID:                 replicationSessionID,
						State:              "Fractured",
						LocalResourceState: "Promoted",
					}, nil)
			},
			wantResponse: &MetroFracturedResponse{IsFractured: true, VolumeName: "myVolume", State: "Promoted"},
			wantErr:      nil,
		},
		{
			name:   "IsMetroFractured - error: unable to get volume",
			client: new(gopowerstoremock.Client),
			before: func(client *gopowerstoremock.Client) {
				client.On("GetVolume", mock.Anything, mock.Anything).Return(
					gopowerstore.Volume{}, errors.New("unable to get volume"))
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
					}, nil)

				client.On("GetReplicationSessionByID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, errors.New("unable to get replication session by ID"))
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
			beforeRemote: func(_ *gopowerstoremock.Client) {
				// Not expected to be called
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
			beforeRemote: func(_ *gopowerstoremock.Client) {
				// Not expected to be called
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
