/*
 *
 * Copyright © 2022-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package node

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gopowerstore"
	"github.com/stretchr/testify/mock"
)

func TestApiRouter2(t *testing.T) {
	// server should not be up and running
	identifiers.APIPort = "abc"
	setVariables()
	nodeSvc.apiRouter(context.Background())

	resp, err := http.Get("http://localhost:8083/node-status")
	if err == nil || resp != nil {
		t.Errorf("Error while probing node status")
	}
}

func TestApiRouter(t *testing.T) {
	identifiers.SetAPIPort(context.Background())
	setVariables()
	go nodeSvc.apiRouter(context.Background())
	time.Sleep(2 * time.Second)

	resp4, err := http.Get("http://localhost:8083/array-status")
	if err != nil || resp4.StatusCode != 500 {
		t.Errorf("Error while probing array status %v", err)
	}
	// fill some invalid dummy data in the cache and try to fetch
	probeStatus = new(sync.Map)
	probeStatus.Store("GlobalID2", "status")

	resp5, err := http.Get("http://localhost:8083/array-status")
	if err != nil || resp5.StatusCode != 500 {
		t.Errorf("Error while probing array status %v, %d", err, resp5.StatusCode)
	}

	// fill some dummy data in the cache and try to fetch
	var status identifiers.ArrayConnectivityStatus
	status.LastSuccess = time.Now().Unix()
	status.LastAttempt = time.Now().Unix()
	probeStatus = new(sync.Map)
	probeStatus.Store("GlobalID", status)

	// array status
	resp2, err := http.Get("http://localhost:8083/array-status")
	if err != nil || resp2.StatusCode != 200 {
		t.Errorf("Error while probing array status %v", err)
	}

	resp3, err := http.Get("http://localhost:8083/array-status/GlobalIdNotPresent")
	if err != nil || resp3.StatusCode != 404 {
		t.Errorf("Error while probing array status %v", err)
	}
	value := make(chan int)
	probeStatus.Store("GlobalID3", value)
	resp9, err := http.Get("http://localhost:8083/array-status/GlobalID3")
	if err != nil || resp9.StatusCode != 500 {
		t.Errorf("Error while probing array status %v", err)
	}
	resp10, err := http.Get("http://localhost:8083/array-status/GlobalID")
	if err != nil || resp10.StatusCode != 200 {
		t.Errorf("Error while probing array status %v", err)
	}
}

func TestMarshalSyncMapToJSON(t *testing.T) {
	type args struct {
		m *sync.Map
	}
	sample := new(sync.Map)
	sample2 := new(sync.Map)
	var status identifiers.ArrayConnectivityStatus
	status.LastSuccess = time.Now().Unix()
	status.LastAttempt = time.Now().Unix()

	sample.Store("GlobalID", status)
	sample2.Store("key", "2.adasd")

	tests := []struct {
		name string
		args args
	}{
		{"storing valid value in map cache", args{m: sample}},
		{"storing valid value in map cache", args{m: sample2}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := MarshalSyncMapToJSON(tt.args.m)
			if len(data) == 0 && i == 0 {
				t.Errorf("MarshalSyncMapToJSON() expecting some data from cache in the response")
				return
			}
		})
	}
}

func TestPopulateTargetsInCache(t *testing.T) {
	t.Run("PopulateTargetsInCache - iscsiTargets should be populated [iSCSI]", func(t *testing.T) {
		setVariables()

		clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "192.168.1.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
				},
			}, nil)

		nodeSvc.populateTargetsInCache(nodeSvc.Arrays()[firstValidIP])

		if len(nodeSvc.iscsiTargets[firstGlobalID]) != 1 {
			t.Errorf("Expected iscsiTargets to be populated")
		}
	})

	t.Run("PopulateTargetsInCache - nvmeTargets should be populated [NVMeTCP]", func(t *testing.T) {
		setVariables()
		nodeSvc.useNVME[firstGlobalID] = true

		clientMock.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address: "192.168.1.1",
					IPPort:  gopowerstore.IPPortInstance{TargetIqn: "iqn"},
				},
			}, nil)

		nodeSvc.populateTargetsInCache(nodeSvc.Arrays()[firstValidIP])

		if len(nodeSvc.nvmeTargets[firstGlobalID]) != 1 {
			t.Errorf("Expected nvmeTargets to be populated")
		}
	})

	t.Run("PopulateTargetsInCache - nvmeTargets should be populated [NVMeFC]", func(t *testing.T) {
		setVariables()
		nodeSvc.useNVME[firstGlobalID] = true
		nodeSvc.useFC[firstGlobalID] = true

		clientMock.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		clientMock.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{
				{
					Wwn:      "58:cc:f0:93:48:a0:03:a3",
					IsLinkUp: true,
				},
			}, nil)

		nodeSvc.populateTargetsInCache(nodeSvc.Arrays()[firstValidIP])

		if len(nodeSvc.nvmeTargets[firstGlobalID]) != 1 {
			t.Errorf("Expected nvmeTargets to be populated")
		}
	})

	t.Run("PopulateTargetsInCache - iscsiTargets should not be populated [iSCSI]", func(t *testing.T) {
		setVariables()

		clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, errors.New("some error"))

		nodeSvc.populateTargetsInCache(nodeSvc.Arrays()[firstValidIP])

		if len(nodeSvc.iscsiTargets[firstGlobalID]) != 0 {
			t.Errorf("Expected iscsiTargets to be empty upon error")
		}
	})

	t.Run("PopulateTargetsInCache - nvmeTargets should not be populated [NVMeTCP]", func(t *testing.T) {
		setVariables()
		nodeSvc.useNVME[firstGlobalID] = true

		clientMock.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{}, errors.New("some error"))

		nodeSvc.populateTargetsInCache(nodeSvc.Arrays()[firstValidIP])

		if len(nodeSvc.nvmeTargets[firstGlobalID]) != 0 {
			t.Errorf("Expected nvmeTargets to be empty upon error")
		}
	})

	t.Run("PopulateTargetsInCache - nvmeTargets should not be populated [NVMeFC]", func(t *testing.T) {
		setVariables()
		nodeSvc.useNVME[firstGlobalID] = true
		nodeSvc.useFC[firstGlobalID] = true

		clientMock.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		clientMock.On("GetFCPorts", mock.Anything).
			Return([]gopowerstore.FcPort{}, errors.New("some error"))

		nodeSvc.populateTargetsInCache(nodeSvc.Arrays()[firstValidIP])

		if len(nodeSvc.nvmeTargets[firstGlobalID]) != 0 {
			t.Errorf("Expected nvmeTargets to be empty upon error")
		}
	})
}
