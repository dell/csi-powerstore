/*
 *
 * Copyright © 2022-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gopowerstore"
	"github.com/stretchr/testify/mock"
)

func TestApiRouter2(t *testing.T) {
	// server should not be up and running
	identifiers.APIPort = "abc"
	setVariables()

	// Since apiRouter blocks indefinitely, run it in a goroutine
	// and verify it fails to start due to invalid port
	go nodeSvc.apiRouter(context.Background())

	// Give it a moment to attempt to start and fail
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:8083/node-status")
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

	t.Run("PopulateTargetsInCache - nvmeTargets should be populated in multiple networks [NVMeTCP]", func(t *testing.T) {
		setVariables(withMockNumberOfNVMeTCPTargets(2))
		nodeSvc.useNVME[firstGlobalID] = true

		clientMock.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		clientMock.On("GetStorageNVMETCPTargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address:   "192.168.1.1",
					IPPort:    gopowerstore.IPPortInstance{TargetIqn: "nqn"},
					NetworkID: "NW1",
				},
				{
					Address:   "192.168.1.2",
					IPPort:    gopowerstore.IPPortInstance{TargetIqn: "nqn"},
					NetworkID: "NW1",
				},
				{
					Address:   "192.168.2.1",
					IPPort:    gopowerstore.IPPortInstance{TargetIqn: "nqn"},
					NetworkID: "NW2",
				},
				{
					Address:   "192.168.2.2",
					IPPort:    gopowerstore.IPPortInstance{TargetIqn: "nqn"},
					NetworkID: "NW2",
				},
			}, nil)

		nodeSvc.populateTargetsInCache(nodeSvc.Arrays()[firstValidIP])
		if len(nodeSvc.nvmeTargets[firstGlobalID]) != 4 {
			t.Errorf("Expected nvmeTargets to be populated")
		}
	})

	t.Run("PopulateTargetsInCache - iscsiTargets should be populated in multiple networks [iSCSI]", func(t *testing.T) {
		setVariables(withMockNumberOfISCSITargets(4))
		nodeSvc.useNVME[firstGlobalID] = false

		clientMock.On("GetCluster", mock.Anything).
			Return(gopowerstore.Cluster{Name: validClusterName}, nil)
		clientMock.On("GetStorageISCSITargetAddresses", mock.Anything).
			Return([]gopowerstore.IPPoolAddress{
				{
					Address:   "192.168.1.1",
					IPPort:    gopowerstore.IPPortInstance{TargetIqn: "nqn"},
					NetworkID: "NW1",
				},
				{
					Address:   "192.168.1.2",
					IPPort:    gopowerstore.IPPortInstance{TargetIqn: "nqn"},
					NetworkID: "NW1",
				},
				{
					Address:   "192.168.2.1",
					IPPort:    gopowerstore.IPPortInstance{TargetIqn: "nqn"},
					NetworkID: "NW2",
				},
				{
					Address:   "192.168.2.2",
					IPPort:    gopowerstore.IPPortInstance{TargetIqn: "nqn"},
					NetworkID: "NW2",
				},
			}, nil)

		nodeSvc.populateTargetsInCache(nodeSvc.Arrays()[firstValidIP])
		if len(nodeSvc.iscsiTargets[firstGlobalID]) != 4 {
			t.Errorf("Expected iscsiTargets to be populated")
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

func TestStartAPIService_PodmonDisabled(_ *testing.T) {
	setVariables()
	nodeSvc.isPodmonEnabled = false

	// Should return early without starting services
	nodeSvc.startAPIService(context.Background())
}

func TestStartAPIService_PodmonEnabled(_ *testing.T) {
	setVariables()
	nodeSvc.isPodmonEnabled = true

	// Set arrays to empty to prevent connectivity check goroutines
	originalArrays := nodeSvc.Arrays()
	defer func() {
		nodeSvc.SetArrays(originalArrays)
	}()
	nodeSvc.SetArrays(map[string]*array.PowerStoreArray{})

	// Run in goroutine with context to avoid blocking on apiRouter
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		nodeSvc.startAPIService(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Service completed
	case <-time.After(200 * time.Millisecond):
		// Service likely blocked on apiRouter, which is expected
	}
}

func TestStartNodeToArrayConnectivityCheck_AdditionalCoverage(_ *testing.T) {
	setVariables()

	// Test with empty arrays to improve coverage
	originalArrays := nodeSvc.Arrays()
	defer func() {
		nodeSvc.SetArrays(originalArrays)
	}()
	nodeSvc.SetArrays(map[string]*array.PowerStoreArray{})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Call startNodeToArrayConnectivityCheck directly to improve coverage
	nodeSvc.startNodeToArrayConnectivityCheck(ctx)
}

func TestGetNodeOptions_AdditionalCoverage(_ *testing.T) {
	// Test getNodeOptions to improve coverage
	// Call with various scenarios
	opts := getNodeOptions()
	_ = opts
}

// TestPodmonAuthMiddleware manipulates the package-level identifiers.PodmonAPIToken; it must not run in parallel.
func TestPodmonAuthMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		token      string
		authHeader string
		wantStatus int
	}{
		{"no token configured", "", "", http.StatusOK},
		{"valid bearer token", "test-token", "Bearer test-token", http.StatusOK},
		{"valid bearer token with extra whitespace", "test-token", "Bearer test-token   ", http.StatusOK},
		{"valid lowercase bearer token (RFC 6750)", "test-token", "bearer test-token", http.StatusOK},
		{"valid mixed case bearer token (RFC 6750)", "test-token", "BEARER test-token", http.StatusOK},
		{"missing authorization header", "test-token", "", http.StatusUnauthorized},
		{"invalid bearer token", "test-token", "Bearer wrong-token", http.StatusUnauthorized},
		{"malformed authorization header", "test-token", "test-token", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := identifiers.PodmonAPIToken
			identifiers.PodmonAPIToken = tt.token
			defer func() { identifiers.PodmonAPIToken = old }()

			req := httptest.NewRequest(http.MethodGet, "/array-status", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()

			podmonAuthMiddleware(next).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
