/*
 *
 * Copyright © 2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func Test_setAPIPort(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{"Fetching port number from Environment variable", args{ctx: context.TODO()}},
		{"Fetching & setting default port number", args{ctx: context.TODO()}},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if i == 0 {
				os.Setenv("X_CSI_PODMON_API_PORT", "8090")
				setAPIPort(tt.args.ctx)
				if apiPort != ":8090" {
					t.Errorf("setAPIPort() error, want 8090 port found %v", apiPort)
				}
				os.Unsetenv("X_CSI_PODMON_API_PORT")
			}
			setAPIPort(tt.args.ctx)
			if apiPort != ":8083" {
				t.Errorf("setAPIPort() error, want 8083 port found %v", apiPort)
			}
		})
	}
}
func TestApiRouter2(t *testing.T) {
	// server should not be up and running
	apiPort = "abc"
	setVariables()
	nodeSvc.apiRouter(context.Background())

	resp, err := http.Get("http://localhost:8083/node-status")
	if err == nil || resp != nil {
		t.Errorf("Error while probing node status")
	}
}
func TestApiRouter(t *testing.T) {
	setAPIPort(context.Background())
	setVariables()
	go nodeSvc.apiRouter(context.Background())
	time.Sleep(2 * time.Second)
	// node status
	resp, err := http.Get("http://localhost:8083/node-status")
	if err != nil || resp.StatusCode != 200 {
		t.Errorf("Error while probing node status %v", err)
	}
	resBody, err := ioutil.ReadAll(resp.Body)
	expectedResp := string(resBody)

	if err != nil || expectedResp != "node is up and running \n" {
		t.Errorf("Error while probing node status %v", err)
	}

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
	var status ArrayConnectivityStatus
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
}

func TestMarshalSyncMapToJSON(t *testing.T) {
	type args struct {
		m *sync.Map
	}
	sample := new(sync.Map)
	sample2 := new(sync.Map)
	var status ArrayConnectivityStatus
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
