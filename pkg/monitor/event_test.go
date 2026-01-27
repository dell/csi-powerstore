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

package monitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	"github.com/dell/gopowerstore/mocks"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
)

const (
	testVolName             string = "csi-test-vol"
	testVolGroupName        string = "test-vol-group"
	testNamespace           string = "test"
	testMessageWarning      string = "this is a test of the emergency alert system"
	testMessageNormal       string = "everything is normal"
	eventMessageTypeWarning string = "Warning"
	eventMessageTypeNormal  string = "Normal"
	alertSeverityInfo       string = "Info"
	alertSeverityMinor      string = "Minor"
	alertSeverityMajor      string = "Major"
	alertSeverityCritical   string = "Critical"
)

var (
	testTime time.Time = time.Now()

	testVolumeEventOldest *corev1.Event = &corev1.Event{
		TypeMeta: v1.TypeMeta{
			Kind: "PersistentVolume",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      "event1",
			Namespace: testNamespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Name:      testVolName,
			Namespace: testNamespace,
		},
		Type: corev1.EventTypeWarning,
		LastTimestamp: v1.Time{
			Time: testTime.Add(-3 * time.Minute),
		},
		Message: testMessageWarning,
	}
	testVolumeEventLatest *corev1.Event = &corev1.Event{
		TypeMeta: v1.TypeMeta{
			Kind: "PersistentVolume",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      "event3",
			Namespace: testNamespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Name:      testVolName,
			Namespace: testNamespace,
		},
		Type: corev1.EventTypeWarning,
		LastTimestamp: v1.Time{
			Time: testTime.Add(-1 * time.Minute),
		},
		Message: testMessageWarning,
	}
	testVolumeEventMiddle *corev1.Event = &corev1.Event{
		TypeMeta: v1.TypeMeta{
			Kind: "PersistentVolume",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      "event2",
			Namespace: testNamespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Name:      testVolName,
			Namespace: testNamespace,
		},
		Type: corev1.EventTypeWarning,
		LastTimestamp: v1.Time{
			Time: testTime.Add(-2 * time.Minute),
		},
		Message: testMessageWarning,
	}
	testVolumeEventNormal *corev1.Event = &corev1.Event{
		TypeMeta: v1.TypeMeta{
			Kind: "PersistentVolume",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      "event2",
			Namespace: testNamespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Name:      testVolName,
			Namespace: testNamespace,
		},
		Type: corev1.EventTypeNormal,
		LastTimestamp: v1.Time{
			Time: testTime.Add(-2 * time.Minute),
		},
		Message: testMessageNormal,
	}

	testVolume *corev1.PersistentVolume = &corev1.PersistentVolume{
		ObjectMeta: v1.ObjectMeta{
			Name:      testVolName,
			Namespace: testNamespace,
		},
		TypeMeta: v1.TypeMeta{
			Kind: "PersistentVolume",
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeBound,
		},
	}

	testEvents []runtime.Object = []runtime.Object{testVolumeEventMiddle, testVolumeEventOldest, testVolumeEventLatest}
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name    string // description of this test case
		init    func(context.Context, *testing.T)
		cleanup func()
		want    *Service
		wantErr bool
	}{
		{
			name: "fail to create kubeclient",
			init: func(ctx context.Context, tt *testing.T) {
				k8sutils.Kubeclient = nil
				tt.Setenv(identifiers.EnvKubeConfigPath, "")
				err := csictx.Setenv(ctx, identifiers.EnvKubeConfigPath, "")
				if err != nil {
					tt.Fatalf("failed to overwrite kubeconfig path: %v", err)
				}

				tempNewForConfigFunc := k8sutils.NewForConfigFunc
				k8sutils.NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return nil, errors.New("new for config error")
				}
				tt.Cleanup(func() {
					k8sutils.NewForConfigFunc = tempNewForConfigFunc
				})
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			init: func(ctx context.Context, tt *testing.T) {
				kubeconfigPath, err := createFakeKubeconfig(t)
				if err != nil {
					tt.Fatalf("failed to create fake kubeconfig for test: %s", err.Error())
					return
				}
				if err := csictx.Setenv(ctx, identifiers.EnvKubeConfigPath, kubeconfigPath); err != nil {
					tt.Fatalf("failed to add kubeconfig variable to context: %s", err.Error())
					return
				}
			},
			want:    &Service{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tt.init(ctx, t)
			got, gotErr := NewMonitorService(ctx)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewService() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("NewService() succeeded unexpectedly")
			}

			if tt.want == nil && got != nil {
				t.Errorf("NewService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func createFakeKubeconfig(t *testing.T) (kubeconfigPath string, err error) {
	fakeConfig := `
apiVersion: v1
clusters:
- cluster:
    server: https://localhost:8080
  name: foo-cluster
contexts:
- context:
    cluster: foo-cluster
    user: foo-user
    namespace: bar
  name: foo-context
current-context: foo-context
kind: Config
users:
- name: foo-user
`
	tmpKubeconfigDir := t.TempDir()
	tmpfile, err := os.CreateTemp(tmpKubeconfigDir, "kubeconfig")
	if err != nil {
		return "", fmt.Errorf("failed to create temp kubeconfig file: %s", err.Error())
	}
	if err := os.WriteFile(tmpfile.Name(), []byte(fakeConfig), 0o600); err != nil {
		return "", fmt.Errorf("failed to write config to the kubeconfig file: %s", err.Error())
	}
	return tmpfile.Name(), nil
}

func TestService_Start(t *testing.T) {
	defaultArray := &array.PowerStoreArray{
		Endpoint:      "my-powerstore.com/api/rest",
		GlobalID:      "gid1",
		Username:      "user",
		Password:      "password",
		BlockProtocol: identifiers.ISCSITransport,
		Insecure:      true,
		IsDefault:     true,
	}
	type params struct {
		pollPeriod time.Duration
		ctxTimeout time.Duration
	}
	type fields struct {
		service *Service
	}
	tests := []struct {
		name      string
		fields    fields
		params    params
		getArrays func() map[string]*array.PowerStoreArray
	}{
		{
			name: "context timeout",
			fields: fields{
				service: &Service{
					kubeclient: &k8sutils.K8sClient{
						Clientset: fake.NewClientset(),
					},
					EventRecorder:    record.NewFakeRecorder(0),
					EventBroadcaster: record.NewBroadcasterForTests(0 * time.Second),
				},
			},
			params: params{
				pollPeriod: 10 * time.Second,
				// timeout being less than polling period will ensure
				// the context is canceled before the initial poll.
				ctxTimeout: 100 * time.Millisecond,
			},
			getArrays: func() map[string]*array.PowerStoreArray {
				return map[string]*array.PowerStoreArray{
					defaultArray.GlobalID: defaultArray,
				}
			},
		},
		{
			name: "a single monitor loop execution",
			fields: fields{
				service: &Service{
					kubeclient: &k8sutils.K8sClient{
						Clientset: fake.NewClientset(),
					},
					EventRecorder:    record.NewFakeRecorder(0),
					EventBroadcaster: record.NewBroadcasterForTests(0 * time.Second),
				},
			},
			params: params{
				pollPeriod: 10 * time.Millisecond,
				// give enough time to run the request
				// but ensure the context is canceled after the first run
				ctxTimeout: 11 * time.Millisecond,
			},
			getArrays: func() map[string]*array.PowerStoreArray {
				client := mocks.NewClient(t)
				client.On("GetAlerts", mock.Anything, mock.Anything).Return(&gopowerstore.GetAlertsResponse{}, nil)

				defaultArray.Client = client
				return map[string]*array.PowerStoreArray{
					defaultArray.GlobalID: defaultArray,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.params.ctxTimeout)
			defer cancel()

			s := tt.fields.service
			s.SetArrays(tt.getArrays())
			s.SetDefaultArray(defaultArray)

			// it may appear nothing is being tested here, but
			// the tests will pass or fail based on whether the mocked
			// functions are called.
			s.Start(ctx, tt.params.pollPeriod)
		})
	}
}

func TestService_monitorSince(t *testing.T) {
	defaultArray := &array.PowerStoreArray{
		Endpoint:      "primary.my-powerstore.com/api/rest",
		GlobalID:      "gid1",
		Username:      "user",
		Password:      "password",
		BlockProtocol: identifiers.ISCSITransport,
		Insecure:      true,
		IsDefault:     true,
	}
	secondaryArray := &array.PowerStoreArray{
		Endpoint:      "secondary.my-powerstore.com/api/rest",
		GlobalID:      "gid2",
		Username:      "user",
		Password:      "password",
		BlockProtocol: identifiers.ISCSITransport,
		Insecure:      true,
		IsDefault:     false,
	}
	tests := []struct {
		name      string
		getArrays func() map[string]*array.PowerStoreArray
		getClient func(time.Time) gopowerstore.Client
	}{
		{
			name: "query array without issues",
			getArrays: func() map[string]*array.PowerStoreArray {
				return map[string]*array.PowerStoreArray{
					defaultArray.GlobalID: defaultArray,
				}
			},
			getClient: func(timeStamp time.Time) gopowerstore.Client {
				client := mocks.NewClient(t)

				client.On("GetAlerts", mock.Anything, gopowerstore.GetAlertsOpts{
					RequestPagination: gopowerstore.RequestPagination{
						PageSize:   1000,
						StartIndex: 0,
					},
					Queries: map[string]string{
						"generated_timestamp": fmt.Sprintf("gte.%s", timeStamp.Format(timeFormat)),
						"order":               "generated_timestamp.asc",
					},
				}).Return(&gopowerstore.GetAlertsResponse{}, nil)

				return client
			},
		},
		{
			name: "query all arrays",
			getArrays: func() map[string]*array.PowerStoreArray {
				return map[string]*array.PowerStoreArray{
					defaultArray.GlobalID:   defaultArray,
					secondaryArray.GlobalID: secondaryArray,
				}
			},
			getClient: func(timestamp time.Time) gopowerstore.Client {
				client := mocks.NewClient(t)
				client.On("GetAlerts", mock.Anything, gopowerstore.GetAlertsOpts{
					RequestPagination: gopowerstore.RequestPagination{
						PageSize:   1000,
						StartIndex: 0,
					},
					Queries: map[string]string{
						"generated_timestamp": fmt.Sprintf("gte.%s", timestamp.Format(timeFormat)),
						"order":               "generated_timestamp.asc",
					},
				}).Return(&gopowerstore.GetAlertsResponse{}, nil)

				return client
			},
		},
		{
			name: "query paginated data",
			getArrays: func() map[string]*array.PowerStoreArray {
				return map[string]*array.PowerStoreArray{
					defaultArray.GlobalID:   defaultArray,
					secondaryArray.GlobalID: secondaryArray,
				}
			},
			getClient: func(timestamp time.Time) gopowerstore.Client {
				client := mocks.NewClient(t)
				client.On("GetAlerts", mock.Anything, gopowerstore.GetAlertsOpts{
					RequestPagination: gopowerstore.RequestPagination{
						PageSize:   1000,
						StartIndex: 0,
					},
					Queries: map[string]string{
						"generated_timestamp": fmt.Sprintf("gte.%s", timestamp.Format(timeFormat)),
						"order":               "generated_timestamp.asc",
					},
				}).Return(&gopowerstore.GetAlertsResponse{
					AlertsResponseMeta: gopowerstore.AlertsResponseMeta{
						RespMeta: api.RespMeta{
							Pagination: api.PaginationInfo{
								First:      0,
								Last:       999,
								Next:       1000,
								Total:      2000,
								IsPaginate: true,
							},
						},
					},
					Alerts: gopowerstore.Alerts{},
				}, nil)
				client.On("GetAlerts", mock.Anything, gopowerstore.GetAlertsOpts{
					RequestPagination: gopowerstore.RequestPagination{
						PageSize:   1000,
						StartIndex: 1000,
					},
					Queries: map[string]string{
						"generated_timestamp": fmt.Sprintf("gte.%s", timestamp.Format(timeFormat)),
						"order":               "generated_timestamp.asc",
					},
				}).Return(&gopowerstore.GetAlertsResponse{
					AlertsResponseMeta: gopowerstore.AlertsResponseMeta{
						RespMeta: api.RespMeta{
							Pagination: api.PaginationInfo{
								First:      1000,
								Last:       1999,
								Next:       0,
								Total:      2000,
								IsPaginate: true,
							},
						},
					},
					Alerts: gopowerstore.Alerts{},
				}, nil)

				return client
			},
		},
		{
			name: "error when querying for alerts",
			getArrays: func() map[string]*array.PowerStoreArray {
				return map[string]*array.PowerStoreArray{
					defaultArray.GlobalID: defaultArray,
				}
			},
			getClient: func(timeStamp time.Time) gopowerstore.Client {
				client := mocks.NewClient(t)
				client.On("GetAlerts", mock.Anything, gopowerstore.GetAlertsOpts{
					RequestPagination: gopowerstore.RequestPagination{
						PageSize:   1000,
						StartIndex: 0,
					},
					Queries: map[string]string{
						"generated_timestamp": fmt.Sprintf("gte.%s", timeStamp.Format(timeFormat)),
						"order":               "generated_timestamp.asc",
					},
				}).Return(nil, errors.New("foo error"))

				return client
			},
		},
		{
			name: "error when querying for events",
			getArrays: func() map[string]*array.PowerStoreArray {
				return map[string]*array.PowerStoreArray{
					defaultArray.GlobalID: defaultArray,
				}
			},
			getClient: func(timeStamp time.Time) gopowerstore.Client {
				client := mocks.NewClient(t)

				client.On("GetAlerts", mock.Anything, gopowerstore.GetAlertsOpts{
					RequestPagination: gopowerstore.RequestPagination{
						PageSize:   1000,
						StartIndex: 0,
					},
					Queries: map[string]string{
						"generated_timestamp": fmt.Sprintf("gte.%s", timeStamp.Format(timeFormat)),
						"order":               "generated_timestamp.asc",
					},
				}).Return(&gopowerstore.GetAlertsResponse{}, nil)

				return client
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			s := &Service{
				kubeclient: &k8sutils.K8sClient{
					Clientset: fake.NewClientset(),
				},
				EventRecorder:    record.NewFakeRecorder(0),
				EventBroadcaster: record.NewBroadcasterForTests(0 * time.Second),
			}
			lastTime := time.Now().Add(1 * time.Minute)

			arrays := tt.getArrays()
			for _, arr := range arrays {
				arr.Client = tt.getClient(lastTime)
			}
			s.SetArrays(arrays)
			s.SetDefaultArray(defaultArray)

			// it may appear nothing is being tested here, but
			// the test will confirm the expected mock functions have
			// been called.
			s.monitorSince(lastTime)
		})
	}
}

func TestService_processVolumeObjectEvents(t *testing.T) {
	tests := []struct {
		name             string
		alerts           gopowerstore.Alerts
		clusterResources []runtime.Object
		want             string
	}{
		{
			name: "record a new event from an alert",
			alerts: gopowerstore.Alerts{
				{
					ResourceType: VolumeResourceType,
					ResourceName: testVolume.Name,
					Description:  testMessageWarning,
					Severity:     alertSeverityMinor,
				},
			},
			clusterResources: []runtime.Object{testVolume},
			want:             strings.Join([]string{eventMessageTypeWarning, alertSeverityMinor, testMessageWarning}, " "),
		},
		{
			name: "alert resource type is not a volume",
			alerts: gopowerstore.Alerts{
				{
					ResourceType: "volume_group",
					Description:  testMessageWarning,
				},
			},
			clusterResources: []runtime.Object{testVolume},
			want:             "",
		},
		{
			name: "volume is not being monitored by the driver",
			alerts: gopowerstore.Alerts{
				{
					ResourceName: "csivol-foo", // should not be known to the fake kubeclient
					ResourceType: VolumeResourceType,
					Description:  testMessageWarning,
				},
			},
			clusterResources: []runtime.Object{testVolume},
			want:             "",
		},
		{
			name: "volume alert has already been submitted to event recorder",
			alerts: gopowerstore.Alerts{
				{
					ResourceName: testVolume.Name,
					ResourceType: VolumeResourceType,
					Description:  testMessageWarning,
				},
			},
			clusterResources: []runtime.Object{testVolume, testVolumeEventLatest},
			want:             "",
		},
		{
			name: "volume has a new alert",
			alerts: gopowerstore.Alerts{
				{
					ResourceName: testVolume.Name,
					ResourceType: VolumeResourceType,
					Description:  "this is the second test",
					Severity:     alertSeverityInfo,
				},
			},
			clusterResources: []runtime.Object{testVolume, testVolumeEventLatest},
			want:             strings.Join([]string{eventMessageTypeNormal, alertSeverityInfo, "this is the second test"}, " "),
		},
		{
			name:             "no event updates from the array",
			alerts:           gopowerstore.Alerts{},
			clusterResources: []runtime.Object{testVolume, testVolumeEventLatest},
			want:             "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeRecorder := record.NewFakeRecorder(10)
			s := &Service{
				kubeclient: &k8sutils.K8sClient{
					Clientset: fake.NewClientset(tt.clusterResources...),
				},
				EventBroadcaster: record.NewBroadcaster(),
				EventRecorder:    fakeRecorder,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			go func() {
				defer cancel()
				s.processVolumeObjectEvents(ctx, tt.alerts)
			}()

			for {
				select {
				case <-ctx.Done():
					return
				case event := <-fakeRecorder.Events:
					if tt.want != event {
						t.Errorf("processVolumeObjectEvents() = %v, want: %v", event, tt.want)
					}
				}
			}
		})
	}
}

func TestService_CreateVolumeMap(t *testing.T) {
	type fields struct {
		s *Service
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]PersistentVolumeEvent
	}{
		{
			name: "fail to list volumes",
			fields: fields{
				s: &Service{
					// client is nil and will error
					kubeclient: &k8sutils.K8sClient{},
				},
			},
			want: nil,
		},
		{
			name: "get volume map",
			fields: fields{
				s: &Service{
					kubeclient: &k8sutils.K8sClient{
						Clientset: fake.NewClientset(append(testEvents, testVolume)...),
					},
				},
			},
			want: map[string]PersistentVolumeEvent{
				testVolName: {
					Volume: *testVolume,
					EventContent: EventContent{
						LatestRecord: testVolumeEventLatest,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.fields.s

			got := s.createVolumeMap(context.Background())

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateVolumeMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_GetLastK8sEvents(t *testing.T) {
	type params struct {
		name      string
		namespace string
		kind      string
	}
	type fields struct {
		s *Service
	}
	tests := []struct {
		name   string
		fields fields
		params params
		want   *corev1.Event
	}{
		{
			name: "no kubeclient",
			fields: fields{
				s: &Service{
					kubeclient: &k8sutils.K8sClient{},
				},
			},
			params: params{
				name:      "",
				namespace: "",
				kind:      "",
			},
			want: nil,
		},
		{
			name: "no events",
			fields: fields{
				s: &Service{
					kubeclient: &k8sutils.K8sClient{
						// init client without any resources
						Clientset: fake.NewClientset(),
					},
				},
			},
			params: params{
				name:      "",
				namespace: "",
				kind:      "",
			},
			want: nil,
		},
		{
			name: "get the most recent event",
			fields: fields{
				s: &Service{
					kubeclient: &k8sutils.K8sClient{
						Clientset: fake.NewClientset(testEvents...),
					},
				},
			},
			params: params{
				name:      testVolName,
				namespace: "test",
				kind:      "PersistentVolume",
			},
			want: testVolumeEventLatest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.fields.s
			got := s.getLatestK8sEvent(context.Background(), tt.params.name, tt.params.namespace, tt.params.kind)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetLastK8sEvents() = %v, want %v", got, tt.want)
			}
		})
	}
}
