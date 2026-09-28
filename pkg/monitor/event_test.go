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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
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
			Kind:      "PersistentVolume",
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
			Kind:      "PersistentVolume",
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
			Kind:      "PersistentVolume",
		},
		Type: corev1.EventTypeWarning,
		LastTimestamp: v1.Time{
			Time: testTime.Add(-2 * time.Minute),
		},
		Message: testMessageWarning,
	}

	testVolume *corev1.PersistentVolume = &corev1.PersistentVolume{
		ObjectMeta: v1.ObjectMeta{
			Name:      testVolName,
			Namespace: testNamespace,
		},
		TypeMeta: v1.TypeMeta{
			Kind: "PersistentVolume",
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       identifiers.Name,
					VolumeHandle: testVolName,
				},
			},
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
	if err := os.WriteFile(tmpfile.Name(), []byte(fakeConfig), 0o600); err != nil { // #nosec G703
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
				// but keep the context open long enough for informer sync
				// and at least one polling interval.
				ctxTimeout: 100 * time.Millisecond,
			},
			getArrays: func() map[string]*array.PowerStoreArray {
				client := mocks.NewClient(t)
				client.On("GetAlerts", mock.Anything, mock.Anything).Maybe().Return(&gopowerstore.GetAlertsResponse{}, nil)

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

func TestService_populateInitialCache_WithStandaloneIndexer(t *testing.T) {
	// Create a standalone indexer using NewSharedIndexInformer with nil ListWatch
	// This gives us a real informer without background threads or network calls
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	pvInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{}, // nil ListWatch - no network calls
		&corev1.PersistentVolume{},
		0, // resync period
		indexers,
	)

	// Add test PV directly to the informer's indexer
	err := pvInformer.GetIndexer().Add(testVolume)
	assert.NoError(t, err)

	s := &Service{
		pvInformer:       pvInformer,
		volumeCache:      make(map[string]PersistentVolumeEvent),
		cacheInitialized: false,
	}

	ctx := context.Background()
	s.populateInitialCache(ctx)

	assert.True(t, s.cacheInitialized)
	assert.Equal(t, 1, len(s.volumeCache))
	assert.Equal(t, testVolume.Name, s.volumeCache[testVolume.Name].Volume.Name)
}

func TestService_populateInitialCache_WithMultiplePVs(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	pvInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.PersistentVolume{},
		0,
		indexers,
	)

	pv2 := testVolume.DeepCopy()
	pv2.Name = "csi-test-vol-2"

	err := pvInformer.GetIndexer().Add(testVolume)
	assert.NoError(t, err)
	err = pvInformer.GetIndexer().Add(pv2)
	assert.NoError(t, err)

	s := &Service{
		pvInformer:       pvInformer,
		volumeCache:      make(map[string]PersistentVolumeEvent),
		cacheInitialized: false,
	}

	ctx := context.Background()
	s.populateInitialCache(ctx)

	assert.True(t, s.cacheInitialized)
	assert.Equal(t, 2, len(s.volumeCache))
}

func TestService_populateInitialCache_WithNonPVObject(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	pvInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.PersistentVolume{},
		0,
		indexers,
	)

	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-pod",
		},
	}

	err := pvInformer.GetIndexer().Add(pod)
	assert.NoError(t, err)

	s := &Service{
		pvInformer:       pvInformer,
		volumeCache:      make(map[string]PersistentVolumeEvent),
		cacheInitialized: false,
	}

	ctx := context.Background()
	s.populateInitialCache(ctx)

	assert.True(t, s.cacheInitialized)
	assert.Equal(t, 0, len(s.volumeCache))
}

func TestService_getLatestEventFromCache_WithStandaloneIndexer(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	eventInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.Event{},
		0,
		indexers,
	)

	// Add test events directly to the informer's indexer
	err := eventInformer.GetIndexer().Add(testVolumeEventLatest)
	assert.NoError(t, err)
	err = eventInformer.GetIndexer().Add(testVolumeEventOldest)
	assert.NoError(t, err)

	s := &Service{
		eventInformer: eventInformer,
	}

	latestEvent := s.getLatestEventFromCache(testVolume.Name, testNamespace, "PersistentVolume")
	assert.NotNil(t, latestEvent)
	assert.Equal(t, testVolumeEventLatest.LastTimestamp, latestEvent.LastTimestamp)
}

func TestService_getLatestEventFromCache_FilterByKind(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	eventInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.Event{},
		0,
		indexers,
	)

	err := eventInformer.GetIndexer().Add(testVolumeEventLatest)
	assert.NoError(t, err)

	s := &Service{
		eventInformer: eventInformer,
	}

	latestEvent := s.getLatestEventFromCache(testVolume.Name, testNamespace, "Pod")
	assert.Nil(t, latestEvent)
}

func TestService_getLatestEventFromCache_FilterByName(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	eventInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.Event{},
		0,
		indexers,
	)

	err := eventInformer.GetIndexer().Add(testVolumeEventLatest)
	assert.NoError(t, err)

	s := &Service{
		eventInformer: eventInformer,
	}

	latestEvent := s.getLatestEventFromCache("other-volume", testNamespace, "PersistentVolume")
	assert.Nil(t, latestEvent)
}

func TestService_getLatestEventFromCache_FilterByNamespace(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	eventInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.Event{},
		0,
		indexers,
	)

	err := eventInformer.GetIndexer().Add(testVolumeEventLatest)
	assert.NoError(t, err)

	s := &Service{
		eventInformer: eventInformer,
	}

	latestEvent := s.getLatestEventFromCache(testVolume.Name, "other-namespace", "PersistentVolume")
	assert.Nil(t, latestEvent)
}

func TestService_getLatestEventFromCache_NonEventObject(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	eventInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.Event{},
		0,
		indexers,
	)

	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-pod",
		},
	}

	err := eventInformer.GetIndexer().Add(pod)
	assert.NoError(t, err)

	s := &Service{
		eventInformer: eventInformer,
	}

	latestEvent := s.getLatestEventFromCache(testVolume.Name, testNamespace, "PersistentVolume")
	assert.Nil(t, latestEvent)
}

func TestService_updateVolumeCache(t *testing.T) {
	s := &Service{
		volumeCache: make(map[string]PersistentVolumeEvent),
	}

	s.updateVolumeCache(testVolume)
	assert.Equal(t, 1, len(s.volumeCache))
	assert.Equal(t, testVolume.Name, s.volumeCache[testVolume.Name].Volume.Name)
}

func TestService_updateVolumeCache_WithExistingVolume(t *testing.T) {
	s := &Service{
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
			},
		},
	}

	updatedPV := testVolume.DeepCopy()
	updatedPV.Status.Phase = corev1.VolumeReleased
	s.updateVolumeCache(updatedPV)
	assert.Equal(t, 1, len(s.volumeCache))
	assert.Equal(t, corev1.VolumeReleased, s.volumeCache[testVolume.Name].Volume.Status.Phase)
}

func TestService_removeVolumeCache(t *testing.T) {
	s := &Service{
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
			},
		},
	}

	s.removeVolumeCache(testVolume.Name)
	assert.Equal(t, 0, len(s.volumeCache))
}

func TestService_removeVolumeCache_NonExistent(t *testing.T) {
	s := &Service{
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
			},
		},
	}

	s.removeVolumeCache("non-existent")
	assert.Equal(t, 1, len(s.volumeCache))
}

func TestService_updateEventCache(t *testing.T) {
	s := &Service{
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
				EventContent: EventContent{
					LatestRecord: testVolumeEventOldest,
				},
			},
		},
	}

	s.updateEventCache(testVolumeEventLatest)
	assert.NotNil(t, s.volumeCache[testVolume.Name].LatestRecord)
	assert.Equal(t, testVolumeEventLatest.UID, s.volumeCache[testVolume.Name].LatestRecord.UID)
}

func TestService_updateEventCache_NonPVKind(t *testing.T) {
	s := &Service{
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
				EventContent: EventContent{
					LatestRecord: testVolumeEventOldest,
				},
			},
		},
	}

	nonPVEvent := testVolumeEventLatest.DeepCopy()
	nonPVEvent.InvolvedObject.Kind = "Pod"
	s.updateEventCache(nonPVEvent)
	assert.Equal(t, testVolumeEventOldest.UID, s.volumeCache[testVolume.Name].LatestRecord.UID)
}

func TestService_updateEventCache_OlderEvent(t *testing.T) {
	s := &Service{
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
				EventContent: EventContent{
					LatestRecord: testVolumeEventLatest,
				},
			},
		},
	}

	olderEvent := testVolumeEventOldest.DeepCopy()
	s.updateEventCache(olderEvent)
	assert.Equal(t, testVolumeEventLatest.UID, s.volumeCache[testVolume.Name].LatestRecord.UID)
}

func TestService_removeEventCache(t *testing.T) {
	s := &Service{
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
				EventContent: EventContent{
					LatestRecord: testVolumeEventLatest,
				},
			},
		},
		eventInformer: nil,
	}

	s.removeEventCache(testVolumeEventLatest)
	assert.Nil(t, s.volumeCache[testVolume.Name].LatestRecord)
}

func TestService_removeEventCache_VolumeNotInCache(t *testing.T) {
	s := &Service{
		volumeCache:   map[string]PersistentVolumeEvent{},
		eventInformer: nil,
	}

	assert.NotPanics(t, func() {
		s.removeEventCache(testVolumeEventLatest)
	})
}

func TestService_persistentVolumeFromDelete(t *testing.T) {
	deleteObj := cache.DeletedFinalStateUnknown{
		Key: "test-pv",
		Obj: testVolume,
	}

	pv, ok := persistentVolumeFromDelete(deleteObj)
	assert.True(t, ok)
	assert.Equal(t, testVolume.Name, pv.Name)
}

func TestService_persistentVolumeFromDelete_DirectPV(t *testing.T) {
	pv, ok := persistentVolumeFromDelete(testVolume)
	assert.True(t, ok)
	assert.Equal(t, testVolume.Name, pv.Name)
}

func TestService_persistentVolumeFromDelete_Invalid(t *testing.T) {
	pv, ok := persistentVolumeFromDelete("invalid")
	assert.False(t, ok)
	assert.Nil(t, pv)
}

func TestService_eventFromDelete(t *testing.T) {
	deleteObj := cache.DeletedFinalStateUnknown{
		Key: "test-event",
		Obj: testVolumeEventLatest,
	}

	event, ok := eventFromDelete(deleteObj)
	assert.True(t, ok)
	assert.Equal(t, testVolumeEventLatest.Name, event.Name)
}

func TestService_eventFromDelete_DirectEvent(t *testing.T) {
	event, ok := eventFromDelete(testVolumeEventLatest)
	assert.True(t, ok)
	assert.Equal(t, testVolumeEventLatest.Name, event.Name)
}

func TestService_eventFromDelete_Invalid(t *testing.T) {
	event, ok := eventFromDelete("invalid")
	assert.False(t, ok)
	assert.Nil(t, event)
}

func TestService_setupPVInformer_DoesNotPanic(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	pvInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.PersistentVolume{},
		0,
		indexers,
	)

	s := &Service{
		pvInformer:  pvInformer,
		volumeCache: make(map[string]PersistentVolumeEvent),
	}

	assert.NotPanics(t, func() {
		s.setupPVInformer()
	})
}

func TestService_setupEventInformer_DoesNotPanic(t *testing.T) {
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	eventInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.Event{},
		0,
		indexers,
	)

	s := &Service{
		eventInformer: eventInformer,
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
			},
		},
	}

	assert.NotPanics(t, func() {
		s.setupEventInformer()
	})
}

func TestService_createVolumeMap_WithCacheInitialized(t *testing.T) {
	s := &Service{
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
			},
		},
		cacheInitialized: true,
	}

	ctx := context.Background()
	result := s.createVolumeMap(ctx)
	assert.Equal(t, 1, len(result))
	assert.Equal(t, testVolume.Name, result[testVolume.Name].Volume.Name)
}

func TestService_createVolumeMap_ListError(t *testing.T) {
	mockKubeClient := &k8sutils.K8sClient{
		Clientset: nil,
	}

	s := &Service{
		kubeclient:       mockKubeClient,
		volumeCache:      make(map[string]PersistentVolumeEvent),
		cacheInitialized: false,
	}

	ctx := context.Background()
	result := s.createVolumeMap(ctx)
	assert.Nil(t, result)
}

func TestService_createVolumeMap_EmptyCache(t *testing.T) {
	s := &Service{
		volumeCache:      map[string]PersistentVolumeEvent{},
		cacheInitialized: true,
	}

	ctx := context.Background()
	result := s.createVolumeMap(ctx)
	assert.Equal(t, 0, len(result))
}

// mockSharedInformer captures the handler closures for direct testing
type mockSharedInformer struct {
	cache.SharedInformer

	OnAdd    func(obj interface{})
	OnUpdate func(oldObj, newObj interface{})
	OnDelete func(obj interface{})
}

func (m *mockSharedInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	// Extract the closures from the handler
	if handlerFuncs, ok := handler.(cache.ResourceEventHandlerFuncs); ok {
		m.OnAdd = handlerFuncs.AddFunc
		m.OnUpdate = handlerFuncs.UpdateFunc
		m.OnDelete = handlerFuncs.DeleteFunc
	}
	var reg cache.ResourceEventHandlerRegistration
	return reg, nil
}

func (m *mockSharedInformer) AddEventHandlerWithOptions(handler cache.ResourceEventHandler, _ cache.HandlerOptions) (cache.ResourceEventHandlerRegistration, error) {
	// Extract the closures from the handler
	if handlerFuncs, ok := handler.(cache.ResourceEventHandlerFuncs); ok {
		m.OnAdd = handlerFuncs.AddFunc
		m.OnUpdate = handlerFuncs.UpdateFunc
		m.OnDelete = handlerFuncs.DeleteFunc
	}
	var reg cache.ResourceEventHandlerRegistration
	return reg, nil
}

func (m *mockSharedInformer) AddIndexers(_ cache.Indexers) error {
	return nil
}

func (m *mockSharedInformer) HasSynced() bool {
	return true
}

func (m *mockSharedInformer) Run(_ <-chan struct{}) {
	// No-op for testing
}

func (m *mockSharedInformer) GetStore() cache.Store {
	return cache.NewStore(cache.MetaNamespaceKeyFunc, nil)
}

func (m *mockSharedInformer) GetIndexer() cache.Indexer {
	return cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
}

func (m *mockSharedInformer) LastSyncResourceVersion() string {
	return ""
}

func TestService_setupPVInformer_Handlers(t *testing.T) {
	mockPVInformer := &mockSharedInformer{}

	s := &Service{
		pvInformer:  mockPVInformer,
		volumeCache: make(map[string]PersistentVolumeEvent),
	}

	// Execute setup to capture closures
	s.setupPVInformer()

	// Test ADD handler (lines 382-393)
	mockPVInformer.OnAdd(testVolume)
	assert.Equal(t, 1, len(s.volumeCache))
	assert.Equal(t, testVolume.Name, s.volumeCache[testVolume.Name].Volume.Name)

	// Test ADD handler with non-PV object (lines 383-386)
	mockPVInformer.OnAdd("not-a-pv")
	assert.Equal(t, 1, len(s.volumeCache)) // Should not add

	// Test UPDATE handler (lines 394-405)
	updatedPV := testVolume.DeepCopy()
	updatedPV.Status.Phase = corev1.VolumeReleased
	mockPVInformer.OnUpdate(nil, updatedPV)
	assert.Equal(t, corev1.VolumeReleased, s.volumeCache[testVolume.Name].Volume.Status.Phase)

	// Test UPDATE handler with non-PV object (lines 395-398)
	mockPVInformer.OnUpdate(nil, "not-a-pv")
	assert.Equal(t, corev1.VolumeReleased, s.volumeCache[testVolume.Name].Volume.Status.Phase) // Should not update

	// Test DELETE handler (lines 406-417)
	mockPVInformer.OnDelete(testVolume)
	assert.Equal(t, 0, len(s.volumeCache))

	// Test DELETE handler with invalid object (lines 407-410)
	s.volumeCache[testVolume.Name] = PersistentVolumeEvent{Volume: *testVolume}
	mockPVInformer.OnDelete("invalid")
	assert.Equal(t, 1, len(s.volumeCache)) // Should not delete
}

func TestService_setupEventInformer_Handlers(t *testing.T) {
	mockEventInformer := &mockSharedInformer{}

	s := &Service{
		eventInformer: mockEventInformer,
		volumeCache: map[string]PersistentVolumeEvent{
			testVolume.Name: {
				Volume: *testVolume,
				EventContent: EventContent{
					LatestRecord: testVolumeEventOldest,
				},
			},
		},
	}

	// Execute setup to capture closures
	s.setupEventInformer()

	// Test ADD handler (lines 424-436)
	mockEventInformer.OnAdd(testVolumeEventLatest)
	assert.NotNil(t, s.volumeCache[testVolume.Name].LatestRecord)
	assert.Equal(t, testVolumeEventLatest.UID, s.volumeCache[testVolume.Name].LatestRecord.UID)

	// Test ADD handler with non-Event object (lines 425-428)
	s.volumeCache[testVolume.Name] = PersistentVolumeEvent{
		Volume: *testVolume,
		EventContent: EventContent{
			LatestRecord: testVolumeEventOldest,
		},
	}
	mockEventInformer.OnAdd("not-an-event")
	assert.Equal(t, testVolumeEventOldest.UID, s.volumeCache[testVolume.Name].LatestRecord.UID) // Should not update

	// Test UPDATE handler (lines 437-449)
	updatedEvent := testVolumeEventLatest.DeepCopy()
	updatedEvent.Reason = "UpdatedReason"
	mockEventInformer.OnUpdate(nil, updatedEvent)
	assert.NotNil(t, s.volumeCache[testVolume.Name].LatestRecord)

	// Test UPDATE handler with non-Event object (lines 438-441)
	mockEventInformer.OnUpdate(nil, "not-an-event")
	assert.NotNil(t, s.volumeCache[testVolume.Name].LatestRecord) // Should not update

	// Test DELETE handler (lines 450-462)
	s.volumeCache[testVolume.Name] = PersistentVolumeEvent{
		Volume: *testVolume,
		EventContent: EventContent{
			LatestRecord: testVolumeEventLatest,
		},
	}
	mockEventInformer.OnDelete(testVolumeEventLatest)
	assert.Nil(t, s.volumeCache[testVolume.Name].LatestRecord)

	// Test DELETE handler with invalid object (lines 451-454)
	s.volumeCache[testVolume.Name] = PersistentVolumeEvent{
		Volume: *testVolume,
		EventContent: EventContent{
			LatestRecord: testVolumeEventLatest,
		},
	}
	mockEventInformer.OnDelete("invalid")
	assert.NotNil(t, s.volumeCache[testVolume.Name].LatestRecord) // Should not delete
}

func TestService_Start_ContextCancellation(_ *testing.T) {
	// Create a brand new instance to ensure handlersOnce.Do runs
	mockPVInformer := &mockSharedInformer{}
	mockEventInformer := &mockSharedInformer{}

	s := &Service{
		pvInformer:    mockPVInformer,
		eventInformer: mockEventInformer,
		volumeCache:   make(map[string]PersistentVolumeEvent),
		stopCh:        make(chan struct{}),
	}

	// Pre-cancel the context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Start should immediately exit due to context cancellation
	s.Start(ctx, 1*time.Second)
}

func TestService_Start_HandlersOnce(_ *testing.T) {
	// Test that handlersOnce.Do runs correctly
	mockPVInformer := &mockSharedInformer{}
	mockEventInformer := &mockSharedInformer{}

	s := &Service{
		pvInformer:    mockPVInformer,
		eventInformer: mockEventInformer,
		volumeCache:   make(map[string]PersistentVolumeEvent),
		stopCh:        make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start with very short poll period to force ticker to fire
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	s.Start(ctx, 10*time.Millisecond)
}

func TestService_Start_TickerLoop(_ *testing.T) {
	// Test the ticker.C case (lines 528-531)
	mockPVInformer := &mockSharedInformer{}
	mockEventInformer := &mockSharedInformer{}

	s := &Service{
		pvInformer:    mockPVInformer,
		eventInformer: mockEventInformer,
		volumeCache:   make(map[string]PersistentVolumeEvent),
		stopCh:        make(chan struct{}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start with very short poll period to force ticker to fire multiple times
	s.Start(ctx, 10*time.Millisecond)
}

// TestService_AlertsProducedAsKubernetesEvents is an integration test that verifies
// the full pipeline: PowerStore GetAlerts → processVolumeObjectEvents → K8s EventRecorder.
// It uses fake.NewClientset to provide a real informer-backed k8s API and
// gopowerstore/mocks.Client to simulate the PowerStore array.
func TestService_AlertsProducedAsKubernetesEvents(t *testing.T) {
	tests := []struct {
		name        string
		pv          *corev1.PersistentVolume
		alerts      gopowerstore.Alerts
		wantEvent   string
		wantNoEvent bool
	}{
		{
			name: "minor severity alert produces a warning K8s event",
			pv: &corev1.PersistentVolume{
				ObjectMeta: v1.ObjectMeta{Name: "csi-integration-vol"},
				Spec: corev1.PersistentVolumeSpec{
					PersistentVolumeSource: corev1.PersistentVolumeSource{
						CSI: &corev1.CSIPersistentVolumeSource{
							Driver:       identifiers.Name,
							VolumeHandle: "csi-integration-vol",
						},
					},
				},
			},
			alerts: gopowerstore.Alerts{
				{
					ResourceType: VolumeResourceType,
					ResourceName: "csi-integration-vol",
					Description:  "disk performance degraded",
					Severity:     alertSeverityMinor,
				},
			},
			wantEvent: strings.Join([]string{eventMessageTypeWarning, alertSeverityMinor, "disk performance degraded"}, " "),
		},
		{
			name: "info severity alert produces a normal K8s event",
			pv: &corev1.PersistentVolume{
				ObjectMeta: v1.ObjectMeta{Name: "csi-integration-vol-2"},
				Spec: corev1.PersistentVolumeSpec{
					PersistentVolumeSource: corev1.PersistentVolumeSource{
						CSI: &corev1.CSIPersistentVolumeSource{
							Driver:       identifiers.Name,
							VolumeHandle: "csi-integration-vol-2",
						},
					},
				},
			},
			alerts: gopowerstore.Alerts{
				{
					ResourceType: VolumeResourceType,
					ResourceName: "csi-integration-vol-2",
					Description:  "volume health restored",
					Severity:     alertSeverityInfo,
				},
			},
			wantEvent: strings.Join([]string{eventMessageTypeNormal, alertSeverityInfo, "volume health restored"}, " "),
		},
		{
			name: "alert for volume not in cluster produces no K8s event",
			pv: &corev1.PersistentVolume{
				ObjectMeta: v1.ObjectMeta{Name: "csi-integration-vol-3"},
				Spec: corev1.PersistentVolumeSpec{
					PersistentVolumeSource: corev1.PersistentVolumeSource{
						CSI: &corev1.CSIPersistentVolumeSource{
							Driver:       identifiers.Name,
							VolumeHandle: "csi-integration-vol-3",
						},
					},
				},
			},
			alerts: gopowerstore.Alerts{
				{
					ResourceType: VolumeResourceType,
					ResourceName: "some-other-vol-unknown-to-cluster",
					Description:  "disk performance degraded",
					Severity:     alertSeverityMinor,
				},
			},
			wantNoEvent: true,
		},
		{
			name: "non-volume alert type produces no K8s event",
			pv: &corev1.PersistentVolume{
				ObjectMeta: v1.ObjectMeta{Name: "csi-integration-vol-4"},
				Spec: corev1.PersistentVolumeSpec{
					PersistentVolumeSource: corev1.PersistentVolumeSource{
						CSI: &corev1.CSIPersistentVolumeSource{
							Driver:       identifiers.Name,
							VolumeHandle: "csi-integration-vol-4",
						},
					},
				},
			},
			alerts: gopowerstore.Alerts{
				{
					ResourceType: "volume_group",
					ResourceName: "csi-integration-vol-4",
					Description:  "volume group alert",
					Severity:     alertSeverityMajor,
				},
			},
			wantNoEvent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := mocks.NewClient(t)
			client.On("GetAlerts", mock.Anything, mock.Anything).
				Maybe().
				Return(&gopowerstore.GetAlertsResponse{Alerts: tt.alerts}, nil)

			arr := &array.PowerStoreArray{
				GlobalID: "gid-integration",
				Client:   client,
			}

			fakeClientset := fake.NewClientset(tt.pv)
			fakeRecorder := record.NewFakeRecorder(10)

			s := &Service{
				kubeclient: &k8sutils.K8sClient{
					Clientset: fakeClientset,
				},
				EventRecorder:    fakeRecorder,
				EventBroadcaster: record.NewBroadcasterForTests(0),
			}
			s.SetArrays(map[string]*array.PowerStoreArray{arr.GlobalID: arr})
			s.SetDefaultArray(arr)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			go s.Start(ctx, 50*time.Millisecond)

			if tt.wantNoEvent {
				select {
				case event := <-fakeRecorder.Events:
					t.Errorf("expected no K8s event but got: %q", event)
				case <-time.After(300 * time.Millisecond):
					// no event within the grace period — as expected
				}
				return
			}

			select {
			case event := <-fakeRecorder.Events:
				assert.Equal(t, tt.wantEvent, event, "K8s event did not match expected PowerStore alert")
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for K8s event to be recorded from PowerStore alert")
			}
		})
	}
}
