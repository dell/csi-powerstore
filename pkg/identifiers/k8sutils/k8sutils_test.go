/*
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
 */

package k8sutils

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

const (
	testEventKind string = "PersistentVolume"
	testNamespace string = "default"
	testVolName   string = "csivol-aabccdd"
)

var (
	testPV *corev1.PersistentVolume = &corev1.PersistentVolume{
		TypeMeta: v1.TypeMeta{
			Kind: "PersistentVolume",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      testVolName,
			Namespace: "",
		},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
			StorageClassName:              "powerstore-block",
		},
	}
	testVolumeEvent *corev1.Event = &corev1.Event{
		TypeMeta: v1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Event",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      "event1",
			Namespace: "default",
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "v1",
			Name:       testVolName,
			Kind:       testEventKind,
		},
		Type:   corev1.EventTypeWarning,
		Reason: "Minor",
	}
	testPodEvent *corev1.Event = &corev1.Event{
		TypeMeta: v1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Event",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      "powerstore-node-event",
			Namespace: "powerstore",
		},
		InvolvedObject: corev1.ObjectReference{
			Name:      "powerstore-node-aabbccdd",
			Kind:      "Pod",
			Namespace: "powerstore",
		},
		Type:   corev1.EventTypeNormal,
		Reason: "Scheduled",
	}
)

func GetMockNodeWithLabels() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			Annotations: map[string]string{
				"csi.volume.kubernetes.io/nodeid": "{\"node1\":\"myCsiNode\"}",
			},
			Labels: map[string]string{
				"max-powerstore-volumes-per-node": "2",
				"hostnqn-uuid":                    "uuid1",
			},
		},
	}
}

func GetMockNodeWithoutLabels() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
	}
}

func TestCreateKubeClientSet(t *testing.T) {
	var tempConfigFunc func() (*rest.Config, error)                               // must return getInClusterConfig to its original value
	var tempClientsetFunc func(config *rest.Config) (kubernetes.Interface, error) // must return getK8sClientset to its original value

	tests := []struct {
		name    string
		before  func(*testing.T) error
		after   func()
		wantErr bool
	}{
		{
			name: "success: manually set InClusterConfig with mock",
			before: func(_ *testing.T) error {
				Kubeclient = nil // reset Clientset before each run
				tempConfigFunc = InClusterConfigFunc
				InClusterConfigFunc = func() (*rest.Config, error) { return &rest.Config{}, nil }
				return nil
			},
			after:   func() { InClusterConfigFunc = tempConfigFunc },
			wantErr: false,
		},
		{
			name: "failure: unmocked config function",
			before: func(tt *testing.T) error {
				Kubeclient = nil // reset Clientset before each run
				tempConfigFunc = InClusterConfigFunc
				// Mock InClusterConfigFunc to return an error to simulate failure
				InClusterConfigFunc = func() (*rest.Config, error) {
					return nil, errors.New("unable to load in-cluster configuration")
				}
				// Clear KUBECONFIG to ensure fallback also fails
				tt.Setenv(identifiers.EnvKubeConfigPath, "")
				return nil
			},
			after: func() {
				InClusterConfigFunc = tempConfigFunc
			},
			wantErr: true,
		},
		{
			name: "failure: error returned by kubernetes.NewForConfig",
			before: func(_ *testing.T) error { // overrides to get past a mock and inject a failure
				Kubeclient = nil // reset Clientset before each run
				tempConfigFunc = InClusterConfigFunc
				tempClientsetFunc = NewForConfigFunc
				InClusterConfigFunc = func() (*rest.Config, error) { return &rest.Config{}, nil }
				NewForConfigFunc = func(_ *rest.Config) (kubernetes.Interface, error) {
					return nil, assert.AnError
				}
				return nil
			},
			after: func() { // restore functions to their defaults
				InClusterConfigFunc = tempConfigFunc
				NewForConfigFunc = tempClientsetFunc
			},
			wantErr: true,
		},
		{
			name: "fail to get in-cluster config and no kubeconfig provided",
			before: func(tt *testing.T) error {
				Kubeclient = nil
				// keep InClusterConfigFunc as-is
				// Clear KUBECONFIG to ensure fallback also fails
				tt.Setenv(identifiers.EnvKubeConfigPath, "")
				// ensure failure of InClusterConfigFunc
				tt.Setenv("KUBERNETES_SERVICE_HOST", "")
				return nil
			},
			after:   func() {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.before(t)
			defer tt.after()

			_, err := CreateKubeClientSet()

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, Kubeclient.Clientset)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, Kubeclient.Clientset)
			}

			// Reset Clientset for the second test call
			Kubeclient = nil

			// Test 2: Call CreateKubeClientSet(kubeConfig) with parameters
			// For the failure test case, we need to ensure this also fails
			if tt.name == "failure: unmocked config function" {
				// For this test case, pass an invalid kubeconfig path to ensure failure
				_, err = CreateKubeClientSet("/invalid/path/to/kubeconfig")
			} else {
				// For other tests, use the original kubeconfig (if any)
				_, err = CreateKubeClientSet(os.Getenv(identifiers.EnvKubeConfigPath))
			}

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, Kubeclient.Clientset)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, Kubeclient.Clientset)
			}
		})
	}
}

func TestGetNode(t *testing.T) {
	t.Run("GetNode success", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithoutLabels()),
		}

		_, err := Kubeclient.GetNode(context.Background(), "node1")
		assert.NoError(t, err)
	})

	t.Run("GetNode no client", func(t *testing.T) {
		Kubeclient = &K8sClient{}

		_, err := Kubeclient.GetNode(context.Background(), "node1")
		assert.Error(t, err)
	})

	t.Run("GetNode not found", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(),
		}

		_, err := Kubeclient.GetNode(context.Background(), "node1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestGetNodeLabels(t *testing.T) {
	t.Run("GetNodeLabels success", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithLabels()),
		}

		labels, err := Kubeclient.GetNodeLabels(context.Background(), "node1")
		assert.NoError(t, err)
		assert.Equal(t, len(labels), 2)
	})

	t.Run("GetNodeLabels success - no labels", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithoutLabels()),
		}

		labels, err := Kubeclient.GetNodeLabels(context.Background(), "node1")
		assert.NoError(t, err)
		assert.Equal(t, len(labels), 0)
	})

	t.Run("GetNodeLabels no client", func(t *testing.T) {
		Kubeclient = &K8sClient{}

		_, err := Kubeclient.GetNodeLabels(context.Background(), "node1")
		assert.Error(t, err)
	})

	t.Run("GetNodeLabels not found", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(),
		}

		_, err := Kubeclient.GetNodeLabels(context.Background(), "node1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestSetNodeLabel(t *testing.T) {
	t.Run("SetNodeLabel success", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithLabels()),
		}

		err := Kubeclient.SetNodeLabel(context.Background(), "node1", "topology.kubernetes.io/zone", "zone1")
		assert.NoError(t, err)

		labels, err := Kubeclient.GetNodeLabels(context.Background(), "node1")
		assert.NoError(t, err)

		assert.Equal(t, labels["topology.kubernetes.io/zone"], "zone1")
	})

	t.Run("SetNodeLabel no client", func(t *testing.T) {
		Kubeclient = &K8sClient{}

		err := Kubeclient.SetNodeLabel(context.Background(), "", "", "")
		assert.Error(t, err)
	})

	t.Run("SetNodeLabel not found", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(),
		}

		err := Kubeclient.SetNodeLabel(context.Background(), "node1", "", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestGetNVMeUUIDs(t *testing.T) {
	t.Run("GetNVMeUUIDs success", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithLabels()),
		}

		nodeUUIDs, err := Kubeclient.GetNVMeUUIDs(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"node1": "uuid1"}, nodeUUIDs)
	})

	t.Run("GetNVMeUUIDs success - no uuids", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithoutLabels()),
		}

		nodeUUIDs, err := Kubeclient.GetNVMeUUIDs(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, len(nodeUUIDs), 0)
	})

	t.Run("GetNVMeUUIDs no client", func(t *testing.T) {
		Kubeclient = &K8sClient{}

		_, err := Kubeclient.GetNVMeUUIDs(context.Background())
		assert.Error(t, err)
	})
}

func TestAddNVMeLabels(t *testing.T) {
	t.Run("AddNVMeLabels success", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithLabels()),
		}

		err := Kubeclient.AddNVMeLabels(context.Background(), "node1", "newNVME", []string{"nqn.yyyy-mm.nvmexpress:uuid:xxxx-yyyy-zzzz"})
		assert.NoError(t, err)
	})

	t.Run("AddNVMeLabels success - empty labels", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithoutLabels()),
		}

		err := Kubeclient.AddNVMeLabels(context.Background(), "node1", "newNVME", []string{"nqn.yyyy-mm.nvmexpress:uuid:xxxx-yyyy-zzzz"})
		assert.NoError(t, err)
	})

	t.Run("AddNVMeLabels no client", func(t *testing.T) {
		Kubeclient = &K8sClient{}

		err := Kubeclient.AddNVMeLabels(context.Background(), "node1", "newNVME", []string{"nqn.yyyy-mm.nvmexpress:uuid:xxxx-yyyy-zzzz"})
		assert.Error(t, err)
	})
}

func TestGetNodeByCSINodeID(t *testing.T) {
	t.Run("GetNodeByCSINodeID success", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithLabels()),
		}

		_, err := Kubeclient.GetNodeByCSINodeID(context.Background(), "node1", "myCsiNode", "csi.volume.kubernetes.io/nodeid")
		assert.NoError(t, err)
	})

	t.Run("GetNodeByCSINodeID failed", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithoutLabels()),
		}

		_, err := Kubeclient.GetNodeByCSINodeID(context.Background(), "node1", "myCsiNode", "csi.volume.kubernetes.io/nodeid")
		assert.Error(t, err)
	})

	t.Run("GetNodeByCSINodeID failed - no node found", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithoutLabels()),
		}

		_, err := Kubeclient.GetNodeByCSINodeID(context.Background(), "invalidNode", "myCsiNode", "csi.volume.kubernetes.io/nodeid")
		assert.Error(t, err)
	})

	t.Run("GetNodeByCSINodeID no client", func(t *testing.T) {
		Kubeclient = &K8sClient{}

		_, err := Kubeclient.GetNodeByCSINodeID(context.Background(), "node1", "myCsiNode", "csi.volume.kubernetes.io/nodeid")
		assert.Error(t, err)
	})
}

func TestK8sClient_ListPersistentVolumes(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for receiver constructor.
		k8s     func() *K8sClient
		want    *corev1.PersistentVolumeList
		wantErr bool
	}{
		{
			name: "uninitialized kube client",
			k8s: func() *K8sClient {
				return &K8sClient{}
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			k8s: func() *K8sClient {
				return &K8sClient{
					Clientset: fake.NewClientset([]runtime.Object{testPV}...),
				}
			},
			want:    &corev1.PersistentVolumeList{Items: []corev1.PersistentVolume{*testPV}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := tt.k8s()

			got, gotErr := k8s.ListPersistentVolumes(context.Background())
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ListPersistentVolumes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ListPersistentVolumes() succeeded unexpectedly")
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListPersistentVolumes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestK8sClient_GetEvents(t *testing.T) {
	type args struct {
		name      string
		kind      string
		namespace string
	}
	tests := []struct {
		name string // description of this test case
		// Named input parameters for receiver constructor.
		k8s     func() *K8sClient
		args    args
		want    *corev1.EventList
		wantErr bool
	}{
		{
			name: "client is uninitialized",
			k8s:  func() *K8sClient { return &K8sClient{} },
			args: args{
				name:      testVolName,
				kind:      testEventKind,
				namespace: "",
			},
			want:    nil,
			wantErr: true,
		},
		// NOTE: "k8s.io/client-go/kubernetes/fake" as of version v0.34.0 does not support filtering events
		// based on FieldSelector, so we cannot accurately test the functionality of the GetEvents() func.
		// {
		// 	name: "without a kind",
		// 	k8s: func() *K8sClient {
		// 		client := fake.NewClientset([]runtime.Object{testVolumeEvent, testPodEvent}...)
		// 		return &K8sClient{
		// 			Clientset: client,
		// 		}
		// 	},
		// 	args: args{
		// 		name:      testVolName,
		// 		kind:      "",
		// 		namespace: "",
		// 	},
		// 	want:    &corev1.EventList{Items: []corev1.Event{*testVolumeEvent}},
		// 	wantErr: false,
		// },
		{
			name: "gets all events in the default namespace",
			k8s: func() *K8sClient {
				client := fake.NewClientset([]runtime.Object{testVolumeEvent, testPodEvent}...)
				return &K8sClient{
					Clientset: client,
				}
			},
			args: args{
				name:      "",
				kind:      "",
				namespace: "default",
			},
			want:    &corev1.EventList{Items: []corev1.Event{*testVolumeEvent}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := tt.k8s()
			got, gotErr := k8s.GetEvents(context.Background(), tt.args.kind, tt.args.name, tt.args.namespace)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GetEvents() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("GetEvents() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(tt.want, got) {
				t.Errorf("GetEvents() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetNodeByCSINodeIDVar(t *testing.T) {
	t.Run("GetNodeByCSINodeIDVar success", func(t *testing.T) {
		Kubeclient = &K8sClient{
			Clientset: fake.NewSimpleClientset(GetMockNodeWithLabels()),
		}

		_, err := GetNodeByCSINodeID(context.Background(), "node1", "myCsiNode", "csi.volume.kubernetes.io/nodeid")
		assert.NoError(t, err)
	})
}
