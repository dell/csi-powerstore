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

package k8sutils_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/csi-powerstore/v2/pkg/common/k8sutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetNodeLabels(t *testing.T) {
	SetK8sClientSetMock()
	nodeLabelsRetriever := &k8sutils.NodeLabelsRetrieverImpl{}

	labels, err := nodeLabelsRetriever.GetNodeLabels(context.Background(), "node1")

	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"max-powerstore-volumes-per-node": "2", "hostnqn-uuid": "uuid1"}, labels)
}

func TestGetNVMeUUIDs(t *testing.T) {
	SetK8sClientSetMock()
	nodeLabelsRetriever := &k8sutils.NodeLabelsRetrieverImpl{}

	labels, err := nodeLabelsRetriever.GetNVMeUUIDs(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"node1": "uuid1"}, labels)
}

func SetK8sClientSetMock() {
	k8sClientset := fake.NewClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			Labels: map[string]string{
				"max-powerstore-volumes-per-node": "2",
				"hostnqn-uuid":                    "uuid1",
			},
		},
	})
	k8sutils.Clientset = k8sClientset
}

func TestGetNodeLabelsRetriever(t *testing.T) {
	nodeLabelsRetrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock

	nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything, mock.Anything).Return(
		map[string]string{"max-powerstore-volumes-per-node": "2"}, nil)

	labels, err := k8sutils.GetNodeLabels(context.Background(), "", "test-node")

	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"max-powerstore-volumes-per-node": "2"}, labels)
}

func TestGetNodeLabelsRetrieverError(t *testing.T) {
	nodeLabelsRetrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock

	nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, errors.New("Unable to create kubeclientset"))

	_, err := k8sutils.GetNodeLabels(context.Background(), "", "test-node")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unable to create kubeclientset")
}

func TestGetNVMeUUIDsRetriever(t *testing.T) {
	nodeLabelsRetrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock

	nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("GetNVMeUUIDs", mock.Anything, mock.Anything).Return(
		map[string]string{"node1": "uuid1", "node2": "uuid2"}, nil)

	uuids, err := k8sutils.GetNVMeUUIDs(context.Background(), "")

	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"node1": "uuid1", "node2": "uuid2"}, uuids)
}

func TestGetNVMeUUIDsRetrieverError(t *testing.T) {
	nodeLabelsRetrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock

	nodeLabelsRetrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, errors.New("Unable to create kubeclientset"))

	_, err := k8sutils.GetNVMeUUIDs(context.Background(), "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unable to create kubeclientset")
}

func TestAddNVMeLabelsRetriever(t *testing.T) {
	nodeLabelsRetrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
	nodeLabelsModifierMock := new(mocks.NodeLabelsModifierInterface)
	k8sutils.NodeLabelsModifier = nodeLabelsModifierMock

	nodeLabelsRetrieverMock.On("BuildConfigFromFlags", mock.Anything, mock.Anything).Return(nil, nil)
	nodeLabelsRetrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)
	nodeLabelsModifierMock.On("AddNVMeLabels", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	err := k8sutils.AddNVMeLabels(context.Background(), "/config/path", "test-node", "max-powerstore-volumes-per-node", []string{"2"})

	assert.NoError(t, err)
}

func TestAddNVMeLabelsRetrieverError(t *testing.T) {
	nodeLabelsRetrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = nodeLabelsRetrieverMock
	nodeLabelsModifierMock := new(mocks.NodeLabelsModifierInterface)
	k8sutils.NodeLabelsModifier = nodeLabelsModifierMock

	nodeLabelsRetrieverMock.On("BuildConfigFromFlags", mock.Anything, mock.Anything).Return(nil, errors.New("Unable to build config"))

	err := k8sutils.AddNVMeLabels(context.Background(), "/config/path", "test-node", "max-powerstore-volumes-per-node", []string{"2"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unable to build config")
}
