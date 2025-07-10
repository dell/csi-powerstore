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
	"github.com/dell/csi-powerstore/v2/pkg/commonutils/k8sutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func GetMockNodeWithLabels() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
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

func TestUtilFunctions(t *testing.T) {
	nodeLabelsRetriever := &k8sutils.NodeLabelsRetrieverImpl{}
	nodeLabelsModifier := &k8sutils.NodeLabelsModifierImpl{}
	t.Run("GetNodeLabels", func(t *testing.T) {
		k8sutils.Clientset = fake.NewClientset(GetMockNodeWithLabels())

		labels, err := nodeLabelsRetriever.GetNodeLabels(context.Background(), "node1")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"max-powerstore-volumes-per-node": "2", "hostnqn-uuid": "uuid1"}, labels)
	})

	t.Run("GetNVMeUUIDs", func(t *testing.T) {
		k8sutils.Clientset = fake.NewClientset(GetMockNodeWithLabels())

		nodeUUIDs, err := nodeLabelsRetriever.GetNVMeUUIDs(context.Background())

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"node1": "uuid1"}, nodeUUIDs)
	})

	t.Run("AddNVMeLabels", func(t *testing.T) {
		k8sutils.Clientset = fake.NewClientset(GetMockNodeWithoutLabels())

		err := nodeLabelsModifier.AddNVMeLabels(context.Background(), "node1", "hostnqn", []string{"nqn.2025-mm.nvmexpress:uuid:xxxx-yyyy-zzzz"})

		assert.NoError(t, err)
		// Assert the node labels in the fake client set
		node, err := k8sutils.Clientset.CoreV1().Nodes().Get(context.Background(), "node1", metav1.GetOptions{})
		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"hostnqn": "xxxx-yyyy-zzzz"}, node.Labels)
	})
}

func TestUtilFunctions_Error(t *testing.T) {
	nodeLabelsRetriever := &k8sutils.NodeLabelsRetrieverImpl{}
	nodeLabelsModifier := &k8sutils.NodeLabelsModifierImpl{}
	t.Run("GetNodeLabels error", func(t *testing.T) {
		k8sutils.Clientset = fake.NewClientset()

		labels, err := nodeLabelsRetriever.GetNodeLabels(context.Background(), "node1")

		assert.Error(t, err)
		assert.Nil(t, labels)
	})

	t.Run("GetNVMeUUIDs error", func(t *testing.T) {
		k8sutils.Clientset = nil

		_, err := nodeLabelsRetriever.GetNVMeUUIDs(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "k8sclientset is nil")
	})

	t.Run("AddNVMeLabels get error", func(t *testing.T) {
		k8sutils.Clientset = fake.NewClientset()

		err := nodeLabelsModifier.AddNVMeLabels(context.Background(), "node1", "hostnqn", []string{"nqn.2025-mm.nvmexpress:uuid:xxxx-yyyy-zzzz"})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get node")
	})

	t.Run("AddNVMeLabels error", func(t *testing.T) {
		k8sutils.Clientset = nil

		err := nodeLabelsModifier.AddNVMeLabels(context.Background(), "node1", "hostnqn", []string{"nqn.2025-mm.nvmexpress:uuid:xxxx-yyyy-zzzz"})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "k8sclientset is nil")
	})
}

func TestNodeLabelRetrieverAndModifier(t *testing.T) {
	retrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = retrieverMock
	modifierMock := new(mocks.NodeLabelsModifierInterface)
	k8sutils.NodeLabelsModifier = modifierMock

	retrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
	retrieverMock.On("BuildConfigFromFlags", mock.Anything, mock.Anything).Return(nil, nil)
	retrieverMock.On("NewForConfig", mock.Anything).Return(nil, nil)

	t.Run("GetNodeLabels", func(t *testing.T) {
		retrieverMock.On("GetNodeLabels", mock.Anything, mock.Anything, mock.Anything).Return(
			map[string]string{"max-powerstore-volumes-per-node": "2"}, nil)

		labels, err := k8sutils.GetNodeLabels(context.Background(), "", "test-node")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"max-powerstore-volumes-per-node": "2"}, labels)
	})

	t.Run("GetNVMeUUIDs", func(t *testing.T) {
		retrieverMock.On("GetNVMeUUIDs", mock.Anything, mock.Anything).Return(
			map[string]string{"node1": "uuid1", "node2": "uuid2"}, nil)

		nodeUUIDs, err := k8sutils.GetNVMeUUIDs(context.Background(), "")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"node1": "uuid1", "node2": "uuid2"}, nodeUUIDs)
	})

	t.Run("AddNVMeLabels", func(t *testing.T) {
		modifierMock.On("AddNVMeLabels", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

		err := k8sutils.AddNVMeLabels(context.Background(), "/config/path", "test-node", "max-powerstore-volumes-per-node", []string{"2"})

		assert.NoError(t, err)
	})
}

func TestNodeLabelRetriever_ConfigError(t *testing.T) {
	k8sutils.Clientset = nil
	retrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = retrieverMock
	retrieverMock.On("InClusterConfig", mock.Anything).Return(nil, errors.New("Unable to create kubeclientset"))
	retrieverMock.On("BuildConfigFromFlags", mock.Anything, mock.Anything).Return(nil, errors.New("Unable to build config"))

	t.Run("GetNodeLabels error", func(t *testing.T) {
		_, err := k8sutils.GetNodeLabels(context.Background(), "", "test-node")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unable to create kubeclientset")
	})

	t.Run("AddNVMeLabels error", func(t *testing.T) {
		err := k8sutils.AddNVMeLabels(context.Background(), "/config/path", "test-node", "max-powerstore-volumes-per-node", []string{"2"})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unable to build config")
	})
}

func TestNodeLabelRetriever_CreateError(t *testing.T) {
	k8sutils.Clientset = nil
	retrieverMock := new(mocks.NodeLabelsRetrieverInterface)
	k8sutils.NodeLabelsRetriever = retrieverMock
	retrieverMock.On("InClusterConfig", mock.Anything).Return(nil, nil)
	retrieverMock.On("NewForConfig", mock.Anything).Return(nil, errors.New("Unable to create kubeclientset"))

	t.Run("GetNVMeUUIDs error", func(t *testing.T) {
		_, err := k8sutils.GetNVMeUUIDs(context.Background(), "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unable to create kubeclientset")
	})
}
