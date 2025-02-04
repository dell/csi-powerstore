/*
 Copyright (c) 2023-2025 Dell Inc, or its subsidiaries.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package k8sutils

import (
	"context"
	"fmt"
	"strings"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NodeLabelsRetrieverInterface defines the methods for retrieving Kubernetes Node Labels
type NodeLabelsRetrieverInterface interface {
	BuildConfigFromFlags(masterURL, kubeconfig string) (*rest.Config, error)
	InClusterConfig() (*rest.Config, error)
	NewForConfig(config *rest.Config) (*kubernetes.Clientset, error)
	GetNodeLabels(ctx context.Context, kubeNodeName string) (map[string]string, error)
	GetNVMeUUIDs(ctx context.Context) (map[string]string, error)
}

// NodeLabelsModifierInterface defines the methods for retrieving Kubernetes Node Labels
type NodeLabelsModifierInterface interface {
	AddNVMeLabels(ctx context.Context, kubeNodeName string, labelKey string, labelValue []string) error
}

// NodeLabelsRetrieverImpl provided the implementation for NodeLabelsRetrieverInterface
type NodeLabelsRetrieverImpl struct{}

// NodeLabelsModifierImpl provides the implementation for NodeLabelsModifierInterface
type NodeLabelsModifierImpl struct{}

// NodeLabelsRetriever is the actual instance of NodeLabelsRetrieverInterface which is used to retrieve the node labels
var (
	NodeLabelsRetriever NodeLabelsRetrieverInterface
	NodeLabelsModifier  NodeLabelsModifierInterface
)

// Clientset - Interface to kubernetes
var Clientset kubernetes.Interface

func init() {
	NodeLabelsRetriever = new(NodeLabelsRetrieverImpl)
	NodeLabelsModifier = new(NodeLabelsModifierImpl)
}

// BuildConfigFromFlags is a method for building kubernetes client config
func (svc *NodeLabelsRetrieverImpl) BuildConfigFromFlags(masterURL, kubeconfig string) (*rest.Config, error) {
	return clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
}

// InClusterConfig returns a config object which uses the service account kubernetes gives to pods
func (svc *NodeLabelsRetrieverImpl) InClusterConfig() (*rest.Config, error) {
	return rest.InClusterConfig()
}

// NewForConfig creates a new Clientset for the given config
func (svc *NodeLabelsRetrieverImpl) NewForConfig(config *rest.Config) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(config)
}

// GetNodeLabels retrieves the kubernetes node object and returns its labels
func (svc *NodeLabelsRetrieverImpl) GetNodeLabels(ctx context.Context, kubeNodeName string) (map[string]string, error) {
	if Clientset != nil {
		node, err := Clientset.CoreV1().Nodes().Get(ctx, kubeNodeName, v1.GetOptions{})
		if err != nil {
			return nil, err
		}

		return node.Labels, nil
	}

	return nil, nil
}

// CreateKubeClientSet creates and returns kubeclient set
func CreateKubeClientSet(kubeconfig string) error {
	var config *rest.Config
	var err error
	if kubeconfig != "" {
		config, err = NodeLabelsRetriever.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return err
		}
	} else {
		config, err = NodeLabelsRetriever.InClusterConfig()
		if err != nil {
			return err
		}
	}
	// create the clientset
	Clientset, err = NodeLabelsRetriever.NewForConfig(config)
	if err != nil {
		return err
	}
	return nil
}

// AddNVMeLabels adds a hostnqn uuid label to the specified Kubernetes node
func (svc *NodeLabelsModifierImpl) AddNVMeLabels(ctx context.Context, kubeNodeName string, labelKey string, labelValue []string) error {
	if Clientset == nil {
		return fmt.Errorf("k8sclientset is nil")
	}

	// Get the current node
	node, err := Clientset.CoreV1().Nodes().Get(ctx, kubeNodeName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get node %s: %v", kubeNodeName, err.Error())
	}

	// Initialize node labels if it is nil
	if node.Labels == nil {
		node.Labels = make(map[string]string)
	}

	// Fetch the uuids from hostnqns
	var uuids []string
	for _, nqn := range labelValue {
		parts := strings.Split(nqn, ":")
		if len(parts) == 3 { // nqn format is nqn.yyyy-mm.nvmexpress:uuid:xxxx-yyyy-zzzz
			uuids = append(uuids, parts[2]) // Extract the UUID
		}
	}

	// Update the node with the new labels
	node.Labels[labelKey] = strings.Join(uuids, ",")
	_, err = Clientset.CoreV1().Nodes().Update(ctx, node, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update node %s labels: %v", kubeNodeName, err.Error())
	}
	return nil
}

// GetNVMeUUIDs returns map of hosts with their hostnqn uuids
func (svc *NodeLabelsRetrieverImpl) GetNVMeUUIDs(ctx context.Context) (map[string]string, error) {
	nodeUUIDs := make(map[string]string)
	if Clientset == nil {
		return nodeUUIDs, fmt.Errorf("k8sclientset is nil")
	}

	// Retrieve the list of nodes
	nodes, err := Clientset.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	if err != nil {
		return nodeUUIDs, fmt.Errorf("failed to get node list: %v", err.Error())
	}

	// Iterate over all nodes to check their labels
	for _, node := range nodes.Items {
		labels := node.Labels
		if uuid, exists := labels["hostnqn-uuid"]; exists {
			nodeUUIDs[node.Name] = uuid
		}
	}

	return nodeUUIDs, nil
}

// GetNodeLabels returns labels present in the k8s node
func GetNodeLabels(ctx context.Context, kubeConfigPath string, kubeNodeName string) (map[string]string, error) {
	err := CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return nil, err
	}

	return NodeLabelsRetriever.GetNodeLabels(ctx, kubeNodeName)
}

// AddNVMeLabels adds a hostnqn uuid label in the k8s node
func AddNVMeLabels(ctx context.Context, kubeConfigPath string, kubeNodeName string, labelKey string, labelValue []string) error {
	err := CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return err
	}

	return NodeLabelsModifier.AddNVMeLabels(ctx, kubeNodeName, labelKey, labelValue)
}

// GetNVMeUUIDs checks for duplicate hostnqn uuid labels in the k8s node
func GetNVMeUUIDs(ctx context.Context, kubeConfigPath string) (map[string]string, error) {
	err := CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return map[string]string{}, err
	}

	return NodeLabelsRetriever.GetNVMeUUIDs(ctx)
}
