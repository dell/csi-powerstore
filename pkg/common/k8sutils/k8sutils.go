/*
 Copyright (c) 2023 Dell Inc, or its subsidiaries.

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
	GetNodeLabels(ctx context.Context, k8sclientset *kubernetes.Clientset, kubeNodeName string) (map[string]string, error)
}

// NodeLabelsRetrieverImpl provided the implementation for NodeLabelsRetrieverInterface
type NodeLabelsRetrieverImpl struct{}

// NodeLabelsRetriever is the actual instance of NodeLabelsRetrieverInterface which is used to retrieve the node labels
var NodeLabelsRetriever NodeLabelsRetrieverInterface

func init() {
	NodeLabelsRetriever = new(NodeLabelsRetrieverImpl)
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
func (svc *NodeLabelsRetrieverImpl) GetNodeLabels(ctx context.Context, k8sclientset *kubernetes.Clientset, kubeNodeName string) (map[string]string, error) {
	if k8sclientset != nil {
		node, err := k8sclientset.CoreV1().Nodes().Get(ctx, kubeNodeName, v1.GetOptions{})
		if err != nil {
			return nil, err
		}

		return node.Labels, nil
	}

	return nil, nil
}

// CreateKubeClientSet creates and returns kubeclient set
func CreateKubeClientSet(kubeconfig string) (*kubernetes.Clientset, error) {
	var clientset *kubernetes.Clientset
	if kubeconfig != "" {
		config, err := NodeLabelsRetriever.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
		// create the clientset
		clientset, err = NodeLabelsRetriever.NewForConfig(config)
		if err != nil {
			return nil, err
		}
	} else {
		config, err := NodeLabelsRetriever.InClusterConfig()
		if err != nil {
			return nil, err
		}
		// creates the clientset
		clientset, err = NodeLabelsRetriever.NewForConfig(config)
		if err != nil {
			return nil, err
		}
	}
	return clientset, nil
}

// GetNodeLabels returns labels present in the k8s node
func GetNodeLabels(ctx context.Context, kubeConfigPath string, kubeNodeName string) (map[string]string, error) {
	k8sclientset, err := CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return nil, err
	}

	return NodeLabelsRetriever.GetNodeLabels(ctx, k8sclientset, kubeNodeName)
}
