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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dell/csmlog"
	k8score "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type K8sClient struct {
	Clientset kubernetes.Interface
}

// Instantiate csmlog on a package level
var log = csmlog.GetLogger()

// Kube Kubeclient
var Kubeclient *K8sClient

// used for unit testing -
// allows CreateKubeClientSet to be mocked
var InClusterConfigFunc = func() (*rest.Config, error) {
	return rest.InClusterConfig()
}

var NewForConfigFunc = func(config *rest.Config) (kubernetes.Interface, error) {
	return kubernetes.NewForConfig(config)
}

// CreateKubeClientSet creates kubeclient set if not created already
func CreateKubeClientSet(kubeconfig ...string) (*K8sClient, error) {
	Kubeclient = &K8sClient{}

	config, err := InClusterConfigFunc()
	if err != nil {
		if len(kubeconfig) == 0 {
			return nil, err
		}

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig[0])
		if err != nil {
			return nil, err
		}
	}

	Kubeclient.Clientset, err = NewForConfigFunc(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %s", err.Error())
	}

	return Kubeclient, nil
}

func (k8s *K8sClient) GetNode(ctx context.Context, kubeNodeName string) (*k8score.Node, error) {
	if k8s.Clientset == nil {
		return nil, fmt.Errorf("unable to get node %q, kubernetes client is uninitialized", kubeNodeName)
	}

	node, err := k8s.Clientset.CoreV1().Nodes().Get(ctx, kubeNodeName, v1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return node, nil
}

// GetNodeLabels retrieves the kubernetes node object and returns its labels
func (k8s *K8sClient) GetNodeLabels(ctx context.Context, kubeNodeName string) (map[string]string, error) {
	if k8s.Clientset == nil {
		return nil, fmt.Errorf("unable to get node labels for node %q, kubernetes client is uninitialized", kubeNodeName)
	}

	node, err := k8s.GetNode(ctx, kubeNodeName)
	if err != nil {
		return nil, err
	}

	return node.Labels, nil
}

// GetNodeLabels retrieves the kubernetes node object and returns its labels
func (k8s *K8sClient) SetNodeLabel(ctx context.Context, kubeNodeName string, labelKey string, labelValue string) error {
	if k8s.Clientset == nil {
		return fmt.Errorf("unable to get node labels for node %q, kubernetes client is uninitialized", kubeNodeName)
	}

	node, err := k8s.GetNode(ctx, kubeNodeName)
	if err != nil {
		return err
	}

	// Update the node with the new labels
	node.Labels[labelKey] = labelValue
	_, err = k8s.Clientset.CoreV1().Nodes().Update(ctx, node, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update node %s labels: %v", kubeNodeName, err.Error())
	}

	return nil
}

// AddNVMeLabels adds a hostnqn uuid label to the specified Kubernetes node
func (k8s *K8sClient) AddNVMeLabels(ctx context.Context, kubeNodeName string, labelKey string, labelValue []string) error {
	if k8s.Clientset == nil {
		return fmt.Errorf("unable to add NVMe labels to node %q, kubernetes client is uninitialized", kubeNodeName)
	}

	// Get the current node
	node, err := k8s.GetNode(ctx, kubeNodeName)
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
	_, err = k8s.Clientset.CoreV1().Nodes().Update(ctx, node, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update node %s labels: %v", kubeNodeName, err.Error())
	}
	return nil
}

// GetNVMeUUIDs returns map of hosts with their hostnqn uuids
func (k8s *K8sClient) GetNVMeUUIDs(ctx context.Context) (map[string]string, error) {
	nodeUUIDs := make(map[string]string)
	if k8s.Clientset == nil {
		return nodeUUIDs, errors.New("unable to get NVMe UUIDs, kubernetes client is uninitialized")
	}

	// Retrieve the list of nodes
	nodes, err := k8s.Clientset.CoreV1().Nodes().List(ctx, v1.ListOptions{})
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

func (k8s *K8sClient) GetNodeByCSINodeID(ctx context.Context, driverKey string, csiNodeID string, keyNodeID string) (*k8score.Node, error) {
	if k8s.Clientset == nil {
		return nil, errors.New("unable to get node, kubernetes client is uninitialized")
	}

	// Retrieve the list of nodes
	nodes, err := k8s.Clientset.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node list: %v", err.Error())
	}

	for _, node := range nodes.Items {
		if annotation, exists := node.Annotations[keyNodeID]; exists {
			var nodeIDMap map[string]string
			if err := json.Unmarshal([]byte(annotation), &nodeIDMap); err != nil {
				continue
			}

			if value, found := nodeIDMap[driverKey]; found && value == csiNodeID {
				return &node, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to find a Node matching csiNodeId %s", csiNodeID)
}

// ListVolumes lists all persistent volumes.
func (k8s *K8sClient) ListPersistentVolumes(ctx context.Context) (*k8score.PersistentVolumeList, error) {
	if k8s.Clientset == nil {
		return nil, errors.New("unable to list volumes, kubernetes client is uninitialized")
	}

	return k8s.Clientset.CoreV1().PersistentVolumes().List(ctx, v1.ListOptions{})
}

// GetEvents gets events for the named resource of the given kind in the given namespace.
// If name is empty, it gets all events for the given kind in the given namespace.
func (k8s *K8sClient) GetEvents(ctx context.Context, kind, name, namespace string) (*k8score.EventList, error) {
	if k8s.Clientset == nil {
		return nil, errors.New("unable to get events, kubernetes client is uninitialized")
	}

	var fieldSelector string
	if name != "" {
		fieldSelector = fmt.Sprintf("involvedObject.name=%s", name)
	}
	if kind != "" {
		fieldSelector = strings.Join([]string{fieldSelector, fmt.Sprintf("involvedObject.kind=%s", kind)}, ",")
	}

	log.Debugf("getting events for %q %q in namespace %q", kind, name, namespace)

	return k8s.Clientset.CoreV1().Events(namespace).List(ctx, v1.ListOptions{
		FieldSelector: fieldSelector,
	})
}

var GetNodeByCSINodeID = func(ctx context.Context, driverKey string, csiNodeID string, keyNodeID string) (*k8score.Node, error) {
	return Kubeclient.GetNodeByCSINodeID(ctx, driverKey, csiNodeID, keyNodeID)
}
