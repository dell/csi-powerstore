package array

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dell/csi-powerstore/pkg/common"
	"github.com/dell/csi-powerstore/pkg/common/fs"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type ClusterInfoStruct struct {
	Server string `yaml:"server"`
}

type Cluster struct {
	ClusterInfo ClusterInfoStruct `yaml:"cluster"`
	Name        string            `yaml:"name"`
}

type KubeConfig struct {
	ApiVersion string    `yaml:"apiVersion"`
	Clusters   []Cluster `yaml:"clusters,flow"`
}

type K8sClusterInfo struct {
	Name      string
	IPAddress string
	Port      int
	Token     string
}

func getRootDirectory() string {
	if rootPath, ok := csictx.LookupEnv(context.Background(), common.EnvCtrlRootPath); ok {
		return rootPath
	}
	return "/"
}

func getKubeConfigInfo(fs fs.Interface) (KubeConfig, error) {
	var kubeconfig KubeConfig
	kubeconfigInfo := []byte{}
	kubeconfigDir := filepath.Join(getRootDirectory(), "etc/kubernetes")

	kubeconfigPath := filepath.Join(kubeconfigDir, "kubelet.conf")

	log.Debug("K8s visibility: Reading file: \n", kubeconfigPath)
	kubeconfigInfo, err := fs.ReadFile(kubeconfigPath)
	if err != nil {
		log.Warnf("K8s visibility: Error reading file: %s err: %s\n", kubeconfigPath, err.Error())

		kubeconfigPath = filepath.Join(kubeconfigDir, "admin.conf")
		log.Info("K8s visibility: Reading file: \n", kubeconfigPath)
		kubeconfigInfo, err = fs.ReadFile(kubeconfigPath)
		if err != nil {
			return kubeconfig, err
		}
	}

	err = yaml.Unmarshal([]byte(kubeconfigInfo), &kubeconfig)
	if err != nil {
		return kubeconfig, err
	}

	return kubeconfig, nil
}

func getK8sVisibilityServiceToken(fs fs.Interface) (string, error) {
	tokenPath := filepath.Join("/powerstore-visibility", "token")
	token, err := fs.ReadFile(tokenPath)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func getK8sClusterInfo(fs fs.Interface) ([]K8sClusterInfo, error) {
	k8sClusters := []K8sClusterInfo{}

	kubeconfig, err := getKubeConfigInfo(fs)
	if err != nil {
		return k8sClusters, err
	}
	log.Debug("K8s visibility: Number of clusters in kube config file: \n", len(kubeconfig.Clusters))

	token, err := getK8sVisibilityServiceToken(fs)
	if err != nil {
		return k8sClusters, err
	}

	for _, cluster := range kubeconfig.Clusters {
		log.Debugf("K8s visibility: cluster name: %s server IP: %s", cluster.Name, cluster.ClusterInfo.Server)
		ipAddressPort := strings.Replace(cluster.ClusterInfo.Server, "https://", "", 1)
		ipAddressPortArray := strings.Split(ipAddressPort, ":")

		if len(ipAddressPortArray) != 2 {
			log.Errorf("cannot determine k8s cluster IP address and port from kube config\n")
			continue
		}

		port, err := strconv.Atoi(ipAddressPortArray[1])
		if err != nil {
			log.Errorf("cannot determine k8s cluster port from kube config\n")
			continue
		}

		log.Debugf("K8s visibility: K8s Cluster IP Address: %s Port: %s", ipAddressPortArray[0], ipAddressPortArray[1])
		k8sClusters = append(k8sClusters, K8sClusterInfo{
			Name:      cluster.Name,
			IPAddress: ipAddressPortArray[0],
			Port:      port,
			Token:     token,
		})
	}

	return k8sClusters, nil
}

func isK8sVisibilitySupported(client gopowerstore.Client) bool {
	k8sVisibilitySupported := false
	resp, err := client.GetSoftwareInstalled(context.Background())
	if err != nil {
		log.Errorf("couldn't get the software version installed on the PowerStore array: %v", err)
		return k8sVisibilitySupported
	}

	for _, softwareInstalled := range resp {
		if softwareInstalled.IsCluster {
			versionString := softwareInstalled.BuildVersion
			versions := strings.Split(versionString, ".")
			if len(versions) > 2 {
				var majorMinorVersion float32
				var majorVersion, minorVersion int

				if majorVersion, err = strconv.Atoi(versions[0]); err != nil {
					log.Errorf("couldn't get the software major version installed on the PowerStore array: %v", err)
					break
				}
				if minorVersion, err = strconv.Atoi(versions[1]); err != nil {
					log.Errorf("couldn't get the software minor version installed on the PowerStore array: %v", err)
					break
				}

				majorMinorVersion = float32(majorVersion) + float32(minorVersion)*0.1
				if majorMinorVersion >= 3.1 {
					k8sVisibilitySupported = true
				} else {
					log.Debugf("Software version installed on the PowerStore array: %v\n", majorMinorVersion)
				}
			}
			break
		}
	}

	return k8sVisibilitySupported
}
