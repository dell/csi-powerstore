// Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	"github.com/dell/csm-sharednfs/nfs"
	"github.com/dell/gocsi"
	csictx "github.com/dell/gocsi/context"
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

// Log controlls the logger
// give default value, will be overwritten by configmap
var log = logrus.New()

var (
	// DriverConfig driver config
	DriverConfig string
	// DriverSecret driver secret
	DriverSecret string
	// Name of the driver
	controllerSvc controller.Interface
	nodeSvc       node.Interface
	nfssvc        nfs.Service

	mx = sync.Mutex{}
)

type service struct {
	mode string
}

func New() nfs.Service {
	return &service{}
}

func (s *service) BeforeServe(ctx context.Context, _ *gocsi.StoragePlugin, _ net.Listener) error {
	log.Info("-----Inside Before Serve-----")
	// Get the SP's operating mode.
	s.mode = csictx.Getenv(ctx, gocsi.EnvVarMode)
	log.Info("Driver Mode:", s.mode)
	// TODO: add nfs code here
	nodeName := os.Getenv(common.EnvKubeNodeName)
	if nodeName == "" {
		nodeName = os.Getenv("KUBE_NODE_NAME")
	}

	if nodeName == "" {
		nodeName = os.Getenv("X_CSI_NODE_NAME")
	}

	if s.mode == "node" {
		nodeRoot := os.Getenv(common.EnvNodeChrootPath)
		if nodeRoot == "" {
			return fmt.Errorf("X_CSI_POWERSTORE_NODE_CHROOT_PATH environment variable not set")
		}
		nfs.NodeRoot = nodeRoot
	}

	log.Infof("Setting node name env to %s for NFS", nodeName)
	err := os.Setenv("X_CSI_NODE_NAME", nodeName)
	if err != nil {
		log.Errorf("failed to set env X_CSI_NODE_NAME. err: %s", err.Error())
		return err
	}

	// The block is commented out for performance issue caused by sharednfs.
	// Remove the comment when enabling sharednfs feature.
	/*
		err = nfssvc.BeforeServe(ctx, sp, lis)
		if err != nil {
			log.Errorf("unable to start up nfsserver: %s", err.Error())
		}
	*/
	return nil
}

func (s *service) RegisterAdditionalServers(server *grpc.Server) {
	controllerSvc.RegisterAdditionalServers(server)
}

func (s *service) ProcessMapSecretChange() error {
	// Update dynamic config params
	vc := viper.New()
	vc.AutomaticEnv()
	paramsPath, ok := csictx.LookupEnv(context.Background(), common.EnvConfigParamsFilePath)
	if !ok {
		log.Warnf("config path X_CSI_POWERSTORE_CONFIG_PARAMS_PATH is not specified")
	}
	log.WithField("file", paramsPath).Info("driver configuration file ")
	vc.SetConfigFile(paramsPath)
	vc.SetConfigType("yaml")
	if err := vc.ReadInConfig(); err != nil {
		log.WithError(err).Error("unable to read config file, using default values")
	}

	vc.WatchConfig()
	vc.OnConfigChange(func(_ fsnotify.Event) {
		// Putting in mutex to allow tests to pass with race flag
		mx.Lock()
		defer mx.Unlock()
		log.WithField("file", paramsPath).Info("log configuration file changed")
		updateDriverConfigParams(vc)
	})

	updateDriverConfigParams(vc)

	// If we don't set this env gocsi will overwrite log level with default Info level
	err := os.Setenv(gocsi.EnvVarLogLevel, log.GetLevel().String())
	if err != nil {
		log.WithError(err).Errorf("unable to set env variable %s", gocsi.EnvVarDebug)
	}

	return err
}

func updateDriverConfigParams(v *viper.Viper) {
	logLevelParam := "CSI_LOG_LEVEL"
	logFormatParam := "CSI_LOG_FORMAT"
	logFormat := strings.ToLower(v.GetString(logFormatParam))
	fmt.Printf("Read CSI_LOG_FORMAT from log configuration file, format: %s\n", logFormat)

	// Use JSON logger as default
	if !strings.EqualFold(logFormat, "text") {
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		})
	} else {
		log.SetFormatter(&logrus.TextFormatter{})
	}

	level := logrus.DebugLevel
	if v.IsSet(logLevelParam) {
		logLevel := v.GetString(logLevelParam)
		if logLevel != "" {
			logLevel = strings.ToLower(logLevel)
			fmt.Printf("Read CSI_LOG_LEVEL from log configuration file, level: %s\n", logLevel)
			var err error

			l, err := logrus.ParseLevel(logLevel)
			if err != nil {
				log.WithError(err).Errorf("LOG_LEVEL %s value not recognized, setting to default error: %s ", logLevel, err.Error())
			} else {
				level = l
			}
		}
	}
	log.SetLevel(level)
}

// VolumeIDToArrayID returns the array ID for a given volume.
// Example: abc-123 returns abc
func (s *service) VolumeIDToArrayID(volumeID string) string {
	if volumeID == "" {
		return ""
	}
	fields := strings.Split(volumeID, "-")
	return fields[0]
}

func PutNfsService(nfs nfs.Service) {
	nfssvc = nfs
}

func PutControllerService(ctlSvc controller.Interface) {
	controllerSvc = ctlSvc
}

func PutNodeService(nsSvc node.Interface) {
	nodeSvc = nsSvc
}
