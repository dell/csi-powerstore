/*
 *
 * Copyright © 2021-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identity"
	"github.com/dell/csi-powerstore/v2/pkg/interceptors"
	"github.com/dell/csi-powerstore/v2/pkg/monitor"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	"github.com/dell/csi-powerstore/v2/pkg/tracer"
	drController "github.com/dell/csm-dr/pkg/controller"
	"github.com/dell/csmlog"
	"github.com/dell/gocsi"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gofsutil"
	"github.com/fsnotify/fsnotify"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/uber/jaeger-client-go/config"
	"google.golang.org/grpc"
)

var log = csmlog.GetLogger()

//go:generate go generate ../../core

func init() {
	// We set X_CSI_DEBUG to false, because we don't want gocsi to override our logging level
	_ = os.Setenv(identifiers.EnvGOCSIDebug, "false")
	// Enable X_CSI_REQ_LOGGING and X_CSI_REP_LOGGING to see gRPC request information
	_ = os.Setenv(gocsi.EnvVarReqLogging, "true")
	_ = os.Setenv(gocsi.EnvVarRepLogging, "true")

	updateDriverName()

	initilizeDriverConfigParams()

	// If we don't set this env gocsi will overwrite log level with default Info level
	_ = os.Setenv(gocsi.EnvVarLogLevel, csmlog.GetLevel().String())
}

func updateDriverName() {
	if name, ok := csictx.LookupEnv(context.Background(), identifiers.EnvDriverName); ok {
		identifiers.Name = name
	}
}

func initilizeDriverConfigParams() {
	log.SetLevel(csmlog.InfoLevel)
	paramsPath, ok := csictx.LookupEnv(context.Background(), identifiers.EnvConfigParamsFilePath)
	if !ok {
		log.Warn("config path X_CSI_POWERSTORE_CONFIG_PARAMS_PATH is not specified")
	}

	paramsViper := viper.New()
	paramsViper.SetConfigFile(paramsPath)
	paramsViper.SetConfigType("yaml")

	err := paramsViper.ReadInConfig()
	// if unable to read configuration file, default values will be used in updateDriverConfigParams
	if err != nil {
		log.Warnf("unable to read config file, using default values %s ", err.Error())
	}
	paramsViper.WatchConfig()
	paramsViper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Params config file changed:", e.Name)
		updateDriverConfigParams(paramsViper)
	})

	updateDriverConfigParams(paramsViper)
}

var ManifestSemver string

func main() {
	log.SetLevel(csmlog.InfoLevel)
	f := &fs.Fs{Util: &gofsutil.FS{}}

	identifiers.RmSockFile(f)

	if ManifestSemver != "" {
		log.Info("ManifestVersion isn't empty, setting it")
		identifiers.ManifestSemver = ManifestSemver
		identifiers.Manifest["semver"] = ManifestSemver
	}

	identityService := identity.NewIdentityService(identifiers.Name, ManifestSemver, identifiers.Manifest)
	var controllerService *controller.Service
	var nodeService *node.Service

	mode := csictx.Getenv(context.Background(), gocsi.EnvVarMode)

	configPath, ok := csictx.LookupEnv(context.Background(), identifiers.EnvArrayConfigFilePath)
	if !ok {
		log.Fatalf("config path X_CSI_POWERSTORE_CONFIG_PATH is not specified")
	}

	if name, ok := csictx.LookupEnv(context.Background(), identifiers.EnvDriverName); ok {
		identifiers.Name = name
	}
	identifiers.SetAPIPort(context.Background())

	var nodeName string
	var arrayLocker *array.Locker

	isCSMDREnabled, err := strconv.ParseBool(os.Getenv(identifiers.EnvCSMDREnabled))
	if err != nil {
		log.Infof("Error parsing %s: %s. Defaulting to true", identifiers.EnvCSMDREnabled, err.Error())
		isCSMDREnabled = true
	}

	if strings.EqualFold(mode, "controller") {

		var err error
		controllerService, err = initControllerService(f, configPath)
		if err != nil {
			log.Fatalf("couldn't initialize controller service: %s", err.Error())
		}

		arrayLocker = &controllerService.Locker
		controllerService.IsCSMDREnabled = isCSMDREnabled
	} else if strings.EqualFold(mode, "node") {
		var err error
		nodeService, err = initNodeService(f, configPath)
		if err != nil {
			log.Fatalf("couldn't initialize node service: %s", err.Error())
		}

		nodeName = os.Getenv(identifiers.EnvKubeNodeName)
		arrayLocker = &nodeService.Locker
	}

	if isCSMDREnabled {
		// Initialize CSM DR volume journal reconciler.
		log.Infof("Initializing CSM-DR controller ")
		_, err := drController.Initialize(nodeService, controllerService, arrayLocker, mode, nodeName, ":8080", false, ":8081")
		if err != nil {
			log.Errorf("[METRO] Unable to initialize volume journal reconciler: %s", err.Error())
		}
	}

	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Infof("Config file changed: %s", e.Name)

		if strings.EqualFold(mode, "controller") {
			err := controllerService.UpdateArrays(configPath, f)
			if err != nil {
				log.Fatalf("couldn't initialize arrays in controller service: %s", err.Error())
			}
		} else if strings.EqualFold(mode, "node") {
			err := nodeService.UpdateArrays(configPath, f)
			if err != nil {
				log.Fatalf("couldn't initialize arrays in node service: %s", err.Error())
			}
		}
	})

	InterceptorsList := []grpc.UnaryServerInterceptor{
		interceptors.NewCustomSerialLock(mode),
		interceptors.NewRewriteRequestIDInterceptor(),
	}

	if enableTracing, ok := csictx.LookupEnv(context.Background(), identifiers.EnvDebugEnableTracing); ok && enableTracing != "" {
		log.Infof("Detected debug flag. Enabling Interceptors..")

		t, closer, err := tracer.NewTracer(&config.Configuration{})
		if err != nil {
			log.Fatalf("couldn't create tracer for Jaeger: %s", err.Error())
		}
		defer closer.Close() // #nosec G307
		opentracing.SetGlobalTracer(t)
		InterceptorsList = append(InterceptorsList, grpc_opentracing.UnaryServerInterceptor(grpc_opentracing.WithTracer(t)))
	}

	storageProvider := &gocsi.StoragePlugin{
		Controller:                controllerService,
		Identity:                  identityService,
		Node:                      nodeService,
		Interceptors:              InterceptorsList,
		RegisterAdditionalServers: controllerService.RegisterAdditionalServers,

		EnvVars: []string{
			// Enable request validation.
			gocsi.EnvVarSpecReqValidation + "=true",
			// Enable serial volume access.
			gocsi.EnvVarSerialVolAccess + "=true",
		},
	}

	runCSIPlugin(storageProvider)
}

var runCSIPlugin = func(storageProvider *gocsi.StoragePlugin) {
	gocsi.Run(context.Background(), identifiers.Name,
		"A PowerStore Container Storage Interface (CSI) Driver",
		usage,
		storageProvider,
	)
}

func updateDriverConfigParams(v *viper.Viper) {
	logLevelParam := "CSI_LOG_LEVEL"
	logFormatParam := "CSI_LOG_FORMAT"
	logFormat := strings.ToLower(v.GetString(logFormatParam))
	fmt.Printf("Read CSI_LOG_FORMAT from log configuration file, format: %s\n", logFormat)

	// Use JSON logger as default
	if strings.EqualFold(logFormat, "JSON") {
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	}

	level := csmlog.DebugLevel
	if v.IsSet(logLevelParam) {
		logLevel := v.GetString(logLevelParam)
		if logLevel != "" {
			logLevel = strings.ToLower(logLevel)
			fmt.Printf("Read CSI_LOG_LEVEL from log configuration file, level: %s\n", logLevel)
			var err error

			l, err := csmlog.ParseLevel(logLevel)
			if err != nil {
				log.Errorf("LOG_LEVEL %s value not recognized, setting to default error: %s ", logLevel, err.Error())
			} else {
				level = l
			}
		}
	}
	csmlog.SetLevel(level)
}

func initControllerService(f fs.Interface, configPath string) (*controller.Service, error) {
	cs := &controller.Service{
		Fs: f,
	}

	err := cs.UpdateArrays(configPath, f)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize arrays in controller service: %v", err)
	}

	err = cs.Init()
	if err != nil {
		return nil, fmt.Errorf("couldn't create controller service: %v", err)
	}

	ms, err := monitor.NewMonitorService(context.Background())
	if err != nil {
		return nil, fmt.Errorf("could not start monitor service: %v", err)
	}
	err = ms.UpdateArrays(configPath, f)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize arrays in the monitor service: %v", err)
	}

	go ms.Start(context.Background(), 1*time.Minute)

	return cs, nil
}

func initNodeService(f fs.Interface, configPath string) (*node.Service, error) {
	ns := &node.Service{
		Fs: f,
	}

	err := ns.UpdateArrays(configPath, f)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize arrays in node service: %v", err)
	}

	err = ns.Init()
	if err != nil {
		return nil, fmt.Errorf("couldn't create node service: %v", err)
	}
	return ns, nil
}

const usage = `
	  X_CSI_POWERSTORE_INSECURE
		  Specifies that the PowerStore's hostname and certificate chain
		  should not be verified.

		  The default value is false.

	  X_CSI_POWERSTORE_NODE_ID_PATH
		  Specifies the name of the text file contents of which will
		  be appended to the node ID

	  X_CSI_POWERSTORE_KUBE_NODE_NAME
		  Specifies the name of the kubernetes node

	  X_CSI_POWERSTORE_NODE_NAME_PREFIX
		  Specifies prefix which will be used when registering node
		  on PowerStore array

	  X_CSI_POWERSTORE_NODE_CHROOT_PATH
		  Specifies path to chroot where to execute iSCSI commands

	  X_CSI_POWERSTORE_TMP_DIR
		  Specifies path to the folder which will be used for csi-powerstore temporary files

	  X_CSI_FC_PORTS_FILTER_FILE_PATH
		  Specifies path to the file which provide list of WWPN which
		  should be used by the driver for FC connection on this node
		  example content of the file:
		  21:00:00:29:ff:48:9f:6e,21:00:00:29:ff:48:9f:6e
		  If file does not exist, empty or in invalid format,
		  then the driver will use all available FC ports

	  X_CSI_POWERSTORE_THROTTLING_RATE_LIMIT
		  Specifies a number of concurrent requests to one storage API

	  X_CSI_POWERSTORE_ENABLE_CHAP
		  Specifies whether driver should set CHAP credentials in the ISCSI
		  node database at the time of node plugin boot

	  X_CSI_POWERSTORE_EXTERNAL_ACCESS
		  Specifies an IP of the additional router you wish to add for nfs export
		  Used to provide NFS volumes behind NAT

	  X_CSI_POWERSTORE_CONFIG_PATH
		  Specifies the filepath to PowerStore arrays config file which will be used
		  for connection to PowerStore arrays

	  X_CSI_REPLICATION_CONTEXT_PREFIX
		  Enables sidecars to read required information from volume context

	  X_CSI_REPLICATION_PREFIX
		  Used as a prefix to find out if replication is enabled
  `
