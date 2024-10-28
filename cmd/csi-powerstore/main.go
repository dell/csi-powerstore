/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"strings"
	"time"

	"github.com/dell/csi-powerstore/v2/core"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/common/fs"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/identity"
	"github.com/dell/csi-powerstore/v2/pkg/interceptors"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	"github.com/dell/csi-powerstore/v2/pkg/tracer"
	"github.com/dell/gocsi"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gofsutil"
	"github.com/fsnotify/fsnotify"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/opentracing/opentracing-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/uber/jaeger-client-go/config"
	"google.golang.org/grpc"
)

//go:generate go generate ../../core

func init() {
	// We set X_CSI_DEBUG to false, because we don't want gocsi to override our logging level
	_ = os.Setenv(common.EnvGOCSIDebug, "false")
	// Enable X_CSI_REQ_LOGGING and X_CSI_REP_LOGGING to see gRPC request information
	_ = os.Setenv(gocsi.EnvVarReqLogging, "true")
	_ = os.Setenv(gocsi.EnvVarRepLogging, "true")

	paramsPath, ok := csictx.LookupEnv(context.Background(), common.EnvConfigParamsFilePath)
	if !ok {
		log.Warnf("config path X_CSI_POWERSTORE_CONFIG_PARAMS_PATH is not specified")
	}

	if name, ok := csictx.LookupEnv(context.Background(), common.EnvDriverName); ok {
		common.Name = name
	}

	paramsViper := viper.New()
	paramsViper.SetConfigFile(paramsPath)
	paramsViper.SetConfigType("yaml")

	err := paramsViper.ReadInConfig()
	// if unable to read configuration file, default values will be used in updateDriverConfigParams
	if err != nil {
		log.WithError(err).Error("unable to read config file, using default values")
	}
	paramsViper.WatchConfig()
	paramsViper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Params config file changed:", e.Name)
		updateDriverConfigParams(paramsViper)
	})

	updateDriverConfigParams(paramsViper)

	// If we don't set this env gocsi will overwrite log level with default Info level
	err = os.Setenv(gocsi.EnvVarLogLevel, log.GetLevel().String())
	if err != nil {
		log.WithError(err).Errorf("unable to set env variable %s", gocsi.EnvVarDebug)
	}
}

func main() {
	f := &fs.Fs{Util: &gofsutil.FS{SysBlockDir: "/sys/block"}}

	common.RmSockFile(f)

	identityService := identity.NewIdentityService(common.Name, core.SemVer, common.Manifest)
	var controllerService *controller.Service
	var nodeService *node.Service

	mode := csictx.Getenv(context.Background(), gocsi.EnvVarMode)

	configPath, ok := csictx.LookupEnv(context.Background(), common.EnvArrayConfigFilePath)
	if !ok {
		log.Fatalf("config path X_CSI_POWERSTORE_CONFIG_PATH is not specified")
	}

	if name, ok := csictx.LookupEnv(context.Background(), common.EnvDriverName); ok {
		common.Name = name
	}
	common.SetAPIPort(context.Background())
	if strings.EqualFold(mode, "controller") {
		cs := &controller.Service{
			Fs: f,
		}

		err := cs.UpdateArrays(configPath, f)
		if err != nil {
			log.Fatalf("couldn't initialize arrays in controller service: %s", err.Error())
		}

		err = cs.Init()
		if err != nil {
			log.Fatalf("couldn't create controller service: %s", err.Error())
		}

		controllerService = cs
	} else if strings.EqualFold(mode, "node") {
		ns := &node.Service{
			Fs: f,
		}

		err := ns.UpdateArrays(configPath, f)
		if err != nil {
			log.Fatalf("couldn't initialize arrays in node service: %s", err.Error())
		}

		err = ns.Init()
		if err != nil {
			log.Fatalf("couldn't create node service: %s", err.Error())
		}
		nodeService = ns
	}

	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Config file changed:", e.Name)

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

	interList := []grpc.UnaryServerInterceptor{
		interceptors.NewCustomSerialLock(mode),
		interceptors.NewRewriteRequestIDInterceptor(),
	}

	if enableTracing, ok := csictx.LookupEnv(context.Background(), common.EnvDebugEnableTracing); ok && enableTracing != "" {
		log.Infof("Detected debug flag. Enabling Interceptors..")

		t, closer, err := tracer.NewTracer(&config.Configuration{})
		if err != nil {
			log.Fatalf("couldn't create tracer for Jaeger: %s", err.Error())
		}
		defer closer.Close() // #nosec G307
		opentracing.SetGlobalTracer(t)
		interList = append(interList, grpc_opentracing.UnaryServerInterceptor(grpc_opentracing.WithTracer(t)))
	}

	gocsi.Run(context.Background(), common.Name,
		"A PowerStore Container Storage Interface (CSI) Driver",
		usage,
		&gocsi.StoragePlugin{
			Controller:                controllerService,
			Identity:                  identityService,
			Node:                      nodeService,
			Interceptors:              interList,
			RegisterAdditionalServers: controllerService.RegisterAdditionalServers,

			EnvVars: []string{
				// Enable request validation.
				gocsi.EnvVarSpecReqValidation + "=true",
				// Enable serial volume access.
				gocsi.EnvVarSerialVolAccess + "=true",
			},
		})
}

func updateDriverConfigParams(v *viper.Viper) {
	logLevelParam := "CSI_LOG_LEVEL"
	logFormatParam := "CSI_LOG_FORMAT"
	logFormat := strings.ToLower(v.GetString(logFormatParam))
	fmt.Printf("Read CSI_LOG_FORMAT from log configuration file, format: %s\n", logFormat)

	// Use JSON logger as default
	if !strings.EqualFold(logFormat, "text") {
		log.SetFormatter(&log.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		})
	} else {
		log.SetFormatter(&log.TextFormatter{})
	}

	level := log.DebugLevel
	if v.IsSet(logLevelParam) {
		logLevel := v.GetString(logLevelParam)
		if logLevel != "" {
			logLevel = strings.ToLower(logLevel)
			fmt.Printf("Read CSI_LOG_LEVEL from log configuration file, level: %s\n", logLevel)
			var err error

			l, err := log.ParseLevel(logLevel)
			if err != nil {
				log.WithError(err).Errorf("LOG_LEVEL %s value not recognized, setting to default error: %s ", logLevel, err.Error())
			} else {
				level = l
			}
		}
	}
	log.SetLevel(level)
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
