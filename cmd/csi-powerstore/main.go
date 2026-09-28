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
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/collectors"
	"github.com/dell/csi-powerstore/v2/pkg/controller"
	"github.com/dell/csi-powerstore/v2/pkg/groupcontroller"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csi-powerstore/v2/pkg/identity"
	"github.com/dell/csi-powerstore/v2/pkg/interceptors"
	"github.com/dell/csi-powerstore/v2/pkg/metrics"
	"github.com/dell/csi-powerstore/v2/pkg/metricsruntime"
	"github.com/dell/csi-powerstore/v2/pkg/monitor"
	"github.com/dell/csi-powerstore/v2/pkg/node"
	"github.com/dell/csi-powerstore/v2/pkg/tracer"
	drController "github.com/dell/csm-dr/pkg/controller"
	log "github.com/dell/csmlog"
	"github.com/dell/gocsi"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gofsutil"
	"github.com/fsnotify/fsnotify"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	"github.com/uber/jaeger-client-go/config"
	"google.golang.org/grpc"
)

//go:generate go generate ../../core

func init() {
	updateDriverName()

	initilizeDriverConfigParams()
}

func updateDriverName() {
	if name, ok := csictx.LookupEnv(context.Background(), identifiers.EnvDriverName); ok {
		identifiers.Name = name
	}
}

func initilizeDriverConfigParams() {
	log.SetLevel(log.InfoLevel)
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
		log.Infof("Configuration change: driver parameters config file changed: %s", e.Name)
		updateDriverConfigParams(paramsViper)
	})

	updateDriverConfigParams(paramsViper)
}

var ManifestSemver string

// validateAndSetDRBindPort validates the CSM DR bind port environment variable
// and returns a valid port string, defaulting to ":8082" if invalid
func validateAndSetDRBindPort(envPort string) string {
	defaultPort := ":8082"
	if envPort == "" {
		return defaultPort
	}

	port, err := strconv.Atoi(envPort)
	if err != nil {
		log.Warnf("Invalid CSM DR bind port '%s'. Must be a valid number (e.g., ':8082'). Using default :8082", envPort)
		return defaultPort
	}

	if port < 1 || port > 65535 {
		log.Warnf("Invalid CSM DR bind port '%d'. Must be between 1 and 65535. Using default :8082", port)
		return defaultPort
	}

	return ":" + envPort
}

func main() {
	log.WithFields(log.Fields{
		log.FieldComponent: "driver",
		log.FieldOperation: "startup",
		"version":          ManifestSemver,
		"driver_name":      identifiers.Name,
	}).Info("initializing CSI PowerStore driver")

	f := &fs.Fs{Util: &gofsutil.FS{}}

	identifiers.RmSockFile(f)

	if ManifestSemver != "" {
		log.Info("ManifestVersion isn't empty, setting it")
		identifiers.ManifestSemver = ManifestSemver
		identifiers.Manifest["semver"] = ManifestSemver
	}

	identityService := identity.NewIdentityService(identifiers.Name, ManifestSemver, identifiers.Manifest)
	var controllerService *controller.Service
	var groupControllerService *groupcontroller.Service
	var nodeService *node.Service

	mode := csictx.Getenv(context.Background(), gocsi.EnvVarMode)
	log.WithFields(log.Fields{
		log.FieldComponent: "driver",
		log.FieldOperation: "startup",
		"mode":             mode,
	}).Info("operating mode determined")

	configPath, ok := csictx.LookupEnv(context.Background(), identifiers.EnvArrayConfigFilePath)
	if !ok {
		log.Fatalf("config path X_CSI_POWERSTORE_CONFIG_PATH is not specified")
	}
	metricsRegistry := metrics.NewRegistry()
	metricsEnabled := false
	if enabled, ok := csictx.LookupEnv(context.Background(), identifiers.EnvMetricsEnabled); ok {
		metricsEnabled = strings.EqualFold(enabled, "true")
	}
	if metricsEnabled {
		_, _ = ensureKubeClient(context.Background())
	}
	var metricsServer *metrics.Server
	if metricsEnabled {
		metricsServer = metrics.StartServerFromEnv(context.Background(), metricsRegistry)
	}

	if name, ok := csictx.LookupEnv(context.Background(), identifiers.EnvDriverName); ok {
		identifiers.Name = name
	}
	identifiers.SetAPIPort(context.Background())

	var nodeName string
	var arrayLocker *array.Locker
	var monitorService monitor.IMonitorService
	var metricsState *metricsruntime.RuntimeState
	var metricsStateMu sync.Mutex
	sharedMetadataChecker := &collectors.SharedMetadataChecker{}

	isCSMDREnabled, err := strconv.ParseBool(os.Getenv(identifiers.EnvCSMDREnabled))
	if err != nil {
		log.Infof("Error parsing %s: %s. Defaulting to true", identifiers.EnvCSMDREnabled, err.Error())
		isCSMDREnabled = true
	}

	// Parse CSI-Addons replication feature flag (default: false)
	csiAddonsEnv := os.Getenv(identifiers.EnvCSIAddonsReplicationEnabled)
	isCSIAddonsReplicationEnabled := false
	if csiAddonsEnv != "" {
		var addonsErr error
		isCSIAddonsReplicationEnabled, addonsErr = strconv.ParseBool(csiAddonsEnv)
		if addonsErr != nil {
			log.Infof("Error parsing %s: %s. Defaulting to false", identifiers.EnvCSIAddonsReplicationEnabled, addonsErr.Error())
			isCSIAddonsReplicationEnabled = false
		}
	}

	if strings.EqualFold(mode, "controller") {
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "startup",
			"config_path":      configPath,
		}).Info("initializing controller service")

		var err error
		controllerService, err = initControllerService(f, configPath, metricsRegistry)
		if err != nil {
			log.Fatalf("couldn't initialize controller service: %s", err.Error())
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "startup",
		}).Info("controller service initialized successfully")

		groupControllerService, err = initGroupControllerService(f, configPath, metricsRegistry)
		if err != nil {
			log.Fatalf("couldn't initialize group controller service: %s", err.Error())
		}

		// Check if monitor service is enabled
		monitorEnabled := true
		if enabled, ok := csictx.LookupEnv(context.Background(), identifiers.EnvMonitorEnabled); ok {
			parsed, err := strconv.ParseBool(enabled)
			if err != nil {
				log.Warnf("invalid %s value %q, defaulting to true", identifiers.EnvMonitorEnabled, enabled)
			} else {
				monitorEnabled = parsed
			}
		}

		if monitorEnabled {
			monitorService, err = newMonitorServiceFunc(context.Background())
			if err != nil {
				log.Fatalf("couldn't initialize monitor service: %s", err.Error())
			}
			monitorService.SetArrays(controllerService.Arrays())
			monitorService.SetDefaultArray(controllerService.DefaultArray())

			// Get monitor poll interval (default: 5 minutes)
			monitorPollInterval := 5 * time.Minute
			if intervalStr, ok := csictx.LookupEnv(context.Background(), identifiers.EnvMonitorPollInterval); ok {
				if interval, err := time.ParseDuration(intervalStr); err == nil && interval > 0 {
					monitorPollInterval = interval
				} else if err != nil {
					log.Warnf("invalid %s value %q, using default %s", identifiers.EnvMonitorPollInterval, intervalStr, monitorPollInterval)
				} else {
					log.Warnf("%s value %q is not positive, using default %s", identifiers.EnvMonitorPollInterval, intervalStr, monitorPollInterval)
				}
			}

			go monitorService.Start(context.Background(), monitorPollInterval)
		} else {
			log.Infof("monitor service disabled")
		}
		if metricsEnabled {
			metricsStateMu.Lock()
			metricsState = metricsruntime.StartCollectors(context.Background(), metricsRegistry, metricsServer, mode, controllerService.Arrays(), metricsState, sharedMetadataChecker)
			metricsStateMu.Unlock()
		}

		arrayLocker = &controllerService.Locker
		controllerService.IsCSMDREnabled = isCSMDREnabled
		controllerService.IsCSIAddonsReplicationEnabled = isCSIAddonsReplicationEnabled

		if isCSIAddonsReplicationEnabled {
			log.Info("CSI-Addons replication support is enabled")
		}

		if isCSMDREnabled && isCSIAddonsReplicationEnabled {
			log.Warnf("Both CSM-DR and CSI-Addons replication are enabled. This is not recommended and may cause conflicts.")
		}
	} else if strings.EqualFold(mode, "node") {
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "startup",
			"config_path":      configPath,
		}).Info("initializing node service")

		var err error
		nodeService, err = initNodeServiceFunc(f, configPath, metricsRegistry)
		if err != nil {
			log.Fatalf("couldn't initialize node service: %s", err.Error())
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "startup",
		}).Info("node service initialized successfully")
		if metricsEnabled {
			metricsStateMu.Lock()
			metricsState = metricsruntime.StartCollectors(context.Background(), metricsRegistry, metricsServer, mode, nodeService.Arrays(), metricsState, sharedMetadataChecker)
			metricsStateMu.Unlock()
		}

		nodeName = os.Getenv(identifiers.EnvKubeNodeName)
		arrayLocker = &nodeService.Locker
	}

	if isCSMDREnabled {
		// Initialize CSM DR volume journal reconciler.
		drBindPort := validateAndSetDRBindPort(os.Getenv(identifiers.EnvCSMDRBindPort))

		log.Infof("Initializing CSM-DR controller with bind port %s", drBindPort)

		_, err := drController.Initialize(nodeService, controllerService, arrayLocker, mode, nodeName, drBindPort, false)
		if err != nil {
			log.Errorf("[METRO] Unable to initialize volume journal reconciler: %s", err.Error())
		}
	}

	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		handleConfigChange(e, mode, f, configPath, metricsRegistry, metricsEnabled, metricsServer, &metricsStateMu, &metricsState, sharedMetadataChecker, controllerService, groupControllerService, nodeService, monitorService)
	})

	InterceptorsList := []grpc.UnaryServerInterceptor{
		interceptors.NewCustomSerialLock(mode),
		interceptors.NewRewriteRequestIDInterceptor(),
	}

	// Reuse the collector metadata checker for metrics interceptor protocol resolution.
	var protocolResolver collectors.ProtocolResolver
	if metricsEnabled {
		protocolResolver = sharedMetadataChecker
		InterceptorsList = append(InterceptorsList, interceptors.NewMetricsInterceptor(metricsRegistry, "unknown", protocolResolver))
	}

	if enableTracing, ok := csictx.LookupEnv(context.Background(), identifiers.EnvDebugEnableTracing); ok && enableTracing != "" {
		log.Infof("Detected debug flag. Enabling Interceptors..")

		t, closer, err := tracer.NewTracer(&config.Configuration{})
		if err != nil {
			log.Fatalf("couldn't create tracer for Jaeger: %s", err.Error())
		}
		defer func() { _ = closer.Close() }() // #nosec G307
		opentracing.SetGlobalTracer(t)
		InterceptorsList = append(InterceptorsList, grpc_opentracing.UnaryServerInterceptor(grpc_opentracing.WithTracer(t)))
	}

	var registerAdditionalServers func(*grpc.Server)
	if controllerService != nil {
		registerAdditionalServers = controllerService.RegisterAdditionalServers
	}
	storageProvider := &gocsi.StoragePlugin{
		Controller:                controllerService,
		Identity:                  identityService,
		GroupController:           groupControllerService,
		Node:                      nodeService,
		Interceptors:              InterceptorsList,
		RegisterAdditionalServers: registerAdditionalServers,

		EnvVars: []string{
			// Enable request validation.
			gocsi.EnvVarSpecReqValidation + "=true",
			// Enable serial volume access.
			gocsi.EnvVarSerialVolAccess + "=true",
		},
	}

	// Graceful shutdown handling
	setupGracefulShutdown(mode, &metricsStateMu, &metricsState, controllerService)

	log.WithFields(log.Fields{
		log.FieldComponent: "driver",
		log.FieldOperation: "startup",
		"driver_name":      identifiers.Name,
		"mode":             mode,
	}).Info("CSI PowerStore driver ready to serve")
	runCSIPlugin(storageProvider)
}

// handleConfigChange handles configuration file changes
func handleConfigChange(e fsnotify.Event, mode string, f fs.Interface, configPath string, metricsRegistry *prometheus.Registry, metricsEnabled bool, metricsServer *metrics.Server, metricsStateMu *sync.Mutex, metricsState **metricsruntime.RuntimeState, sharedMetadataChecker *collectors.SharedMetadataChecker, controllerService *controller.Service, groupControllerService *groupcontroller.Service, nodeService *node.Service, monitorService monitor.IMonitorService) {
	log.WithFields(log.Fields{
		log.FieldComponent: "driver",
		log.FieldOperation: "ConfigChange",
		"file":             e.Name,
		"op":               e.Op.String(),
	}).Info("configuration change detected")

	if strings.EqualFold(mode, "controller") {
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "ConfigChange",
		}).Info("reloading arrays for controller and group controller services")
		err := controllerService.UpdateArrays(configPath, f, metricsRegistry)
		if err != nil {
			log.Fatalf("couldn't initialize arrays in controller service: %s", err.Error())
		}
		if monitorService != nil {
			monitorService.SetArrays(controllerService.Arrays())
			monitorService.SetDefaultArray(controllerService.DefaultArray())
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "ConfigChange",
		}).Info("controller service arrays reloaded successfully")
		err = groupControllerService.UpdateArrays(configPath, f, metricsRegistry)
		if err != nil {
			log.Fatalf("couldn't initialize arrays in group controller service: %s", err.Error())
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "ConfigChange",
		}).Info("group controller service arrays reloaded successfully")
		if metricsEnabled {
			metricsStateMu.Lock()
			*metricsState = metricsruntime.StartCollectors(context.Background(), metricsRegistry, metricsServer, mode, controllerService.Arrays(), *metricsState, sharedMetadataChecker)
			metricsStateMu.Unlock()
		}
	} else if strings.EqualFold(mode, "node") {
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "ConfigChange",
		}).Info("reloading arrays for node service")
		err := nodeService.UpdateArrays(configPath, f, metricsRegistry)
		if err != nil {
			log.Fatalf("couldn't initialize arrays in node service: %s", err.Error())
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "ConfigChange",
		}).Info("node service arrays reloaded successfully")
		if metricsEnabled {
			metricsStateMu.Lock()
			*metricsState = metricsruntime.StartCollectors(context.Background(), metricsRegistry, metricsServer, mode, nodeService.Arrays(), *metricsState, sharedMetadataChecker)
			metricsStateMu.Unlock()
		}
	}
}

// setupGracefulShutdown sets up graceful shutdown signal handling
func setupGracefulShutdown(mode string, metricsStateMu *sync.Mutex, metricsState **metricsruntime.RuntimeState, controllerService *controller.Service) {
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigChan
		metricsStateMu.Lock()
		if *metricsState != nil {
			(*metricsState).Stop()
			*metricsState = nil
		}
		metricsStateMu.Unlock()
		// Shutdown controller service to stop EventBroadcaster goroutines
		if controllerService != nil {
			controllerService.Shutdown()
		}
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "shutdown",
			"signal":           sig.String(),
		}).Info("received signal, initiating graceful shutdown")
		log.WithFields(log.Fields{
			log.FieldComponent: "driver",
			log.FieldOperation: "shutdown",
			"driver_name":      identifiers.Name,
			"mode":             mode,
		}).Info("CSI PowerStore driver shutting down")
	}()
}

var initNodeServiceFunc = initNodeService

var newMonitorServiceFunc = monitor.NewMonitorService

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
	logFormat := "json"

	if v.IsSet(logFormatParam) {
		logFormat = strings.ToLower(v.GetString(logFormatParam))
		if logFormat == "" || (logFormat != "json" && logFormat != "text") {
			log.Info("CSI_LOG_FORMAT not specified or invalid, setting to default (JSON)")
			logFormat = "json"
		}
	}
	log.SetFormat(logFormat)

	level := log.InfoLevel
	if v.IsSet(logLevelParam) {
		logLevel := v.GetString(logLevelParam)
		if logLevel != "" {
			logLevel = strings.ToLower(logLevel)

			var err error

			l, err := log.ParseLevel(logLevel)
			if err != nil {
				log.Errorf("LOG_LEVEL %s value not recognized, setting to default (info): %s ", logLevel, err.Error())
			} else {
				level = l
			}
		}
	}
	log.SetLevel(level)
	log.WithFields(log.Fields{
		log.FieldComponent: "driver",
		log.FieldOperation: "ConfigChange",
		"log_level":        level.String(),
		"log_format":       logFormat,
	}).Info("log level and format applied")
}

func initControllerService(f fs.Interface, configPath string, metricsRegistry prometheus.Registerer) (*controller.Service, error) {
	cs := &controller.Service{
		Fs: f,
	}

	err := cs.UpdateArrays(configPath, f, metricsRegistry)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize arrays in controller service: %v", err)
	}

	err = cs.Init()
	if err != nil {
		return nil, fmt.Errorf("couldn't create controller service: %v", err)
	}

	return cs, nil
}

func initGroupControllerService(f fs.Interface, configPath string, metricsRegistry prometheus.Registerer) (*groupcontroller.Service, error) {
	log.Infof("Initializing group controller service with config path: %s", configPath)
	gcs := &groupcontroller.Service{
		Fs: f,
	}

	err := gcs.UpdateArrays(configPath, f, metricsRegistry)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize arrays in group controller service: %v", err)
	}

	err = gcs.Init()
	if err != nil {
		return nil, fmt.Errorf("couldn't create group controller service: %v", err)
	}
	log.Infof("Done initializing group controller service with config path: %s", configPath)

	return gcs, nil
}

func initNodeService(f fs.Interface, configPath string, metricsRegistry prometheus.Registerer) (*node.Service, error) {
	ns := &node.Service{
		Fs: f,
	}

	err := ns.UpdateArrays(configPath, f, metricsRegistry)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize arrays in node service: %v", err)
	}

	err = ns.Init()
	if err != nil {
		return nil, fmt.Errorf("couldn't create node service: %v", err)
	}
	return ns, nil
}

func ensureKubeClient(ctx context.Context) (*k8sutils.K8sClient, error) {
	if k8sutils.Kubeclient != nil && k8sutils.Kubeclient.Clientset != nil {
		return k8sutils.Kubeclient, nil
	}
	kubeConfigPath, _ := csictx.LookupEnv(ctx, identifiers.EnvKubeConfigPath)
	return k8sutils.CreateKubeClientSet(kubeConfigPath)
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
