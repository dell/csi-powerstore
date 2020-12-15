/*
 *
 * Copyright © 2020 Dell Inc. or its subsidiaries. All Rights Reserved.
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
 *
 */

package service

import (
	"context"
	"fmt"
	"github.com/dell/csi-powerstore/core"
	"github.com/dell/gofsutil"
	"github.com/dell/goiscsi"
	"github.com/dell/gopowerstore"
	"github.com/rexray/gocsi"
	csictx "github.com/rexray/gocsi/context"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type transportType string

const (
	defaultNodeNamePrefix = "csi_node"
	defaultNodeChrootPath = "/noderoot"

	// default opts values
	defaultNodePublishDeviceWaitRetries = 3
	defaultNodePublishDeviceWaitSeconds = 15
	defaultThrottlingTimeoutSeconds     = 120
	defaultThrottlingRateLimit          = 20
	defaultDebugHTTPServerListenAddress = "0.0.0.0:8080"
	defaultTmpDir                       = "tmp"

	contextLogFieldsKey = "logFields"

	fcTransport         transportType = "FC"
	iSCSITransport      transportType = "iSCSI"
	autoDetectTransport transportType = "AUTO"
	noneTransport       transportType = "None"
)

// Name is the name of the CSI plug-in.
var Name = "csi-powerstore.dellemc.com"
var VerboseName = "CSI Driver for Dell EMC PowerStore"

// Manifest is the SP's manifest.
var Manifest = map[string]string{
	"url":    "http://github.com/dell/csi-powerstore",
	"semver": core.SemVer,
	"commit": core.CommitSha32,
	"formed": core.CommitTime.Format(time.RFC1123),
}

// Opts defines service configuration options.
type Opts struct {
	Endpoint                     string
	User                         string
	Password                     string
	NodeIDFilePath               string
	NodeNamePrefix               string
	KubeNodeName                 string
	NodeChrootPath               string
	FCPortsFilterFilePath        string
	TmpDir                       string
	CHAPUserName                 string
	CHAPPassword                 string
	DebugHTTPServerListenAddress string
	Insecure                     bool
	AutoProbe                    bool
	EnableTracing                bool
	EnableCHAP                   bool
	NodePublishDeviceWaitRetries int
	NodePublishDeviceWaitSeconds int
	ThrottlingTimeoutSeconds     int
	ThrottlingRateLimit          int
	PreferredTransport           transportType
}

// ISCSITargetInfo represents basic information about iSCSI target
type ISCSITargetInfo struct {
	Portal string
	Target string
}

// FCTargetInfo represents basic information about FC target
type FCTargetInfo struct {
	WWPN string
}

type TimeoutSemaphoreError struct {
	msg string
}

func (e *TimeoutSemaphoreError) Error() string {
	return e.msg
}

type timeoutSemaphoreIMPL struct {
	timeout   time.Duration
	semaphore chan struct{}
}

func newTimeoutSemaphore(timeout, rateLimit int) *timeoutSemaphoreIMPL {
	return &timeoutSemaphoreIMPL{
		timeout:   time.Duration(timeout) * time.Second,
		semaphore: make(chan struct{}, rateLimit),
	}
}

func (ts *timeoutSemaphoreIMPL) Acquire(ctx context.Context) error {
	var cancelFunc func()
	ctx, cancelFunc = context.WithTimeout(ctx, ts.timeout)
	defer cancelFunc()
	for {
		select {
		case ts.semaphore <- struct{}{}:
			log.WithFields(getLogFields(ctx)).Info("acquire a lock")
			return nil
		case <-ctx.Done():
			msg := "lock is acquire failed, timeout expired"
			log.WithFields(getLogFields(ctx)).Info(msg)
			return &TimeoutSemaphoreError{msg}
		}
	}
}

func (ts *timeoutSemaphoreIMPL) Release(ctx context.Context) {
	<-ts.semaphore
	log.WithFields(getLogFields(ctx)).Info("release a lock")
}

type service struct {
	opts Opts
	mode string

	// controller
	adminClient gopowerstore.Client
	apiThrottle timeoutSemaphore

	// node
	nodeID            string
	nodeRescanMutex   sync.Mutex
	nodeIsInitialized bool
	nodeFSLib         wrapperFsLib
	impl              internalServiceAPI
	nodeMountLib      mountLib
	iscsiConnector    iSCSIConnector
	fcConnector       fcConnector
	volToDevMapper    volToDevMapper
	endpointIP        string
	iscsiLib          goiscsi.ISCSIinterface
	reusedHost        bool

	// wrappers
	fileReader fileReader
	fileWriter fileWriter
	filePath   filePath
	os         limitedOSIFace
	mkdir      dirCreator

	useFC bool

	debugHTTPServer *http.Server
}

// New returns a new Service.
func New() Service {
	return initService()
}

func NewWithOptions(client gopowerstore.Client) Service {
	svc := initService()
	if client != nil {
		svc.adminClient = client
	}
	return svc
}

func initService() *service {
	osWrp := &osWrapper{}
	ioutilWrp := &ioutilWrapper{}
	serv := &service{
		fileReader: ioutilWrp,
		fileWriter: ioutilWrp,
		filePath:   &filepathWrapper{},
		os:         osWrp,
		mkdir:      newMkdir(osWrp),
	}
	impl := serviceIMPL{}
	impl.service = serv
	impl.implProxy = &impl
	serv.impl = &impl
	return serv
}

func (s *service) BeforeServe(
	ctx context.Context, sp *gocsi.StoragePlugin, lis net.Listener) error {

	if name, ok := csictx.LookupEnv(ctx, EnvDriverName); ok {
		Name = name
	}
	log.WithFields(log.Fields{"version": core.SemVer, "commit": core.CommitSha32}).Info(Name)
	defer func() {
		fields := map[string]interface{}{
			"endpoint":         s.opts.Endpoint,
			"user":             s.opts.User,
			"password":         "",
			"insecure":         s.opts.Insecure,
			"autoprobe":        s.opts.AutoProbe,
			"node_id_filepath": s.opts.NodeIDFilePath,
			"tmp_dir":          s.opts.TmpDir,
			"mode":             s.mode,
		}

		if s.opts.Password != "" {
			fields["password"] = "******"
		}

		log.WithFields(fields).Infof("configured %s", Name)
	}()
	// Get the SP's operating mode.
	s.mode = csictx.Getenv(ctx, gocsi.EnvVarMode)

	opts := Opts{}

	opts.NodePublishDeviceWaitRetries = defaultNodePublishDeviceWaitRetries
	opts.NodePublishDeviceWaitSeconds = defaultNodePublishDeviceWaitSeconds

	if ep, ok := csictx.LookupEnv(ctx, EnvEndpoint); ok {
		opts.Endpoint = ep

		ipList := getIPListFromString(ep)
		if ipList == nil || len(ipList) == 0 {
			log.Error("can't find ip in endpoint")
		} else {
			s.endpointIP = ipList[0]
		}

	}
	if user, ok := csictx.LookupEnv(ctx, EnvUser); ok {
		opts.User = strings.Trim(user, "\n")
	}
	if opts.User == "" {
		opts.User = "admin"
	}
	if pw, ok := csictx.LookupEnv(ctx, EnvPassword); ok {
		opts.Password = strings.Trim(pw, "\n")
	}
	if path, ok := csictx.LookupEnv(ctx, EnvNodeIDFilePath); ok {
		opts.NodeIDFilePath = path
	}

	if prefix, ok := csictx.LookupEnv(ctx, EnvNodeNamePrefix); ok {
		opts.NodeNamePrefix = prefix
	}
	if opts.NodeNamePrefix == "" {
		opts.NodeNamePrefix = defaultNodeNamePrefix
	}

	if kubeNodeName, ok := csictx.LookupEnv(ctx, EnvKubeNodeName); ok {
		opts.KubeNodeName = kubeNodeName
	}

	if nodeChrootPath, ok := csictx.LookupEnv(ctx, EnvNodeChrootPath); ok {
		opts.NodeChrootPath = nodeChrootPath
	}

	if opts.NodeChrootPath == "" {
		opts.NodeChrootPath = defaultNodeChrootPath
	}

	if debugHTTPServerListenAddress, ok := csictx.LookupEnv(ctx, EnvDebugHTTPServerListenAddress); ok {
		opts.DebugHTTPServerListenAddress = debugHTTPServerListenAddress
	}

	if opts.DebugHTTPServerListenAddress == "" {
		opts.DebugHTTPServerListenAddress = defaultDebugHTTPServerListenAddress
	}

	if fcPortsFilterFilePath, ok := csictx.LookupEnv(ctx, EnvFCPortsFilterFilePath); ok {
		opts.FCPortsFilterFilePath = fcPortsFilterFilePath
	}

	if chapUsername, ok := csictx.LookupEnv(ctx, EnvCHAPUserName); ok {
		opts.CHAPUserName = chapUsername
	}

	if chapPw, ok := csictx.LookupEnv(ctx, EnvCHAPPassword); ok {
		opts.CHAPPassword = chapPw
	}

	if tmpDir, ok := csictx.LookupEnv(ctx, EnvTmpDir); ok {
		opts.TmpDir = tmpDir
	}
	if opts.TmpDir == "" {
		opts.TmpDir = defaultTmpDir
	}
	_, err := s.mkdir.mkDir(opts.TmpDir)
	if err != nil {
		log.Error("failed to create tmp dir")
		return err
	}

	opts.PreferredTransport = getTransportProtocolFromEnv()

	// // pb parses an environment variable into a boolean value. If an error
	// // is encountered, default is set to false, and error is logged
	pb := func(n string) bool {
		if v, ok := csictx.LookupEnv(ctx, n); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				log.WithField(n, v).Debug(
					"invalid boolean value. defaulting to false")
				return false
			}
			return b
		}
		return false
	}

	opts.Insecure = pb(EnvInsecure)
	opts.AutoProbe = pb(EnvAutoProbe)
	opts.EnableTracing = pb(EnvEnableTracing)
	opts.EnableCHAP = pb(EnvEnableCHAP)

	if throttlingRateLimit, ok := csictx.LookupEnv(ctx, EnvThrottlingRateLimit); ok {
		opts.ThrottlingRateLimit, err = strconv.Atoi(throttlingRateLimit)
		if err != nil {
			return err
		}
	}
	s.opts = opts

	s.impl.initCustomInterceptors(sp, opts)

	if opts.EnableTracing {
		go s.impl.runDebugHTTPServer(ctx, sp)
	}

	// seed the random methods
	rand.Seed(time.Now().Unix())

	if _, ok := csictx.LookupEnv(ctx, EnvNoProbeOnStart); !ok {
		// Do a controller probe
		if strings.EqualFold(s.mode, "controller") {
			if _, err := s.controllerProbe(ctx); err != nil {
				return err
			}
		}

		// Do a node probe
		if strings.EqualFold(s.mode, "node") {
			if _, err := s.impl.nodeProbe(ctx); err != nil {
				return err
			}
		}
	}

	// If this is a node, run the node startup logic
	if _, ok := csictx.LookupEnv(ctx, EnvNoNodeRegistration); !ok && strings.EqualFold(s.mode, "node") {
		if err := s.impl.nodeStartup(ctx, sp); err != nil {
			return err
		}
	} else {
		log.Info("skip node registration")
	}

	return nil
}

func (s *service) ShutDown(ctx context.Context) error {
	log.Info("service shutdown")
	if s.debugHTTPServer != nil {
		return s.debugHTTPServer.Close()
	}
	return nil
}

func getTransportProtocolFromEnv() transportType {
	if tp, ok := csictx.LookupEnv(context.Background(), EnvPreferredTransportProtocol); ok {
		tp = strings.ToLower(tp)
		switch tp {
		case "fc":
			return fcTransport
		case "iscsi":
			return iSCSITransport
		case "none":
			return noneTransport
		}
	}
	log.Errorf("enable storage transport auto detect")
	return autoDetectTransport
}

func (si *serviceIMPL) runDebugHTTPServer(ctx context.Context, gs gracefulStopper) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/requests", func(writer http.ResponseWriter, request *http.Request) {
		trace.Render(writer, request, false)
	})
	si.service.debugHTTPServer = &http.Server{Handler: mux, Addr: si.service.opts.DebugHTTPServerListenAddress}
	err := si.service.debugHTTPServer.ListenAndServe()
	if err != nil {
		log.Errorf("failed to start debug http server: %s", err.Error())
		gs.GracefulStop(ctx)
	}
}

func (si *serviceIMPL) initCustomInterceptors(sp *gocsi.StoragePlugin, opts Opts) {
	log.Info("initialization of a custom interceptors")
	sp.Interceptors = append(sp.Interceptors, NewCustomSerialLock(), NewRewriteRequestIDInterceptor())
	if opts.EnableTracing {
		sp.Interceptors = append(sp.Interceptors, NewTracingInterceptor())
	}
}

type customLogger struct{}

func (lg *customLogger) Info(ctx context.Context, format string, args ...interface{}) {
	log.WithFields(getLogFields(ctx)).Infof(format, args...)
}
func (lg *customLogger) Debug(ctx context.Context, format string, args ...interface{}) {
	log.WithFields(getLogFields(ctx)).Debugf(format, args...)
}
func (lg *customLogger) Error(ctx context.Context, format string, args ...interface{}) {
	log.WithFields(getLogFields(ctx)).Errorf(format, args...)
}

type customTracer struct{}

func (ct *customTracer) Trace(ctx context.Context, format string, args ...interface{}) {
	if tr, ok := trace.FromContext(ctx); ok {
		tr.LazyPrintf(format, args...)
		return
	}
}

func copyTraceObj(src context.Context, dst context.Context) context.Context {
	if tr, ok := trace.FromContext(src); ok {
		return trace.NewContext(dst, tr)
	}
	return dst
}

func (si *serviceIMPL) initPowerStoreClient() error {

	// Check that we have the details needed to login to the API
	if si.service.opts.Endpoint == "" {
		return status.Error(codes.FailedPrecondition,
			"missing PowerStore API endpoint")
	}
	if si.service.opts.User == "" {
		return status.Error(codes.FailedPrecondition,
			"missing PowerStore API user")
	}
	if si.service.opts.Password == "" {
		return status.Error(codes.FailedPrecondition,
			"missing PowerStore API password")
	}

	// Create our PowerStore API client, if needed
	if si.service.adminClient == nil {
		clientOptions := gopowerstore.NewClientOptions()
		clientOptions.SetInsecure(si.service.opts.Insecure)

		c, err := gopowerstore.NewClientWithArgs(
			si.service.opts.Endpoint, si.service.opts.User, si.service.opts.Password, clientOptions)
		if err != nil {
			return status.Errorf(codes.FailedPrecondition,
				"unable to create PowerStore client: %s", err.Error())
		}
		c.SetCustomHTTPHeaders(http.Header{
			"Application-Type": {fmt.Sprintf("%s/%s", VerboseName, core.SemVer)}})

		c.SetLogger(&customLogger{})
		si.service.adminClient = c
	}
	return nil
}

func (si *serviceIMPL) initApiThrottle() error {
	log.Info("initialization of api throttle")
	if si.service.opts.ThrottlingRateLimit < 1 {
		si.service.opts.ThrottlingRateLimit = defaultThrottlingRateLimit
	}
	if si.service.opts.ThrottlingTimeoutSeconds < 1 {
		si.service.opts.ThrottlingTimeoutSeconds = defaultThrottlingTimeoutSeconds
	}

	if si.service.apiThrottle == nil {
		si.service.apiThrottle = newTimeoutSemaphore(
			si.service.opts.ThrottlingTimeoutSeconds,
			si.service.opts.ThrottlingRateLimit,
		)
	}
	return nil
}

func (s *service) getVolByID(ctx context.Context, id string) (*gopowerstore.Volume, error) {
	vol, err := s.adminClient.GetVolume(ctx, id)
	if err != nil {
		return nil, err
	}
	return &vol, nil
}

func (s *service) getNodeByID(ctx context.Context, id string) (*gopowerstore.Host, error) {
	node, err := s.adminClient.GetHostByName(ctx, id)
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// Returns list of ips in string form found in input string
// A return value of nil indicates no match
func getIPListFromString(input string) []string {
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	return re.FindAllString(input, -1)
}

// internal API implementation
type serviceIMPL struct {
	// service is a pointer to the service instance
	service *service
	// implProxy provide "self" or "this" pointer. Needed to simplify internalServiceAPI methods mocking.
	implProxy internalServiceAPI
}

type ioutilWrapper struct{}

func (io *ioutilWrapper) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename) // #nosec G304
}

func (io *ioutilWrapper) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(filename, data, perm) // #nosec G304
}

type filepathWrapper struct{}

func (io *filepathWrapper) Glob(pattern string) (matches []string, err error) {
	return filepath.Glob(pattern)
}

type osWrapper struct{}

func (io *osWrapper) OpenFile(name string, flag int, perm os.FileMode) (limitedFileIFace, error) {
	return os.OpenFile(name, flag, perm) // #nosec G304
}

func (io *osWrapper) WriteString(file *os.File, string string) (int, error) {
	return file.WriteString(string) // #nosec G304
}

func (io *osWrapper) Create(name string) (*os.File, error) {
	return os.Create(name) // #nosec G304
}

func (io *osWrapper) ReadFile(name string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Clean(name))
}

func (io *osWrapper) Stat(name string) (limitedFileInfoIFace, error) {
	return os.Stat(name)
}

func (io *osWrapper) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

func (io *osWrapper) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

func (io *osWrapper) MkdirAll(name string, perm os.FileMode) error {
	return os.MkdirAll(name, perm)
}

func (io *osWrapper) Remove(name string) error {
	return os.Remove(name)
}

type gofsutilWrapper struct {
	gofsutil.FS
}

func (fsu *gofsutilWrapper) ParseProcMounts(
	ctx context.Context,
	content io.Reader) ([]gofsutil.Info, error) {
	r, _, err := gofsutil.ReadProcMountsFrom(ctx, content, false,
		gofsutil.ProcMountsFields, gofsutil.DefaultEntryScanFunc())
	return r, err
}

func (io *osWrapper) ExecCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput() // #nosec G204
}

func setLogFields(ctx context.Context, fields log.Fields) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, contextLogFieldsKey, fields)
}

func getLogFields(ctx context.Context) log.Fields {
	if ctx == nil {
		return log.Fields{}
	}
	fields, ok := ctx.Value(contextLogFieldsKey).(log.Fields)
	if !ok {
		fields = log.Fields{}
	}
	csiReqID, ok := ctx.Value(csictx.RequestIDKey).(string)
	if !ok {
		return fields
	}
	fields["RequestID"] = csiReqID
	return fields
}

func traceFuncCall(ctx context.Context, funcName string) {
	if tr, ok := trace.FromContext(ctx); ok {
		tr.LazyPrintf(funcName)
	}
}
