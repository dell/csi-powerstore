/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

/*
 *
 * Copyright © 2021-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package array provides structs and methods for configuring connection to PowerStore array.
package array

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/core"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

var (
	// IPToArray - Store Array IPs
	IPToArray                map[string]string
	ipToArrayMux             sync.Mutex
	defaultMultiNasThreshold = 5
	defaultMultiNasCooldown  = 5 * time.Minute
)

// Consumer provides methods for safe management of arrays
type Consumer interface {
	Arrays() map[string]*PowerStoreArray
	SetArrays(map[string]*PowerStoreArray)
	DefaultArray() *PowerStoreArray
	SetDefaultArray(*PowerStoreArray)
	UpdateArrays(string, fs.Interface) error
}

// Locker provides implementation for safe management of arrays
type Locker struct {
	arraysLock       sync.Mutex
	defaultArrayLock sync.Mutex
	arrays           map[string]*PowerStoreArray
	defaultArray     *PowerStoreArray
}

// Arrays is a getter for list of arrays
func (s *Locker) Arrays() map[string]*PowerStoreArray {
	s.arraysLock.Lock()
	defer s.arraysLock.Unlock()
	return s.arrays
}

// GetOneArray is a getter for an arrays based on globalID
func (s *Locker) GetOneArray(globalID string) (*PowerStoreArray, error) {
	s.arraysLock.Lock()
	defer s.arraysLock.Unlock()
	if arrayConfig, ok := s.arrays[globalID]; ok {
		return arrayConfig, nil
	}
	log.Errorf("array having globalID %s is not found in cache", globalID)
	return nil, fmt.Errorf("array not found")
}

// SetArrays adds an array
func (s *Locker) SetArrays(arrays map[string]*PowerStoreArray) {
	s.arraysLock.Lock()
	defer s.arraysLock.Unlock()
	s.arrays = arrays
}

// DefaultArray is a getter for default array
func (s *Locker) DefaultArray() *PowerStoreArray {
	s.defaultArrayLock.Lock()
	defer s.defaultArrayLock.Unlock()
	return s.defaultArray
}

// SetDefaultArray sets default array
func (s *Locker) SetDefaultArray(array *PowerStoreArray) {
	s.defaultArrayLock.Lock()
	defer s.defaultArrayLock.Unlock()
	s.defaultArray = array
}

// setIPToArray safely updates the IPToArray matcher.
func setIPToArray(matcher map[string]string) {
	ipToArrayMux.Lock()
	defer ipToArrayMux.Unlock()
	IPToArray = matcher
}

// UpdateArrays updates array info
func (s *Locker) UpdateArrays(configPath string, fs fs.Interface) error {
	log.Info("updating array info")
	arrays, matcher, defaultArray, err := GetPowerStoreArrays(fs, configPath)
	if err != nil {
		return fmt.Errorf("can't get config for arrays: %s", err.Error())
	}
	s.SetArrays(arrays)
	setIPToArray(matcher)
	s.SetDefaultArray(defaultArray)
	return nil
}

type NASCooldownTracker interface {
	MarkFailure(nas string)
	IsInCooldown(nas string) bool
	ResetFailure(nas string)
	FallbackRetry(nasList []string) string
}

type NASStatus struct {
	Failures      int
	CooldownUntil time.Time
}

type NASCooldown struct {
	statusMap      map[string]*NASStatus
	cooldownPeriod time.Duration
	threshold      int
	mu             sync.Mutex
}

// NewNASCooldown returns a new instance of NASCooldown.
func NewNASCooldown(cooldownPeriod time.Duration, threshold int) *NASCooldown {
	return &NASCooldown{
		statusMap:      make(map[string]*NASStatus),
		cooldownPeriod: cooldownPeriod,
		threshold:      threshold,
		mu:             sync.Mutex{},
	}
}

// GetStatusMap is a getter for statusMap
func (n *NASCooldown) GetStatusMap() map[string]*NASStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	// Return a copy of statusMap so that the original statusMap cannot be updated by the caller
	statusMapCopy := make(map[string]*NASStatus)
	for key, value := range n.statusMap {
		statusMapCopy[key] = value
	}
	return statusMapCopy
}

// GetCooldownPeriod is a getter for cooldownPeriod
func (n *NASCooldown) GetCooldownPeriod() time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cooldownPeriod
}

// GetThreshold is a getter for threshold
func (n *NASCooldown) GetThreshold() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.threshold
}

// Mark NAS as failed; only enter cooldown if threshold exceeded
func (n *NASCooldown) MarkFailure(nas string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	status, exists := n.statusMap[nas]
	if !exists {
		status = &NASStatus{}
		n.statusMap[nas] = status
	}

	status.Failures++
	if status.Failures >= n.threshold {
		status.CooldownUntil = time.Now().Add(n.cooldownPeriod)
	}
}

// Check if NAS is in cooldown
func (n *NASCooldown) IsInCooldown(nas string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if status, exists := n.statusMap[nas]; exists {
		return time.Now().Before(status.CooldownUntil)
	}
	return false
}

// Reset failure count on successful FS creation
func (n *NASCooldown) ResetFailure(nas string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	delete(n.statusMap, nas)
}

// Fallback logic - Retry all NAS servers, prioritizing least failed ones
func (n *NASCooldown) FallbackRetry(nasList []string) string {
	n.mu.Lock()
	defer n.mu.Unlock()

	sort.Slice(nasList, func(i, j int) bool {
		if n.statusMap[nasList[i]] == nil {
			return true
		} else if n.statusMap[nasList[j]] == nil {
			return false
		}
		return n.statusMap[nasList[i]].Failures < n.statusMap[nasList[j]].Failures
	})

	return nasList[0] // Pick NAS with least failures
}

// PowerStoreArray is a struct that stores all PowerStore connection information.
// It stores gopowerstore client that can be directly used to invoke PowerStore API calls.
// This structure is supposed to be parsed from config and mainly is created by GetPowerStoreArrays function.
type PowerStoreArray struct {
	Endpoint      string                    `yaml:"endpoint"`
	GlobalID      string                    `yaml:"globalID"`
	Username      string                    `yaml:"username"`
	Password      string                    `yaml:"password"`
	NasName       string                    `yaml:"nasName"`
	BlockProtocol identifiers.TransportType `yaml:"blockProtocol"`
	Insecure      bool                      `yaml:"skipCertificateValidation"`
	IsDefault     bool                      `yaml:"isDefault"`
	NfsAcls       string                    `yaml:"nfsAcls"`
	MetroTopology string                    `yaml:"metroTopology"`
	Labels        map[string]string         `yaml:"labels"`

	Client             gopowerstore.Client
	IP                 string
	NASCooldownTracker NASCooldownTracker
}

// GetNasName is a getter that returns name of configured NAS
func (psa *PowerStoreArray) GetNasName() string {
	return psa.NasName
}

// GetClient is a getter that returns gopowerstore Client interface
func (psa *PowerStoreArray) GetClient() gopowerstore.Client {
	return psa.Client
}

// GetIP is a getter that returns IP address of the array
func (psa *PowerStoreArray) GetIP() string {
	return psa.IP
}

// GetGlobalID is a getter that returns GlobalID address of the array
func (psa *PowerStoreArray) GetGlobalID() string {
	return psa.GlobalID
}

// GetPowerStoreArrays parses config.yaml file, initializes gopowerstore Clients and composes map of arrays for ease of access.
// It will return array that can be used as default as a second return parameter.
// If config does not have any array as a default then the first will be returned as a default.
func GetPowerStoreArrays(fs fs.Interface, filePath string) (map[string]*PowerStoreArray, map[string]string, *PowerStoreArray, error) {
	type config struct {
		Arrays []*PowerStoreArray `yaml:"arrays"`
	}

	data, err := fs.ReadFile(filepath.Clean(filePath))
	if err != nil {
		log.Errorf("cannot read file %s : %s", filePath, err.Error())
		return nil, nil, nil, err
	}

	var cfg config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		log.Errorf("cannot unmarshal data: %s", err.Error())
		return nil, nil, nil, err
	}

	arrayMap := make(map[string]*PowerStoreArray)
	mapper := make(map[string]string)
	var defaultArray *PowerStoreArray
	foundDefault := false

	if len(cfg.Arrays) == 0 {
		return arrayMap, mapper, defaultArray, nil
	}

	// Safeguard if user doesn't set any array as default, we just use first one
	defaultArray = cfg.Arrays[0]

	// Convert to map for convenience and init gopowerstore.Client
	for _, array := range cfg.Arrays {
		array := array
		if array == nil {
			return arrayMap, mapper, defaultArray, nil
		}
		if array.GlobalID == "" {
			return nil, nil, nil, errors.New("no GlobalID field found in config.yaml - update config.yaml according to the documentation")
		}
		clientOptions := gopowerstore.NewClientOptions()
		log.Debugf("PowerStore REST API timeout set to %s", identifiers.PowerstoreRESTApiTimeout)
		clientOptions.SetDefaultTimeout(identifiers.PowerstoreRESTApiTimeout)
		clientOptions.SetInsecure(array.Insecure)

		if throttlingRateLimit, ok := csictx.LookupEnv(context.Background(), identifiers.EnvThrottlingRateLimit); ok {
			rateLimit, err := strconv.Atoi(throttlingRateLimit)
			if err != nil {
				log.Errorf("can't get throttling rate limit, using default")
			} else if rateLimit < 0 {
				log.Errorf("throttling rate limit is negative, using default")
			} else {
				clientOptions.SetRateLimit(rateLimit)
			}
		}

		c, err := gopowerstore.NewClientWithArgs(
			array.Endpoint, array.Username, array.Password, clientOptions)
		if err != nil {
			return nil, nil, nil, status.Errorf(codes.FailedPrecondition,
				"unable to create PowerStore client: %s", err.Error())
		}
		c.SetCustomHTTPHeaders(http.Header{
			"Application-Type": {fmt.Sprintf("%s/%s", identifiers.VerboseName, core.SemVer)},
		})

		c.SetLogger(&identifiers.CustomLogger{})
		array.Client = c

		if array.BlockProtocol == "" {
			array.BlockProtocol = identifiers.AutoDetectTransport
		}
		array.BlockProtocol = identifiers.TransportType(strings.ToUpper(string(array.BlockProtocol)))
		var ip string
		ips := identifiers.GetIPListFromString(array.Endpoint)
		if ips == nil {
			log.Warnf("didn't found an IP from the provided endPoint, it could be a FQDN. Please make sure to enter a valid FQDN in https://abc.com/api/rest format")
			sub := strings.Split(array.Endpoint, "/")
			if len(sub) > 2 {
				ip = sub[2]
				if regexp.MustCompile(`^[0-9.]*$`).MatchString(sub[2]) {
					return nil, nil, nil, fmt.Errorf("can't get ips from endpoint: %s", array.Endpoint)
				}
			} else {
				return nil, nil, nil, fmt.Errorf("can't get ips from endpoint: %s", array.Endpoint)
			}
		} else {
			ip = ips[0]
		}
		array.IP = ip
		log.Infof("%s,%s,%s,%s,%t,%t,%s,%s", array.Endpoint, array.GlobalID, array.Username, array.NasName, array.Insecure, array.IsDefault, array.BlockProtocol, ip)
		arrayMap[array.GlobalID] = array
		mapper[ip] = array.GlobalID
		if array.IsDefault && !foundDefault {
			defaultArray = array
			foundDefault = true
		}
		failureThreshold := defaultMultiNasThreshold
		if threshold, ok := csictx.LookupEnv(context.Background(), identifiers.EnvMultiNASFailureThreshold); ok {
			if thresholdInt, err := strconv.Atoi(threshold); err != nil {
				log.Warnf("can't parse multi NAS failure threshold, using default %d", failureThreshold)
			} else if thresholdInt <= 0 {
				log.Warnf("multi NAS filure threshold is 0 or negative, using default %d", failureThreshold)
			} else {
				log.Debugf("use multi NAS failure threshold as %d", thresholdInt)
				failureThreshold = thresholdInt
			}
		}
		cooldownPeriod := defaultMultiNasCooldown
		if cp, ok := csictx.LookupEnv(context.Background(), identifiers.EnvMultiNASCooldownPeriod); ok {
			if duration, err := time.ParseDuration(cp); err != nil {
				log.Warnf("can't parse multi NAS cooldown period, using default %v", cooldownPeriod)
			} else if duration <= 0 {
				log.Warnf("multi NAS cooldown period 0 or negative, using default %d", failureThreshold)
			} else {
				log.Debugf("use multi NAS cooldown period as %v", duration)
				cooldownPeriod = duration
			}
		}
		array.NASCooldownTracker = NewNASCooldown(cooldownPeriod, failureThreshold)
	}

	return arrayMap, mapper, defaultArray, nil
}

// VolumeHandle represents the components of a unique csi-powerstore volume identifier and any remote
// volumes associated with the volume via data replication.
type VolumeHandle struct {
	// The UUID of a volume provisioned by a PowerStore system that is locally managed by this driver.
	LocalUUID string
	// The Global ID of the PowerStore system that is locally managed by this driver. The Global ID
	// can be found in the PowerStore UI under Settings > Properties
	LocalArrayGlobalID string
	// The UUID of a volume provisioned by a PowerStore system that is paired for replication with the
	// PowerStore system managed by this driver. Currently only used for Metro replicated volume handles.
	RemoteUUID string
	// The Global ID of the PowerStore system that is paired for replication with the PowerStore system
	// managed by this driver. Currently only used for Metro replicated volume handles.
	// The Global ID can be found in the PowerStore UI under Settings > Properties
	RemoteArrayGlobalID string
	// One of "scsi" or "nfs"
	Protocol string
}

// ParseVolumeID parses a volume id from the CO (Kubernetes) and tries to extract local and remote PowerStore volume UUID, Global ID, and protocol.
//
// Example:
//
//	ParseVolumeID("1cd254s/192.168.0.1/scsi") assuming 192.168.0.1 is the IP array PSabc0123def will return
//		VolumeHandle{
//			LocalUUID: "1cd254s",
//			LocalArrayGlobalID: "PSabc0123def",
//			RemoteUUID: "",
//			RemoteArrayGlobalID: "",
//			Protocol: "scsi",
//		}, nil
//
// Example:
//
//	ParseVolumeID("9f840c56-96e6-4de9-b5a3-27e7c20eaa77/PSabcdef0123/scsi:9f840c56-96e6-4de9-b5a3-27e7c20eaa77/PS0123abcdef") returns
//		VolumeHandle{
//			LocalUUID: "9f840c56-96e6-4de9-b5a3-27e7c20eaa77",
//			LocalArrayGlobalID: "PSabcdef0123",
//			RemoteUUID: "9f840c56-96e6-4de9-b5a3-27e7c20eaa77",
//			RemoteArrayGlobalID: "PS0123abcdef",
//			Protocol: "scsi",
//		}, nil
//
// This function is backwards compatible and will try to understand volume protocol even if there is no such information in volume id.
// It will do that by querying default powerstore array passed as one of the arguments
func ParseVolumeID(ctx context.Context, volumeHandleRaw string,
	defaultArray *PowerStoreArray, /*legacy support*/
	vc *csi.VolumeCapability, /*legacy support*/
) (volumeHandle VolumeHandle, err error) {
	log.Debugf("ParseVolumeID: parsing volume handle %s", volumeHandleRaw)

	if volumeHandleRaw == "" {
		return volumeHandle, status.Errorf(codes.FailedPrecondition,
			"unable to parse volume handle. volumeHandle is empty")
	}

	// metro volume handles will have a colon separating the local
	// volume handle and remote volume handle
	// e.g. 9f840c56-96e6-4de9-b5a3-27e7c20eaa77/PSabcdef0123/scsi:9f840c56-96e6-4de9-b5a3-27e7c20eaa77/PS0123abcdef
	volumeHandles := strings.Split(volumeHandleRaw, ":")

	// parse the first (potentially only) volume handle
	localVolumeHandle := strings.Split(volumeHandles[0], "/")
	volumeHandle.LocalUUID = localVolumeHandle[0]
	log.Debugf("ParseVolumeID: local volume handle: %s", localVolumeHandle)

	if len(localVolumeHandle) == 1 {
		// Legacy support where the volume name consists of only the volume ID.

		// We've got a volume from previous version
		// We assume that we should use default array for that
		// Try to understand whether it is an nfs or scsi based volume

		volumeHandle.LocalArrayGlobalID = defaultArray.GetGlobalID()

		// If we have volume capability in request we can check FsType
		if vc != nil && vc.GetMount() != nil {
			if vc.GetMount().GetFsType() == "nfs" {
				volumeHandle.Protocol = "nfs"
			} else {
				volumeHandle.Protocol = "scsi"
			}
		} else {
			// Try to just find out volume type by querying it's id from array
			_, err := defaultArray.GetClient().GetVolume(ctx, volumeHandle.LocalUUID)
			if err == nil {
				volumeHandle.Protocol = "scsi"
			} else {
				_, err := defaultArray.GetClient().GetFS(ctx, volumeHandle.LocalUUID)
				if err == nil {
					volumeHandle.Protocol = "nfs"
				} else {
					if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
						return volumeHandle, apiError
					}
					return volumeHandle, status.Errorf(codes.Unknown, "failure checking volume status: %s", err.Error())
				}
			}
		}
	} else {
		if ips := identifiers.GetIPListFromString(localVolumeHandle[1]); ips != nil {
			// Legacy support where IP is used in the volume name in place of a PowerStore Global ID.
			volumeHandle.LocalArrayGlobalID = IPToArray[ips[0]]
		} else {
			volumeHandle.LocalArrayGlobalID = localVolumeHandle[1]
		}
		volumeHandle.Protocol = localVolumeHandle[2]
	}

	// Parse the second portion of a metro volume handle
	if len(volumeHandles) > 1 {
		remoteVolumeHandle := strings.Split(volumeHandles[1], "/")
		log.Debugf("ParseVolumeID: remote volume handle: %s", remoteVolumeHandle)

		volumeHandle.RemoteUUID = remoteVolumeHandle[0]
		volumeHandle.RemoteArrayGlobalID = remoteVolumeHandle[1]
	}

	log.Debugf(
		"ParseVolumeID: volumeID: %s, arrayID: %s, protocol: %s, remoteVolumeID: %s, remoteArrayID: %s",
		volumeHandle.LocalUUID, volumeHandle.LocalArrayGlobalID, volumeHandle.Protocol, volumeHandle.RemoteUUID, volumeHandle.RemoteArrayGlobalID,
	)
	return volumeHandle, nil
}

// GetVolumeUUIDPrefix extracts the prefix, if any exists, from a volume ID with a UUID format.
// The prefix is assumed to be all characters preceding the volume UUID including separators/delimiters,
// e.g. '-'. If no prefix is found, or the volume ID is not of the UUID format, the function returns an
// empty string.
func GetVolumeUUIDPrefix(volumeID string) (prefix string) {
	matchUUID := regexp.MustCompile(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)

	// if the ID does not contain a UUID, return as-is.
	if matchUUID.FindString(volumeID) == "" {
		return ""
	}

	// get the index of the UUID in the volumeID and use that
	// to extract the prefix.
	i := matchUUID.FindStringIndex(volumeID)
	// create a slice from the beginning of the volume ID up to,
	// but excluding, the UUID. This is the prefix.
	prefix = volumeID[:i[0]]

	return prefix
}

// GetLeastUsedActiveNAS finds the active NAS with the least FS count
func GetLeastUsedActiveNAS(ctx context.Context, arr *PowerStoreArray, nasServers []string) (string, error) {
	nasList, err := arr.Client.GetNASServers(ctx)
	if err != nil {
		log.Errorf("Failed to fetch NAS servers: %v", err)
		return "", err
	}

	nasMap := createNASMap(nasServers)
	leastUsedNAS := findLeastUsedActiveNAS(arr, nasList, nasMap)

	if leastUsedNAS == nil {
		nasInCooldown := GetNASInCooldown(arr, nasServers)
		if len(nasInCooldown) != 0 {
			log.Debugf("some NAS servers are in cooldown, moving to fallback retry")
			return arr.NASCooldownTracker.FallbackRetry(nasInCooldown), nil
		}
		log.Warnf("all NAS servers are inactive/unhealthy")
		return "", fmt.Errorf("no suitable NAS server found, please ensure the NAS is running and healthy")
	}

	return leastUsedNAS.Name, nil
}

func createNASMap(nasServers []string) map[string]bool {
	nasMap := make(map[string]bool)
	for _, nasServer := range nasServers {
		nasMap[nasServer] = true
	}
	return nasMap
}

func findLeastUsedActiveNAS(arr *PowerStoreArray, nasList []gopowerstore.NAS, nasMap map[string]bool) *gopowerstore.NAS {
	var leastUsedNAS *gopowerstore.NAS
	for i := range nasList {
		nas := &nasList[i]
		if !isEligibleNAS(arr, nas, nasMap) {
			continue
		}
		if leastUsedNAS == nil || IsLessUsed(nas, leastUsedNAS) {
			leastUsedNAS = nas
		}
	}
	return leastUsedNAS
}

func isEligibleNAS(arr *PowerStoreArray, nas *gopowerstore.NAS, nasMap map[string]bool) bool {
	if !nasMap[nas.Name] {
		return false
	}
	if arr.NASCooldownTracker.IsInCooldown(nas.Name) {
		return false
	}
	if nas.OperationalStatus != gopowerstore.Started {
		return false
	}
	if !(nas.HealthDetails.State == gopowerstore.Info || nas.HealthDetails.State == gopowerstore.None) {
		return false
	}
	return true
}

func IsLessUsed(nas, current *gopowerstore.NAS) bool {
	if len(nas.FileSystems) < len(current.FileSystems) {
		return true
	}
	if len(nas.FileSystems) == len(current.FileSystems) && nas.Name < current.Name {
		return true
	}
	return false
}

// GetNASInCooldown returns a list of NAS servers that are in cooldown
func GetNASInCooldown(arr *PowerStoreArray, nasServers []string) []string {
	nasInCooldown := make([]string, 0)
	for _, nas := range nasServers {
		if arr.NASCooldownTracker.IsInCooldown(nas) {
			nasInCooldown = append(nasInCooldown, nas)
		}
	}
	return nasInCooldown
}
