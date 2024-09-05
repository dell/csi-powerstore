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
	"strconv"
	"strings"
	"sync"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/core"
	"github.com/dell/csi-powerstore/v2/pkg/common"
	"github.com/dell/csi-powerstore/v2/pkg/common/fs"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// IPToArray - Store Array IPs
var IPToArray map[string]string

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

// UpdateArrays updates array info
func (s *Locker) UpdateArrays(configPath string, fs fs.Interface) error {
	log.Info("updating array info")
	arrays, matcher, defaultArray, err := GetPowerStoreArrays(fs, configPath)
	if err != nil {
		return fmt.Errorf("can't get config for arrays: %s", err.Error())
	}
	s.SetArrays(arrays)
	IPToArray = matcher
	s.SetDefaultArray(defaultArray)
	return nil
}

// PowerStoreArray is a struct that stores all PowerStore connection information.
// It stores gopowerstore client that can be directly used to invoke PowerStore API calls.
// This structure is supposed to be parsed from config and mainly is created by GetPowerStoreArrays function.
type PowerStoreArray struct {
	Endpoint      string               `yaml:"endpoint"`
	GlobalID      string               `yaml:"globalID"`
	Username      string               `yaml:"username"`
	Password      string               `yaml:"password"`
	NasName       string               `yaml:"nasName"`
	BlockProtocol common.TransportType `yaml:"blockProtocol"`
	Insecure      bool                 `yaml:"skipCertificateValidation"`
	IsDefault     bool                 `yaml:"isDefault"`
	NfsAcls       string               `yaml:"nfsAcls"`

	Client gopowerstore.Client
	IP     string
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
		clientOptions.SetInsecure(array.Insecure)

		if throttlingRateLimit, ok := csictx.LookupEnv(context.Background(), common.EnvThrottlingRateLimit); ok {
			rateLimit, err := strconv.Atoi(throttlingRateLimit)
			if err != nil {
				log.Errorf("can't get throttling rate limit, using default")
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
			"Application-Type": {fmt.Sprintf("%s/%s", common.VerboseName, core.SemVer)},
		})

		c.SetLogger(&common.CustomLogger{})
		array.Client = c

		if array.BlockProtocol == "" {
			array.BlockProtocol = common.AutoDetectTransport
		}
		array.BlockProtocol = common.TransportType(strings.ToUpper(string(array.BlockProtocol)))
		var ip string
		ips := common.GetIPListFromString(array.Endpoint)
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
	}

	return arrayMap, mapper, defaultArray, nil
}

// ParseVolumeID parses volume id in from CO (Kubernetes) and tries to understand what in it are PowerStore volume id, and what is ip, protocol.
// "/" is used as a delimiter.
//
// Example:
//
//	ParseVolumeID("1cd254s/192.168.0.1/scsi") will return
//		id = "1cd254s"
//		ip = "192.168.0.1"
//		protocol = "scsi"
//
// This function is backwards compatible and will try to understand volume protocol even if there is no such information in volume id.
// It will do that by querying default powerstore array passed as one of the arguments
func ParseVolumeID(ctx context.Context, volumeID string, defaultArray *PowerStoreArray /*optional*/, cap *csi.VolumeCapability) (id string, arrayID string, protocol string, e error) {
	if volumeID == "" {
		return "", "", "", status.Errorf(codes.FailedPrecondition,
			"incorrect volume id ")
	}
	volID := strings.Split(volumeID, "/")
	id = volID[0]
	log.Infof("volid %s", volID)
	if len(volID) == 1 {
		// We've got volume from previous version
		// We assume that we should use default array for that
		// Try to understand whether it is a nfs or scsi based volume

		// If we have volume capability in request we can check FsType
		if cap != nil && cap.GetMount() != nil {
			if cap.GetMount().GetFsType() == "nfs" {
				protocol = "nfs"
			} else {
				protocol = "scsi"
			}
			arrayID = defaultArray.GetGlobalID()
			return id, arrayID, protocol, nil
		}

		// Try to just find out volume type by querying it's id from array
		_, err := defaultArray.GetClient().GetVolume(ctx, id)
		if err == nil {
			protocol = "scsi"
		} else {
			_, err := defaultArray.GetClient().GetFS(ctx, id)
			if err == nil {
				protocol = "nfs"
			} else {
				if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
					return id, arrayID, protocol, apiError
				}
				return id, arrayID, protocol, status.Errorf(codes.Unknown,
					"failure checking volume status: %s", err.Error())
			}
		}
		arrayID = defaultArray.GetGlobalID()
	} else {
		if ips := common.GetIPListFromString(volID[1]); ips != nil {
			arrayID = IPToArray[ips[0]]
		} else {
			arrayID = volID[1]
		}
		protocol = volID[2]
	}
	log.Infof("id %s arrayID %s proto %s", id, arrayID, protocol)
	return id, arrayID, protocol, nil
}
