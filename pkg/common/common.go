/*
 *
 * Copyright © 2021 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package common provides common constants, variables and function used in both controller and node services.
package common

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/core"
	"github.com/dell/csi-powerstore/pkg/common/fs"
	"github.com/dell/gobrick"
	csictx "github.com/dell/gocsi/context"
	"github.com/dell/gocsi/utils"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
)

// Name contains default name of the driver, can be overridden
var Name = "csi-powerstore.dellemc.com"

// Manifest contains additional information about the driver
var Manifest = map[string]string{
	"url":    "https://github.com/dell/csi-powerstore",
	"semver": core.SemVer,
	"commit": core.CommitSha32,
	"formed": core.CommitTime.Format(time.RFC1123),
}

type key int

const (
	// KeyAllowRoot key value to check if driver should enable root squashing for nfs volumes
	KeyAllowRoot = "allowRoot"
	// KeyNfsExportPath key value to pass in publish context
	KeyNfsExportPath = "NfsExportPath"
	// KeyHostIP key value to pass in publish context
	KeyHostIP = "HostIP"
	// KeyExportID key value to pass in publish context
	KeyExportID = "ExportID"
	// KeyNatIP key value to pass in publish context
	KeyNatIP = "NatIP"
	// KeyArrayID key value to check in request parameters for array ip
	KeyArrayID = "arrayID"
	// KeyArrayVolumeName key value to check in request parameters for volume name
	KeyArrayVolumeName = "Name"
	// KeyProtocol key value to check in request parameters for volume name
	KeyProtocol = "Protocol"
	// VerboseName longer description of the driver
	VerboseName = "CSI Driver for Dell EMC PowerStore"
	// FcTransport indicates that FC is chosen as a SCSI transport protocol
	FcTransport TransportType = "FC"
	// ISCSITransport indicates that ISCSI is chosen as a SCSI transport protocol
	ISCSITransport TransportType = "ISCSI"
	// NVMETransport indicates that NVMe is chosen as a transport protocol
	NVMETransport TransportType = "NVME"
	// AutoDetectTransport indicates that SCSI transport protocol would be detected automatically
	AutoDetectTransport TransportType = "AUTO"
	// NoneTransport indicates that no SCSI transport protocol needed
	NoneTransport TransportType = "NONE"
	// PublishContextDeviceWWN indicates publish context device wwn
	PublishContextDeviceWWN = "DEVICE_WWN"
	// PublishContextLUNAddress indicates publish context LUN address
	PublishContextLUNAddress = "LUN_ADDRESS"
	// PublishContextISCSIPortalsPrefix indicates publish context iSCSI portals prefix
	PublishContextISCSIPortalsPrefix = "PORTAL"
	// PublishContextISCSITargetsPrefix indicates publish context iSCSI targets prefix
	PublishContextISCSITargetsPrefix = "TARGET"
	// PublishContextFCWWPNPrefix indicates publish context FC WWPN prefix
	PublishContextFCWWPNPrefix = "FCWWPN"
	// WWNPrefix indicates WWN prefix
	WWNPrefix = "naa."

	contextLogFieldsKey key = iota
)

// TransportType differentiates different SCSI transport protocols (FC, iSCSI, Auto, None)
type TransportType string

// RmSockFile removes socket files that left after previous installation
func RmSockFile(f fs.Interface) {
	proto, addr, err := utils.GetCSIEndpoint()
	if err != nil {
		log.Errorf("Error: failed to get CSI endpoint: %s\n", err.Error())
	}

	var rmSockFileOnce sync.Once
	rmSockFileOnce.Do(func() {
		if proto == "unix" {
			if _, err := f.Stat(addr); err == nil {
				if err = f.RemoveAll(addr); err != nil {
					log.Errorf("Error: failed to remove socket file %s: %s\n", addr, err.Error())
				}
				log.Infof("removed socket file %s\n", addr)
			} else if os.IsNotExist(err) {
				return
			} else {
				log.Errorf("Error: socket file %s may or may not exist: %s\n", addr, err.Error())
			}
		}
	})
}

// GetIPListFromString returns list of ips in string form found in input string
// A return value of nil indicates no match
func GetIPListFromString(input string) []string {
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	return re.FindAllString(input, -1)
}

func parseMask(ipaddr string) (mask string, err error) {
	removeExtra := regexp.MustCompile("^(.*[\\/])")
	asd := ipaddr[len(ipaddr)-3:]
	findSubnet := removeExtra.ReplaceAll([]byte(asd), []byte(""))
	subnet, err := strconv.ParseInt(string(findSubnet), 10, 64)
	if err != nil {
		return "", errors.New("Parse Mask: Error parsing mask")
	}
	var buff bytes.Buffer
	for i := 0; i < int(subnet); i++ {
		buff.WriteString("1")
	}
	for i := subnet; i < 32; i++ {
		buff.WriteString("0")
	}
	masker := buff.String()
	a, _ := strconv.ParseUint(masker[:8], 2, 64)
	b, _ := strconv.ParseUint(masker[8:16], 2, 64)
	c, _ := strconv.ParseUint(masker[16:24], 2, 64)
	d, _ := strconv.ParseUint(masker[24:32], 2, 64)
	resultMask := fmt.Sprintf("%v.%v.%v.%v", a, b, c, d)
	return resultMask, nil
}

// GetIPListWithMaskFromString returns ip and mask in string form found in input string
// A return value of nil indicates no match
func GetIPListWithMaskFromString(input string) (string, error) {
	re := regexp.MustCompile(`^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.(?:[01]?\d\d?|2[0-4]\d|25[0-5])){3}(?:/[0-2]\d|/3[0-2])?$`)
	validated := re.FindAllString(input, 1)
	if validated != nil {
		mask, err := parseMask(validated[0])
		if err != nil {
			return validated[0], nil
		}
		if i := strings.Index(input, "/"); i != -1 {
			return validated[0][:i+1] + mask, nil
		}
	}
	return "", errors.New("doesn't seem to be a valid IP")
}

// SetLogFields returns modified context with fields inserted as values by using contextLogFieldsKey key
func SetLogFields(ctx context.Context, fields log.Fields) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, contextLogFieldsKey, fields)
}

// RandomString returns a random string of specified length.
// String is generated by using crypto/rand.
func RandomString(len int) string {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		log.Errorf("Can't generate random string; error = %v", err)
	}
	suff := fmt.Sprintf("%x", b[0:])
	return suff
}

// GetLogFields extracts log fields from context by using contextLogFieldsKey key
func GetLogFields(ctx context.Context) log.Fields {
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

// GetISCSITargetsInfoFromStorage returns list of gobrick compatible iscsi tragets by querying PowerStore array
func GetISCSITargetsInfoFromStorage(client gopowerstore.Client) ([]gobrick.ISCSITargetInfo, error) {
	addrInfo, err := client.GetStorageISCSITargetAddresses(context.Background())
	if err != nil {
		log.Error(err.Error())
		return []gobrick.ISCSITargetInfo{}, err
	}
	// sort data by id
	sort.Slice(addrInfo, func(i, j int) bool {
		return addrInfo[i].ID < addrInfo[j].ID
	})
	result := make([]gobrick.ISCSITargetInfo, len(addrInfo))
	for i, t := range addrInfo {
		result[i] = gobrick.ISCSITargetInfo{Target: t.IPPort.TargetIqn, Portal: fmt.Sprintf("%s:3260", t.Address)}
	}
	return result, nil
}

// GetFCTargetsInfoFromStorage returns list of gobrick compatible FC tragets by querying PowerStore array
func GetFCTargetsInfoFromStorage(client gopowerstore.Client) ([]gobrick.FCTargetInfo, error) {
	fcPorts, err := client.GetFCPorts(context.Background())
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	var result []gobrick.FCTargetInfo
	for _, t := range fcPorts {
		if t.IsLinkUp {
			result = append(result, gobrick.FCTargetInfo{WWPN: strings.Replace(t.Wwn, ":", "", -1)})
		}
	}
	return result, nil
}
