/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package identifiers provides common constants, variables and function used in both controller and node services.
package identifiers

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/v2/core"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/gobrick"
	csictx "github.com/dell/gocsi/context"
	csiutils "github.com/dell/gocsi/utils/csi"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
)

// Name contains default name of the driver, can be overridden
var Name = "csi-powerstore.dellemc.com"

// APIPort port for API calls
var APIPort string

// Manifest contains additional information about the driver
var Manifest = map[string]string{
	"url":    "https://github.com/dell/csi-powerstore",
	"semver": core.SemVer,
	"commit": core.CommitSha32,
	"formed": core.CommitTime.Format(time.RFC1123),
}

type key int

// ArrayConnectivityStatus Status of the array probe
type ArrayConnectivityStatus struct {
	LastSuccess int64 `json:"lastSuccess"` // connectivity status
	LastAttempt int64 `json:"lastAttempt"` // last timestamp attempted to check connectivity
}

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
	// KeyNfsACL key value to specify NFS ACLs for NFS volume
	KeyNfsACL = "nfsAcls"
	// KeyNasName key value to specify NAS server name
	KeyNasName = "nasName"
	// KeyVolumeDescription key value to specify volume description
	KeyVolumeDescription = "csi.dell.com/description"
	// KeyApplianceID key value to specify appliance_id
	KeyApplianceID = "csi.dell.com/appliance_id"
	// KeyProtectionPolicyID key value to specify protection_policy_id
	KeyProtectionPolicyID = "csi.dell.com/protection_policy_id"
	// KeyPerformancePolicyID key value to specify performance_policy_id
	KeyPerformancePolicyID = "csi.dell.com/performance_policy_id"
	// KeyAppType key value to specify app_type
	KeyAppType = "csi.dell.com/app_type"
	// KeyAppTypeOther key value to specify app_type_other
	KeyAppTypeOther = "csi.dell.com/app_type_other"
	// KeyConfigType key value to specify volume config_type
	KeyConfigType = "csi.dell.com/config_type"
	// KeyAccessPolicy key value to specify volume access_policy
	KeyAccessPolicy = "csi.dell.com/access_policy"
	// KeyLockingPolicy key value to specify volume locking_policy
	KeyLockingPolicy = "csi.dell.com/locking_policy"
	// KeyFolderRenamePolicy key value to specify volume folder_rename_policy
	KeyFolderRenamePolicy = "csi.dell.com/folder_rename_policy"
	// KeyIsAsyncMtimeEnabled key value to specify volume is_async_mtime_enabled
	KeyIsAsyncMtimeEnabled = "csi.dell.com/is_async_mtime_enabled"
	// KeyFileEventsPublishingMode key value to specify volume file_events_publishing_mode
	KeyFileEventsPublishingMode = "csi.dell.com/file_events_publishing_mode"
	// KeyHostIoSize key value to specify volume host_io_size
	KeyHostIoSize = "csi.dell.com/host_io_size"
	// KeyVolumeGroupID key value to specify volume_group_id
	KeyVolumeGroupID = "csi.dell.com/volume_group_id"
	// KeyFlrCreateMode key value to specify flr_attributes.flr_create.mode
	KeyFlrCreateMode = "csi.dell.com/flr_attributes.flr_create.mode"
	// KeyFlrDefaultRetention key value to specify flr_attributes.flr_create.default_retention
	KeyFlrDefaultRetention = "csi.dell.com/flr_attributes.flr_create.default_retention"
	// KeyFlrMinRetention key value to specify flr_attributes.flr_create.minimum_retention
	KeyFlrMinRetention = "csi.dell.com/flr_attributes.flr_create.minimum_retention"
	// KeyFlrMaxRetention key value to specify flr_attributes.flr_create.maximum_retention
	KeyFlrMaxRetention = "csi.dell.com/flr_attributes.flr_create.maximum_retention"
	// KeyServiceTag has the service tag associated to an Appliance
	KeyServiceTag = "serviceTag"
	// VerboseName longer description of the driver
	VerboseName = "CSI Driver for Dell EMC PowerStore"
	// FcTransport indicates that FC is chosen as a SCSI transport protocol
	FcTransport TransportType = "FC"
	// ISCSITransport indicates that ISCSI is chosen as a SCSI transport protocol
	ISCSITransport TransportType = "ISCSI"
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
	// PublishContextNVMETCPPortalsPrefix indicates publish context NVMeTCP portals prefix
	PublishContextNVMETCPPortalsPrefix = "NVMETCPPORTAL"
	// PublishContextNVMETCPTargetsPrefix indicates publish context NVMe targets prefix
	PublishContextNVMETCPTargetsPrefix = "NVMETCPTARGET"
	// PublishContextNVMEFCPortalsPrefix indicates publish context NVMe targets prefix
	PublishContextNVMEFCPortalsPrefix = "NVMEFCPORTAL"
	// PublishContextNVMEFCTargetsPrefix indicates publish context NVMe targets prefix
	PublishContextNVMEFCTargetsPrefix = "NVMEFCTARGET"
	// NVMETCPTransport indicates that NVMe/TCP is chosen as the transport protocol
	NVMETCPTransport TransportType = "NVMETCP"
	// NVMEFCTransport indicates that NVMe/FC is chosen as the transport protocol
	NVMEFCTransport TransportType = "NVMEFC"
	// PublishContextFCWWPNPrefix indicates publish context FC WWPN prefix
	PublishContextFCWWPNPrefix = "FCWWPN"
	// PublishContextRemoteDeviceWWN indicates publish context device wwn of remote device
	PublishContextRemoteDeviceWWN = "REMOTE_DEVICE_WWN"
	// PublishContextRemoteLUNAddress indicates publish context LUN address of remote device
	PublishContextRemoteLUNAddress = "REMOTE_LUN_ADDRESS"
	// PublishContextRemoteISCSIPortalsPrefix indicates publish context iSCSI portals prefix of remote array
	PublishContextRemoteISCSIPortalsPrefix = "REMOTE_PORTAL"
	// PublishContextRemoteISCSITargetsPrefix indicates publish context iSCSI targets prefix of remote array
	PublishContextRemoteISCSITargetsPrefix = "REMOTE_TARGET"
	// PublishContextRemoteNVMETCPPortalsPrefix indicates publish context NVMeTCP portals prefix of remote array
	PublishContextRemoteNVMETCPPortalsPrefix = "REMOTE_NVMETCPPORTAL"
	// PublishContextRemoteNVMETCPTargetsPrefix indicates publish context NVMe targets prefix of remote array
	PublishContextRemoteNVMETCPTargetsPrefix = "REMOTE_NVMETCPTARGET"
	// PublishContextRemoteNVMEFCPortalsPrefix indicates publish context NVMe targets prefix of remote array
	PublishContextRemoteNVMEFCPortalsPrefix = "REMOTE_NVMEFCPORTAL"
	// PublishContextRemoteNVMEFCTargetsPrefix indicates publish context NVMe targets prefix of remote array
	PublishContextRemoteNVMEFCTargetsPrefix = "REMOTE_NVMEFCTARGET"
	// PublishContextRemoteFCWWPNPrefix indicates publish context FC WWPN prefix of remote array
	PublishContextRemoteFCWWPNPrefix = "REMOTE_FCWWPN"
	// WWNPrefix indicates WWN prefix
	WWNPrefix = "naa."
	// SyncMode indicates Synchronous Replication
	SyncMode = "SYNC"
	// AsyncMode indicats Asynchronous Replication
	AsyncMode = "ASYNC"
	// MetroMode indicates Metro Replication
	MetroMode = "METRO"
	// Zero indicates value zero for RPO
	Zero = "Zero"

	contextLogFieldsKey key = iota

	// DefaultPodmonAPIPortNumber is the port number in default to expose internal health APIs
	DefaultPodmonAPIPortNumber = "8083"

	// DefaultPodmonPollRate is the default polling frequency to check for array connectivity
	DefaultPodmonPollRate = 60

	// Timeout for making http requests
	Timeout = time.Second * 5

	// ArrayStatus is the endPoint for polling to check array status
	ArrayStatus = "/array-status"
)

// TransportType differentiates different SCSI transport protocols (FC, iSCSI, Auto, None)
type TransportType string

// RmSockFile removes socket files that left after previous installation
func RmSockFile(f fs.Interface) {
	proto, addr, err := csiutils.GetCSIEndpoint()
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
	if subnet < 0 || subnet > 32 {
		return "", errors.New("Invalid subnet mask")
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
	// Split the IP address and subnet mask if present
	parts := strings.Split(input, "/")
	ip := parts[0]
	result := net.ParseIP(ip)
	if result == nil {
		return "", errors.New("doesn't seem to be a valid IP")
	}
	if len(parts) > 1 {
		// ideally there will be only 2 substrings for a valid IP/SubnetMask
		if len(parts) > 2 {
			return "", errors.New("doesn't seem to be a valid IP")
		}
		mask, err := parseMask(input)
		if err != nil {
			return "", errors.New("doesn't seem to be a valid IP")
		}
		ip = ip + "/" + mask
	}
	return ip, nil
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
func RandomString(length int) string {
	b := make([]byte, length)
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

// GetISCSITargetsInfoFromStorage returns list of gobrick compatible iscsi targets by querying PowerStore array
func GetISCSITargetsInfoFromStorage(client gopowerstore.Client, volumeApplianceID string) ([]gobrick.ISCSITargetInfo, error) {
	addrInfo, err := client.GetStorageISCSITargetAddresses(context.Background())
	if err != nil {
		log.Error(err.Error())
		return []gobrick.ISCSITargetInfo{}, err
	}
	// sort data by id
	sort.Slice(addrInfo, func(i, j int) bool {
		return addrInfo[i].ID < addrInfo[j].ID
	})
	var result []gobrick.ISCSITargetInfo
	for _, t := range addrInfo {
		// volumeApplianceID will be empty in case the call is from NodeGetInfo
		if t.ApplianceID == volumeApplianceID || volumeApplianceID == "" {
			result = append(result, gobrick.ISCSITargetInfo{Target: t.IPPort.TargetIqn, Portal: fmt.Sprintf("%s:3260", t.Address)})
		}
	}
	return result, nil
}

// GetNVMETCPTargetsInfoFromStorage returns list of gobrick compatible NVME TCP targets by querying PowerStore array
func GetNVMETCPTargetsInfoFromStorage(client gopowerstore.Client, volumeApplianceID string) ([]gobrick.NVMeTargetInfo, error) {
	clusterInfo, err := client.GetCluster(context.Background())
	nvmeNQN := clusterInfo.NVMeNQN

	addrInfo, err := client.GetStorageNVMETCPTargetAddresses(context.Background())
	if err != nil {
		log.Error(err.Error())
		return []gobrick.NVMeTargetInfo{}, err
	}
	// sort data by id
	sort.Slice(addrInfo, func(i, j int) bool {
		return addrInfo[i].ID < addrInfo[j].ID
	})
	var result []gobrick.NVMeTargetInfo
	for _, t := range addrInfo {
		// volumeApplianceID will be empty in case the call is from NodeGetInfo
		if t.ApplianceID == volumeApplianceID || volumeApplianceID == "" {
			result = append(result, gobrick.NVMeTargetInfo{Target: nvmeNQN, Portal: fmt.Sprintf("%s:4420", t.Address)})
		}
	}
	return result, nil
}

// GetFCTargetsInfoFromStorage returns list of gobrick compatible FC targets by querying PowerStore array
func GetFCTargetsInfoFromStorage(client gopowerstore.Client, volumeApplianceID string) ([]gobrick.FCTargetInfo, error) {
	fcPorts, err := client.GetFCPorts(context.Background())
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	var result []gobrick.FCTargetInfo
	for _, t := range fcPorts {
		if t.IsLinkUp && t.ApplianceID == volumeApplianceID {
			result = append(result, gobrick.FCTargetInfo{WWPN: strings.Replace(t.Wwn, ":", "", -1)})
		}
	}
	return result, nil
}

// IsK8sMetadataSupported returns info whether Metadata is supported or not
func IsK8sMetadataSupported(client gopowerstore.Client) bool {
	k8sMetadataSupported := false
	majorMinorVersion, err := client.GetSoftwareMajorMinorVersion(context.Background())
	if err != nil {
		log.Errorf("couldn't get the software version installed on the PowerStore array: %v", err)
		return k8sMetadataSupported
	}
	if majorMinorVersion >= 3.0 {
		k8sMetadataSupported = true
	} else {
		log.Debugf("Software version installed on the PowerStore array: %v\n", majorMinorVersion)
	}
	return k8sMetadataSupported
}

// GetNVMEFCTargetInfoFromStorage returns a list of gobrick compatible NVMeFC targets by quering Powerstore Array
func GetNVMEFCTargetInfoFromStorage(client gopowerstore.Client, volumeApplianceID string) ([]gobrick.NVMeTargetInfo, error) {
	clusterInfo, err := client.GetCluster(context.Background())
	nvmeNQN := clusterInfo.NVMeNQN

	fcPorts, err := client.GetFCPorts(context.Background())
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	var result []gobrick.NVMeTargetInfo
	for _, t := range fcPorts {
		if t.IsLinkUp && (t.ApplianceID == volumeApplianceID || volumeApplianceID == "") {
			targetAddress := strings.Replace(fmt.Sprintf("nn-0x%s:pn-0x%s", strings.Replace(t.WwnNode, ":", "", -1), strings.Replace(t.WwnNVMe, ":", "", -1)), "\n", "", -1)
			result = append(result, gobrick.NVMeTargetInfo{Target: nvmeNQN, Portal: targetAddress})
		}
	}
	return result, nil
}

// ParseCIDR parses the CIDR address to the valid start IP range with Mask
func ParseCIDR(externalAccessCIDR string) (string, error) {
	// check if externalAccess has netmask bit or not
	if !strings.Contains(externalAccessCIDR, "/") {
		// if externalAccess is a plane ip we can add /32 from our end
		externalAccessCIDR += "/32"
		log.Debug("externalAccess after appending netMask bit:", externalAccessCIDR)
	}
	ip, ipnet, err := net.ParseCIDR(externalAccessCIDR)
	if err != nil {
		return "", err
	}
	log.Debug("Parsed CIDR:", externalAccessCIDR, "-> ip:", ip, " net:", ipnet)
	start, _ := cidr.AddressRange(ipnet)
	fromString, err := GetIPListWithMaskFromString(externalAccessCIDR)
	if err != nil {
		return "", err
	}
	log.Debug("IP with Mask:", fromString)
	s := strings.Split(fromString, "/")

	// ExernalAccess IP consists of Starting range IP of CIDR+Mask and hence concatenating the same to remove from the array
	externalAccess := start.String() + "/" + s[1]

	return externalAccess, nil
}

// HasRequiredTopology Checks if requiredTopology is present in the topology array and is true
func HasRequiredTopology(topologies []*csi.Topology, arrIP string, requiredTopology string) bool {
	if len(topologies) == 0 || len(arrIP) == 0 || len(requiredTopology) == 0 {
		return false
	}

	topologyKey := Name + "/" + arrIP + "-" + strings.ToLower(requiredTopology)
	for _, topology := range topologies {
		if value, ok := topology.Segments[topologyKey]; ok && strings.EqualFold(value, "true") {
			return true
		}
	}
	return false
}

// GetNfsTopology Returns a topology array with only nfs
func GetNfsTopology(arrIP string) []*csi.Topology {
	nfsTopology := new(csi.Topology)
	nfsTopology.Segments = map[string]string{Name + "/" + arrIP + "-nfs": "true"}
	return []*csi.Topology{nfsTopology}
}

// Contains return true if element is present in the slice
func Contains(slice []string, element string) bool {
	for _, a := range slice {
		if a == element {
			return true
		}
	}
	return false
}

// ExternalAccessAlreadyAdded return true if externalAccess is present on ARRAY in any access mode type
func ExternalAccessAlreadyAdded(export gopowerstore.NFSExport, externalAccess string) bool {
	externalAccess, _ = ParseCIDR(externalAccess)
	if Contains(export.RWRootHosts, externalAccess) || Contains(export.RWHosts, externalAccess) || Contains(export.RORootHosts, externalAccess) || Contains(export.ROHosts, externalAccess) {
		log.Debug("ExternalAccess is already added into Host Access list on array: ", externalAccess)
		return true
	}
	log.Debug("Going to add externalAccess into Host Access list on array: ", externalAccess)
	return false
}

// SetPollingFrequency reads the pollingFrequency from Env, sets default vale if ENV not found
func SetPollingFrequency(ctx context.Context) int64 {
	var pollingFrequency int64
	if pollRateEnv, ok := csictx.LookupEnv(ctx, EnvPodmonArrayConnectivityPollRate); ok {
		if pollingFrequency, _ = strconv.ParseInt(pollRateEnv, 10, 32); pollingFrequency != 0 {
			log.Debugf("use pollingFrequency as %d seconds", pollingFrequency)
			return pollingFrequency
		}
	}
	log.Debugf("use default pollingFrequency as %d seconds", DefaultPodmonPollRate)
	return DefaultPodmonPollRate
}

// SetAPIPort set the port for running server
func SetAPIPort(ctx context.Context) {
	if port, ok := csictx.LookupEnv(ctx, EnvPodmonAPIPORT); ok && strings.TrimSpace(port) != "" {
		APIPort = fmt.Sprintf(":%s", port)
		log.Debugf("set podmon API port to %s", APIPort)
		return
	}
	// If the port number cannot be fetched, set it to default
	APIPort = ":" + DefaultPodmonAPIPortNumber
	log.Debugf("set podmon API port to default %s", APIPort)
}

// ReachableEndPoint checks if this endpoint is reachable or not
func ReachableEndPoint(endpoint string) bool {
	// this endpoint has IP:PORT
	_, err := net.DialTimeout("tcp", endpoint, 2*time.Second)
	if err != nil {
		return false
	}
	return true
}

func GetMountFlags(vc *csi.VolumeCapability) []string {
	if vc != nil {
		if mount := vc.GetMount(); mount != nil {
			return mount.GetMountFlags()
		}
	}
	return nil
}

// IsNFSServiceEnabled checks if NFS service is enabled for the given PowerStore array.
func IsNFSServiceEnabled(ctx context.Context, client gopowerstore.Client) (bool, error) {
	nasList, err := client.GetNASServers(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get NAS servers: %w", err)
	}

	for _, nas := range nasList {
		for _, nasServer := range nas.NfsServers {
			if nasServer.IsNFSv4Enabled || nasServer.IsNFSv3Enabled {
				return true, nil
			}
		}
	}
	return false, nil
}
