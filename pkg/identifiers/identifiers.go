/*
 *
 * Copyright © 2021-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dell/csi-powerstore/v2/core"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	log "github.com/dell/csmlog"
	"github.com/dell/gobrick"
	csictx "github.com/dell/gocsi/context"
	csiutils "github.com/dell/gocsi/utils/csi"
	"github.com/dell/gopowerstore"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/container-storage-interface/spec/lib/go/csi"
)

// Name contains default name of the driver, can be overridden
var Name = "csi-powerstore.dellemc.com"

// APIPort port for API calls
var APIPort string

// PodmonAPIToken is the shared secret token for authenticating podmon API requests.
// This variable is package-scoped; each driver binary maintains its own instance.
var PodmonAPIToken string

// Update when the manifest version changes.
var ManifestSemver string

// Manifest contains additional information about the driver
var Manifest = map[string]string{
	"semver": ManifestSemver,
	"formed": core.CommitTime.Format(time.RFC1123),
}

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
	// KeyNfsAutoSelect key value to pass in publish context for NFS auto-select
	KeyNfsAutoSelect = "NfsAutoSelect"
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
	// KeyNasInterfaceIP key value for NAS preferred file interface IP (AC-007 PV traceability)
	KeyNasInterfaceIP = "nasInterfaceIP"
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
	// PvcLabelFsCheckEnabled key value to enable/disable FS check feature
	PvcLabelFsCheckEnabled = "csi.dell.com/fs_check_enabled"
	// PvcLabelFsCheckMode key value to specify FS check mode
	PvcLabelFsCheckMode = "csi.dell.com/fs_check_mode"
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
	// TargetMapDeviceWWN indicates target map device wwn
	TargetMapDeviceWWN = "DEVICE_WWN"
	// TargetMapLUNAddress indicates publish context LUN address
	TargetMapLUNAddress = "LUN_ADDRESS"
	// TargetMapISCSIPortalsPrefix indicates target map iSCSI portals prefix
	TargetMapISCSIPortalsPrefix = "PORTAL"
	// TargetMapISCSITargetsPrefix indicates target map iSCSI targets prefix
	TargetMapISCSITargetsPrefix = "TARGET"
	// TargetMapNVMETCPPortalsPrefix indicates target map NVMeTCP portals prefix
	TargetMapNVMETCPPortalsPrefix = "NVMETCPPORTAL"
	// TargetMapNVMETCPTargetsPrefix indicates target mapNVMe targets prefix
	TargetMapNVMETCPTargetsPrefix = "NVMETCPTARGET"
	// TargetMapNVMEFCPortalsPrefix indicates publish context NVMe targets prefix
	TargetMapNVMEFCPortalsPrefix = "NVMEFCPORTAL"
	// TargetMapNVMEFCTargetsPrefix indicates target map NVMe targets prefix
	TargetMapNVMEFCTargetsPrefix = "NVMEFCTARGET"
	// NVMETCPTransport indicates that NVMe/TCP is chosen as the transport protocol
	NVMETCPTransport TransportType = "NVMETCP"
	// NVMEFCTransport indicates that NVMe/FC is chosen as the transport protocol
	NVMEFCTransport TransportType = "NVMEFC"
	// TargetMapFCWWPNPrefix indicates target map FC WWPN prefix
	TargetMapFCWWPNPrefix = "FCWWPN"
	// TargetMapRemoteDeviceWWN indicates target map device wwn of remote device
	TargetMapRemoteDeviceWWN = "REMOTE_DEVICE_WWN"
	// TargetMapRemoteLUNAddress indicates target map LUN address of remote device
	TargetMapRemoteLUNAddress = "REMOTE_LUN_ADDRESS"
	// TargetMapRemoteISCSIPortalsPrefix indicates target map iSCSI portals prefix of remote array
	TargetMapRemoteISCSIPortalsPrefix = "REMOTE_PORTAL"
	// TargetMapRemoteISCSITargetsPrefix indicates target map iSCSI targets prefix of remote array
	TargetMapRemoteISCSITargetsPrefix = "REMOTE_TARGET"
	// TargetMapRemoteNVMETCPPortalsPrefix indicates target map NVMeTCP portals prefix of remote array
	TargetMapRemoteNVMETCPPortalsPrefix = "REMOTE_NVMETCPPORTAL"
	// TargetMapRemoteNVMETCPTargetsPrefix indicates target map NVMe targets prefix of remote array
	TargetMapRemoteNVMETCPTargetsPrefix = "REMOTE_NVMETCPTARGET"
	// TargetMapRemoteNVMEFCPortalsPrefix indicates target map NVMe targets prefix of remote array
	TargetMapRemoteNVMEFCPortalsPrefix = "REMOTE_NVMEFCPORTAL"
	// TargetMapRemoteNVMEFCTargetsPrefix indicates target map NVMe targets prefix of remote array
	TargetMapRemoteNVMEFCTargetsPrefix = "REMOTE_NVMEFCTARGET"
	// TargetMapRemoteFCWWPNPrefix indicates target map FC WWPN prefix of remote array
	TargetMapRemoteFCWWPNPrefix = "REMOTE_FCWWPN"
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

	// DefaultPodmonAPIPortNumber is the port number in default to expose internal health APIs
	DefaultPodmonAPIPortNumber = "8083"

	// DefaultPodmonPollRate is the default polling frequency to check for array connectivity
	DefaultPodmonPollRate = 60

	// ArrayStatus is the endPoint for polling to check array status
	ArrayStatus = "/array-status"

	// KeyNodeID represents key for node id
	KeyNodeID = "csi.volume.kubernetes.io/nodeid"
)

// PodmonArrayConnectivityTimeout specifies timeout for making http requests to node services by podmon
var PodmonArrayConnectivityTimeout = GetPodmonArrayConnectivityTimeout()

// DefaultPodmonArrayConnectivityTimeout specifies default timeout for making http requests to node services by podmon
var DefaultPodmonArrayConnectivityTimeout = 10 * time.Second

// PowerstoreRESTApiTimeout specifies timeout for making http requests by Powerstore client
var PowerstoreRESTApiTimeout = GetPowerStoreRESTApiTimeout()

// DefaultPowerstoreRESTApiTimeout specifies default timeout for making http requests by Powerstore client
var DefaultPowerstoreRESTApiTimeout = 120 * time.Second

// DefaultVolumeDisconnectMaxRetries specifies the default maximum number of retry attempts for volume disconnection
var DefaultVolumeDisconnectMaxRetries = 5

// DefaultVolumeDisconnectRetryInterval specifies the default wait time between volume disconnection retries
var DefaultVolumeDisconnectRetryInterval = 5 * time.Second

// DefaultVolumeDisconnectTimeout specifies the default timeout duration for each volume disconnection attempt
var DefaultVolumeDisconnectTimeout = 120 * time.Second

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

// GetIPListFromString returns list of ips in string form found in input string.
// Supports IPv4 (bare and in URLs), FQDNs (in URLs), and IPv6 (bracketed in
// URLs or bare in dash-delimited node-ID strings like "prefix-hostname-::1").
// A return value of nil indicates no match.
func GetIPListFromString(input string) []string {
	// Extract a host from a URL first so embedded IPv4 text in an IPv4-mapped
	// IPv6 address cannot be returned ahead of the complete logical address.
	if u, err := url.Parse(input); err == nil && u.Host != "" {
		host := u.Hostname()
		if host != "" {
			if addr, err := netip.ParseAddr(host); err == nil {
				return []string{addr.String()}
			}
			if isDomain(host) {
				return []string{host}
			}
		}
	}

	// IPv4 addresses and "localhost" — unchanged behaviour for legacy inputs.
	ipv4Re := regexp.MustCompile(`\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}|localhost\b)`)
	matches := ipv4Re.FindAllString(input, -1)

	// Scan dash-delimited tokens for bare IPv6 addresses (node-ID format:
	// "prefix-hostname-2001:db8::1"). IPv6 addresses never contain "-", so
	// splitting on "-" leaves the IPv6 part intact as a single token.
	// However, when IPv6 addresses are encoded for node IDs (colons replaced with dashes),
	// we need to handle the encoded format by reconstructing consecutive dash-separated tokens.
	// Since the IPv6 address is always at the end of the node ID, we try reconstructing
	// from the end backwards to find the longest valid IPv6 address.
	tokens := strings.Split(input, "-")
	for i := 0; i < len(tokens); i++ {
		// Try parsing token directly (for unencoded IPv6 with colons)
		if addr, err := netip.ParseAddr(tokens[i]); err == nil && addr.Is6() {
			if !slices.Contains(matches, tokens[i]) {
				matches = append(matches, tokens[i])
			}
			continue
		}

		// Try reconstructing dash-encoded IPv6 (colons replaced with dashes)
		// Try different lengths of consecutive tokens from the end backwards
		// We try from longest to shortest to prefer the most specific match
		for length := 8; length >= 2 && length <= len(tokens); length-- {
			start := len(tokens) - length
			if start < 0 {
				continue
			}
			reconstructed := tokens[start:]
			// Join with colons - empty strings from double dashes will become ::
			candidate := strings.Join(reconstructed, ":")
			if addr, err := netip.ParseAddr(candidate); err == nil && addr.Is6() {
				if !slices.Contains(matches, candidate) {
					matches = append(matches, candidate)
				}
				// We found the IPv6 at the end, no need to continue
				break
			}
		}
	}

	return matches
}

func isDomain(str string) bool {
	for _, r := range str {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func parseMask(ipaddr string) (string, error) {
	p, err := netip.ParsePrefix(ipaddr)
	if err != nil {
		return "", fmt.Errorf("parse mask: error parsing CIDR: %w", err)
	}
	bits := p.Bits()
	if p.Addr().Is4() {
		// Return dotted-decimal mask for IPv4
		m := net.CIDRMask(bits, 32)
		return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]), nil
	}
	// For IPv6 return the prefix length as a decimal number.
	// netip.ParsePrefix already validates that bits is in [0, 128].
	return strconv.Itoa(bits), nil
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

// RandomString returns a random string of specified length.
// String is generated by using crypto/rand.
func RandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return err.Error()
	}
	suff := fmt.Sprintf("%x", b[0:])
	return suff
}

// GetISCSITargetsInfoFromStorage returns list of gobrick compatible iscsi targets by querying PowerStore array.
// FR-1.4: Multi-purpose block interfaces (Purposes: [Storage_Iscsi_Target, Storage_NVMe_TCP_Port]) are handled
// correctly: the PowerStore API filter "cs.{Storage_Iscsi_Target}" is a "contains-set" query that returns all
// addresses whose purposes array contains the specified value. A dual-purpose address therefore appears in both
// this response and the NVMe response independently — no local Purposes iteration is needed.
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
			// FR-1.2: pass the bare address. For IPv4 gobrick appends ":3260"; for
			// IPv6 gobrick skips port-append (address already contains ":"), and
			// iscsiadm uses the default port. Bracketed "[IPv6]:3260" must NOT be
			// used here: goiscsi.validateIPAddress rejects it (net.ParseIP returns
			// nil for bracketed+port strings). See DEPENDENCIES.md §goiscsi.
			result = append(result, gobrick.ISCSITargetInfo{Target: t.IPPort.TargetIqn, Portal: t.Address, NetworkID: t.NetworkID})
		}
	}
	return result, nil
}

// GetNVMETCPTargetsInfoFromStorage returns list of gobrick compatible NVME TCP targets by querying PowerStore array
func GetNVMETCPTargetsInfoFromStorage(client gopowerstore.Client, volumeApplianceID string) ([]gobrick.NVMeTargetInfo, error) {
	clusterInfo, err := client.GetCluster(context.Background())
	if err != nil {
		log.Error(err.Error())
		return []gobrick.NVMeTargetInfo{}, err
	}
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
			// FR-1.3: same rationale as iSCSI above — pass bare address.
			// gonvme passes "-a <portal> -s 4420" as separate args; bracketed
			// form is unnecessary and causes issues with session matching.
			result = append(result, gobrick.NVMeTargetInfo{Target: nvmeNQN, Portal: t.Address, NetworkID: t.NetworkID})
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
			result = append(result, gobrick.FCTargetInfo{WWPN: strings.ReplaceAll(t.Wwn, ":", "")})
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
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	nvmeNQN := clusterInfo.NVMeNQN

	fcPorts, err := client.GetFCPorts(context.Background())
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	var result []gobrick.NVMeTargetInfo
	for _, t := range fcPorts {
		if t.IsLinkUp && (t.ApplianceID == volumeApplianceID || volumeApplianceID == "") {
			targetAddress := strings.ReplaceAll(fmt.Sprintf("nn-0x%s:pn-0x%s", strings.ReplaceAll(t.WwnNode, ":", ""), strings.ReplaceAll(t.WwnNVMe, ":", "")), "\n", "")
			result = append(result, gobrick.NVMeTargetInfo{Target: nvmeNQN, Portal: targetAddress})
		}
	}
	return result, nil
}

// ParseCIDR parses the CIDR address to the valid start IP range with Mask
func ParseCIDR(externalAccessCIDR string) (string, error) {
	// check if externalAccess has netmask bit or not
	if !strings.Contains(externalAccessCIDR, "/") {
		// FR-7.2: append /128 for bare IPv6, /32 for bare IPv4
		if addr, err := netip.ParseAddr(externalAccessCIDR); err == nil && addr.Is6() {
			externalAccessCIDR += "/128"
		} else {
			externalAccessCIDR += "/32"
		}
		log.Debugf("externalAccess after appending netMask bit: %s", externalAccessCIDR)
	}
	ip, ipnet, err := net.ParseCIDR(externalAccessCIDR)
	if err != nil {
		return "", err
	}
	log.Debugf("Parsed CIDR: %s -> ip: %v and net: %v", externalAccessCIDR, ip, ipnet)
	start, _ := cidr.AddressRange(ipnet)
	fromString, err := GetIPListWithMaskFromString(externalAccessCIDR)
	if err != nil {
		return "", err
	}
	log.Debugf("IP with Mask: %s", fromString)
	s := strings.Split(fromString, "/")

	// ExernalAccess IP consists of Starting range IP of CIDR+Mask and hence concatenating the same to remove from the array
	externalAccess := start.String() + "/" + s[1]

	return externalAccess, nil
}

// FormatNFSHostEntry returns an address in the host-entry format accepted by PowerStore.
func FormatNFSHostEntry(ip string) (string, error) {
	addr, err := netip.ParseAddr(strings.Trim(ip, "[]"))
	if err != nil {
		return "", fmt.Errorf("invalid NFS host IP %q: %w", ip, err)
	}
	if addr.Is4() {
		return addr.String() + "/255.255.255.255", nil
	}
	return addr.String() + "/128", nil
}

// HostEntryMatchesIP reports whether a PowerStore NFS host entry represents ip.
func HostEntryMatchesIP(entry, ip string) bool {
	host := entry
	if slash := strings.LastIndexByte(entry, '/'); slash > 0 {
		host = entry[:slash]
	}
	entryAddr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	target := ip
	if slash := strings.LastIndexByte(ip, '/'); slash > 0 {
		target = ip[:slash]
	}
	targetAddr, err := netip.ParseAddr(strings.Trim(target, "[]"))
	return err == nil && entryAddr == targetAddr
}

// HostEntriesForIP returns entries that represent the supplied IP, preserving their original format.
func HostEntriesForIP(entries []string, ip string) []string {
	matched := make([]string, 0, len(entries))
	for _, entry := range entries {
		if HostEntryMatchesIP(entry, ip) {
			matched = append(matched, entry)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	return matched
}

// ParseNFSExportPath returns the server address from a PowerStore NFS source.
func ParseNFSExportPath(exportPath string) (string, error) {
	if strings.HasPrefix(exportPath, "[") {
		closeBracket := strings.IndexByte(exportPath, ']')
		if closeBracket <= 1 || len(exportPath) <= closeBracket+2 || exportPath[closeBracket+1:closeBracket+3] != ":/" {
			return "", fmt.Errorf("invalid NFS export path %q", exportPath)
		}
		host := exportPath[1:closeBracket]
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("invalid NFS export host %q: %w", host, err)
		}
		return host, nil
	}

	separator := strings.Index(exportPath, ":/")
	if separator == 0 {
		return "", fmt.Errorf("NfsExportPath %q has empty IP component; expected format <IP>:/<path>", exportPath)
	}
	if separator < 0 {
		return "", fmt.Errorf("invalid NFS export path %q", exportPath)
	}
	return exportPath[:separator], nil
}

// EncodeIPForKubernetes returns an address safe for use in a Kubernetes name or label key.
func EncodeIPForKubernetes(ip string) string {
	return strings.NewReplacer(":", "-", "%", "-").Replace(ip)
}

// HasRequiredTopology Checks if requiredTopology is present in the topology array and is true
func HasRequiredTopology(topologies []*csi.Topology, arrIP string, requiredTopology string) bool {
	if len(topologies) == 0 || len(arrIP) == 0 || len(requiredTopology) == 0 {
		return false
	}

	safeIP := EncodeIPForKubernetes(arrIP)
	topologyKey := Name + "/" + safeIP + "-" + strings.ToLower(requiredTopology)
	for _, topology := range topologies {
		if value, ok := topology.Segments[topologyKey]; ok && strings.EqualFold(value, "true") {
			return true
		}
	}
	return false
}

// RuntimeConfig holds the tuning parameters for PowerStore metrics calls.
// This is used by the MetricsRuntime to configure circuit breaker, rate limiting, and caching.
type RuntimeConfig struct {
	Timeout        time.Duration
	CacheTTL       time.Duration
	RateLimit      int
	CBThreshold    int
	CBResetTimeout time.Duration
	StaleReporter  func() func(globalID string, stale bool)
}

// GetNfsTopology Returns a topology array with only nfs
func GetNfsTopology(arrIP string) []*csi.Topology {
	nfsTopology := new(csi.Topology)
	safeIP := EncodeIPForKubernetes(arrIP)
	nfsTopology.Segments = map[string]string{Name + "/" + safeIP + "-nfs": "true"}
	return []*csi.Topology{nfsTopology}
}

// blockProtocolSuffixes lists the PowerStore block-protocol topology key suffixes that must be
// removed from NFS volume topology so that NFS pods are not incorrectly coupled to block-only nodes.
var blockProtocolSuffixes = []string{"-fc", "-iscsi", "-nvmefc", "-nvmetcp"}

// isBlockProtocolSegment reports whether the given topology key represents a PowerStore
// block-protocol segment that should be stripped from NFS volume topology responses.
func isBlockProtocolSegment(key string) bool {
	if !strings.HasPrefix(key, Name+"/") {
		return false
	}
	for _, suffix := range blockProtocolSuffixes {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// GetEligibleNfsAccessibleTopologies returns a list of topologies for NFS-accessible PVs.
// It scans all entries in Preferred (then Requisite if needed), retains only those
// containing the correct NFS key from GetNfsTopology(arrIP), strips block protocol keys,
// preserves custom labels, and deduplicates entries. Falls back to the legacy NFS-only topology.
func GetEligibleNfsAccessibleTopologies(preferred, requisite []*csi.Topology, arrIP string) []*csi.Topology {
	// Construct the NFS key directly - matches the format used by GetNfsTopology
	nfsKey := Name + "/" + arrIP + "-nfs"
	nfsValue := "true"

	seen := make(map[string]struct{})
	result := []*csi.Topology{}
	filter := func(topos []*csi.Topology) {
		for _, topo := range topos {
			if v, ok := topo.Segments[nfsKey]; !ok || !strings.EqualFold(v, nfsValue) {
				continue
			}
			// Remove block protocol keys, keep custom labels and the NFS key
			newSegs := make(map[string]string)
			for k, v := range topo.Segments {
				if !isBlockProtocolSegment(k) {
					newSegs[k] = v
				}
			}
			// Normalize the NFS value to preserve the canonical topology format.
			newSegs[nfsKey] = nfsValue
			// Deduplicate by canonical key
			key := canonicalTopologyKey(newSegs)
			if _, found := seen[key]; !found {
				result = append(result, &csi.Topology{Segments: newSegs})
				seen[key] = struct{}{}
			}
		}
	}
	filter(preferred)
	if len(result) == 0 {
		filter(requisite)
	}
	if len(result) == 0 {
		return GetNfsTopology(arrIP)
	}
	return result
}

// canonicalTopologyKey builds a stable string key for deduplication
func canonicalTopologyKey(segs map[string]string) string {
	keys := make([]string, 0, len(segs))
	for k := range segs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k + "=" + segs[k] + ";")
	}
	return sb.String()
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
		log.Debugf("ExternalAccess is already added into Host Access list on array: %s ", externalAccess)
		return true
	}
	log.Debugf("Going to add externalAccess into Host Access list on array: %s", externalAccess)
	return false
}

// SetPollingFrequency reads the pollingFrequency from Env, sets default vale if ENV not found
func SetPollingFrequency(ctx context.Context) int64 {
	var pollingFrequency int64
	if pollRateEnv, ok := csictx.LookupEnv(ctx, EnvPodmonArrayConnectivityPollRate); ok {
		if pollingFrequency, _ = strconv.ParseInt(pollRateEnv, 10, 32); pollingFrequency != 0 {
			log.WithContext(ctx).Debugf("use pollingFrequency as %d seconds", pollingFrequency)
			return pollingFrequency
		}
	}
	log.WithContext(ctx).Debugf("use default pollingFrequency as %d seconds", DefaultPodmonPollRate)
	return DefaultPodmonPollRate
}

// SetAPIPort set the port for running server
func SetAPIPort(ctx context.Context) {
	if port, ok := csictx.LookupEnv(ctx, EnvPodmonAPIPORT); ok && strings.TrimSpace(port) != "" {
		APIPort = fmt.Sprintf(":%s", port)
		log.WithContext(ctx).Debugf("set podmon API port to %s", APIPort)
		return
	}
	// If the port number cannot be fetched, set it to default
	APIPort = ":" + DefaultPodmonAPIPortNumber
	log.WithContext(ctx).Debugf("set podmon API port to default %s", APIPort)
}

// ReachableEndPoint checks if this endpoint is reachable or not.
// It accepts IPv4 and IPv6 endpoints with or without a port, bracketed or unbracketed,
// and handles trailing target portal group tags (e.g. "10.0.0.1:3260,1" or "[2001:db8::1]:3260,1").
// When a port is omitted, it defaults to the standard iSCSI port 3260.
func ReachableEndPoint(endpoint string) bool {
	ep := endpoint
	if commaIdx := strings.Index(ep, ","); commaIdx >= 0 {
		ep = ep[:commaIdx]
	}
	if _, _, err := net.SplitHostPort(ep); err != nil {
		bare := strings.Trim(ep, "[]")
		if bare != "" {
			ep = net.JoinHostPort(bare, "3260")
		}
	}
	_, err := net.DialTimeout("tcp", ep, 2*time.Second)
	return err == nil
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

// GetTimeoutFromEnv retrieves a timeout value from the specified environment variable or returns default value.
func GetTimeoutFromEnv(envvar string) (time.Duration, error) {
	var timeout time.Duration
	var err error
	if duration, ok := csictx.LookupEnv(context.Background(), envvar); ok {
		timeout, err = time.ParseDuration(duration)
		if err != nil {
			return -1, err
		}
	} else {
		return -1, errors.New("failed to get timeout from env")
	}
	log.Infof("%s set to: %v", envvar, timeout)
	return timeout, nil
}

// GetIntFromEnv retrieves an integer value from the specified environment variable or returns an error.
func GetIntFromEnv(envvar string) (int, error) {
	if valStr, ok := csictx.LookupEnv(context.Background(), envvar); ok {
		val, err := strconv.Atoi(valStr)
		if err != nil {
			return -1, err
		}
		log.Infof("%s set to: %d", envvar, val)
		return val, nil
	}
	return -1, errors.New("failed to get integer value from env")
}

// GetPodmonArrayConnectivityPollRate retrieves a timeout value for podmon node array connectivity check from env var or returns default value.
func GetPodmonArrayConnectivityTimeout() time.Duration {
	timeout, err := GetTimeoutFromEnv(EnvPodmonArrayConnectivityTimeout)
	if err != nil {
		log.Debugf("failed to get timeout from env %s, using default value %d", EnvPodmonArrayConnectivityTimeout, DefaultPodmonArrayConnectivityTimeout)
		return DefaultPodmonArrayConnectivityTimeout
	}
	return timeout
}

// GetPowerStoreRESTApiTimeout retrieves a timeout value for PowerStore REST API requests from env var or returns default value..
func GetPowerStoreRESTApiTimeout() time.Duration {
	timeout, err := GetTimeoutFromEnv(EnvPowerstoreAPITimeout)
	if err != nil {
		log.Debugf("failed to get timeout from env %s, using default value %d", EnvPowerstoreAPITimeout, DefaultPowerstoreRESTApiTimeout)
		return DefaultPowerstoreRESTApiTimeout
	}
	return timeout
}

// GetVolumeDisconnectMaxRetries retrieves the maximum number of retry attempts for volume disconnection from env var or returns the default value.
func GetVolumeDisconnectMaxRetries() int {
	retries, err := GetIntFromEnv(EnvVolumeDisconnectMaxRetries)
	if err != nil {
		log.Debugf("failed to get max retries from env %s, using default value %d", EnvVolumeDisconnectMaxRetries, DefaultVolumeDisconnectMaxRetries)
		return DefaultVolumeDisconnectMaxRetries
	}
	return retries
}

// GetVolumeDisconnectRetryInterval retrieves the wait time between volume disconnection retries from env var or returns the default value.
func GetVolumeDisconnectRetryInterval() time.Duration {
	timeout, err := GetTimeoutFromEnv(EnvVolumeDisconnectRetryInterval)
	if err != nil {
		log.Debugf("failed to get RetryInterval from env %s, using default value %d", EnvVolumeDisconnectRetryInterval, DefaultVolumeDisconnectRetryInterval)
		return DefaultVolumeDisconnectRetryInterval
	}
	return timeout
}

// GetVolumeDisconnectTimeout retrieves a timeout value for volume disconnection from env var or returns the default value.
func GetVolumeDisconnectTimeout() time.Duration {
	timeout, err := GetTimeoutFromEnv(EnvVolumeDisconnectTimeoutSeconds)
	if err != nil {
		log.Debugf("failed to get timeout from env %s, using default value %d", EnvVolumeDisconnectTimeoutSeconds, DefaultVolumeDisconnectTimeout)
		return DefaultVolumeDisconnectTimeout
	}
	return timeout
}

// HostAlreadyPresentInNFSExport checks if the given host IP is already present in any of the NFS export host lists.
func HostAlreadyPresentInNFSExport(export gopowerstore.NFSExport, ip string) bool {
	for _, entries := range [][]string{export.ROHosts, export.RORootHosts, export.RWHosts, export.RWRootHosts} {
		if len(HostEntriesForIP(entries, ip)) > 0 {
			log.Debug("Host IP is already present in NFS Export")
			return true
		}
	}
	return false
}

// ParseNfsAutoSelectEnv parses the X_CSI_POWERSTORE_NFS_AUTO_SELECT environment variable.
// Returns (bool, error). If the variable is unset or empty, it returns (false, nil).
func ParseNfsAutoSelectEnv(ctx context.Context) (bool, error) {
	if nfsAutoSelectVal, ok := csictx.LookupEnv(ctx, EnvNfsAutoSelect); ok && nfsAutoSelectVal != "" {
		switch strings.ToLower(nfsAutoSelectVal) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return false, fmt.Errorf("invalid value for %s: %q, valid values are 'true' and 'false'", EnvNfsAutoSelect, nfsAutoSelectVal)
		}
	}
	return false, nil
}
