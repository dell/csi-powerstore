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

package helpers

import (
	"errors"
	"net"
	"net/netip"

	log "github.com/dell/csmlog"
)

// InterfaceProvider allows mocking net.Interfaces
type InterfaceProvider interface {
	Interfaces() ([]net.Interface, error)
}

// AddrProvider allows mocking iface.Addrs()
type AddrProvider interface {
	Addrs(iface net.Interface) ([]net.Addr, error)
}

// Default providers for production use
type defaultProvider struct{}

func (p defaultProvider) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

func (p defaultProvider) Addrs(iface net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

func GetNodeIP() (net.IP, error) {
	return GetNodeIPWithProvider(defaultProvider{}, defaultProvider{})
}

// GetNodeIPWithProvider retrieves the node's outbound IP address.
// FR-5.2: Pass 1 returns the first non-loopback IPv4 address (preserves
// existing behaviour). Pass 2 returns the first non-loopback, non-link-local
// IPv6 unicast address so that IPv6-only nodes are supported.
// FR-10.1/FR-10.2: Link-local IPv6 addresses are accepted as a last-resort
// fallback (Pass 3). A warning is emitted when a link-local address without
// a zone ID is selected on a node with more than one non-loopback interface,
// because routing to link-local destinations is interface-scoped and may be
// ambiguous without an explicit zone ID.
func GetNodeIPWithProvider(ifProvider InterfaceProvider, addrProvider AddrProvider) (net.IP, error) {
	interfaces, err := ifProvider.Interfaces()
	if err != nil {
		return nil, err
	}

	var ipv6Candidate net.IP
	var linkLocalCandidate net.IP
	var linkLocalZone string
	nonLoopbackCount := 0

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		nonLoopbackCount++

		addrs, err := addrProvider.Addrs(iface)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			var zone string
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
				zone = v.Zone // FR-10.2: preserve zone ID for link-local detection
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}
			// Pass 1: prefer IPv4
			if ip.To4() != nil {
				return ip, nil
			}
			// Pass 2 candidate: first non-loopback, non-link-local IPv6
			if ipv6Candidate == nil && !ip.IsLinkLocalUnicast() {
				ipv6Candidate = ip
			}
			// Pass 3 candidate: link-local IPv6 as last resort (FR-10.1)
			if linkLocalCandidate == nil && ip.IsLinkLocalUnicast() {
				linkLocalCandidate = ip
				linkLocalZone = zone
			}
		}
	}

	if ipv6Candidate != nil {
		return ipv6Candidate, nil
	}

	// FR-10.1: accept link-local as last resort.
	// FR-10.2: warn if zone ID is absent on a multi-interface node — routing may be ambiguous.
	if linkLocalCandidate != nil {
		if linkLocalZone == "" {
			// Double-check via netip.ParseAddr which preserves zone (handles %iface suffix)
			if parsed, parseErr := netip.ParseAddr(linkLocalCandidate.String()); parseErr == nil {
				linkLocalZone = parsed.Zone()
			}
		}
		if linkLocalZone == "" && nonLoopbackCount > 1 {
			log.Warn("link-local IPv6 address selected with no zone ID on multi-interface node; routing may be ambiguous")
		}
		return linkLocalCandidate, nil
	}

	return nil, errors.New("no valid non-loopback IP address found")
}
