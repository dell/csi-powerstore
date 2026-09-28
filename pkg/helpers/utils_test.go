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
	"testing"

	"github.com/stretchr/testify/assert"
)

// Mock implementations
type mockInterfaceProvider struct {
	interfaces []net.Interface
	err        error
}

func (m mockInterfaceProvider) Interfaces() ([]net.Interface, error) {
	return m.interfaces, m.err
}

type mockAddrProvider struct {
	addrMap map[string][]net.Addr
	errMap  map[string]error
}

func (m mockAddrProvider) Addrs(iface net.Interface) ([]net.Addr, error) {
	if err, ok := m.errMap[iface.Name]; ok {
		return nil, err
	}
	return m.addrMap[iface.Name], nil
}

func TestGetNodeIP_AllCases(t *testing.T) {
	tests := []struct {
		name         string
		ifProvider   InterfaceProvider
		addrProvider AddrProvider
		wantErr      bool
		expectedIP   string
	}{
		{
			name: "error from net.Interfaces",
			ifProvider: mockInterfaceProvider{
				err: errors.New("interface error"),
			},
			addrProvider: mockAddrProvider{},
			wantErr:      true,
		},
		{
			name: "no interfaces returned",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{},
			},
			addrProvider: mockAddrProvider{},
			wantErr:      true,
		},
		{
			name: "all interfaces are down or loopback",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{
					{Name: "lo", Flags: net.FlagLoopback},
					{Name: "eth0", Flags: 0},
				},
			},
			addrProvider: mockAddrProvider{},
			wantErr:      true,
		},
		{
			name: "interface returns error on Addrs()",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{
					{Name: "eth0", Flags: net.FlagUp},
				},
			},
			addrProvider: mockAddrProvider{
				errMap: map[string]error{
					"eth0": errors.New("addr error"),
				},
			},
			wantErr: true,
		},
		{
			name: "addresses are loopback or non-IPv4",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{
					{Name: "eth0", Flags: net.FlagUp},
				},
			},
			addrProvider: mockAddrProvider{
				addrMap: map[string][]net.Addr{
					"eth0": {
						&net.IPNet{IP: net.ParseIP("127.0.0.1")},
						&net.IPNet{IP: net.ParseIP("::1")},
					},
				},
			},
			wantErr: true,
		},
		// FR-5.2: IPv6-only node — return first non-loopback, non-link-local IPv6
		{
			name: "IPv6-only node returns global unicast IPv6",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{
					{Name: "eth0", Flags: net.FlagUp},
				},
			},
			addrProvider: mockAddrProvider{
				addrMap: map[string][]net.Addr{
					"eth0": {
						&net.IPNet{IP: net.ParseIP("2001:db8::1")},
					},
				},
			},
			wantErr:    false,
			expectedIP: "2001:db8::1",
		},
		// FR-10.1/FR-10.2: link-local is now accepted as a last-resort fallback.
		// Single-interface node: no warning.
		{
			name: "link-local IPv6 only is accepted as fallback (single interface)",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{
					{Name: "eth0", Flags: net.FlagUp},
				},
			},
			addrProvider: mockAddrProvider{
				addrMap: map[string][]net.Addr{
					"eth0": {
						&net.IPNet{IP: net.ParseIP("fe80::1")},
					},
				},
			},
			wantErr:    false,
			expectedIP: "fe80::1",
		},
		// FR-5.2 regression: IPv4 preferred over IPv6 on dual-stack node
		{
			name: "dual-stack node returns IPv4 first",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{
					{Name: "eth0", Flags: net.FlagUp},
				},
			},
			addrProvider: mockAddrProvider{
				addrMap: map[string][]net.Addr{
					"eth0": {
						&net.IPNet{IP: net.ParseIP("2001:db8::1")},
						&net.IPNet{IP: net.ParseIP("192.168.1.1")},
					},
				},
			},
			wantErr:    false,
			expectedIP: "192.168.1.1",
		},
		{
			name: "valid IPv4 address found",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{
					{Name: "eth0", Flags: net.FlagUp},
				},
			},
			addrProvider: mockAddrProvider{
				addrMap: map[string][]net.Addr{
					"eth0": {
						&net.IPNet{IP: net.ParseIP("192.168.1.100")},
					},
				},
			},
			wantErr:    false,
			expectedIP: "192.168.1.100",
		},
		{
			name: "valid IP found in second interface",
			ifProvider: mockInterfaceProvider{
				interfaces: []net.Interface{
					{Name: "lo", Flags: net.FlagLoopback},
					{Name: "eth1", Flags: net.FlagUp},
				},
			},
			addrProvider: mockAddrProvider{
				addrMap: map[string][]net.Addr{
					"eth1": {
						&net.IPAddr{IP: net.ParseIP("10.0.0.5")},
					},
				},
			},
			wantErr:    false,
			expectedIP: "10.0.0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := GetNodeIPWithProvider(tt.ifProvider, tt.addrProvider)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, ip)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ip)
				assert.Equal(t, tt.expectedIP, ip.String())
			}
		})
	}
}

func TestDefaultProvider_Interfaces(t *testing.T) {
	provider := defaultProvider{}

	interfaces, err := provider.Interfaces()
	assert.NoError(t, err)
	assert.NotNil(t, interfaces)
	assert.Greater(t, len(interfaces), 0, "Expected at least one network interface")
}

func TestDefaultProvider_Addrs(t *testing.T) {
	provider := defaultProvider{}

	interfaces, err := provider.Interfaces()
	assert.NoError(t, err)
	assert.NotEmpty(t, interfaces)

	for _, iface := range interfaces {
		_, err := provider.Addrs(iface)
		// Some interfaces may not have addresses, but the call shouldn't fail
		assert.NoError(t, err)
	}
}

func TestGetNodeIP_Integration(t *testing.T) {
	ip, err := GetNodeIP()
	if err != nil {
		t.Logf("No valid IP found: %v", err)
	} else {
		assert.NotNil(t, ip)
		t.Logf("Found IP: %s", ip.String())
	}
}

// FR-10.1: link-local IPv6 with zone ID (%eth0) accepted as fallback.
// FR-10.2: no warning when zone ID is present.
func TestGetNodeIPWithProvider_LinkLocalWithZone(t *testing.T) {
	ip, err := GetNodeIPWithProvider(
		mockInterfaceProvider{
			interfaces: []net.Interface{
				{Name: "eth0", Flags: net.FlagUp},
				{Name: "eth1", Flags: net.FlagUp},
			},
		},
		mockAddrProvider{
			addrMap: map[string][]net.Addr{
				"eth0": {
					// Link-local with zone via IPAddr.Zone
					&net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"},
				},
				"eth1": {
					&net.IPAddr{IP: net.ParseIP("fe80::2"), Zone: "eth1"},
				},
			},
		},
	)
	assert.NoError(t, err, "link-local with zone ID must be accepted")
	assert.NotNil(t, ip)
	assert.Equal(t, "fe80::1", ip.String())
}

// FR-10.2: multi-interface node, link-local without zone ID — accepted but warning logged.
// The test verifies the function succeeds (warning is non-blocking).
func TestGetNodeIPWithProvider_LinkLocalNoZoneMultiInterface(t *testing.T) {
	ip, err := GetNodeIPWithProvider(
		mockInterfaceProvider{
			interfaces: []net.Interface{
				{Name: "eth0", Flags: net.FlagUp},
				{Name: "eth1", Flags: net.FlagUp},
			},
		},
		mockAddrProvider{
			addrMap: map[string][]net.Addr{
				"eth0": {
					// Link-local without zone (IPNet has no Zone field)
					&net.IPNet{IP: net.ParseIP("fe80::1")},
				},
				"eth1": {
					&net.IPNet{IP: net.ParseIP("fe80::2")},
				},
			},
		},
	)
	// Warning is logged (non-blocking); function still returns success
	assert.NoError(t, err, "link-local without zone on multi-interface should succeed with warning")
	assert.NotNil(t, ip)
	assert.Equal(t, "fe80::1", ip.String())
}

// FR-10.2 regression: global unicast IPv6 preferred over link-local
func TestGetNodeIPWithProvider_GlobalUnicastPreferredOverLinkLocal(t *testing.T) {
	ip, err := GetNodeIPWithProvider(
		mockInterfaceProvider{
			interfaces: []net.Interface{
				{Name: "eth0", Flags: net.FlagUp},
			},
		},
		mockAddrProvider{
			addrMap: map[string][]net.Addr{
				"eth0": {
					&net.IPNet{IP: net.ParseIP("fe80::1")},
					&net.IPNet{IP: net.ParseIP("2001:db8::1")},
				},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::1", ip.String(), "global unicast must be preferred over link-local")
}
