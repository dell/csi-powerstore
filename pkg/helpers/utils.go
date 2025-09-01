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

package helpers

import (
	"errors"
	"net"
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

// GetNodeIP retrieves the first valid non-loopback IPv4 addres
func GetNodeIPWithProvider(ifProvider InterfaceProvider, addrProvider AddrProvider) (net.IP, error) {
	interfaces, err := ifProvider.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := addrProvider.Addrs(iface)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			return ip, nil
		}
	}
	return nil, errors.New("no valid non-loopback IPv4 address found")
}
