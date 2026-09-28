/*
 *
 * Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// This file contains regression tests for CSME-262: NodeGetInfo's NVMe/TCP portal discovery
// must not block the CSI registration-critical RPC beyond the caller's deadline (e.g. kubelet's
// CSI plugin registration timeout) when some configured NVMe/TCP portals/networks in the array's
// IP pool are unreachable from the node.
package node

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/dell/gobrick"
	"github.com/dell/gonvme"
)

// fakeNVMeDiscoverer is a hand-rolled fake implementing gonvme.NVMEinterface that allows tests to
// control, per invocation, how long DiscoverNVMeTCPTargets blocks and what it returns. This gives
// finer-grained control than the package's global GONVMEMock (which cannot simulate some portals
// being reachable/slow and others not within a single call).
type fakeNVMeDiscoverer struct {
	gonvme.NVMeType

	mu        sync.Mutex
	calls     int
	callsByIP map[string]int

	// discover is invoked for every DiscoverNVMeTCPTargets call and controls its outcome.
	discover func(address string) ([]gonvme.NVMeTarget, error)
}

func newFakeNVMeDiscoverer(discover func(address string) ([]gonvme.NVMeTarget, error)) *fakeNVMeDiscoverer {
	return &fakeNVMeDiscoverer{callsByIP: map[string]int{}, discover: discover}
}

func (f *fakeNVMeDiscoverer) DiscoverNVMeTCPTargets(address string, login bool) ([]gonvme.NVMeTarget, error) {
	return f.discoverNVMeTCPTargets(context.Background(), address, login)
}

func (f *fakeNVMeDiscoverer) DiscoverNVMeTCPTargetsContext(ctx context.Context, address string, _ bool) ([]gonvme.NVMeTarget, error) {
	return f.discoverNVMeTCPTargets(ctx, address, false)
}

func (f *fakeNVMeDiscoverer) discoverNVMeTCPTargets(ctx context.Context, address string, _ bool) ([]gonvme.NVMeTarget, error) {
	f.mu.Lock()
	f.calls++
	f.callsByIP[address]++
	f.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return f.discover(address)
	}
}

func (f *fakeNVMeDiscoverer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeNVMeDiscoverer) DiscoverNVMeFCTargets(_ string, _ bool) ([]gonvme.NVMeTarget, error) {
	return nil, nil
}

func (f *fakeNVMeDiscoverer) GetInitiators(_ string) ([]string, error) { return nil, nil }

func (f *fakeNVMeDiscoverer) GetHostID() (string, error) { return "", nil }

func (f *fakeNVMeDiscoverer) NVMeTCPConnect(_ gonvme.NVMeTarget, _ bool) error { return nil }

func (f *fakeNVMeDiscoverer) NVMeFCConnect(_ gonvme.NVMeTarget, _ bool) error { return nil }

func (f *fakeNVMeDiscoverer) NVMeDisconnect(_ gonvme.NVMeTarget) error { return nil }

func (f *fakeNVMeDiscoverer) ListNVMeDeviceAndNamespace() ([]gonvme.DevicePathAndNamespace, error) {
	return nil, nil
}

func (f *fakeNVMeDiscoverer) ListNVMeNamespaceID(_ []gonvme.DevicePathAndNamespace) (map[gonvme.DevicePathAndNamespace][]string, error) {
	return nil, nil
}

func (f *fakeNVMeDiscoverer) GetNVMeDeviceData(_ string) (string, string, error) { return "", "", nil }

func (f *fakeNVMeDiscoverer) GetSessions() ([]gonvme.NVMESession, error) { return nil, nil }

func (f *fakeNVMeDiscoverer) DeviceRescan(_ string) error { return nil }

// compile-time check that fakeNVMeDiscoverer satisfies gonvme.NVMEinterface
var _ gonvme.NVMEinterface = &fakeNVMeDiscoverer{}

func targetInfo(portal, networkID string) gobrick.NVMeTargetInfo {
	return gobrick.NVMeTargetInfo{Portal: portal, NetworkID: networkID}
}

// TestDiscoverNVMeTCPTargets_ParallelizesAcrossUnreachableNetworks verifies that discovery
// attempts against several distinct (unreachable) networks run concurrently, so the total time
// is bounded by roughly a single attempt's duration rather than the sum of every attempt's
// duration. This is the core of the CSME-262 fix: without it, several unreachable networks in the
// array's IP pool could serialize into a delay exceeding kubelet's CSI registration RPC deadline.
func TestDiscoverNVMeTCPTargets_ParallelizesAcrossUnreachableNetworks(t *testing.T) {
	setVariables()

	const perAttemptDelay = 100 * time.Millisecond
	const numUnreachableNetworks = 5

	fake := newFakeNVMeDiscoverer(func(_ string) ([]gonvme.NVMeTarget, error) {
		time.Sleep(perAttemptDelay)
		return nil, fmt.Errorf("connection refused")
	})
	nodeSvc.nvmeLib = fake

	var infoList []gobrick.NVMeTargetInfo
	for i := 0; i < numUnreachableNetworks; i++ {
		infoList = append(infoList, targetInfo(fmt.Sprintf("10.0.%d.1:4420", i), fmt.Sprintf("NW%d", i)))
	}

	start := time.Now()
	targets := nodeSvc.discoverNVMeTCPTargets(context.Background(), infoList)
	elapsed := time.Since(start)

	if len(targets) != 0 {
		t.Errorf("expected no targets to be discovered, got %d", len(targets))
	}
	if fake.callCount() != numUnreachableNetworks {
		t.Errorf("expected %d discovery attempts (one per network), got %d", numUnreachableNetworks, fake.callCount())
	}
	// Serial execution would take numUnreachableNetworks*perAttemptDelay (~500ms). Concurrent
	// execution should take roughly perAttemptDelay. Use a generous bound to avoid CI flakiness
	// while still clearly distinguishing the two.
	maxAllowed := perAttemptDelay * 3
	if elapsed > maxAllowed {
		t.Errorf("expected discovery across %d networks to complete in well under %v (parallel), took %v", numUnreachableNetworks, maxAllowed, elapsed)
	}
}

// TestDiscoverNVMeTCPTargets_RespectsContextDeadline verifies that NodeGetInfo's NVMe/TCP
// discovery returns promptly once ctx's deadline is reached, instead of blocking until every
// portal's discovery attempt completes. This directly protects kubelet's CSI plugin registration
// RPC deadline (observed ~2 minutes in the field) from being exceeded.
func TestDiscoverNVMeTCPTargets_RespectsContextDeadline(t *testing.T) {
	setVariables()

	// Simulate portals that hang far longer than the caller's deadline.
	fake := newFakeNVMeDiscoverer(func(_ string) ([]gonvme.NVMeTarget, error) {
		time.Sleep(300 * time.Millisecond)
		return nil, fmt.Errorf("i/o timeout")
	})
	nodeSvc.nvmeLib = fake

	infoList := []gobrick.NVMeTargetInfo{
		targetInfo("10.0.0.1:4420", "NW1"),
		targetInfo("10.0.1.1:4420", "NW2"),
		targetInfo("10.0.2.1:4420", "NW3"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	targets := nodeSvc.discoverNVMeTCPTargets(ctx, infoList)
	elapsed := time.Since(start)

	if len(targets) != 0 {
		t.Errorf("expected no targets to be returned before the deadline, got %d", len(targets))
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("expected discoverNVMeTCPTargets to return promptly once ctx's deadline (30ms) was reached, took %v", elapsed)
	}
}

// TestDiscoverNVMeTCPTargets_OneAttemptPerNetwork verifies that a network ID is marked as
// attempted as soon as discovery is kicked off for it (not only on success), so that a network
// with multiple configured (unreachable) portals is only attempted once instead of once per
// portal in that network.
func TestDiscoverNVMeTCPTargets_OneAttemptPerNetwork(t *testing.T) {
	setVariables()

	fake := newFakeNVMeDiscoverer(func(_ string) ([]gonvme.NVMeTarget, error) {
		return nil, fmt.Errorf("connection refused")
	})
	nodeSvc.nvmeLib = fake

	infoList := []gobrick.NVMeTargetInfo{
		targetInfo("10.0.0.1:4420", "NW1"),
		targetInfo("10.0.0.2:4420", "NW1"),
		targetInfo("10.0.0.3:4420", "NW1"),
		targetInfo("10.0.0.4:4420", "NW1"),
		targetInfo("10.0.1.1:4420", "NW2"),
	}

	nodeSvc.discoverNVMeTCPTargets(context.Background(), infoList)

	if fake.callCount() != 2 {
		t.Errorf("expected exactly 2 discovery attempts (one per distinct network ID), got %d", fake.callCount())
	}
}

// TestDiscoverNVMeTCPTargets_AggregatesAllReachableNetworks is a regression test ensuring the
// concurrent implementation still returns the union of targets discovered across all reachable
// networks, matching the previous serial behavior for the healthy-configuration case.
func TestDiscoverNVMeTCPTargets_AggregatesAllReachableNetworks(t *testing.T) {
	setVariables()

	fake := newFakeNVMeDiscoverer(func(address string) ([]gonvme.NVMeTarget, error) {
		return []gonvme.NVMeTarget{{Portal: address, TargetNqn: "nqn.test:" + address}}, nil
	})
	nodeSvc.nvmeLib = fake

	infoList := []gobrick.NVMeTargetInfo{
		targetInfo("10.0.0.1:4420", "NW1"),
		targetInfo("10.0.1.1:4420", "NW2"),
		targetInfo("10.0.2.1:4420", "NW3"),
	}

	targets := nodeSvc.discoverNVMeTCPTargets(context.Background(), infoList)

	if len(targets) != len(infoList) {
		t.Fatalf("expected %d targets (one per reachable network), got %d", len(infoList), len(targets))
	}

	var gotNqns []string
	for _, tg := range targets {
		gotNqns = append(gotNqns, tg.TargetNqn)
	}
	sort.Strings(gotNqns)

	wantNqns := []string{"nqn.test:10.0.0.1", "nqn.test:10.0.1.1", "nqn.test:10.0.2.1"}
	sort.Strings(wantNqns)

	for i := range wantNqns {
		if gotNqns[i] != wantNqns[i] {
			t.Errorf("expected targets %v, got %v", wantNqns, gotNqns)
			break
		}
	}
}

// TestDiscoverNVMeTCPTargets_MixOfReachableAndUnreachableNetworks reproduces the CSME-262
// scenario at a smaller scale: some networks are unreachable (slow to fail) while others are
// reachable. The reachable networks' targets must still be discovered and returned, and the
// overall call must not take substantially longer than the slowest single attempt.
func TestDiscoverNVMeTCPTargets_MixOfReachableAndUnreachableNetworks(t *testing.T) {
	setVariables()

	const unreachableDelay = 80 * time.Millisecond

	fake := newFakeNVMeDiscoverer(func(address string) ([]gonvme.NVMeTarget, error) {
		switch address {
		case "10.0.0.1", "10.0.1.1", "10.0.2.1", "10.0.3.1":
			time.Sleep(unreachableDelay)
			return nil, fmt.Errorf("connection refused")
		default:
			return []gonvme.NVMeTarget{{Portal: address, TargetNqn: "nqn.test:" + address}}, nil
		}
	})
	nodeSvc.nvmeLib = fake

	infoList := []gobrick.NVMeTargetInfo{
		targetInfo("10.0.0.1:4420", "NW1-unreachable"),
		targetInfo("10.0.1.1:4420", "NW2-unreachable"),
		targetInfo("10.0.2.1:4420", "NW3-unreachable"),
		targetInfo("10.0.3.1:4420", "NW4-unreachable"),
		targetInfo("10.0.4.1:4420", "NW5-reachable"),
	}

	start := time.Now()
	targets := nodeSvc.discoverNVMeTCPTargets(context.Background(), infoList)
	elapsed := time.Since(start)

	if len(targets) != 1 || targets[0].TargetNqn != "nqn.test:10.0.4.1" {
		t.Errorf("expected exactly the one target from the reachable network, got %+v", targets)
	}
	if elapsed > unreachableDelay*3 {
		t.Errorf("expected mixed reachable/unreachable discovery to complete in well under %v, took %v", unreachableDelay*3, elapsed)
	}
}
