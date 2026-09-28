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

package protocol

import (
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	corev1 "k8s.io/api/core/v1"
)

const (
	ISCSI   = "iSCSI"
	FC      = "FC"
	NVMeTCP = "NVMeTCP"
	NVMeFC  = "NVMeFC"
	NFS     = "NFS"
	Unknown = "unknown"
)

// Normalize returns the canonical protocol label used by metrics. Generic
// block protocol values such as "scsi" intentionally resolve to unknown.
func Normalize(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "iscsi":
		return ISCSI
	case "fc":
		return FC
	case "nvmeof", "nvme_fc", "nvme-fc", "nvmefc":
		return NVMeFC
	case "nvme_tcp", "nvme-tcp", "nvmetcp":
		return NVMeTCP
	case "nfs":
		return NFS
	case "unknown", "":
		return Unknown
	default:
		return Unknown
	}
}

// IsGenericBlock returns true when the value means block storage but does not
// identify the actual transport.
func IsGenericBlock(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "scsi":
		return true
	default:
		return false
	}
}

// FromCSIRequirements derives the protocol from CSI topology requirements.
func FromCSIRequirements(requirements *csi.TopologyRequirement) string {
	if requirements == nil {
		return Unknown
	}
	if protocol := FromCSITopologies(requirements.GetPreferred()); protocol != Unknown {
		return protocol
	}
	return FromCSITopologies(requirements.GetRequisite())
}

// FromCSITopologies derives the protocol from CSI topology segment keys.
func FromCSITopologies(topologies []*csi.Topology) string {
	for _, topology := range topologies {
		if topology == nil {
			continue
		}
		for key := range topology.GetSegments() {
			if protocol := FromTopologyKey(key); protocol != Unknown {
				return protocol
			}
		}
	}
	return Unknown
}

// FromNodeAffinity derives the protocol from Kubernetes PV node affinity.
func FromNodeAffinity(nodeAffinity *corev1.VolumeNodeAffinity) string {
	if nodeAffinity == nil || nodeAffinity.Required == nil {
		return Unknown
	}

	for _, term := range nodeAffinity.Required.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if protocol := FromTopologyKey(expr.Key); protocol != Unknown {
				return protocol
			}
		}
	}
	return Unknown
}

// FromTopologyKey derives the protocol from a topology key suffix.
func FromTopologyKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	switch {
	case strings.HasSuffix(key, "-iscsi"):
		return ISCSI
	case strings.HasSuffix(key, "-nvmetcp"), strings.HasSuffix(key, "-nvme-tcp"):
		return NVMeTCP
	case strings.HasSuffix(key, "-nvmefc"), strings.HasSuffix(key, "-nvme-fc"):
		return NVMeFC
	case strings.HasSuffix(key, "-fc"):
		return FC
	case strings.HasSuffix(key, "-nfs"):
		return NFS
	default:
		return Unknown
	}
}
