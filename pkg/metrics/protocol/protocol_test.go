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
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		"iscsi":     ISCSI,
		" ISCSI ":   ISCSI,
		"fc":        FC,
		"FC":        FC,
		"nvmeof":    NVMeFC,
		"nvme_fc":   NVMeFC,
		"nvme-fc":   NVMeFC,
		"nvmefc":    NVMeFC,
		"NVMeFC":    NVMeFC,
		"nvme_tcp":  NVMeTCP,
		"nvme-tcp":  NVMeTCP,
		"nvmetcp":   NVMeTCP,
		"NVMeTCP":   NVMeTCP,
		"nfs":       NFS,
		"NFS":       NFS,
		"scsi":      Unknown,
		"":          Unknown,
		"unknown":   Unknown,
		"something": Unknown,
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			require.Equal(t, want, Normalize(input))
		})
	}
}

func TestIsGenericBlock(t *testing.T) {
	require.True(t, IsGenericBlock(""))
	require.True(t, IsGenericBlock("scsi"))
	require.True(t, IsGenericBlock(" SCSI "))
	require.False(t, IsGenericBlock("iSCSI"))
	require.False(t, IsGenericBlock("NFS"))
}

func TestFromTopologyKey(t *testing.T) {
	tests := map[string]string{
		"csi-powerstore.dellemc.com/10.247.27.44-iscsi":    ISCSI,
		"csi-powerstore.dellemc.com/10.247.27.44-fc":       FC,
		"csi-powerstore.dellemc.com/10.247.27.44-nvmetcp":  NVMeTCP,
		"csi-powerstore.dellemc.com/10.247.27.44-nvme-tcp": NVMeTCP,
		"csi-powerstore.dellemc.com/10.247.27.44-nvmefc":   NVMeFC,
		"csi-powerstore.dellemc.com/10.247.27.44-nvme-fc":  NVMeFC,
		"csi-powerstore.dellemc.com/10.247.27.44-nfs":      NFS,
		"csi-powerstore.dellemc.com/10.247.27.44":          Unknown,
		"": Unknown,
	}

	for key, want := range tests {
		t.Run(key, func(t *testing.T) {
			require.Equal(t, want, FromTopologyKey(key))
		})
	}
}

func TestFromCSITopologies(t *testing.T) {
	require.Equal(t, Unknown, FromCSITopologies(nil))
	require.Equal(t, Unknown, FromCSITopologies([]*csi.Topology{nil}))
	require.Equal(t, NVMeTCP, FromCSITopologies([]*csi.Topology{
		{Segments: map[string]string{"ignored": "true"}},
		{Segments: map[string]string{"csi-powerstore.dellemc.com/10.247.27.44-nvme-tcp": "true"}},
	}))
}

func TestFromCSIRequirements(t *testing.T) {
	require.Equal(t, Unknown, FromCSIRequirements(nil))
	require.Equal(t, FC, FromCSIRequirements(&csi.TopologyRequirement{
		Preferred: []*csi.Topology{
			{Segments: map[string]string{"csi-powerstore.dellemc.com/10.247.27.44-fc": "true"}},
		},
		Requisite: []*csi.Topology{
			{Segments: map[string]string{"csi-powerstore.dellemc.com/10.247.27.44-iscsi": "true"}},
		},
	}))
	require.Equal(t, ISCSI, FromCSIRequirements(&csi.TopologyRequirement{
		Preferred: []*csi.Topology{
			{Segments: map[string]string{"ignored": "true"}},
		},
		Requisite: []*csi.Topology{
			{Segments: map[string]string{"csi-powerstore.dellemc.com/10.247.27.44-iscsi": "true"}},
		},
	}))
}

func TestFromNodeAffinity(t *testing.T) {
	require.Equal(t, Unknown, FromNodeAffinity(nil))
	require.Equal(t, Unknown, FromNodeAffinity(&corev1.VolumeNodeAffinity{}))
	require.Equal(t, NVMeFC, FromNodeAffinity(&corev1.VolumeNodeAffinity{
		Required: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{
					MatchExpressions: []corev1.NodeSelectorRequirement{
						{Key: "ignored"},
						{Key: "csi-powerstore.dellemc.com/10.247.27.44-nvme-fc"},
					},
				},
			},
		},
	}))
}
