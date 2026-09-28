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

package controller

import (
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// snapshotMetadataServer is a stub implementation of the CSI 1.12
// SnapshotMetadata service. Both RPCs return codes.Unimplemented
// because PowerStore does not currently support changed-block tracking.
type snapshotMetadataServer struct {
	csi.UnimplementedSnapshotMetadataServer
}

// GetMetadataAllocated returns Unimplemented.
func (s *snapshotMetadataServer) GetMetadataAllocated(
	_ *csi.GetMetadataAllocatedRequest,
	_ csi.SnapshotMetadata_GetMetadataAllocatedServer,
) error {
	return status.Error(codes.Unimplemented, "GetMetadataAllocated is not supported")
}

// GetMetadataDelta returns Unimplemented.
func (s *snapshotMetadataServer) GetMetadataDelta(
	_ *csi.GetMetadataDeltaRequest,
	_ csi.SnapshotMetadata_GetMetadataDeltaServer,
) error {
	return status.Error(codes.Unimplemented, "GetMetadataDelta is not supported")
}
