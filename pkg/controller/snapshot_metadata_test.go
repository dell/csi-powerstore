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
	"strings"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSnapshotMetadataServer_GetMetadataDelta_ReturnsUnimplemented(t *testing.T) {
	srv := &snapshotMetadataServer{}
	err := srv.GetMetadataDelta(&csi.GetMetadataDeltaRequest{}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got: %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "GetMetadataDelta") {
		t.Fatalf("error should mention GetMetadataDelta, got: %v", err)
	}
}

func TestSnapshotMetadataServer_GetMetadataAllocated_ReturnsUnimplemented(t *testing.T) {
	srv := &snapshotMetadataServer{}
	err := srv.GetMetadataAllocated(&csi.GetMetadataAllocatedRequest{}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got: %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "GetMetadataAllocated") {
		t.Fatalf("error should mention GetMetadataAllocated, got: %v", err)
	}
}
