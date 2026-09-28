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
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFormatCreateVolumeErrorPreservesCallerDeadline(t *testing.T) {
	err := formatCreateVolumeError(context.DeadlineExceeded, "https://[2001:db8::1]/api/rest")

	if got := status.Code(err); got != codes.DeadlineExceeded {
		t.Fatalf("status code = %s, want %s", got, codes.DeadlineExceeded)
	}
}
