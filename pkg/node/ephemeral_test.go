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

package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeEphemeralCreateVolumeParams(t *testing.T) {
	t.Parallel()

	input := map[string]string{
		"arrayID":     "attacker-array-upper",
		"arrayId":     "attacker-array",
		"nasName":     "attacker-nas",
		"storagePool": "attacker-pool",
		"protocol":    "NFS",
		"size":        "1Gi",
	}

	got := sanitizeEphemeralCreateVolumeParams(input)

	assert.Equal(t, "1Gi", got["size"])
	assert.NotContains(t, got, "arrayID")
	assert.NotContains(t, got, "arrayId")
	assert.NotContains(t, got, "nasName")
	assert.Equal(t, "attacker-pool", got["storagePool"])
	assert.Equal(t, "NFS", got["protocol"])
}
