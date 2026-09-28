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

package collectors

import (
	"context"
	"testing"

	"github.com/dell/csm-metrics-common/pkg/naming"
	"github.com/dell/gopowerstore"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestVolumeCollector_RegistryIsolation(t *testing.T) {
	regA := prometheus.NewRegistry()
	regB := prometheus.NewRegistry()

	collectorA := mustNewVolumeCollector(t, &mockVolumeClient{
		volumes: []gopowerstore.Volume{{ID: "vol-a", Size: 1 << 30}},
	}, regA, "global-a")
	collectorB := mustNewVolumeCollector(t, &mockVolumeClient{
		volumes: []gopowerstore.Volume{{ID: "vol-b", Size: 5 << 30}},
	}, regB, "global-b")

	require.NoError(t, collectorA.Collect(context.Background()))
	require.NoError(t, collectorB.Collect(context.Background()))

	mfA := gatherPSTMetric(t, regA, naming.MetricCSIVolumeTotal)
	mfB := gatherPSTMetric(t, regB, naming.MetricCSIVolumeTotal)
	require.NotNil(t, mfA)
	require.NotNil(t, mfB)

	_, ok := gaugePST(mfA, map[string]string{"global_id": "global-a", "protocol": "unknown"})
	require.True(t, ok)
	_, ok = gaugePST(mfB, map[string]string{"global_id": "global-b", "protocol": "unknown"})
	require.True(t, ok)
}
