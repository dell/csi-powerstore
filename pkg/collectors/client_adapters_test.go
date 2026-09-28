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
	"errors"
	"testing"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/gopowerstore"
	gpmocks "github.com/dell/gopowerstore/mocks"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCollectorConstructorsWithClient(t *testing.T) {
	gpClient := &gpmocks.Client{}
	reg := prometheus.NewRegistry()

	assert.NotNil(t, mustNewApplianceCollectorWithClient(t, gpClient, reg, "global-1"))
	assert.NotNil(t, mustNewApplianceCollector(t, &testApplianceClient{}, prometheus.NewRegistry(), "global-1"))
	assert.NotNil(t, mustNewVolumeCollectorWithClient(t, gpClient, prometheus.NewRegistry(), "global-1"))
	assert.NotNil(t, mustNewVolumeCollector(t, &mockVolumeClient{}, prometheus.NewRegistry(), "global-1"))
	assert.NotNil(t, &gopowerstoreApplianceAdapter{client: gpClient})
	assert.NotNil(t, &gopowerstoreVolumeAdapter{client: gpClient})
}

func TestApplianceAdapterWrappers(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{ID: "cluster-1", Name: "cluster-a", State: "Configured"}, nil)
	client.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", gopowerstore.FiveMins).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	client.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)
	client.On("SpaceMetricsByAppliance", mock.Anything, "app-1", gopowerstore.FiveMins).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)

	adapter := &gopowerstoreApplianceAdapter{client: client}

	cluster, err := adapter.GetCluster(ctx)
	require.NoError(t, err)
	assert.Equal(t, "cluster-1", cluster.ID)

	clusterMetrics, err := adapter.SpaceMetricsByCluster(ctx, "cluster-1", gopowerstore.FiveMins)
	require.NoError(t, err)
	assert.Len(t, clusterMetrics, 1)

	appliances, err := adapter.GetAppliances(ctx)
	require.NoError(t, err)
	assert.Len(t, appliances, 1)

	appMetrics, err := adapter.SpaceMetricsByAppliance(ctx, "app-1", gopowerstore.FiveMins)
	require.NoError(t, err)
	assert.Len(t, appMetrics, 1)

	client.AssertExpectations(t)
}

func TestApplianceAdapter_GetCluster_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetCluster", mock.Anything).Return(gopowerstore.Cluster{}, errors.New("cluster error"))

	adapter := &gopowerstoreApplianceAdapter{client: client}

	_, err := adapter.GetCluster(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cluster error")
}

func TestApplianceAdapterRuntimeWrappers(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", gopowerstore.FiveMins).Return([]gopowerstore.SpaceMetricsByClusterResponse{{}}, nil)
	client.On("SpaceMetricsByAppliance", mock.Anything, "app-1", gopowerstore.FiveMins).Return([]gopowerstore.SpaceMetricsByApplianceResponse{{}}, nil)

	adapter := &gopowerstoreApplianceAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	clusterMetrics, err := adapter.SpaceMetricsByCluster(ctx, "cluster-1", gopowerstore.FiveMins)
	require.NoError(t, err)
	assert.Len(t, clusterMetrics, 1)

	appMetrics, err := adapter.SpaceMetricsByAppliance(ctx, "app-1", gopowerstore.FiveMins)
	require.NoError(t, err)
	assert.Len(t, appMetrics, 1)

	client.AssertExpectations(t)
}

func TestVolumeAdapterWrappers(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)
	client.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-1", VolumeID: "vol-1"}}, nil)
	client.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{ID: "host-1"}, nil)

	adapter := &gopowerstoreVolumeAdapter{client: client}

	volumes, err := adapter.GetVolumes(ctx)
	require.NoError(t, err)
	assert.Len(t, volumes, 1)

	mappings, err := adapter.GetHostVolumeMappingByVolumeID(ctx, "vol-1")
	require.NoError(t, err)
	assert.Len(t, mappings, 1)

	host, err := adapter.GetHost(ctx, "host-1")
	require.NoError(t, err)
	assert.Equal(t, "host-1", host.ID)

	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetVolumes(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{{ID: "vol-1", Size: 1}}, nil)

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	volumes, err := adapter.GetVolumes(ctx)
	require.NoError(t, err)
	assert.Len(t, volumes, 1)
	client.AssertExpectations(t)
}

func TestNewApplianceAdapterWithRuntime(t *testing.T) {
	client := &gpmocks.Client{}
	runtime := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{})
	adapter := NewApplianceAdapterWithRuntime(client, runtime)
	assert.NotNil(t, adapter)
}

func TestNewVolumeAdapterWithRuntime(t *testing.T) {
	client := &gpmocks.Client{}
	runtime := NewMetricsRuntime("global-1", identifiers.RuntimeConfig{})
	adapter := NewVolumeAdapterWithRuntime(client, runtime)
	assert.NotNil(t, adapter)
}

func TestVolumeAdapterRuntimeListFS(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{{ID: "fs-1", Name: "fs-1"}}, nil)

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	fileSystems, err := adapter.ListFS(ctx)
	require.NoError(t, err)
	assert.Len(t, fileSystems, 1)
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetNFSExportByFileSystemID(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{ID: "export-1", FileSystemID: "fs-1"}, nil)

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	export, err := adapter.GetNFSExportByFileSystemID(ctx, "fs-1")
	require.NoError(t, err)
	assert.Equal(t, "export-1", export.ID)
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetNFSExports(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-1"}}, nil)

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	exports, err := adapter.GetNFSExports(ctx)
	require.NoError(t, err)
	assert.Len(t, exports, 1)
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetNFSExportsByFileSystemID(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{{ID: "export-1", FileSystemID: "fs-1"}}, nil)

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	exports, err := adapter.GetNFSExportsByFileSystemID(ctx, "fs-1")
	require.NoError(t, err)
	assert.Len(t, exports, 1)
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetHost(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{ID: "host-1"}, nil)

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	host, err := adapter.GetHost(ctx, "host-1")
	require.NoError(t, err)
	assert.Equal(t, "host-1", host.ID)
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetHostVolumeMappingByVolumeID(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{{HostID: "host-1", VolumeID: "vol-1"}}, nil)

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	mappings, err := adapter.GetHostVolumeMappingByVolumeID(ctx, "vol-1")
	require.NoError(t, err)
	assert.Len(t, mappings, 1)
	client.AssertExpectations(t)
}

func TestApplianceAdapterRuntimeGetAppliances(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{{ID: "app-1", Name: "appliance-1"}}, nil)

	adapter := &gopowerstoreApplianceAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	appliances, err := adapter.GetAppliances(ctx)
	require.NoError(t, err)
	assert.Len(t, appliances, 1)
	client.AssertExpectations(t)
}

func TestApplianceAdapterRuntimeGetAppliances_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetAppliances", mock.Anything).Return([]gopowerstore.ApplianceInstance{}, errors.New("get appliances error"))

	adapter := &gopowerstoreApplianceAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.GetAppliances(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get appliances error")
	client.AssertExpectations(t)
}

func TestApplianceAdapterRuntimeSpaceMetricsByCluster_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("SpaceMetricsByCluster", mock.Anything, "cluster-1", gopowerstore.FiveMins).Return([]gopowerstore.SpaceMetricsByClusterResponse{}, errors.New("metrics error"))

	adapter := &gopowerstoreApplianceAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.SpaceMetricsByCluster(ctx, "cluster-1", gopowerstore.FiveMins)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metrics error")
	client.AssertExpectations(t)
}

func TestApplianceAdapterRuntimeSpaceMetricsByAppliance_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("SpaceMetricsByAppliance", mock.Anything, "app-1", gopowerstore.FiveMins).Return([]gopowerstore.SpaceMetricsByApplianceResponse{}, errors.New("metrics error"))

	adapter := &gopowerstoreApplianceAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.SpaceMetricsByAppliance(ctx, "app-1", gopowerstore.FiveMins)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metrics error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeListFS_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{}, errors.New("list error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.ListFS(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetNFSExportByFileSystemID_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{}, errors.New("get export error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.GetNFSExportByFileSystemID(ctx, "fs-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get export error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetNFSExports_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{}, errors.New("get exports error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.GetNFSExports(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get exports error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetNFSExportsByFileSystemID_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{}, errors.New("get exports error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.GetNFSExportsByFileSystemID(ctx, "fs-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get exports error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetHostVolumeMappingByVolumeID_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetHostVolumeMappingByVolumeID", mock.Anything, "vol-1").Return([]gopowerstore.HostVolumeMapping{}, errors.New("get mapping error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.GetHostVolumeMappingByVolumeID(ctx, "vol-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get mapping error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetHost_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetHost", mock.Anything, "host-1").Return(gopowerstore.Host{}, errors.New("get host error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.GetHost(ctx, "host-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get host error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterRuntimeGetVolumes_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetVolumes", mock.Anything).Return([]gopowerstore.Volume{}, errors.New("get volumes error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: NewMetricsRuntime("global-1", identifiers.RuntimeConfig{}),
	}

	_, err := adapter.GetVolumes(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get volumes error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterNonRuntimeListFS_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("ListFS", mock.Anything).Return([]gopowerstore.FileSystem{}, errors.New("list error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: nil,
	}

	_, err := adapter.ListFS(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterNonRuntimeGetNFSExportByFileSystemID_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFileSystemID", mock.Anything, "fs-1").Return(gopowerstore.NFSExport{}, errors.New("get export error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: nil,
	}

	_, err := adapter.GetNFSExportByFileSystemID(ctx, "fs-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get export error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterNonRuntimeGetNFSExports_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{}, errors.New("get exports error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: nil,
	}

	_, err := adapter.GetNFSExports(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get exports error")
	client.AssertExpectations(t)
}

func TestVolumeAdapterNonRuntimeGetNFSExportsByFileSystemID_Error(t *testing.T) {
	ctx := context.Background()
	client := &gpmocks.Client{}
	client.On("GetNFSExportByFilter", mock.Anything, mock.Anything).Return([]gopowerstore.NFSExport{}, errors.New("get exports error"))

	adapter := &gopowerstoreVolumeAdapter{
		client:  client,
		runtime: nil,
	}

	_, err := adapter.GetNFSExportsByFileSystemID(ctx, "fs-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get exports error")
	client.AssertExpectations(t)
}
