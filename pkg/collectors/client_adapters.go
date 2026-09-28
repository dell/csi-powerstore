/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

	"github.com/dell/gopowerstore"
)

// ClusterInfo holds cluster information for metrics collection.
type ClusterInfo struct {
	ID    string
	Name  string
	State string
}

// ApplianceClient is the interface required by ApplianceCollector
type ApplianceClient interface {
	GetCluster(ctx context.Context) (ClusterInfo, error)
	SpaceMetricsByCluster(ctx context.Context, clusterID string, interval gopowerstore.MetricsIntervalEnum) ([]gopowerstore.SpaceMetricsByClusterResponse, error)
	GetAppliances(ctx context.Context) ([]gopowerstore.ApplianceInstance, error)
	SpaceMetricsByAppliance(ctx context.Context, applianceID string, interval gopowerstore.MetricsIntervalEnum) ([]gopowerstore.SpaceMetricsByApplianceResponse, error)
}

// gopowerstoreApplianceAdapter wraps gopowerstore.Client to implement ApplianceClient
type gopowerstoreApplianceAdapter struct {
	client  gopowerstore.Client
	runtime *MetricsRuntime
}

func (a *gopowerstoreApplianceAdapter) GetCluster(ctx context.Context) (ClusterInfo, error) {
	gpCluster, err := a.client.GetCluster(ctx)
	if err != nil {
		return ClusterInfo{}, err
	}
	return ClusterInfo{
		ID:    gpCluster.ID,
		Name:  gpCluster.Name,
		State: string(gpCluster.State),
	}, nil
}

func (a *gopowerstoreApplianceAdapter) SpaceMetricsByCluster(ctx context.Context, clusterID string, interval gopowerstore.MetricsIntervalEnum) ([]gopowerstore.SpaceMetricsByClusterResponse, error) {
	if a.runtime == nil {
		return a.client.SpaceMetricsByCluster(ctx, clusterID, interval)
	}
	cacheKey := clusterID + string(interval)
	v, err := a.runtime.Do(ctx, "cluster_space_metrics", cacheKey, func(callCtx context.Context) (any, error) {
		return a.client.SpaceMetricsByCluster(callCtx, clusterID, interval)
	})
	if err != nil {
		return nil, err
	}
	result, _ := v.([]gopowerstore.SpaceMetricsByClusterResponse)
	return result, nil
}

func (a *gopowerstoreApplianceAdapter) GetAppliances(ctx context.Context) ([]gopowerstore.ApplianceInstance, error) {
	if a.runtime == nil {
		return a.client.GetAppliances(ctx)
	}
	v, err := a.runtime.Do(ctx, "appliances", "all_appliances", func(callCtx context.Context) (any, error) {
		return a.client.GetAppliances(callCtx)
	})
	if err != nil {
		return nil, err
	}
	result, _ := v.([]gopowerstore.ApplianceInstance)
	return result, nil
}

func (a *gopowerstoreApplianceAdapter) SpaceMetricsByAppliance(ctx context.Context, applianceID string, interval gopowerstore.MetricsIntervalEnum) ([]gopowerstore.SpaceMetricsByApplianceResponse, error) {
	if a.runtime == nil {
		return a.client.SpaceMetricsByAppliance(ctx, applianceID, interval)
	}
	cacheKey := applianceID + string(interval)
	v, err := a.runtime.Do(ctx, "appliance_space_metrics", cacheKey, func(callCtx context.Context) (any, error) {
		return a.client.SpaceMetricsByAppliance(callCtx, applianceID, interval)
	})
	if err != nil {
		return nil, err
	}
	result, _ := v.([]gopowerstore.SpaceMetricsByApplianceResponse)
	return result, nil
}

// NewApplianceAdapterWithRuntime creates a new gopowerstoreApplianceAdapter with runtime support
func NewApplianceAdapterWithRuntime(client gopowerstore.Client, runtime *MetricsRuntime) ApplianceClient {
	return &gopowerstoreApplianceAdapter{client: client, runtime: runtime}
}

// VolumeClient is the interface required by VolumeCollector
type VolumeClient interface {
	GetVolumes(ctx context.Context) ([]gopowerstore.Volume, error)
	ListFS(ctx context.Context) ([]gopowerstore.FileSystem, error)
	GetHostVolumeMappingByVolumeID(ctx context.Context, volumeID string) ([]gopowerstore.HostVolumeMapping, error)
	GetNFSExportByFileSystemID(ctx context.Context, fsID string) (gopowerstore.NFSExport, error)
	GetNFSExports(ctx context.Context) ([]gopowerstore.NFSExport, error)
	GetNFSExportsByFileSystemID(ctx context.Context, fsID string) ([]gopowerstore.NFSExport, error)
	GetHost(ctx context.Context, hostID string) (gopowerstore.Host, error)
}

// gopowerstoreVolumeAdapter wraps gopowerstore.Client to implement VolumeClient
type gopowerstoreVolumeAdapter struct {
	client  gopowerstore.Client
	runtime *MetricsRuntime
}

func (a *gopowerstoreVolumeAdapter) GetVolumes(ctx context.Context) ([]gopowerstore.Volume, error) {
	if a.runtime == nil {
		return a.client.GetVolumes(ctx)
	}
	v, err := a.runtime.Do(ctx, "volumes", "all_volumes", func(callCtx context.Context) (any, error) {
		return a.client.GetVolumes(callCtx)
	})
	if err != nil {
		return nil, err
	}
	result, _ := v.([]gopowerstore.Volume)
	return result, nil
}

func (a *gopowerstoreVolumeAdapter) ListFS(ctx context.Context) ([]gopowerstore.FileSystem, error) {
	if a.runtime == nil {
		return a.client.ListFS(ctx)
	}
	v, err := a.runtime.Do(ctx, "file_systems", "all_file_systems", func(callCtx context.Context) (any, error) {
		return a.client.ListFS(callCtx)
	})
	if err != nil {
		return nil, err
	}
	result, _ := v.([]gopowerstore.FileSystem)
	return result, nil
}

func (a *gopowerstoreVolumeAdapter) GetHostVolumeMappingByVolumeID(ctx context.Context, volumeID string) ([]gopowerstore.HostVolumeMapping, error) {
	if a.runtime == nil {
		return a.client.GetHostVolumeMappingByVolumeID(ctx, volumeID)
	}
	v, err := a.runtime.Do(ctx, "host_volume_mappings", "mapping_"+volumeID, func(callCtx context.Context) (any, error) {
		return a.client.GetHostVolumeMappingByVolumeID(callCtx, volumeID)
	})
	if err != nil {
		return nil, err
	}
	result, _ := v.([]gopowerstore.HostVolumeMapping)
	return result, nil
}

func (a *gopowerstoreVolumeAdapter) GetNFSExportByFileSystemID(ctx context.Context, fsID string) (gopowerstore.NFSExport, error) {
	if a.runtime == nil {
		return a.client.GetNFSExportByFileSystemID(ctx, fsID)
	}
	v, err := a.runtime.Do(ctx, "nfs_exports", "filesystem_"+fsID, func(callCtx context.Context) (any, error) {
		return a.client.GetNFSExportByFileSystemID(callCtx, fsID)
	})
	if err != nil {
		return gopowerstore.NFSExport{}, err
	}
	result, _ := v.(gopowerstore.NFSExport)
	return result, nil
}

func (a *gopowerstoreVolumeAdapter) GetNFSExports(ctx context.Context) ([]gopowerstore.NFSExport, error) {
	if a.runtime == nil {
		return a.client.GetNFSExportByFilter(ctx, nil)
	}
	v, err := a.runtime.Do(ctx, "nfs_exports", "all_nfs_exports", func(callCtx context.Context) (any, error) {
		return a.client.GetNFSExportByFilter(callCtx, nil)
	})
	if err != nil {
		return nil, err
	}
	result, _ := v.([]gopowerstore.NFSExport)
	return result, nil
}

func (a *gopowerstoreVolumeAdapter) GetNFSExportsByFileSystemID(ctx context.Context, fsID string) ([]gopowerstore.NFSExport, error) {
	filter := map[string]string{"file_system_id": "eq." + fsID}
	if a.runtime == nil {
		return a.client.GetNFSExportByFilter(ctx, filter)
	}
	v, err := a.runtime.Do(ctx, "nfs_exports", "filesystem_exports_"+fsID, func(callCtx context.Context) (any, error) {
		return a.client.GetNFSExportByFilter(callCtx, filter)
	})
	if err != nil {
		return nil, err
	}
	result, _ := v.([]gopowerstore.NFSExport)
	return result, nil
}

func (a *gopowerstoreVolumeAdapter) GetHost(ctx context.Context, hostID string) (gopowerstore.Host, error) {
	if a.runtime == nil {
		return a.client.GetHost(ctx, hostID)
	}
	v, err := a.runtime.Do(ctx, "hosts", "host_"+hostID, func(callCtx context.Context) (any, error) {
		return a.client.GetHost(callCtx, hostID)
	})
	if err != nil {
		return gopowerstore.Host{}, err
	}
	result, _ := v.(gopowerstore.Host)
	return result, nil
}

// NewVolumeAdapterWithRuntime creates a new gopowerstoreVolumeAdapter with runtime support
func NewVolumeAdapterWithRuntime(client gopowerstore.Client, runtime *MetricsRuntime) VolumeClient {
	return &gopowerstoreVolumeAdapter{client: client, runtime: runtime}
}
