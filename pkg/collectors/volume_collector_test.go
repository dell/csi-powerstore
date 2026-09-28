package collectors

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/dell/csm-metrics-common/pkg/naming"
	"github.com/dell/gopowerstore"
	gpmocks "github.com/dell/gopowerstore/mocks"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

var (
	testVolumeRegistry = prometheus.NewRegistry()
	volumeMetricsReset sync.Once
)

// resetVolumeMetrics resets the singleton metrics for testing
func resetVolumeMetrics() {
	volumeMetricsReset.Do(func() {
		// No-op for registry-scoped metrics; retained for older test helpers.
	})
}

func mustNewVolumeCollector(t *testing.T, client VolumeClient, reg *prometheus.Registry, globalID string) *VolumeCollector {
	t.Helper()
	collector, err := NewVolumeCollector(client, reg, globalID, &NoopVolumeMetadataProvider{})
	require.NoError(t, err)
	return collector
}

func mustNewVolumeCollectorWithClient(t *testing.T, client gopowerstore.Client, reg *prometheus.Registry, globalID string) *VolumeCollector {
	t.Helper()
	collector, err := NewVolumeCollectorWithClient(client, reg, globalID, &NoopVolumeMetadataProvider{})
	require.NoError(t, err)
	return collector
}

// mockVolumeClient implements VolumeClient for testing
type mockVolumeClient struct {
	volumes         []gopowerstore.Volume
	fileSystems     []gopowerstore.FileSystem
	mappings        []gopowerstore.HostVolumeMapping
	nfsExport       gopowerstore.NFSExport
	nfsExports      []gopowerstore.NFSExport
	host            gopowerstore.Host
	getVolumesErr   error
	listFSErr       error
	getMappingsErr  error
	getNFSExportErr error
	getHostErr      error
	mappingCalls    int
	nfsExportCalls  int
}

type mockVolumeValidator struct {
	refreshErr   error
	isManagedErr error
	managed      map[string]bool
	protocol     map[string]string
	attached     map[string]bool
}

func (m *mockVolumeValidator) RefreshCache(_ context.Context) error {
	return m.refreshErr
}

func (m *mockVolumeValidator) IsDriverManaged(_ context.Context, volumeID string) (bool, error) {
	if m.isManagedErr != nil {
		return false, m.isManagedErr
	}
	if m.managed != nil {
		return m.managed[volumeID], nil
	}
	return true, nil
}

func (m *mockVolumeValidator) IsDriverManagedByName(_ context.Context, volumeName string) (bool, error) {
	if m.managed != nil {
		return m.managed[volumeName], nil
	}
	return true, nil
}

func (m *mockVolumeValidator) Available() bool {
	return true
}

func (m *mockVolumeValidator) MarkDeleteComplete(_ string) {}

func (m *mockVolumeValidator) MarkDeleteCompleteByName(_ string) {}

func (m *mockVolumeValidator) GetProtocol(_ context.Context, volumeID string) string {
	if m.protocol != nil {
		if p, ok := m.protocol[volumeID]; ok {
			return p
		}
	}
	return "unknown"
}

func (m *mockVolumeValidator) GetAttachmentStateForVolumeID(_ context.Context, volumeID string, _ string) (bool, error) {
	if m.attached != nil {
		return m.attached[volumeID], nil
	}
	return false, nil
}

func (m *mockVolumeValidator) GetAttachmentStateForPVName(_ context.Context, pvName string) (bool, error) {
	if m.attached != nil {
		return m.attached[pvName], nil
	}
	return false, nil
}

type mapProtocolResolver map[string]string

func (r mapProtocolResolver) GetProtocol(_ context.Context, volumeID string) string {
	return r[volumeID]
}

func (r mapProtocolResolver) RefreshCache(_ context.Context) error {
	return nil
}

func (r mapProtocolResolver) IsDriverManaged(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func (r mapProtocolResolver) IsDriverManagedByName(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func (r mapProtocolResolver) Available() bool {
	return true
}

func (r mapProtocolResolver) MarkDeleteComplete(_ string) {}

func (r mapProtocolResolver) MarkDeleteCompleteByName(_ string) {}

func (r mapProtocolResolver) GetAttachmentStateForVolumeID(_ context.Context, _ string, _ string) (bool, error) {
	return false, nil
}

func (r mapProtocolResolver) GetAttachmentStateForPVName(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func TestNoopProtocolResolver(t *testing.T) {
	resolver := &NoopProtocolResolver{}

	// Test GetProtocol
	protocol := resolver.GetProtocol(context.Background(), "vol1")
	require.Equal(t, "unknown", protocol)

	// Test RefreshCache
	err := resolver.RefreshCache(context.Background())
	require.NoError(t, err)
}

func TestNewVolumeCollector_NilRegistryReturnsError(t *testing.T) {
	collector, err := NewVolumeCollector(&mockVolumeClient{}, nil, "global-1", &NoopVolumeMetadataProvider{})
	require.Error(t, err)
	require.Nil(t, collector)
}

func TestNormalizeVolumeProtocol(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"iscsi", "iSCSI"},
		{"ISCSI", "iSCSI"},
		{" iSCSI ", "iSCSI"},
		{"fc", "FC"},
		{"FC", "FC"},
		{" fc ", "FC"},
		{"nvmetcp", "NVMeTCP"},
		{"nvme-tcp", "NVMeTCP"},
		{"NVMeTCP", "NVMeTCP"},
		{" nvmE-tcp ", "NVMeTCP"},
		{"nvmefc", "NVMeFC"},
		{"nvme-fc", "NVMeFC"},
		{"NVMeFC", "NVMeFC"},
		{" nvmE-fc ", "NVMeFC"},
		{"nfs", "NFS"},
		{"NFS", "NFS"},
		{" nfs ", "NFS"},
		{"unknown", "unknown"},
		{"", "unknown"},
		{"invalid", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeVolumeProtocol(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func newTestVolumeCollector(t *testing.T, client VolumeClient, reg *prometheus.Registry, globalID string) *VolumeCollector {
	t.Helper()
	return mustNewVolumeCollector(t, client, reg, globalID)
}

func (m *mockVolumeClient) GetVolumes(_ context.Context) ([]gopowerstore.Volume, error) {
	return m.volumes, m.getVolumesErr
}

func (m *mockVolumeClient) ListFS(_ context.Context) ([]gopowerstore.FileSystem, error) {
	return m.fileSystems, m.listFSErr
}

func (m *mockVolumeClient) GetHostVolumeMappingByVolumeID(_ context.Context, _ string) ([]gopowerstore.HostVolumeMapping, error) {
	m.mappingCalls++
	return m.mappings, m.getMappingsErr
}

func (m *mockVolumeClient) GetNFSExportByFileSystemID(_ context.Context, _ string) (gopowerstore.NFSExport, error) {
	return m.nfsExport, m.getNFSExportErr
}

func (m *mockVolumeClient) GetNFSExports(_ context.Context) ([]gopowerstore.NFSExport, error) {
	m.nfsExportCalls++
	if m.getNFSExportErr != nil {
		return nil, m.getNFSExportErr
	}
	if m.nfsExports != nil {
		return m.nfsExports, nil
	}
	if m.nfsExport.ID != "" || m.nfsExport.FileSystemID != "" {
		return []gopowerstore.NFSExport{m.nfsExport}, nil
	}
	return nil, nil
}

func (m *mockVolumeClient) GetNFSExportsByFileSystemID(_ context.Context, _ string) ([]gopowerstore.NFSExport, error) {
	if m.getNFSExportErr != nil {
		return nil, m.getNFSExportErr
	}
	if m.nfsExports != nil {
		return m.nfsExports, nil
	}
	if m.nfsExport.ID != "" || m.nfsExport.FileSystemID != "" {
		return []gopowerstore.NFSExport{m.nfsExport}, nil
	}
	return nil, nil
}

func (m *mockVolumeClient) GetHost(_ context.Context, _ string) (gopowerstore.Host, error) {
	return m.host, m.getHostErr
}

func TestVolumeCollector_Collect(t *testing.T) {
	tests := []struct {
		name         string
		client       VolumeClient
		wantErr      bool
		wantVolumes  int
		wantAttached int
	}{
		{
			name: "successful collection with attached volumes",
			client: &mockVolumeClient{
				volumes: []gopowerstore.Volume{
					{ID: "vol1", Name: "volume1", Size: 10737418240, MappedVolumes: []gopowerstore.MappedVolumes{{ID: "mapping1"}}},
					{ID: "vol2", Name: "volume2", Size: 5368709120},
				},
				mappings: []gopowerstore.HostVolumeMapping{
					{HostID: "host1", VolumeID: "vol1"},
				},
				host: gopowerstore.Host{ID: "host1", Name: "host1"},
			},
			wantErr:      false,
			wantVolumes:  2,
			wantAttached: 1,
		},
		{
			name: "successful collection with no volumes",
			client: &mockVolumeClient{
				volumes: []gopowerstore.Volume{},
			},
			wantErr:      false,
			wantVolumes:  0,
			wantAttached: 0,
		},
		{
			name: "successful collection with NVMe volumes",
			client: &mockVolumeClient{
				volumes: []gopowerstore.Volume{
					{ID: "vol1", Name: "nvme1", Size: 10737418240, Nsid: 1},
					{ID: "vol2", Name: "nvme2", Size: 5368709120, Nsid: 2},
				},
			},
			wantErr:      false,
			wantVolumes:  2,
			wantAttached: 0,
		},
		{
			name: "error getting volumes",
			client: &mockVolumeClient{
				getVolumesErr: errors.New("client error"),
			},
			wantErr: true,
		},
		{
			name: "host mappings are not fetched",
			client: &mockVolumeClient{
				volumes: []gopowerstore.Volume{
					{ID: "vol1", Name: "volume1", Size: 10737418240},
				},
				getMappingsErr: errors.New("client error"),
			},
			wantErr:      false,
			wantVolumes:  1,
			wantAttached: 0,
		},
		{
			name: "attached volume from mapped volumes",
			client: &mockVolumeClient{
				volumes: []gopowerstore.Volume{
					{ID: "vol1", Name: "volume1", Size: 10737418240, MappedVolumes: []gopowerstore.MappedVolumes{{ID: "mapping1"}}},
				},
				mappings: []gopowerstore.HostVolumeMapping{
					{HostID: "host1", VolumeID: "vol1"},
				},
				getHostErr: errors.New("client error"),
			},
			wantErr:      false,
			wantVolumes:  1,
			wantAttached: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetVolumeMetrics()
			collector := newTestVolumeCollector(t, tt.client, testVolumeRegistry, "test-global-id-"+tt.name)

			err := collector.Collect(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Check volume total metric
				metricFamilies, err := testVolumeRegistry.Gather()
				if err != nil {
					t.Fatalf("Failed to gather metrics: %v", err)
				}

				for _, mf := range metricFamilies {
					if *mf.Name == naming.MetricCSIVolumeTotal {
						total := 0
						for _, m := range mf.Metric {
							// Only count metrics for this test's global ID
							for _, label := range m.Label {
								if *label.Name == "global_id" && *label.Value == "test-global-id-"+tt.name {
									total += int(*m.Gauge.Value)
								}
							}
						}
						if total != tt.wantVolumes {
							t.Errorf("Expected %d volumes, got %d", tt.wantVolumes, total)
						}
					}
					if *mf.Name == "dell_powerstore_volume_attached_total" {
						attachedCount := 0
						for _, m := range mf.Metric {
							for _, label := range m.Label {
								if *label.Name == "global_id" && *label.Value == "test-global-id-"+tt.name {
									attachedCount += int(*m.Gauge.Value)
								}
							}
						}
						if attachedCount != tt.wantAttached {
							t.Errorf("Expected %d attached volumes, got %d", tt.wantAttached, attachedCount)
						}
					}
				}
			}
		})
	}
}

func TestVolumeCollector_Collect_RefreshCacheFailureFailsClosed(t *testing.T) {
	reg := prometheus.NewRegistry()
	collector, err := NewVolumeCollector(
		&mockVolumeClient{
			volumes: []gopowerstore.Volume{
				{ID: "vol1", Name: "volume1", Size: 10737418240},
			},
		},
		reg,
		"test-global-id-refresh-failure",
		&mockVolumeValidator{refreshErr: errors.New("refresh failed")},
	)
	require.NoError(t, err)

	// With best-effort semantics, RefreshCache failure should not return an error
	// Instead, it should preserve last good values
	err = collector.Collect(context.Background())
	require.NoError(t, err)
}

func TestVolumeCollector_Collect_BestEffortSemantics(t *testing.T) {
	reg := prometheus.NewRegistry()

	// First collection succeeds
	collector, err := NewVolumeCollector(
		&mockVolumeClient{
			volumes: []gopowerstore.Volume{
				{ID: "vol1", Name: "volume1", Size: 10737418240},
			},
		},
		reg,
		"test-global-id-best-effort",
		&mockVolumeValidator{
			managed:  map[string]bool{"vol1": true},
			protocol: map[string]string{"vol1": "iSCSI"},
			attached: map[string]bool{"vol1": true},
		},
	)
	require.NoError(t, err)

	err = collector.Collect(context.Background())
	require.NoError(t, err)

	// Check that attached metric was set
	metricFamilies, err := reg.Gather()
	require.NoError(t, err)

	attachedCount := 0
	for _, mf := range metricFamilies {
		if *mf.Name == "dell_powerstore_volume_attachment_status_total" {
			for _, m := range mf.Metric {
				if m.Label[2].GetName() == "status" && m.Label[2].GetValue() == "attached" {
					attachedCount = int(m.Gauge.GetValue())
				}
			}
		}
	}
	require.Equal(t, 1, attachedCount, "Expected 1 attached volume")

	// Now metadata refresh fails - should preserve last good values
	collector.metadata = &mockVolumeValidator{
		refreshErr: errors.New("refresh failed"),
		managed:    map[string]bool{"vol1": true},
	}

	err = collector.Collect(context.Background())
	require.NoError(t, err)

	// Check that attached metric is still preserved
	metricFamilies, err = reg.Gather()
	require.NoError(t, err)

	attachedCount = 0
	for _, mf := range metricFamilies {
		if *mf.Name == "dell_powerstore_volume_attachment_status_total" {
			for _, m := range mf.Metric {
				if m.Label[2].GetName() == "status" && m.Label[2].GetValue() == "attached" {
					attachedCount = int(m.Gauge.GetValue())
				}
			}
		}
	}
	require.Equal(t, 1, attachedCount, "Expected attached metric to be preserved on metadata failure")
}

func TestVolumeCollector_Collect_MetadataLookupFailure_PreservesCounts(t *testing.T) {
	reg := prometheus.NewRegistry()

	// First collection succeeds with 2 attached, 1 detached
	collector, err := NewVolumeCollector(
		&mockVolumeClient{
			volumes: []gopowerstore.Volume{
				{ID: "vol1", Name: "volume1", Size: 10737418240},
				{ID: "vol2", Name: "volume2", Size: 10737418240},
				{ID: "vol3", Name: "volume3", Size: 10737418240},
			},
		},
		reg,
		"test-global-id-counts",
		&mockVolumeValidator{
			managed:  map[string]bool{"vol1": true, "vol2": true, "vol3": true},
			protocol: map[string]string{"vol1": "iSCSI", "vol2": "iSCSI", "vol3": "iSCSI"},
			attached: map[string]bool{"vol1": true, "vol2": true, "vol3": false},
		},
	)
	require.NoError(t, err)

	err = collector.Collect(context.Background())
	require.NoError(t, err)

	// Check that metrics were set correctly
	metricFamilies, err := reg.Gather()
	require.NoError(t, err)

	attachedCount := 0
	detachedCount := 0
	for _, mf := range metricFamilies {
		if *mf.Name == "dell_powerstore_volume_attachment_status_total" {
			for _, m := range mf.Metric {
				if m.Label[2].GetName() == "status" && m.Label[2].GetValue() == "attached" {
					attachedCount = int(m.Gauge.GetValue())
				}
				if m.Label[2].GetName() == "status" && m.Label[2].GetValue() == "detached" {
					detachedCount = int(m.Gauge.GetValue())
				}
			}
		}
	}
	require.Equal(t, 2, attachedCount, "Expected 2 attached volumes")
	require.Equal(t, 1, detachedCount, "Expected 1 detached volume")

	// Now metadata refresh fails - should preserve last good counts
	collector.metadata = &mockVolumeValidator{
		refreshErr: errors.New("refresh failed"),
		managed:    map[string]bool{"vol1": true, "vol2": true, "vol3": true},
	}

	err = collector.Collect(context.Background())
	require.NoError(t, err)

	// Check that counts are still preserved
	metricFamilies, err = reg.Gather()
	require.NoError(t, err)

	attachedCount = 0
	detachedCount = 0
	for _, mf := range metricFamilies {
		if *mf.Name == "dell_powerstore_volume_attachment_status_total" {
			for _, m := range mf.Metric {
				if m.Label[2].GetName() == "status" && m.Label[2].GetValue() == "attached" {
					attachedCount = int(m.Gauge.GetValue())
				}
				if m.Label[2].GetName() == "status" && m.Label[2].GetValue() == "detached" {
					detachedCount = int(m.Gauge.GetValue())
				}
			}
		}
	}
	require.Equal(t, 2, attachedCount, "Expected attached count to be preserved on metadata failure")
	require.Equal(t, 1, detachedCount, "Expected detached count to be preserved on metadata failure")
}

func TestNewVolumeCollector_NilRegistry(t *testing.T) {
	_, err := NewVolumeCollector(
		&mockVolumeClient{},
		nil,
		"test-global-id",
		&mockVolumeValidator{},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "registry is nil")
}

func TestNewVolumeCollector_RegistrationError(t *testing.T) {
	client := &mockVolumeClient{}
	reg := prometheus.NewRegistry()

	// Register a counter with the same name as the first gauge to cause registration error
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: naming.MetricCSIVolumeTotal,
		Help: "Test counter",
	}, []string{"global_id", "protocol"})
	reg.MustRegister(counter)

	_, err := NewVolumeCollector(client, reg, "test-global-id", &mockVolumeValidator{})
	require.Error(t, err)
}

func TestNewVolumeCollectorWithClient_RegistrationError(t *testing.T) {
	client := &gpmocks.Client{}
	reg := prometheus.NewRegistry()

	// Register a counter with the same name as the first gauge to cause registration error
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: naming.MetricCSIVolumeTotal,
		Help: "Test counter",
	}, []string{"global_id", "protocol"})
	reg.MustRegister(counter)

	_, err := NewVolumeCollectorWithClient(client, reg, "test-global-id", &mockVolumeValidator{})
	require.Error(t, err)
}

func TestNewVolumeCollector_NilMetadataProvider(t *testing.T) {
	reg := prometheus.NewRegistry()
	_, err := NewVolumeCollector(
		&mockVolumeClient{},
		reg,
		"test-global-id",
		nil,
	)
	// This should succeed with nil metadata provider (defaults to NoopVolumeMetadataProvider)
	require.NoError(t, err)
}

func TestNewVolumeCollector_NilValidator(t *testing.T) {
	reg := prometheus.NewRegistry()
	_, err := NewVolumeCollector(
		&mockVolumeClient{},
		reg,
		"test-global-id",
		nil,
	)
	// This should succeed with nil validator (defaults to NoopVolumeMetadataProvider which implements VolumeValidator)
	require.NoError(t, err)
}

func TestVolumeCollector_Collect_MetadataIsDriverManagedError(t *testing.T) {
	reg := prometheus.NewRegistry()

	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol1", Name: "test-volume", Size: 10737418240},
		},
	}

	validator := &mockVolumeValidator{
		isManagedErr: errors.New("is managed error"),
	}

	collector, err := NewVolumeCollector(
		client,
		reg,
		"test-global-id",
		validator,
	)
	require.NoError(t, err)

	err = collector.Collect(context.Background())
	require.NoError(t, err)
}

func TestVolumeCollector_Collect_EmptyVolumes(t *testing.T) {
	reg := prometheus.NewRegistry()
	collector, err := NewVolumeCollector(
		&mockVolumeClient{
			volumes: []gopowerstore.Volume{},
		},
		reg,
		"test-global-id",
		&mockVolumeValidator{},
	)
	require.NoError(t, err)

	err = collector.Collect(context.Background())
	require.NoError(t, err)
}

func TestVolumeCollector_Collect_MetadataRefreshFailure(t *testing.T) {
	reg := prometheus.NewRegistry()

	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol1", Name: "test-volume", Size: 10737418240},
		},
	}

	validator := &mockVolumeValidator{
		refreshErr: fmt.Errorf("refresh failed"),
	}

	collector, err := NewVolumeCollector(
		client,
		reg,
		"test-global-id",
		validator,
	)
	require.NoError(t, err)

	err = collector.Collect(context.Background())
	require.NoError(t, err)
}

func TestVolumeCollector_Collect_UnhealthyVolume(t *testing.T) {
	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol1", Name: "unhealthy", Size: 10737418240},
		},
	}

	resetVolumeMetrics()
	collector := newTestVolumeCollector(t, client, testVolumeRegistry, "test-global-id-unhealthy")

	err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// Check health metric
	metricFamilies, err := testVolumeRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundMetric := false
	for _, mf := range metricFamilies {
		if *mf.Name == "dell_powerstore_volume_unhealthy_total" {
			foundMetric = true
			break
		}
	}

	if !foundMetric {
		t.Error("Expected unhealthy volume metric to be collected")
	}
}

func TestVolumeCollector_Collect_VolumeSize(t *testing.T) {
	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol1", Name: "volume1", Size: 10737418240},
		},
	}

	resetVolumeMetrics()
	collector := newTestVolumeCollector(t, client, testVolumeRegistry, "test-global-id-size")

	err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// Check volume size metric
	metricFamilies, err := testVolumeRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundMetric := false
	for _, mf := range metricFamilies {
		if *mf.Name == "dell_powerstore_volume_size_distribution_bytes" {
			foundMetric = true
			break
		}
	}

	if !foundMetric {
		t.Error("Expected volume size distribution metric to be collected")
	}
}

func TestVolumeCollector_Collect_VolumeSizeDistributionAndNFSProtocol(t *testing.T) {
	client := &mockVolumeClient{
		fileSystems: []gopowerstore.FileSystem{
			{ID: "fs1", Name: "nfs-volume", SizeTotal: 10737418240},
		},
		nfsExport: gopowerstore.NFSExport{
			FileSystemID: "fs1",
			RWHosts:      []string{"host1"},
		},
	}

	resetVolumeMetrics()
	collector := newTestVolumeCollector(t, client, testVolumeRegistry, "test-global-id-nfs")

	err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	metricFamilies, err := testVolumeRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundDistribution := false
	foundNFSCount := false
	for _, mf := range metricFamilies {
		switch *mf.Name {
		case "dell_powerstore_volume_size_distribution_bytes":
			foundDistribution = true
		case naming.MetricCSIVolumeTotal:
			for _, m := range mf.Metric {
				labels := map[string]string{}
				for _, lp := range m.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["global_id"] == "test-global-id-nfs" && labels["protocol"] == "NFS" && m.GetGauge().GetValue() == 1 {
					foundNFSCount = true
				}
			}
		}
	}

	if !foundDistribution {
		t.Error("Expected volume size distribution metric to be collected")
	}
	if !foundNFSCount {
		t.Error("Expected NFS protocol count to be collected from file systems")
	}
}

func TestVolumeCollector_Collect_ListFSError(t *testing.T) {
	client := &mockVolumeClient{
		volumes:   []gopowerstore.Volume{},
		listFSErr: errors.New("fs list error"),
	}

	collector := newTestVolumeCollector(t, client, prometheus.NewRegistry(), "test-global-id-listfs-error")

	err := collector.Collect(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to get file systems")
}

func TestVolumeCollector_Collect_NFSExportNotFoundMarksUnattached(t *testing.T) {
	// Updated to use VolumeAttachment-based attachment detection
	client := &mockVolumeClient{
		fileSystems: []gopowerstore.FileSystem{
			{ID: "fs1", Name: "nfs-volume", SizeTotal: 10737418240},
		},
	}

	reg := prometheus.NewRegistry()
	collector := newTestVolumeCollector(t, client, reg, "test-global-id-nfs-unattached")

	err := collector.Collect(context.Background())
	require.NoError(t, err)

	metricFamilies, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range metricFamilies {
		if mf.GetName() != "dell_powerstore_volume_attachment_status_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["global_id"] == "test-global-id-nfs-unattached" && labels["protocol"] == "NFS" && labels["status"] == "detached" {
				require.Equal(t, 1.0, m.GetGauge().GetValue())
				return
			}
		}
	}

	t.Fatal("expected NFS attachment status metric with detached status")
}

func TestVolumeCollector_Collect_FetchesNFSExportsOnceForMultipleFileSystems(t *testing.T) {
	// Updated: NFS exports are no longer used for attachment detection
	// Attachment is now determined by VolumeAttachment objects
	client := &mockVolumeClient{
		fileSystems: []gopowerstore.FileSystem{
			{ID: "fs1", Name: "nfs-volume-1", SizeTotal: 10737418240},
			{ID: "fs2", Name: "nfs-volume-2", SizeTotal: 5368709120},
		},
	}

	reg := prometheus.NewRegistry()
	collector := newTestVolumeCollector(t, client, reg, "test-global-id-nfs-export-calls")

	err := collector.Collect(context.Background())
	require.NoError(t, err)

	// NFS export calls are no longer made
	// require.Equal(t, 1, client.nfsExportCalls)

	metricFamilies, err := reg.Gather()
	require.NoError(t, err)

	// Check that volume count metric is correct
	require.Equal(t, 2.0, getGaugeMetric(t, metricFamilies, naming.MetricCSIVolumeTotal, map[string]string{
		"global_id": "test-global-id-nfs-export-calls",
		"protocol":  "NFS",
	}))

	// Attachment status will be detached since no VolumeAttachment objects are mocked
	require.Equal(t, 0.0, getVolumeAttachmentStatusMetric(t, metricFamilies, "test-global-id-nfs-export-calls", "NFS", "attached"))
	require.Equal(t, 2.0, getVolumeAttachmentStatusMetric(t, metricFamilies, "test-global-id-nfs-export-calls", "NFS", "detached"))
}

func TestVolumeCollector_Collect_AttachmentStatusCountsAttachedAndDetached(t *testing.T) {
	// Updated: MappedVolumes are no longer used for attachment detection
	// Attachment is now determined by VolumeAttachment objects
	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol1", Name: "attached", Size: 10737418240}, // No longer uses MappedVolumes
			{ID: "vol2", Name: "detached", Size: 5368709120},
		},
	}

	reg := prometheus.NewRegistry()
	collector := newTestVolumeCollector(t, client, reg, "test-global-id-attachment-status")

	err := collector.Collect(context.Background())
	require.NoError(t, err)

	metricFamilies, err := reg.Gather()
	require.NoError(t, err)

	// Both volumes will be detached since no VolumeAttachment objects are mocked
	require.Equal(t, 0.0, getVolumeAttachmentStatusMetric(t, metricFamilies, "test-global-id-attachment-status", "unknown", "attached"))
	require.Equal(t, 2.0, getVolumeAttachmentStatusMetric(t, metricFamilies, "test-global-id-attachment-status", "unknown", "detached"))
}

func TestVolumeCollector_Collect_MultipleProtocols(t *testing.T) {
	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol1", Name: "scsi1", Size: 10737418240},
			{ID: "vol2", Name: "scsi2", Size: 5368709120},
			{ID: "vol3", Name: "nvme1", Size: 21474836480, Nsid: 1},
		},
	}

	resetVolumeMetrics()
	collector := newTestVolumeCollector(t, client, testVolumeRegistry, "test-global-id-multi")

	err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// Check volume total metric
	metricFamilies, err := testVolumeRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundMetric := false
	for _, mf := range metricFamilies {
		if *mf.Name == naming.MetricCSIVolumeTotal {
			foundMetric = true
			break
		}
	}

	if !foundMetric {
		t.Error("Expected volume total metric to be collected")
	}
}

func TestVolumeCollector_Collect_DoesNotEmitUnusedProtocolOrTransportMetrics(t *testing.T) {
	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol-nvmetcp", Name: "nvme-tcp", Size: 10737418240},
		},
	}
	reg := prometheus.NewRegistry()
	collector, err := NewVolumeCollector(
		client,
		reg,
		"test-global-id-no-unused-labels",
		mapProtocolResolver{"vol-nvmetcp": "NVMeTCP"},
	)
	require.NoError(t, err)

	err = collector.Collect(context.Background())
	require.NoError(t, err)

	metricFamilies, err := reg.Gather()
	require.NoError(t, err)

	require.Equal(t, 1.0, getGaugeMetric(t, metricFamilies, "dell_powerstore_nvme_volume_total", map[string]string{
		"global_id": "test-global-id-no-unused-labels",
		"transport": "NVMeTCP",
	}))
	require.False(t, hasVolumeGaugeMetric(metricFamilies, "dell_powerstore_nvme_volume_total", map[string]string{
		"global_id": "test-global-id-no-unused-labels",
		"transport": "NVMeFC",
	}))
	require.False(t, hasVolumeGaugeMetric(metricFamilies, naming.MetricCSIVolumeTotal, map[string]string{
		"global_id": "test-global-id-no-unused-labels",
		"protocol":  "NVMeFC",
	}))
	require.False(t, hasVolumeGaugeMetric(metricFamilies, "dell_powerstore_volume_attached_total", map[string]string{
		"global_id": "test-global-id-no-unused-labels",
		"protocol":  "NVMeFC",
	}))
	require.False(t, hasVolumeGaugeMetric(metricFamilies, "dell_powerstore_volume_attachment_status_total", map[string]string{
		"global_id": "test-global-id-no-unused-labels",
		"protocol":  "NVMeFC",
		"status":    "attached",
	}))
	require.False(t, hasVolumeGaugeMetric(metricFamilies, "dell_powerstore_volume_unhealthy_total", map[string]string{
		"global_id": "test-global-id-no-unused-labels",
		"protocol":  "NVMeFC",
	}))
	require.False(t, hasVolumeGaugeMetric(metricFamilies, "dell_powerstore_volume_size_distribution_bytes", map[string]string{
		"global_id": "test-global-id-no-unused-labels",
		"protocol":  "NVMeFC",
	}))
}

func TestVolumeCollector_Collect_RemovesLabelsThatDisappear(t *testing.T) {
	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol-nvmefc", Name: "nvme-fc", Size: 10737418240},
		},
	}
	reg := prometheus.NewRegistry()
	resolver := mapProtocolResolver{"vol-nvmefc": "NVMeFC"}
	collector, err := NewVolumeCollector(
		client,
		reg,
		"test-global-id-remove-stale",
		resolver,
	)
	require.NoError(t, err)

	err = collector.Collect(context.Background())
	require.NoError(t, err)
	metricFamilies, err := reg.Gather()
	require.NoError(t, err)
	require.True(t, hasVolumeGaugeMetric(metricFamilies, "dell_powerstore_nvme_volume_total", map[string]string{
		"global_id": "test-global-id-remove-stale",
		"transport": "NVMeFC",
	}))

	client.volumes = nil
	delete(resolver, "vol-nvmefc")
	err = collector.Collect(context.Background())
	require.NoError(t, err)
	metricFamilies, err = reg.Gather()
	require.NoError(t, err)
	require.False(t, hasVolumeGaugeMetric(metricFamilies, "dell_powerstore_nvme_volume_total", map[string]string{
		"global_id": "test-global-id-remove-stale",
		"transport": "NVMeFC",
	}))
}

func TestVolumeCollector_Collect_ReturnsErrorWhenNFSExportsFail(t *testing.T) {
	// This test is no longer relevant since we don't use NFS exports for attachment detection
	// NFS attachment is now determined by VolumeAttachment objects
	client := &mockVolumeClient{
		fileSystems: []gopowerstore.FileSystem{
			{ID: "fs-1", Name: "fs-1", SizeTotal: 10737418240},
		},
	}
	reg := prometheus.NewRegistry()
	collector, err := NewVolumeCollector(
		client,
		reg,
		"test-global-id-nfs-export-error",
		&NoopVolumeMetadataProvider{},
	)
	require.NoError(t, err)

	err = collector.Collect(context.Background())
	require.NoError(t, err) // No longer expects error since GetNFSExports is not called
}

func TestVolumeCollector_Name(t *testing.T) {
	client := &mockVolumeClient{}
	resetVolumeMetrics()
	c := newTestVolumeCollector(t, client, testVolumeRegistry, "global-1")

	if c.Name() != "VolumeCollector" {
		t.Errorf("Expected Name() to return 'VolumeCollector', got '%s'", c.Name())
	}
}

func TestVolumeCollector_Collect_DoesNotFetchHostMappingsPerVolume(t *testing.T) {
	// Updated: MappedVolumes are no longer used for attachment detection
	// Attachment is now determined by VolumeAttachment objects
	client := &mockVolumeClient{
		volumes: []gopowerstore.Volume{
			{ID: "vol1", Name: "scsi1", Size: 10737418240}, // No longer uses MappedVolumes
		},
		getMappingsErr: errors.New("mapping error"),
	}

	resetVolumeMetrics()
	collector := newTestVolumeCollector(t, client, testVolumeRegistry, "test-global-id-mapping")

	err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// Mapping calls are no longer made
	require.Equal(t, 0, client.mappingCalls)

	metricFamilies, err := testVolumeRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	// Check for the new attachment_status metric instead of attached_total
	for _, mf := range metricFamilies {
		if *mf.Name == "dell_powerstore_volume_attachment_status_total" {
			for _, m := range mf.Metric {
				labels := map[string]string{}
				for _, lp := range m.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["global_id"] == "test-global-id-mapping" && labels["protocol"] == "unknown" && labels["status"] == "detached" {
					require.Equal(t, 1.0, m.GetGauge().GetValue())
					return
				}
			}
		}
	}

	t.Fatal("expected attachment status metric with detached status")
}

func getVolumeAttachmentStatusMetric(t *testing.T, metricFamilies []*dto.MetricFamily, globalID, protocol, status string) float64 {
	t.Helper()
	for _, mf := range metricFamilies {
		if mf.GetName() != "dell_powerstore_volume_attachment_status_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["global_id"] == globalID && labels["protocol"] == protocol && labels["status"] == status {
				return m.GetGauge().GetValue()
			}
		}
	}
	t.Fatalf("expected attachment status metric for global_id=%s protocol=%s status=%s", globalID, protocol, status)
	return 0
}

func getGaugeMetric(t *testing.T, metricFamilies []*dto.MetricFamily, metricName string, wantLabels map[string]string) float64 {
	t.Helper()
	if value, ok := findGaugeMetric(metricFamilies, metricName, wantLabels); ok {
		return value
	}
	t.Fatalf("expected metric %s with labels %v", metricName, wantLabels)
	return 0
}

func hasVolumeGaugeMetric(metricFamilies []*dto.MetricFamily, metricName string, wantLabels map[string]string) bool {
	_, ok := findGaugeMetric(metricFamilies, metricName, wantLabels)
	return ok
}

func findGaugeMetric(metricFamilies []*dto.MetricFamily, metricName string, wantLabels map[string]string) (float64, bool) {
	for _, mf := range metricFamilies {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			matches := true
			for key, value := range wantLabels {
				if labels[key] != value {
					matches = false
					break
				}
			}
			if matches {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}
