/*
Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.

* Dell Technologies, Dell and other trademarks are trademarks of Dell Inc.
* or its subsidiaries. Other trademarks may be trademarks of their respective
* owners.
*
*/
package groupcontroller

import (
	"context"
	"fmt"
	"strconv"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/fs"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	"github.com/dell/csmlog"
	csictx "github.com/dell/gocsi/context"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Interface provides most important groupcontroller methods.
// This essentially serves as a wrapper for groupcontroller service that is used in ephemeral volumes.
type Interface interface {
	CreateVolumeGroupSnapshot(ctx context.Context, req *csi.CreateVolumeGroupSnapshotRequest) (*csi.CreateVolumeGroupSnapshotResponse, error)
	DeleteVolumeGroupSnapshot(ctx context.Context, req *csi.DeleteVolumeGroupSnapshotRequest) (*csi.DeleteVolumeGroupSnapshotResponse, error)
	GetVolumeGroupSnapshot(ctx context.Context, req *csi.GetVolumeGroupSnapshotRequest) (*csi.GetVolumeGroupSnapshotResponse, error)
	array.Consumer
}

// Service is a group controller service that contains array connection information and implements GroupControllerServer API
type Service struct {
	csi.UnimplementedGroupControllerServer
	Fs fs.Interface

	array.Locker
	isHealthMonitorEnabled      bool
	isAutoRoundOffFsSizeEnabled bool
	groupSnapshotManager        *VolumeGroupSnapshotManager
}

// Instantiate csmlog at package level
var log = csmlog.GetLogger()

// Init is a method that initializes internal variables of group controller service
func (s *Service) Init() error {
	ctx := context.Background()
	kubeConfigPath, _ := csictx.LookupEnv(ctx, identifiers.EnvKubeConfigPath)
	_, err := k8sutils.CreateKubeClientSet(kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %s", err.Error())
	}

	if isHealthMonitorEnabled, ok := csictx.LookupEnv(ctx, identifiers.EnvIsHealthMonitorEnabled); ok {
		s.isHealthMonitorEnabled, _ = strconv.ParseBool(isHealthMonitorEnabled)
	}

	if isAutoRoundOffFsSizeEnabled, ok := csictx.LookupEnv(ctx, identifiers.EnvAllowAutoRoundOffFilesystemSize); ok {
		log.Warn("Auto round off Filesystem size has been enabled! This will round off NFS PVC size to 3Gi when the requested size is less than 3Gi.")
		s.isAutoRoundOffFsSizeEnabled, _ = strconv.ParseBool(isAutoRoundOffFsSizeEnabled)
	}

	// Initialize group snapshot manager with arrays reference
	s.groupSnapshotManager = NewVolumeGroupSnapshotManager()
	// Set arrays immediately to avoid stale data issues
	s.groupSnapshotManager.SetArrays(s.Arrays())

	return nil
}

// GroupControllerGetCapabilities returns list of capabilities that are supported by the driver.
func (s *Service) GroupControllerGetCapabilities(_ context.Context, _ *csi.GroupControllerGetCapabilitiesRequest) (*csi.GroupControllerGetCapabilitiesResponse, error) {
	newCap := func(capability csi.GroupControllerServiceCapability_RPC_Type) *csi.GroupControllerServiceCapability {
		return &csi.GroupControllerServiceCapability{
			Type: &csi.GroupControllerServiceCapability_Rpc{
				Rpc: &csi.GroupControllerServiceCapability_RPC{
					Type: capability,
				},
			},
		}
	}

	var capabilities []*csi.GroupControllerServiceCapability
	for _, capability := range []csi.GroupControllerServiceCapability_RPC_Type{
		csi.GroupControllerServiceCapability_RPC_CREATE_DELETE_GET_VOLUME_GROUP_SNAPSHOT,
	} {
		capabilities = append(capabilities, newCap(capability))
	}

	return &csi.GroupControllerGetCapabilitiesResponse{
		Capabilities: capabilities,
	}, nil
}

// CreateVolumeGroupSnapshot create volumegroup snapshot
func (s *Service) CreateVolumeGroupSnapshot(ctx context.Context, req *csi.CreateVolumeGroupSnapshotRequest) (*csi.CreateVolumeGroupSnapshotResponse, error) {
	log.Infof("CreateVolumeGroupSnapshot called with req: %s", req)

	// Basic validation first (before checking arrays)
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "group snapshot name cannot be empty")
	}

	// Get default array from Locker for validation
	defaultArray := s.DefaultArray()
	if defaultArray == nil {
		// If no default array is set, use the first available array for volume ID parsing
		arrays := s.Arrays()
		if len(arrays) == 0 {
			return nil, status.Error(codes.Internal, "no arrays available for validation")
		}
		for _, arr := range arrays {
			defaultArray = arr
			break
		}
	}

	// Delegate to the group snapshot manager with default array for validation
	return s.groupSnapshotManager.CreateVolumeGroupSnapshot(ctx, req, defaultArray)
}

func (s *Service) DeleteVolumeGroupSnapshot(ctx context.Context, req *csi.DeleteVolumeGroupSnapshotRequest) (*csi.DeleteVolumeGroupSnapshotResponse, error) {
	log.Infof("DeleteVolumeGroupSnapshot called with req: %+v", req)

	// Delegate to the group snapshot manager (arrays already set in Init)
	return s.groupSnapshotManager.DeleteVolumeGroupSnapshot(ctx, req)
}

func (s *Service) GetVolumeGroupSnapshot(ctx context.Context, req *csi.GetVolumeGroupSnapshotRequest) (*csi.GetVolumeGroupSnapshotResponse, error) {
	log.Infof("GetVolumeGroupSnapshot called with req: %s", req)

	// Delegate to the group snapshot manager (arrays already set in Init)
	return s.groupSnapshotManager.GetVolumeGroupSnapshot(ctx, req)
}
