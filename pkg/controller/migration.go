package controller

import (
	"context"
	"github.com/dell/csi-powerstore/pkg/array"
	"github.com/dell/csi-powerstore/pkg/common"
	migext "github.com/dell/dell-csi-extensions/migration"
	"github.com/dell/gopowerstore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Service) VolumeMigrate(ctx context.Context, req *migext.VolumeMigrateRequest) (*migext.VolumeMigrateResponse, error) {
	volID := req.GetVolumeHandle()
	if volID == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}

	id, arrayID, protocol, err := array.ParseVolumeID(ctx, volID, s.DefaultArray(), nil)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	arr, ok := s.Arrays()[arrayID]
	if !ok {
		log.Info("ip is nil")
		return nil, status.Error(codes.InvalidArgument, "failed to find array with given IP")
	}


	vol, err := arr.GetClient().GetVolume(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find volume with id %s", id)
	}

	// Get the parameters
	params := req.GetScParameters()
	sourceScParams := req.GetScSourceParameters()


	migrateType := req.GetType()
	var migrationFunc func(context.Context, map[string]string, map[string]string, *Service, *array.PowerStoreArray, *gopowerstore.Volume, string) (*migext.VolumeMigrateResponse, error)

	switch migrateType {
	case migext.MigrateTypes_UNKNOWN_MIGRATE:
		return nil, status.Errorf(codes.Unknown, "Unknown Migration Type")
	case migext.MigrateTypes_NON_REPL_TO_REPL:
		migrationFunc = nonReplToRepl
	case migext.MigrateTypes_REPL_TO_NON_REPL:
		migrationFunc = replToNonRepl
	case migext.MigrateTypes_VERSION_UPGRADE:
		migrationFunc = versionUpgrade

	}

	if migrationFunc == nil {
		return nil, status.Errorf(codes.Unknown, "Unknown Migration Type")
	}

	return migrationFunc(ctx, params, sourceScParams, s, arr, &vol, protocol)
}

func nonReplToRepl(ctx context.Context, params map[string]string, sourceScParams map[string]string, s *Service, arr *array.PowerStoreArray, vol *gopowerstore.Volume, protocol string) (*migext.VolumeMigrateResponse, error) {
	var vg gopowerstore.VolumeGroup
	var err error

	replicationEnabled := params[s.WithRP(KeyReplicationEnabled)]

	if replicationEnabled == "true" {
		log.Infof("Enabling replication for volume with id %s", vol.ID)

		vgPrefix, ok := params[s.WithRP(KeyReplicationVGPrefix)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "replication enabled but no volume group prefix specified in storage class")
		}
		rpo, ok := params[s.WithRP(KeyReplicationRPO)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "replication enabled but no RPO specified in storage class")
		}
		rpoEnum := gopowerstore.RPOEnum(rpo)
		if err := rpoEnum.IsValid(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid rpo value")
		}
		remoteSystemName, ok := params[s.WithRP(KeyReplicationRemoteSystem)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "replication enabled but no remote system specified in storage class")
		}

		namespace := ""
		if ignoreNS, ok := params[s.WithRP(KeyReplicationIgnoreNamespaces)]; ok && ignoreNS == "false" {
			pvcNS, ok := params[KeyCSIPVCNamespace]
			if ok {
				namespace = pvcNS + "-"
			}
		}

		vgName := vgPrefix + "-" + namespace + remoteSystemName + "-" + rpo
		if len(vgName) > 128 {
			vgName = vgName[:128]
		}

		vg, err = arr.Client.GetVolumeGroupByName(ctx, vgName)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); ok && apiError.NotFound() {
				log.Infof("Volume group with name %s not found, creating it", vgName)

				// ensure protection policy exists
				pp, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't ensure protection policy exists %s", err.Error())
				}

				group, err := arr.Client.CreateVolumeGroup(ctx, &gopowerstore.VolumeGroupCreate{
					Name:               vgName,
					ProtectionPolicyID: pp,
				})
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't create volume group: %s", err.Error())
				}

				vg, err = arr.Client.GetVolumeGroup(ctx, group.ID)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't query volume group by id %s : %s", group.ID, err.Error())
				}

			} else {
				return nil, status.Errorf(codes.Internal, "can't query volume group by name %s : %s", vgName, err.Error())
			}
		} else {
			// group exists, check that protection policy applied
			if vg.ProtectionPolicyID == "" {
				pp, err := EnsureProtectionPolicyExists(ctx, arr, vgName, remoteSystemName, rpoEnum)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't ensure protection policy exists %s", err.Error())
				}
				policyUpdate := gopowerstore.VolumeGroupChangePolicy{ProtectionPolicyID: pp}
				_, err = arr.Client.UpdateVolumeGroupProtectionPolicy(ctx, vg.ID, &policyUpdate)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "can't update volume group policy %s", err.Error())
				}
			}
		}

		_, err := arr.GetClient().AddMembersToVolumeGroup(ctx, &gopowerstore.VolumeGroupMembers{VolumeIds: []string{vol.ID}}, vg.ID)
		if err != nil {
			if apiError, ok := err.(gopowerstore.APIError); !(ok && apiError.VolumeNameIsAlreadyUse()) {
				return nil, status.Errorf(codes.Internal, "Error adding volume group members: %s", err.Error())
			}
		}
	}

	volume := &migext.Volume{
		CapacityBytes: vol.Size,
		VolumeId:      vol.ID,
	}

	volume.VolumeContext = params
	volume.VolumeContext[common.KeyArrayID] = arr.GetGlobalID()
	volume.VolumeContext[common.KeyArrayVolumeName] = vol.Name
	volume.VolumeContext[common.KeyProtocol] = protocol


	volume.VolumeId = volume.VolumeId + "/" + arr.GetGlobalID() + "/" + protocol
	csiResp := &migext.VolumeMigrateResponse{
		MigratedVolume: volume,
	}

	return csiResp, nil
}

func replToNonRepl(ctx context.Context, params map[string]string, sourceScParams map[string]string, s *Service, arr *array.PowerStoreArray, vol *gopowerstore.Volume, protocol string) (*migext.VolumeMigrateResponse, error) {
	vgs, err := arr.GetClient().GetVolumeGroupsByVolumeID(ctx, vol.ID)
	if err != nil {
		if apiError, ok := err.(gopowerstore.APIError); !ok || !apiError.NotFound() {
			return nil, err
		}
	}

	if len(vgs.VolumeGroup) != 0 {
		_, err := arr.GetClient().RemoveMembersFromVolumeGroup(ctx, &gopowerstore.VolumeGroupMembers{VolumeIds: []string{vol.ID}}, vgs.VolumeGroup[0].ID)
		if err != nil {
			return nil, err
		}

		// Unassign protection policy
		_, err = arr.GetClient().ModifyVolume(ctx, &gopowerstore.VolumeModify{ProtectionPolicyID: ""}, vol.ID)
		if err != nil {
			return nil, err
		}
	}


	volume := &migext.Volume{
		CapacityBytes: vol.Size,
		VolumeId:      vol.ID,
	}

	volume.VolumeContext = params
	volume.VolumeContext[common.KeyArrayID] = arr.GetGlobalID()
	volume.VolumeContext[common.KeyArrayVolumeName] = vol.Name
	volume.VolumeContext[common.KeyProtocol] = protocol


	volume.VolumeId = volume.VolumeId + "/" + arr.GetGlobalID() + "/" + protocol
	csiResp := &migext.VolumeMigrateResponse{
		MigratedVolume: volume,
	}

	return csiResp, nil
}

func versionUpgrade(ctx context.Context, params map[string]string, sourceScParams map[string]string, s *Service, arr *array.PowerStoreArray, vol *gopowerstore.Volume, protocol string) (*migext.VolumeMigrateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Unimplemented")
}

func (s *Service) GetMigrationCapabilities(ctx context.Context, req *migext.GetMigrationCapabilityRequest) (*migext.GetMigrationCapabilityResponse, error) {
	return &migext.GetMigrationCapabilityResponse{
		Capabilities: []*migext.MigrationCapability{
			{
				Type: &migext.MigrationCapability_Rpc{
					Rpc: &migext.MigrationCapability_RPC{
						Type: migext.MigrateTypes_NON_REPL_TO_REPL,
					},
				},
			},
			{
				Type: &migext.MigrationCapability_Rpc{
					Rpc: &migext.MigrationCapability_RPC{
						Type: migext.MigrateTypes_REPL_TO_NON_REPL,
					},
				},
			},
			{
				Type: &migext.MigrationCapability_Rpc{
					Rpc: &migext.MigrationCapability_RPC{
						Type: migext.MigrateTypes_VERSION_UPGRADE,
					},
				},
			},
		},
	}, nil
}