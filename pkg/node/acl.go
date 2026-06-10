/*
 *
 * Copyright © 2022-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"context"
	"os/exec"
	"regexp"
	"strings"

	log "github.com/dell/csmlog"
	"github.com/dell/gopowerstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NFSv4ACLsInterface contains method definition to set NFSv4 ACLs
type NFSv4ACLsInterface interface {
	// SetNfsv4Acls sets NFSv4 ACLs
	SetNfsv4Acls(acls string, dir string) error
}

// NFSv4ACLs implements setting NFSv4 ACLs
type NFSv4ACLs struct{}

func validateAndSetACLs(ctx context.Context, s NFSv4ACLsInterface, nasName string, client gopowerstore.Client, acls string, dir string) (bool, error) {
	aclsConfigured := false
	if nfsv4ACLs(acls) {
		if isNfsv4Enabled(ctx, client, nasName) {
			if err := s.SetNfsv4Acls(acls, dir); err != nil {
				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent: "node",
					log.FieldOperation: "validateAndSetACLs",
					log.FieldProtocol:  "NFS",
					"dir":              dir,
					log.FieldError:     err.Error(),
				}).Error("can't assign NFSv4 ACLs to folder")
				return false, err
			}
			aclsConfigured = true
		} else {
			return false, status.Errorf(codes.Internal, "can't assign NFSv4 ACLs to folder %s: NAS server is not NFSv4 enabled", dir)
		}
	} else {
		return false, status.Errorf(codes.Internal, "can't assign ACLs to folder %s: invalid NFSv4 ACL format %s", dir, acls)
	}

	return aclsConfigured, nil
}

func posixMode(acls string) bool {
	modeRegex := regexp.MustCompile(`\d{3,4}`)
	return modeRegex.MatchString(acls)
}

func nfsv4ACLs(acls string) bool {
	aclsList := strings.Split(acls, ",")
	aclRegex := regexp.MustCompile(`([ADUL]:\w*:[\w.]*[@]*[\w.]*:\w*)`)
	for _, acl := range aclsList {
		matched := aclRegex.MatchString(acl)
		if !matched {
			return false
		}
	}
	return true
}

// SetNfsv4Acls sets NFSv4 ACLS
func (n *NFSv4ACLs) SetNfsv4Acls(acls string, dir string) error {
	command := []string{"nfs4_setfacl", "-s", acls, dir}
	log.WithFields(log.Fields{
		log.FieldComponent: "node",
		log.FieldOperation: "SetNfsv4Acls",
		log.FieldProtocol:  "NFS",
		"command":          strings.Join(command, " "),
	}).Info("executing NFSv4 ACL command")
	// arguments for exec.Command() are validated in caller
	cmd := exec.Command(command[0], command[1:]...) // #nosec G204
	outStr, err := cmd.Output()
	log.WithFields(log.Fields{
		log.FieldComponent: "node",
		log.FieldOperation: "SetNfsv4Acls",
		log.FieldProtocol:  "NFS",
		"output":           string(outStr),
	}).Info("NFSv4 ACL command output")
	return err
}

func isNfsv4Enabled(ctx context.Context, client gopowerstore.Client, nasName string) bool {
	nfsv4Enabled := false
	nas, err := gopowerstore.Client.GetNASByName(client, ctx, nasName)
	if err == nil {
		nfsServer, err := gopowerstore.Client.GetNfsServer(client, ctx, nas.NfsServers[0].ID)
		if err == nil {
			if nfsServer.IsNFSv4Enabled {
				nfsv4Enabled = true
			} else {
				log.WithContext(ctx).WithFields(log.Fields{
					log.FieldComponent: "node",
					log.FieldOperation: "isNfsv4Enabled",
					log.FieldProtocol:  "NFS",
					"nas_name":         nasName,
				}).Error("NFSv4 not enabled on NAS server")
			}
		} else {
			log.WithContext(ctx).WithFields(log.Fields{
				log.FieldComponent: "node",
				log.FieldOperation: "isNfsv4Enabled",
				log.FieldProtocol:  "NFS",
				"nfs_server_id":    nas.NfsServers[0].ID,
				log.FieldError:     err.Error(),
			}).Error("can't fetch NFS server")
		}
	} else {
		log.WithContext(ctx).WithFields(log.Fields{
			log.FieldComponent: "node",
			log.FieldOperation: "isNfsv4Enabled",
			log.FieldProtocol:  "NFS",
			log.FieldError:     err.Error(),
		}).Error("can't determine if NFSv4 is enabled")
	}
	return nfsv4Enabled
}
