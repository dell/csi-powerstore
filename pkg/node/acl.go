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
	"fmt"
	"os/exec"
	"regexp"
	"strings"

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
	log := log.WithContext(ctx)
	aclsConfigured := false
	if nfsv4ACLs(acls) {
		if isNfsv4Enabled(ctx, client, nasName) {
			if err := s.SetNfsv4Acls(acls, dir); err != nil {
				log.Error(fmt.Sprintf("can't assign NFSv4 ACLs to folder %s: %s", dir, err.Error()))
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
	if matched, _ := regexp.Match(`\d{3,4}`, []byte(acls)); matched {
		return true
	}
	return false
}

func nfsv4ACLs(acls string) bool {
	aclsList := strings.Split(acls, ",")
	for _, acl := range aclsList {
		matched, err := regexp.Match(`([ADUL]:\w*:[\w.]*[@]*[\w.]*:\w*)`, []byte(acl))
		if !matched || err != nil {
			return false
		}
	}
	return true
}

// SetNfsv4Acls sets NFSv4 ACLS
func (n *NFSv4ACLs) SetNfsv4Acls(acls string, dir string) error {
	command := []string{"nfs4_setfacl", "-s", acls, dir}
	log.Infof("NFSv4 ACL command: %s \n", strings.Join(command, " "))
	// arguments for exec.Command() are validated in caller
	cmd := exec.Command(command[0], command[1:]...) // #nosec G204
	outStr, err := cmd.Output()
	log.Infof("NFSv4 ACL output: %s \n", string(outStr))
	return err
}

func isNfsv4Enabled(ctx context.Context, client gopowerstore.Client, nasName string) bool {
	log := log.WithContext(ctx)
	nfsv4Enabled := false
	nas, err := gopowerstore.Client.GetNASByName(client, ctx, nasName)
	if err == nil {
		nfsServer, err := gopowerstore.Client.GetNfsServer(client, ctx, nas.NfsServers[0].ID)
		if err == nil {
			if nfsServer.IsNFSv4Enabled {
				nfsv4Enabled = true
			} else {
				log.Error(fmt.Sprintf("NFS v4 not enabled on NAS server: %s\n", nasName))
			}
		} else {
			log.Error(fmt.Sprintf("can't fetch nfs server with id %s: %s", nas.NfsServers[0].ID, err.Error()))
		}
	} else {
		log.Error(fmt.Sprintf("can't determine nfsv4 enabled: %s", err.Error()))
	}
	return nfsv4Enabled
}
