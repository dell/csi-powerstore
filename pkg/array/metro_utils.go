/*
 *
 * Copyright © 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package array

import (
	"context"
	"time"

	drv1 "github.com/dell/csm-dr/api/v1"
	drv1Client "github.com/dell/csm-dr/pkg/client"
	"github.com/dell/gopowerstore"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

var GetDRClientFunc = drv1Client.Get

type MetroFracturedResponse struct {
	IsFractured bool
	VolumeName  string
	State       string
}

const (
	MediumTimeout    = 30 * time.Second
	MetroPrefixRegex = `^Metro_(Demote|Promote|Reprotect).*`
)

func IsMetroFractured(ctx context.Context, client gopowerstore.Client, id string) (*MetroFracturedResponse, error) {
	log := log.WithContext(ctx)
	arrayVolume, err := client.GetVolume(ctx, id)
	if err != nil {
		return nil, err
	}

	if arrayVolume.MetroReplicationSessionID != "" {
		log.Infof("[METRO] MetroReplicationSessionID %s", arrayVolume.MetroReplicationSessionID)

		ctxLocal, cancelLocal := context.WithTimeout(ctx, 5*time.Second)
		defer cancelLocal()
		replicationSession, err := client.GetReplicationSessionByID(ctxLocal, arrayVolume.MetroReplicationSessionID)
		if err != nil {
			log.Errorf("[METRO] Unable to get replication session information by ID: %s, errror: %s", arrayVolume.MetroReplicationSessionID, err.Error())
			return nil, err
		}

		if replicationSession.State == "Fractured" {
			// We should only go here if the replicationSession is Fractured.
			log.Infof("[METRO] ReplicationSession Status %s, LocalResourceState %s", replicationSession.State, replicationSession.LocalResourceState)

			return &MetroFracturedResponse{true, arrayVolume.Name, replicationSession.LocalResourceState}, nil
		}
	}

	return &MetroFracturedResponse{false, arrayVolume.Name, ""}, nil
}

// checkMetroState checks metro state of a volume.
// Tries to get metroState from the localArray first. if there was error fetching this, tries to get the metro state from the remote array.
// Parameters: volumeHandle of the metro volume and the clients for the local and remote arrays.
// Returns: MetroFracturedResponse, bool indicating if localVolume of the metro was demoted or not and error
//   - empty MetroFracturedResponse , false and error in case of error checking metro state.
//   - MetroFracturedResponse(including isFractured and volumeName), true, nil error in case metro is Fractured and localVolume is demoted.
//   - MetroFracturedResponse(including isFractured and volumeName), false, nil error in case metro is Fractured and localVolume is promoted.
//
// MetroFracturedResponse  ( includes isFractured and volumeName which are used from the response) , a boolean that indicates whether the localVolume of the metro was demoted or not and error.
func CheckMetroState(ctx context.Context, volumeHandle VolumeHandle, localClient gopowerstore.Client, remoteClient gopowerstore.Client) (*MetroFracturedResponse, bool, error) {
	log := log.WithContext(ctx)
	localDemoted := false
	ctxLocal, cancelLocal := context.WithTimeout(context.Background(), MediumTimeout)
	defer cancelLocal()
	metroResp, err := IsMetroFractured(ctxLocal, localClient, volumeHandle.LocalUUID)
	if err != nil {
		log.Errorf("error checking on local array if metro is fractured: %s", err.Error())
		ctxRemote, cancelRemote := context.WithTimeout(context.Background(), MediumTimeout)
		defer cancelRemote()
		metroResp, err = IsMetroFractured(ctxRemote, remoteClient, volumeHandle.RemoteUUID)
		if err != nil {
			log.Errorf("error checking on remote array if metro is fractured: %s", err.Error())
			return metroResp, false, err
		}

		if metroResp.IsFractured && (metroResp.State == "Demoted" || metroResp.State == "System_Demoted") {
			// Remote is Demoted. So local must be Promoted
			localDemoted = false
		} else {
			localDemoted = true
		}
	} else {
		if metroResp.IsFractured && (metroResp.State == "Demoted" || metroResp.State == "System_Demoted") {
			localDemoted = true
		}
	}
	return metroResp, localDemoted, nil
}

func CreateOrUpdateJournalEntry(ctx context.Context, name string,
	volumeHandle VolumeHandle, deferredArrayID, nodeName, operation string,
	request []byte,
) error {
	log := log.WithContext(ctx)

	id := volumeHandle.LocalUUID
	arrayID := volumeHandle.LocalArrayGlobalID
	remoteArrayID := volumeHandle.RemoteArrayGlobalID

	drClient, err := GetDRClientFunc(ctx)
	if err != nil {
		log.Errorf("[METRO] Unable to get dr client, error: %s", err.Error())
		return err
	}

	var journal drv1.VolumeJournal
	key := ctrlClient.ObjectKey{
		Name: "journal-" + name,
	}

	deferEntry := drv1.JournalEntry{
		Operation: operation,
		Status:    "pending-reconciliation",
		Time:      time.Now().Format(time.RFC3339),
		Host:      nodeName,
		Array:     deferredArrayID,
		Request:   request,
	}

	err = drClient.Get(ctx, key, &journal)
	if err != nil {
		if !k8sErrors.IsNotFound(err) {
			log.Errorf("Unable to retrieve volume journal: %s", err.Error())
			return err
		}

		// We didn't find the entry so we would need to create it.
		journal = drv1.VolumeJournal{
			ObjectMeta: metav1.ObjectMeta{
				Name: "journal-" + name,
			},
			Spec: drv1.VolumeJournalSpec{
				VolumeUUID:    id,
				OriginalArray: arrayID,
				FailoverArray: remoteArrayID,
				JournalEntries: []drv1.JournalEntry{
					deferEntry,
				},
			},
		}

		err = drClient.Create(context.Background(), &journal)
		if err != nil {
			log.Errorf("[METRO] Error creating volume journals: %s", err.Error())
			return err
		}

		log.Infof("[METRO] Successfully created volume journal: %s", journal.Name)
		return nil
	}

	found := false
	for i, entry := range journal.Spec.JournalEntries {
		if entry.Operation == operation {
			if entry.Status == "pending-reconciliation" && entry.Host == nodeName {
				journal.Spec.JournalEntries[i] = deferEntry
			}

			found = true

			break
		}
	}

	if !found {
		journal.Spec.JournalEntries = append(journal.Spec.JournalEntries, deferEntry)
	}

	err = drClient.Update(ctx, &journal)
	if err != nil {
		log.Errorf("Unable to update volume journal: %s", err)
		return err
	}

	return nil
}
