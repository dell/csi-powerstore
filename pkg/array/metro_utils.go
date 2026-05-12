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
	"errors"
	"fmt"
	"sync"
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
	// ShortTimeout is reasonably long for lightweight array queries,
	// but at the same time it allows faster unreachable array detection.
	// Don't use it to get lists of resources or execute synchronous actions.
	ShortTimeout     = 15 * time.Second
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

		replicationSession, err := client.GetReplicationSessionByID(ctx, arrayVolume.MetroReplicationSessionID)
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
	type metroStatus struct {
		isLocal bool
		resp    *MetroFracturedResponse
		err     error
	}

	metroCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	chs := make([]<-chan metroStatus, 0)
	isLocalFractured := func() <-chan metroStatus {
		ch := make(chan metroStatus)

		go func() {
			defer close(ch)

			log.Debug("checking if local volume is fractured")
			resp, err := IsMetroFractured(metroCtx, localClient, volumeHandle.LocalUUID)

			select {
			case <-metroCtx.Done():
				return
			default:
				ch <- metroStatus{true, resp, err}
			}
		}()
		return ch
	}

	isRemoteFractured := func() <-chan metroStatus {
		ch := make(chan metroStatus)

		go func() {
			defer close(ch)
			log.Debug("checking if remote volume is fractured")

			var resp *MetroFracturedResponse
			var err error
			if volumeHandle.RemoteUUID == "" {
				log.Debug("remote volume UUID is empty, skipping check")
				resp = nil
				err = errors.New("metro volume remote volume UUID is empty")
			} else {
				resp, err = IsMetroFractured(metroCtx, remoteClient, volumeHandle.RemoteUUID)
			}

			select {
			case <-metroCtx.Done():
				return
			default:
				ch <- metroStatus{false, resp, err}
			}
		}()
		return ch
	}

	// dispatch the requests as async so we don't get
	// stuck waiting for one to complete before sending the other
	// this is important because if one array is down, we don't want to wait
	// for it to timeout before sending the other request
	chs = append(chs, isLocalFractured())
	chs = append(chs, isRemoteFractured())

	// asynchronously receive the responses
	wg := sync.WaitGroup{}
	resps := make(chan metroStatus, 2)
	for _, ch := range chs {
		wg.Add(1)
		go func(ch <-chan metroStatus) {
			defer wg.Done()
			select {
			case <-metroCtx.Done():
				resps <- metroStatus{false, nil, metroCtx.Err()}
				return
			case r := <-ch:
				resps <- r
			}
		}(ch)
	}
	// ensure all channels are closed when all goroutines are done
	go func() {
		wg.Wait()
		close(resps)
	}()

	var localResp, remoteResp *MetroFracturedResponse
	var localErr, remoteErr error

	for status := range resps {
		if status.err == nil && status.resp != nil && status.resp.IsFractured {
			// if we found a fractured session, cancel the context to stop other checks and return
			// because the other array may not respond before the context times out
			log.Infof("metro session fractured detected for volume %s", status.resp.VolumeName)
			cancel()
			if status.isLocal {
				if status.resp.State == string(gopowerstore.ReplicationResourceStateSystemDemoted) || status.resp.State == string(gopowerstore.ReplicationResourceStateDemoted) {
					localDemoted = true
				}
			} else {
				if status.resp.State == string(gopowerstore.ReplicationResourceStateSystemDemoted) || status.resp.State == string(gopowerstore.ReplicationResourceStateDemoted) {
					localDemoted = false
				} else {
					localDemoted = true
				}
			}
			return status.resp, localDemoted, nil
		}

		if status.isLocal {
			localResp = status.resp
			localErr = status.err
		} else {
			remoteResp = status.resp
			remoteErr = status.err
		}
	}

	if localErr != nil && remoteErr != nil {
		if localErr, ok := localErr.(gopowerstore.APIError); ok && localErr.NotFound() {
			if remoteErr, ok := remoteErr.(gopowerstore.APIError); ok && remoteErr.NotFound() {
				log.Infof("metro session not found on both arrays for volume %s", volumeHandle)

				// Since both arrays returned not found, we assume the volume is not part of a metro session or deleted.
				// The localErr will contain this information.
				return nil, false, localErr
			}

			// Only local array returned not found, remote array has a different error.
			log.Errorf("metro session not found on local array but error checking metro state on remote array - remote: %s", remoteErr.Error())
			return nil, false, fmt.Errorf("metro session not found on local array, error checking remote array: %s", remoteErr.Error())
		}

		// Both arrays returned errors, but they are not both not found.
		log.Errorf("error checking metro state on both arrays - local: %s, remote: %s", localErr.Error(), remoteErr.Error())
		return nil, false, fmt.Errorf("error checking metro state on both arrays - local: %s, remote: %s", localErr.Error(), remoteErr.Error())
	}

	if localErr == nil && localResp != nil {
		return localResp, localDemoted, nil
	}

	if remoteErr == nil && remoteResp != nil {
		return remoteResp, localDemoted, nil
	}

	return &MetroFracturedResponse{false, "", ""}, false, fmt.Errorf("failed to determine metro replication session state for volume %s", volumeHandle)
}

// matchSessionForClone checks if a replication session is healthy and suitable for cloning.
// if asPreferred is true, match the preferred side if session state is acceptable
func matchSessionForClone(session *gopowerstore.ReplicationSession, asPreferred bool) bool {
	if session == nil {
		return false
	}
	// Check expected session role
	if (asPreferred && session.Role == string(gopowerstore.ReplicationRoleMetroPreferred)) ||
		(!asPreferred && session.Role == string(gopowerstore.ReplicationRoleMetroNonPreferred)) {
		return session.DataTransferState == gopowerstore.RSDataTransferStateActiveActive ||
			session.LocalResourceState == string(gopowerstore.ReplicationResourceStatePromoted) ||
			session.LocalResourceState == string(gopowerstore.ReplicationResourceStateSystemPromoted)
	}
	return false
}

// Determine if selected array is on-line, if so, check the session state
func DetermineIfArrayCanClone(ctx context.Context, metroSessionID string, arr *PowerStoreArray) (selectedSession *gopowerstore.ReplicationSession, err error) {
	// this call will timeout quickly if unable to get a response
	session := getMetroSessionByID(ctx, arr, metroSessionID, "local")
	if session == nil {
		return nil, fmt.Errorf("unable to get replication session from array")
	}

	// this array must be online and preferred/promoted with data transfer active/active
	// Check expected session role
	if session.DataTransferState == gopowerstore.RSDataTransferStateActiveActive ||
		session.LocalResourceState == string(gopowerstore.ReplicationResourceStatePromoted) ||
		session.LocalResourceState == string(gopowerstore.ReplicationResourceStateSystemPromoted) {
		return session, nil
	}

	return nil, fmt.Errorf("array selected for cloning is not in correct state")
}

// SelectMetroArrayForClone selects the optimal array for cloning a Metro-replicated volume.
// It queries the replication session from both arrays and selects based on the design document priority:
//  1. Preferred array if online
//  2. Non-preferred array if online
//  3. Error if neither is available

// Returns the selected array, the selected replication session, and any error.
func SelectMetroArrayForClone(ctx context.Context, metroSessionID string,
	localArray *PowerStoreArray, remoteArray *PowerStoreArray,
) (selectedArray *PowerStoreArray, selectedSession *gopowerstore.ReplicationSession, err error) {
	log := log.WithContext(ctx)

	// Query replication session info from local and remote array
	localSession := getMetroSessionByID(ctx, localArray, metroSessionID, "local")
	remoteSession := getMetroSessionByID(ctx, remoteArray, metroSessionID, "remote")

	// If both queries failed, we cannot proceed
	if localSession == nil && remoteSession == nil {
		return nil, nil, fmt.Errorf("unable to get replication session from either local or remote array")
	}

	// Determine sessions based on priority: preferred healthy -> non-preferred healthy -> error

	selectedLocal := false
	selectedAs := "preferred"

	// Constants for readability
	const asPreferred = true
	const asNonPreferred = false

	if matchSessionForClone(localSession, asPreferred) {
		selectedLocal = true
	} else if matchSessionForClone(remoteSession, asPreferred) {
		selectedLocal = false
	} else if matchSessionForClone(localSession, asNonPreferred) {
		selectedLocal = true
		selectedAs = "non-preferred"
	} else if matchSessionForClone(remoteSession, asNonPreferred) {
		selectedLocal = false
		selectedAs = "non-preferred"
	} else {
		return nil, nil, fmt.Errorf("neither local nor remote array has a healthy Metro session")
	}

	if selectedLocal {
		log.Infof("[METRO CLONE] Selected local array %s as %s for cloning from volume UUID %s",
			localArray.GetGlobalID(), selectedAs, localSession.LocalResourceID)
		return localArray, localSession, nil
	}

	log.Infof("[METRO CLONE] Selected remote array %s as %s for cloning from volume UUID %s",
		remoteArray.GetGlobalID(), selectedAs, remoteSession.LocalResourceID)
	return remoteArray, remoteSession, nil
}

// matchSessionForExpansion checks if a replication session is Metro_Preferred and online.
// Unlike matchSessionForClone, expansion only targets the preferred side.
// The session is considered eligible when Role is Metro_Preferred AND
// (DataTransferState is Active_Active OR LocalResourceState is Promoted or System_Promoted).
func matchSessionForExpansion(session *gopowerstore.ReplicationSession) bool {
	if session == nil {
		return false
	}
	if session.Role != string(gopowerstore.ReplicationRoleMetroPreferred) {
		return false
	}
	return session.DataTransferState == gopowerstore.RSDataTransferStateActiveActive ||
		session.LocalResourceState == string(gopowerstore.ReplicationResourceStatePromoted) ||
		session.LocalResourceState == string(gopowerstore.ReplicationResourceStateSystemPromoted)
}

// SelectMetroArrayForExpansion selects the correct array for expanding a Metro-replicated volume.
// It queries the replication session from both arrays and selects based on the preferred site:
//  1. Local array if it is Metro_Preferred and online
//  2. Remote array if it is Metro_Preferred and online
//  3. Error if neither preferred side is available
//
// Unlike SelectMetroArrayForClone, expansion does NOT fall back to the non-preferred side.
// Returns the selected array, the selected replication session, and any error.
func SelectMetroArrayForExpansion(ctx context.Context, metroSessionID string,
	localArray *PowerStoreArray, remoteArray *PowerStoreArray,
) (selectedArray *PowerStoreArray, selectedSession *gopowerstore.ReplicationSession, err error) {
	log := log.WithContext(ctx)

	// Query replication session info from local and remote array
	localSession := getMetroSessionByID(ctx, localArray, metroSessionID, "local")
	remoteSession := getMetroSessionByID(ctx, remoteArray, metroSessionID, "remote")

	// Build array IDs for error messages
	localID := "<unknown>"
	remoteID := "<unknown>"
	if localArray != nil {
		localID = localArray.GetGlobalID()
	}
	if remoteArray != nil {
		remoteID = remoteArray.GetGlobalID()
	}

	// If both queries failed, neither array is reachable
	if localSession == nil && remoteSession == nil {
		return nil, nil, fmt.Errorf("unable to verify Preferred site for volume expansion. PowerStore %s and %s are unavailable",
			localID, remoteID)
	}

	// Check if local array is the preferred side and online
	if matchSessionForExpansion(localSession) {
		log.Infof("[METRO EXPAND] Selected local array %s (Metro_Preferred) for volume expansion, session=%s",
			localID, metroSessionID)
		return localArray, localSession, nil
	}

	// Check if remote array is the preferred side and online
	if matchSessionForExpansion(remoteSession) {
		log.Infof("[METRO EXPAND] Selected remote array %s (Metro_Preferred) for volume expansion, session=%s",
			remoteID, metroSessionID)
		return remoteArray, remoteSession, nil
	}

	// Neither side matched — determine which is unavailable for error messaging
	if localSession == nil {
		return nil, nil, fmt.Errorf("unable to verify Preferred site for volume expansion. PowerStore %s is unavailable",
			localID)
	}
	if remoteSession == nil {
		return nil, nil, fmt.Errorf("unable to verify Preferred site for volume expansion. PowerStore %s is unavailable",
			remoteID)
	}

	// Both reachable but neither is Metro_Preferred + online
	return nil, nil, fmt.Errorf("unable to find Metro_Preferred site online for volume expansion. "+
		"Local array %s: Role=%s, State=%s, LocalResourceState=%s. "+
		"Remote array %s: Role=%s, State=%s, LocalResourceState=%s",
		localID, localSession.Role, localSession.State, localSession.LocalResourceState,
		remoteID, remoteSession.Role, remoteSession.State, remoteSession.LocalResourceState)
}

func getMetroSessionByID(ctx context.Context, array *PowerStoreArray, sessionID string, localOrRemote string) *gopowerstore.ReplicationSession {
	if array != nil {
		ctxRemote, cancelRemote := context.WithTimeout(ctx, ShortTimeout)
		defer cancelRemote()
		session, err := array.GetClient().GetReplicationSessionByID(ctxRemote, sessionID)
		if err != nil {
			log.Warnf("Failed to get replication session from %s array: %v", localOrRemote, err)
		} else {
			log.Infof("[METRO CLONE] session on %s array %s: Role=%s, State=%s(%s), LocalResourceState=%s",
				localOrRemote, array.GetGlobalID(), session.Role, session.State, session.DataTransferState, session.LocalResourceState)
			return &session
		}
	}
	return nil
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
