/*
 *
 * Copyright © 2022-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package controller provides CSI specification compatible controller service.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
)

// QueryArrayStatus make API call to the specified url to retrieve connection status
func (s *Service) QueryArrayStatus(ctx context.Context, url string) (bool, error) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("panic occurred in queryStatus:", err)
		}
	}()
	client := http.Client{
		Timeout: identifiers.Timeout,
	}
	resp, err := client.Get(url)

	log.Debugf("Received response %+v for url %s", resp, url)
	if err != nil {
		log.Errorf("failed to call API %s due to %s ", url, err.Error())
		return false, err
	}
	defer resp.Body.Close() // #nosec G307
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("failed to read API response due to %s ", err.Error())
		return false, err
	}
	if resp.StatusCode != 200 {
		log.Errorf("Found unexpected response from the server while fetching array status %d ", resp.StatusCode)
		return false, fmt.Errorf("unexpected response from the server")
	}
	var statusResponse identifiers.ArrayConnectivityStatus
	err = json.Unmarshal(bodyBytes, &statusResponse)
	if err != nil {
		log.Errorf("unable to unmarshal and determine connectivity due to %s ", err)
		return false, err
	}
	log.Infof("API Response received is %+v\n", statusResponse)
	// responseObject has last success and last attempt timestamp in Unix format
	timeDiff := statusResponse.LastAttempt - statusResponse.LastSuccess
	tolerance := identifiers.SetPollingFrequency(ctx)
	currTime := time.Now().Unix()
	// checking if the status response is stale and connectivity test is still running
	// since nodeProbe is run at frequency tolerance/2, ideally below check should never be true
	if (currTime - statusResponse.LastAttempt) > tolerance*2 {
		log.Errorf("seems like connectivity test is not being run, current time is %d and last run was at %d", currTime, statusResponse.LastAttempt)
		// considering connectivity is broken
		return false, nil
	}
	log.Debugf("last connectivity was  %d sec back, tolerance is %d sec", timeDiff, tolerance)
	// give 2s leeway for tolerance check
	if timeDiff <= tolerance+2 {
		return true, nil
	}
	return false, nil
}
