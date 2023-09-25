/*
 *
 * Copyright © 2021 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package controller

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/api"
	"github.com/dell/gopowerstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestVolumeName(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"IsOkName", nil},
		{"", status.Errorf(codes.InvalidArgument, "name cannot be empty")},
		{
			strings.Repeat("N", MaxVolumeNameLength+1),
			status.Errorf(codes.InvalidArgument, "name must contain %d or fewer printable Unicode characters", MaxVolumeNameLength),
		},
	}

	for _, test := range tests {
		test := test
		t.Run("", func(st *testing.T) {
			st.Parallel()
			result := volumeNameValidation(test.name)

			assert.Equal(t, result, test.err)
		})
	}
}

func TestVolumeSize(t *testing.T) {
	tests := []struct {
		min int64
		max int64
		err error
	}{
		{
			-1,
			-1,
			status.Errorf(
				codes.OutOfRange,
				"bad capacity: volume size bytes -1 and limit size bytes: -1 must not be negative"),
		},
		{
			236364574767,
			235345345,
			status.Errorf(
				codes.OutOfRange,
				"bad capacity: max size bytes 235345345 can't be less than minimum size bytes 236364574767"),
		},
		{
			8192,
			MaxVolumeSizeBytes + 1,
			status.Errorf(
				codes.OutOfRange,
				"bad capacity: max size bytes %d can't be more than maximum size bytes %d",
				MaxVolumeSizeBytes+1, MaxVolumeSizeBytes),
		},
		{
			8192,
			MaxVolumeSizeBytes - 1,
			nil,
		},
	}

	for _, test := range tests {
		test := test
		t.Run("", func(st *testing.T) {
			st.Parallel()
			result := volumeSizeValidation(test.min, test.max)

			assert.Equal(t, result, test.err)
		})
	}
}

func TestDetachVolumeFromHost(t *testing.T) {
	t.Run("unknown error", func(t *testing.T) {
		ctx := context.Background()
		hostID := "host-id"
		volumeID := "vol-id"

		clientMock := new(mocks.Client)
		clientMock.On("DetachVolumeFromHost", ctx, hostID, mock.AnythingOfType("*gopowerstore.HostVolumeDetach")).
			Return(gopowerstore.EmptyResponse(""), errors.New("unknown"))

		err := detachVolumeFromHost(ctx, hostID, volumeID, clientMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to detach volume")
	})

	t.Run("host does not exist", func(t *testing.T) {
		ctx := context.Background()
		hostID := "host-id"
		volumeID := "vol-id"

		clientMock := new(mocks.Client)
		clientMock.On("DetachVolumeFromHost", ctx, hostID, mock.AnythingOfType("*gopowerstore.HostVolumeDetach")).
			Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
				ErrorMsg: &api.ErrorMsg{
					StatusCode: http.StatusNotFound,
				},
			})

		err := detachVolumeFromHost(ctx, hostID, volumeID, clientMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "host with ID '"+hostID+"' not found")
	})

	t.Run("unknown api error", func(t *testing.T) {
		ctx := context.Background()
		hostID := "host-id"
		volumeID := "vol-id"

		clientMock := new(mocks.Client)
		clientMock.On("DetachVolumeFromHost", ctx, hostID, mock.AnythingOfType("*gopowerstore.HostVolumeDetach")).
			Return(gopowerstore.EmptyResponse(""), gopowerstore.APIError{
				ErrorMsg: &api.ErrorMsg{
					StatusCode: 0,
					Severity:   "",
					Message:    "",
					Arguments:  nil,
				},
			})

		err := detachVolumeFromHost(ctx, hostID, volumeID, clientMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected api error when detaching volume from host")
	})
}
