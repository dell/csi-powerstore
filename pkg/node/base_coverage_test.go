/*
 *
 * Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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
	"testing"

	"github.com/dell/csi-powerstore/v2/mocks"
	"github.com/dell/gofsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestFormatWWPNSmoke(t *testing.T) {
	got, err := formatWWPN("58ccf09348a003a3")
	require.NoError(t, err)
	assert.Equal(t, "58:cc:f0:93:48:a0:03:a3", got)
}

func TestConsistentRead(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte("same"), nil).Twice()

		got, err := consistentRead("/proc/self/mountinfo", 1, fsMock)
		require.NoError(t, err)
		assert.Equal(t, []byte("same"), got)
		fsMock.AssertExpectations(t)
	})

	t.Run("failure", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		callCount := 0
		fsMock.On("ReadFile", "/proc/self/mountinfo").Return(func(string) []byte {
			callCount++
			if callCount == 1 {
				return []byte("first")
			}
			return []byte("second")
		}, nil).Times(2)

		got, err := consistentRead("/proc/self/mountinfo", 1, fsMock)
		assert.Error(t, err)
		assert.Nil(t, got)
		fsMock.AssertExpectations(t)
	})
}

func TestGetStagedDev(t *testing.T) {
	fsMock := new(mocks.FsInterface)
	fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte("same"), nil).Twice()
	fsMock.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{
		{
			Device: "devtmpfs",
			Path:   validStagingPath,
			Source: "/dev/sda",
		},
	}, nil)

	got, err := getStagedDev(context.Background(), validStagingPath, fsMock)
	require.NoError(t, err)
	assert.Equal(t, "/dev/sda", got)
	fsMock.AssertExpectations(t)
}

func TestIsAlreadyPublished(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte("same"), nil).Twice()
		fsMock.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{}, nil)

		got, err := isAlreadyPublished(context.Background(), "/mnt/test", "rw", fsMock)
		require.NoError(t, err)
		assert.False(t, got)
		fsMock.AssertExpectations(t)
	})

	t.Run("different capabilities", func(t *testing.T) {
		fsMock := new(mocks.FsInterface)
		fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte("same"), nil).Twice()
		fsMock.On("ParseProcMounts", mock.Anything, mock.Anything).Return([]gofsutil.Info{
			{
				Path: "/mnt/test",
				Opts: []string{"rw"},
			},
		}, nil)

		got, err := isAlreadyPublished(context.Background(), "/mnt/test", "ro", fsMock)
		assert.Error(t, err)
		assert.False(t, got)
		fsMock.AssertExpectations(t)
	})
}

func TestConsistentReadError(t *testing.T) {
	fsMock := new(mocks.FsInterface)
	fsMock.On("ReadFile", "/proc/self/mountinfo").Return([]byte(nil), assert.AnError)

	got, err := consistentRead("/proc/self/mountinfo", 1, fsMock)
	assert.Error(t, err)
	assert.Nil(t, got)
	fsMock.AssertExpectations(t)
}
