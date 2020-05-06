/*
 *
 * Copyright © 2020 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package service

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"unicode/utf8"
)

func parameterCreateValidation(params map[string]string) error {
	return nil
}

func volumeNameValidation(volumeName string) error {
	if volumeName == "" {
		return status.Errorf(codes.InvalidArgument,
			"Name cannot be empty")
	}

	if utf8.RuneCountInString(volumeName) > MaxVolumeNameLength {
		return status.Errorf(codes.InvalidArgument,
			"Name must contain %d or fewer printable Unicode characters", MaxVolumeNameLength)
	}

	return nil
}

func volumeSizeValidation(minSize, maxSize int64) error {
	if minSize < 0 || maxSize < 0 {
		return status.Errorf(
			codes.OutOfRange,
			"bad capacity: volume size bytes %d and limit size bytes: %d must not be negative", minSize, maxSize)
	}

	if maxSize < minSize {
		return status.Errorf(
			codes.OutOfRange,
			"bad capacity: max size bytes %d can't be less than minimum size bytes %d", maxSize, minSize)
	}

	if maxSize > MaxVolumeSizeBytes {
		return status.Errorf(
			codes.OutOfRange,
			"bad capacity: max size bytes %d can't be more than maximum size bytes %d", maxSize, MaxVolumeSizeBytes)
	}

	return nil
}
