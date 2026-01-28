/*
 *
 * Copyright © 2021-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

package identifiers

import (
	"context"
)

// CustomLogger is logger wrapper that can be passed to gopowerstore, gobrick allowing to logging context fields with each call
type CustomLogger struct{}

// Info is a wrapper of csmlog Info method
func (lg *CustomLogger) Info(ctx context.Context, format string, args ...interface{}) {
	log.WithContext(ctx).Infof(format, args...)
}

// Debug is a wrapper of csmlog Debug method
func (lg *CustomLogger) Debug(ctx context.Context, format string, args ...interface{}) {
	log.WithContext(ctx).Debugf(format, args...)
}

// Error is a wrapper of csmlog Error method
func (lg *CustomLogger) Error(ctx context.Context, format string, args ...interface{}) {
	log.WithContext(ctx).Errorf(format, args...)
}
