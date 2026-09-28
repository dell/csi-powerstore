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

package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dell/gopowerstore"
	"github.com/dell/gopowerstore/mocks"
	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestExtractNAALabelFromParams(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]string
		expected string
	}{
		{
			name:     "NAA label present with value",
			params:   map[string]string{KeyAffinitySourceNAA: "naa.68ccf098003ceb5e4577a20be6d11bf9"},
			expected: "naa.68ccf098003ceb5e4577a20be6d11bf9",
		},
		{
			name:     "NAA label present without prefix",
			params:   map[string]string{KeyAffinitySourceNAA: "68ccf098003ceb5e4577a20be6d11bf9"},
			expected: "68ccf098003ceb5e4577a20be6d11bf9",
		},
		{
			name:     "NAA label absent",
			params:   map[string]string{"other-label": "value"},
			expected: "",
		},
		{
			name:     "NAA label key absent",
			params:   map[string]string{"other-key": "value"},
			expected: "",
		},
		{
			name:     "NAA label present but empty",
			params:   map[string]string{KeyAffinitySourceNAA: ""},
			expected: "",
		},
		{
			name:     "NAA label with whitespace",
			params:   map[string]string{KeyAffinitySourceNAA: "  naa.68ccf098003ceb5e4577a20be6d11bf9  "},
			expected: "naa.68ccf098003ceb5e4577a20be6d11bf9",
		},
		{
			name:     "Empty params",
			params:   map[string]string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNAALabelFromParams(tt.params)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeNAAID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "NAA with prefix unchanged",
			input:    "naa.68ccf098003ceb5e4577a20be6d11bf9",
			expected: "naa.68ccf098003ceb5e4577a20be6d11bf9",
		},
		{
			name:     "NAA without prefix gets prefix added",
			input:    "68ccf098003ceb5e4577a20be6d11bf9",
			expected: "naa.68ccf098003ceb5e4577a20be6d11bf9",
		},
		{
			name:     "NAA with uppercase prefix - prefix normalized, hex preserved",
			input:    "NAA.68CCF098003CEB5E4577A20BE6D11BF9",
			expected: "naa.68CCF098003CEB5E4577A20BE6D11BF9",
		},
		{
			name:     "Empty string returns empty",
			input:    "",
			expected: "",
		},
		{
			name:     "NAA without prefix uppercase - hex preserved",
			input:    "68CCF098003CEB5E4577A20BE6D11BF9",
			expected: "naa.68CCF098003CEB5E4577A20BE6D11BF9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeNAAID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{"429 Too Many Requests", 429, true},
		{"500 Internal Server Error", 500, true},
		{"502 Bad Gateway", 502, true},
		{"503 Service Unavailable", 503, true},
		{"504 Gateway Timeout", 504, true},
		{"400 Bad Request", 400, false},
		{"401 Unauthorized", 401, false},
		{"403 Forbidden", 403, false},
		{"404 Not Found", 404, false},
		{"200 OK", 200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTransientError(tt.statusCode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResolveNAAToVolumeID_EmptyNAA(t *testing.T) {
	ctx := context.Background()
	result, err := resolveNAAToVolumeID(ctx, nil, "")

	assert.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "empty NAA ID", result.FailureReason)
}

func TestResolveNAAToVolumeID_Success(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	expectedVolumes := []gopowerstore.Volume{
		{
			ID:          "vol-12345",
			ApplianceID: "appliance-A",
		},
	}

	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return(expectedVolumes, nil)

	result, err := resolveNAAToVolumeID(ctx, mockClient, "68ccf098003ceb5e4577a20be6d11bf9")

	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "vol-12345", result.SourceVolumeID)
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	mockClient.AssertExpectations(t)
}

func TestResolveNAAToVolumeID_NotFound(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return([]gopowerstore.Volume{}, nil)

	result, err := resolveNAAToVolumeID(ctx, mockClient, "naa.68ccf098003ceb5e4577a20be6d11bf9")

	assert.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "NAA ID not found", result.FailureReason)
	mockClient.AssertExpectations(t)
}

func TestCheckFirmwareVersion(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(5.1), nil)

	result := CheckFirmwareVersion(ctx, mockClient, "array-1")
	assert.True(t, result)
	mockClient.AssertExpectations(t)
}

func TestCheckFirmwareVersion_OldFirmware(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(5.0), nil)

	result := CheckFirmwareVersion(ctx, mockClient, "array-1")
	assert.False(t, result)
	mockClient.AssertExpectations(t)
}

func TestCheckFirmwareVersion_Error(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(0), errors.New("connection error"))

	result := CheckFirmwareVersion(ctx, mockClient, "array-1")
	assert.False(t, result)
	mockClient.AssertExpectations(t)
}

func TestResolveNAAToVolumeID_MultipleVolumesReturned(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	volumes := []gopowerstore.Volume{
		{ID: "vol-1", ApplianceID: "appliance-A"},
		{ID: "vol-2", ApplianceID: "appliance-B"},
	}
	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return(volumes, nil)

	result, err := resolveNAAToVolumeID(ctx, mockClient, "68ccf098003ceb5e4577a20be6d11bf9")

	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "vol-1", result.SourceVolumeID) // First volume should be used
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	mockClient.AssertExpectations(t)
}

func TestResolveNAAForColocation_NoNAALabel(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()

	// No NAA label in params
	params := map[string]string{
		"arrayID": "test-array",
	}

	result := resolveNAAForColocation(ctx, params, nil, "test-array")
	assert.Nil(t, result) // Should return nil when no NAA label
}

func TestResolveNAAForColocation_EmptyNAALabel(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()

	// NAA label present but empty - should return failure result with warning
	params := map[string]string{
		KeyAffinitySourceNAA: "",
	}

	result := resolveNAAForColocation(ctx, params, nil, "test-array")
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "empty NAA ID", result.FailureReason)
}

func TestResolveNAAForColocation_WithWhitespaceOnlyNAALabel(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()

	// NAA label present but only whitespace - should return failure result with warning
	params := map[string]string{
		KeyAffinitySourceNAA: "   ",
	}

	result := resolveNAAForColocation(ctx, params, nil, "test-array")
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "empty NAA ID", result.FailureReason)
}

func TestResolveNAAForColocation_MultipleLabels(t *testing.T) {
	// Multiple labels including NAA (simulates csi-metadata-retriever merging all PVC labels)
	params := map[string]string{
		"app":                "test",
		KeyAffinitySourceNAA: "naa.68ccf098003ceb5e4577a20be6d11bf9",
		"env":                "prod",
	}

	// Extract should work even with multiple labels
	naaID := extractNAALabelFromParams(params)
	assert.Equal(t, "naa.68ccf098003ceb5e4577a20be6d11bf9", naaID)
}

// Test retry behavior with transient errors
func TestRetryBehavior_TransientErrorCodes(t *testing.T) {
	transientCodes := []int{429, 500, 502, 503, 504}
	for _, code := range transientCodes {
		t.Run(fmt.Sprintf("Code_%d_is_transient", code), func(t *testing.T) {
			assert.True(t, isTransientError(code))
		})
	}
}

func TestRetryBehavior_PermanentErrorCodes(t *testing.T) {
	permanentCodes := []int{400, 401, 403, 404, 422}
	for _, code := range permanentCodes {
		t.Run(fmt.Sprintf("Code_%d_is_permanent", code), func(t *testing.T) {
			assert.False(t, isTransientError(code))
		})
	}
}

// Test NAA normalization edge cases - hex portion preserved, only prefix normalized
func TestNormalizeNAAID_MixedCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"NAA.68CCF098", "naa.68CCF098"},   // prefix normalized, hex preserved
		{"Naa.68CcF098", "naa.68CcF098"},   // prefix normalized, hex preserved
		{"nAa.68ccf098", "naa.68ccf098"},   // prefix normalized, hex preserved
		{"68CCF098ABC", "naa.68CCF098ABC"}, // prefix added, hex preserved
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeNAAID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test NAAResolutionResult struct
func TestNAAResolutionResult_Fields(t *testing.T) {
	result := &NAAResolutionResult{
		SourceVolumeID:    "vol-123",
		SourceApplianceID: "app-456",
		Success:           true,
		FailureReason:     "",
	}

	assert.Equal(t, "vol-123", result.SourceVolumeID)
	assert.Equal(t, "app-456", result.SourceApplianceID)
	assert.True(t, result.Success)
	assert.Empty(t, result.FailureReason)
}

func TestNAAResolutionResult_FailureCase(t *testing.T) {
	result := &NAAResolutionResult{
		SourceVolumeID:    "",
		SourceApplianceID: "",
		Success:           false,
		FailureReason:     "NAA ID not found",
	}

	assert.Empty(t, result.SourceVolumeID)
	assert.Empty(t, result.SourceApplianceID)
	assert.False(t, result.Success)
	assert.Equal(t, "NAA ID not found", result.FailureReason)
}

// Test constants
func TestConstants(t *testing.T) {
	assert.Equal(t, "volume.csi.k8s.io/affinity-source-naa", KeyAffinitySourceNAA)
	assert.Equal(t, "naa.", NAAPrefix)
	assert.Equal(t, float32(5.1), MinFirmwareVersionForNAA)
	assert.Equal(t, 3, NAAResolutionMaxRetries)
}

// Test ResetNAAConfig
func TestResetNAAConfig(t *testing.T) {
	// Set some state via CheckFirmwareVersion
	naaConfigMu.Lock()
	naaConfigMap["test-array"] = &NAAResolutionConfig{enabled: true, checkedVersion: true}
	naaConfigMu.Unlock()

	// Reset
	ResetNAAConfig()

	// Verify reset
	naaConfigMu.Lock()
	assert.Empty(t, naaConfigMap)
	naaConfigMu.Unlock()
}

// Test PlacementOutcome constants
func TestPlacementOutcomeConstants(t *testing.T) {
	assert.Equal(t, PlacementOutcome("XCOPYSuccess"), PlacementXCOPYSuccess)
	assert.Equal(t, PlacementOutcome("HostCopyFallback"), PlacementHostCopyFallback)
	assert.Equal(t, PlacementOutcome("PlacementVerificationFailed"), PlacementVerificationFailed)
}

// Test PlacementVerificationResult struct
func TestPlacementVerificationResult_Fields(t *testing.T) {
	result := &PlacementVerificationResult{
		Outcome:           PlacementXCOPYSuccess,
		TargetApplianceID: "appliance-A",
		SourceApplianceID: "appliance-A",
		Error:             nil,
	}

	assert.Equal(t, PlacementXCOPYSuccess, result.Outcome)
	assert.Equal(t, "appliance-A", result.TargetApplianceID)
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	assert.Nil(t, result.Error)
}

// =============================================================================
// BDD Test Scenarios for NAA Resolution and Placement Verification
// These tests use Ginkgo/Gomega BDD-style syntax for acceptance testing
// =============================================================================

var _ = ginkgo.Describe("NAA Resolution BDD Scenarios", func() {
	ginkgo.BeforeEach(func() {
		ResetNAAConfig()
	})

	ginkgo.Describe("NAA ID Label Extraction", func() {
		ginkgo.Context("When NAA label is present with prefix", func() {
			ginkgo.It("should extract the NAA ID with prefix intact", func() {
				params := map[string]string{
					KeyAffinitySourceNAA: "naa.68ccf098003ceb5e4577a20be6d11bf9",
				}
				naaID := extractNAALabelFromParams(params)
				gomega.Expect(naaID).To(gomega.Equal("naa.68ccf098003ceb5e4577a20be6d11bf9"))
			})
		})

		ginkgo.Context("When NAA label is present without prefix", func() {
			ginkgo.It("should extract the raw NAA ID", func() {
				params := map[string]string{
					KeyAffinitySourceNAA: "68ccf098003ceb5e4577a20be6d11bf9",
				}
				naaID := extractNAALabelFromParams(params)
				gomega.Expect(naaID).To(gomega.Equal("68ccf098003ceb5e4577a20be6d11bf9"))
			})
		})

		ginkgo.Context("When NAA label value is empty", func() {
			ginkgo.It("should return empty string", func() {
				params := map[string]string{
					KeyAffinitySourceNAA: "",
				}
				naaID := extractNAALabelFromParams(params)
				gomega.Expect(naaID).To(gomega.BeEmpty())
			})
		})

		ginkgo.Context("When NAA label is absent", func() {
			ginkgo.It("should return empty string", func() {
				params := map[string]string{
					"other-label": "value",
				}
				naaID := extractNAALabelFromParams(params)
				gomega.Expect(naaID).To(gomega.BeEmpty())
			})
		})

		ginkgo.Context("When NAA label has leading/trailing whitespace", func() {
			ginkgo.It("should trim whitespace", func() {
				params := map[string]string{
					KeyAffinitySourceNAA: "  naa.68ccf098003ceb5e4577a20be6d11bf9  ",
				}
				naaID := extractNAALabelFromParams(params)
				gomega.Expect(naaID).To(gomega.Equal("naa.68ccf098003ceb5e4577a20be6d11bf9"))
			})
		})
	})

	ginkgo.Describe("NAA ID Normalization", func() {
		ginkgo.Context("When NAA ID has lowercase prefix", func() {
			ginkgo.It("should return unchanged", func() {
				normalized := normalizeNAAID("naa.68ccf098003ceb5e4577a20be6d11bf9")
				gomega.Expect(normalized).To(gomega.Equal("naa.68ccf098003ceb5e4577a20be6d11bf9"))
			})
		})

		ginkgo.Context("When NAA ID has uppercase prefix", func() {
			ginkgo.It("should normalize prefix to lowercase and preserve hex case", func() {
				normalized := normalizeNAAID("NAA.68CCF098003CEB5E4577A20BE6D11BF9")
				gomega.Expect(normalized).To(gomega.Equal("naa.68CCF098003CEB5E4577A20BE6D11BF9"))
			})
		})

		ginkgo.Context("When NAA ID has mixed case prefix", func() {
			ginkgo.It("should normalize prefix to lowercase and preserve hex case", func() {
				normalized := normalizeNAAID("Naa.68CcF098003ceb5e4577a20be6d11bf9")
				gomega.Expect(normalized).To(gomega.Equal("naa.68CcF098003ceb5e4577a20be6d11bf9"))
			})
		})

		ginkgo.Context("When NAA ID has no prefix", func() {
			ginkgo.It("should add naa. prefix", func() {
				normalized := normalizeNAAID("68ccf098003ceb5e4577a20be6d11bf9")
				gomega.Expect(normalized).To(gomega.Equal("naa.68ccf098003ceb5e4577a20be6d11bf9"))
			})
		})

		ginkgo.Context("When NAA ID is empty", func() {
			ginkgo.It("should return empty string", func() {
				normalized := normalizeNAAID("")
				gomega.Expect(normalized).To(gomega.BeEmpty())
			})
		})
	})

	ginkgo.Describe("Transient Error Classification", func() {
		ginkgo.Context("When API returns 429 Too Many Requests", func() {
			ginkgo.It("should be classified as transient (retryable)", func() {
				gomega.Expect(isTransientError(429)).To(gomega.BeTrue())
			})
		})

		ginkgo.Context("When API returns 500 Internal Server Error", func() {
			ginkgo.It("should be classified as transient (retryable)", func() {
				gomega.Expect(isTransientError(500)).To(gomega.BeTrue())
			})
		})

		ginkgo.Context("When API returns 502 Bad Gateway", func() {
			ginkgo.It("should be classified as transient (retryable)", func() {
				gomega.Expect(isTransientError(502)).To(gomega.BeTrue())
			})
		})

		ginkgo.Context("When API returns 503 Service Unavailable", func() {
			ginkgo.It("should be classified as transient (retryable)", func() {
				gomega.Expect(isTransientError(503)).To(gomega.BeTrue())
			})
		})

		ginkgo.Context("When API returns 504 Gateway Timeout", func() {
			ginkgo.It("should be classified as transient (retryable)", func() {
				gomega.Expect(isTransientError(504)).To(gomega.BeTrue())
			})
		})

		ginkgo.Context("When API returns 400 Bad Request", func() {
			ginkgo.It("should be classified as permanent (not retryable)", func() {
				gomega.Expect(isTransientError(400)).To(gomega.BeFalse())
			})
		})

		ginkgo.Context("When API returns 401 Unauthorized", func() {
			ginkgo.It("should be classified as permanent (not retryable)", func() {
				gomega.Expect(isTransientError(401)).To(gomega.BeFalse())
			})
		})

		ginkgo.Context("When API returns 403 Forbidden", func() {
			ginkgo.It("should be classified as permanent (not retryable)", func() {
				gomega.Expect(isTransientError(403)).To(gomega.BeFalse())
			})
		})

		ginkgo.Context("When API returns 404 Not Found", func() {
			ginkgo.It("should be classified as permanent (not retryable)", func() {
				gomega.Expect(isTransientError(404)).To(gomega.BeFalse())
			})
		})
	})

	ginkgo.Describe("NAA Resolution Result Structure", func() {
		ginkgo.Context("When resolution succeeds", func() {
			ginkgo.It("should populate all success fields", func() {
				result := &NAAResolutionResult{
					SourceVolumeID:    "vol-12345",
					SourceApplianceID: "appliance-A",
					Success:           true,
					FailureReason:     "",
				}
				gomega.Expect(result.Success).To(gomega.BeTrue())
				gomega.Expect(result.SourceVolumeID).To(gomega.Equal("vol-12345"))
				gomega.Expect(result.SourceApplianceID).To(gomega.Equal("appliance-A"))
				gomega.Expect(result.FailureReason).To(gomega.BeEmpty())
			})
		})

		ginkgo.Context("When resolution fails", func() {
			ginkgo.It("should populate failure reason", func() {
				result := &NAAResolutionResult{
					Success:       false,
					FailureReason: "NAA ID not found",
				}
				gomega.Expect(result.Success).To(gomega.BeFalse())
				gomega.Expect(result.FailureReason).To(gomega.Equal("NAA ID not found"))
			})
		})
	})
})

var _ = ginkgo.Describe("Placement Verification BDD Scenarios", func() {
	var (
		ctx        context.Context
		mockClient *mocks.Client
	)

	ginkgo.BeforeEach(func() {
		ctx = context.Background()
		mockClient = new(mocks.Client)
	})

	ginkgo.Describe("Placement Outcome Determination", func() {
		ginkgo.Context("When target volume is on same appliance as source", func() {
			ginkgo.It("should return XCOPYSuccess outcome indicating XCOPY-offload eligibility", func() {
				mockClient.On("GetVolume", ctx, "target-vol-123").Return(gopowerstore.Volume{
					ID:          "target-vol-123",
					ApplianceID: "appliance-A",
				}, nil)

				result := verifyPlacement(ctx, mockClient, "target-vol-123", "appliance-A")

				gomega.Expect(result.Outcome).To(gomega.Equal(PlacementXCOPYSuccess))
				gomega.Expect(result.TargetApplianceID).To(gomega.Equal("appliance-A"))
				gomega.Expect(result.SourceApplianceID).To(gomega.Equal("appliance-A"))
				gomega.Expect(result.Error).To(gomega.BeNil())
			})
		})

		ginkgo.Context("When target volume is on different appliance than source", func() {
			ginkgo.It("should return HostCopyFallback outcome indicating host-copy required", func() {
				mockClient.On("GetVolume", ctx, "target-vol-123").Return(gopowerstore.Volume{
					ID:          "target-vol-123",
					ApplianceID: "appliance-B",
				}, nil)

				result := verifyPlacement(ctx, mockClient, "target-vol-123", "appliance-A")

				gomega.Expect(result.Outcome).To(gomega.Equal(PlacementHostCopyFallback))
				gomega.Expect(result.TargetApplianceID).To(gomega.Equal("appliance-B"))
				gomega.Expect(result.SourceApplianceID).To(gomega.Equal("appliance-A"))
				gomega.Expect(result.Error).To(gomega.BeNil())
			})
		})

		ginkgo.Context("When placement verification query fails", func() {
			ginkgo.It("should return PlacementVerificationFailed with error details", func() {
				mockClient.On("GetVolume", ctx, "target-vol-123").Return(
					gopowerstore.Volume{}, errors.New("API error"),
				)

				result := verifyPlacement(ctx, mockClient, "target-vol-123", "appliance-A")

				gomega.Expect(result.Outcome).To(gomega.Equal(PlacementVerificationFailed))
				gomega.Expect(result.Error).ToNot(gomega.BeNil())
				gomega.Expect(result.Error.Error()).To(gomega.Equal("API error"))
			})
		})

		ginkgo.Context("When target volume ID is empty", func() {
			ginkgo.It("should return PlacementVerificationFailed without API call", func() {
				result := verifyPlacement(ctx, mockClient, "", "appliance-A")

				gomega.Expect(result.Outcome).To(gomega.Equal(PlacementVerificationFailed))
				// No API call should be made
				mockClient.AssertNotCalled(ginkgo.GinkgoT(), "GetVolume")
			})
		})

		ginkgo.Context("When source appliance ID is empty", func() {
			ginkgo.It("should return PlacementVerificationFailed without API call", func() {
				result := verifyPlacement(ctx, mockClient, "target-vol-123", "")

				gomega.Expect(result.Outcome).To(gomega.Equal(PlacementVerificationFailed))
				// No API call should be made
				mockClient.AssertNotCalled(ginkgo.GinkgoT(), "GetVolume")
			})
		})
	})

	ginkgo.Describe("Placement Outcome Constants", func() {
		ginkgo.It("should have correct string values for event emission", func() {
			gomega.Expect(string(PlacementXCOPYSuccess)).To(gomega.Equal("XCOPYSuccess"))
			gomega.Expect(string(PlacementHostCopyFallback)).To(gomega.Equal("HostCopyFallback"))
			gomega.Expect(string(PlacementVerificationFailed)).To(gomega.Equal("PlacementVerificationFailed"))
		})
	})

	ginkgo.Describe("Non-labeled PVC Handling", func() {
		ginkgo.Context("When PVC has no NAA label", func() {
			ginkgo.It("should skip NAA resolution entirely and return empty string", func() {
				params := map[string]string{
					"storageclass": "powerstore-iscsi",
					"fstype":       "ext4",
				}

				naaID := extractNAALabelFromParams(params)

				gomega.Expect(naaID).To(gomega.BeEmpty())
			})
		})

		ginkgo.Context("When PVC has other labels but no NAA label", func() {
			ginkgo.It("should not extract NAA ID from unrelated labels", func() {
				params := map[string]string{
					"app":         "myapp",
					"environment": "production",
					"team":        "storage",
				}

				naaID := extractNAALabelFromParams(params)

				gomega.Expect(naaID).To(gomega.BeEmpty())
			})
		})
	})
})

// =============================================================================
// Tests using the actual production functions with generated mocks
// These tests ensure the actual code paths are covered
// =============================================================================

func TestResolveNAAToVolumeID_ActualFunction_Success(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	expectedVolumes := []gopowerstore.Volume{
		{
			ID:          "vol-12345",
			ApplianceID: "appliance-A",
		},
	}

	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return(expectedVolumes, nil)

	result, err := resolveNAAToVolumeID(ctx, mockClient, "68ccf098003ceb5e4577a20be6d11bf9")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, "vol-12345", result.SourceVolumeID)
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	mockClient.AssertExpectations(t)
}

func TestResolveNAAToVolumeID_ActualFunction_NotFound(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return([]gopowerstore.Volume{}, nil)

	result, err := resolveNAAToVolumeID(ctx, mockClient, "naa.68ccf098003ceb5e4577a20be6d11bf9")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "NAA ID not found", result.FailureReason)
	mockClient.AssertExpectations(t)
}

func TestResolveNAAToVolumeID_ActualFunction_EmptyNAA(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	result, err := resolveNAAToVolumeID(ctx, mockClient, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "empty NAA ID", result.FailureReason)
}

func TestResolveNAAToVolumeID_ActualFunction_PermanentError(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	// Create a mock API error with 404 status (permanent error)
	apiErr := gopowerstore.NewAPIError()
	apiErr.StatusCode = 404
	apiErr.Message = "Volume not found"

	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return([]gopowerstore.Volume(nil), apiErr)

	result, err := resolveNAAToVolumeID(ctx, mockClient, "68ccf098003ceb5e4577a20be6d11bf9")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	mockClient.AssertExpectations(t)
}

func TestCheckFirmwareVersion_ActualFunction_Enabled(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(5.1), nil)

	result := CheckFirmwareVersion(ctx, mockClient, "array-1")

	assert.True(t, result)
	mockClient.AssertExpectations(t)
}

func TestCheckFirmwareVersion_ActualFunction_Disabled(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(4.9), nil)

	result := CheckFirmwareVersion(ctx, mockClient, "array-1")

	assert.False(t, result)
	mockClient.AssertExpectations(t)
}

func TestCheckFirmwareVersion_ActualFunction_Error(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(0), errors.New("connection error"))

	result := CheckFirmwareVersion(ctx, mockClient, "array-1")

	assert.False(t, result)
	mockClient.AssertExpectations(t)
}

func TestCheckFirmwareVersion_ActualFunction_Cached(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	// First call should query the API
	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(5.1), nil).Once()

	result1 := CheckFirmwareVersion(ctx, mockClient, "array-1")
	assert.True(t, result1)

	// Second call should use cached value (no additional API call)
	result2 := CheckFirmwareVersion(ctx, mockClient, "array-1")
	assert.True(t, result2)

	mockClient.AssertExpectations(t)
}

func TestVerifyPlacement_ActualFunction_SameAppliance(t *testing.T) {
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetVolume", ctx, "vol-67890").Return(gopowerstore.Volume{
		ID:          "vol-67890",
		ApplianceID: "appliance-A",
	}, nil)

	result := verifyPlacement(ctx, mockClient, "vol-67890", "appliance-A")

	assert.Equal(t, PlacementXCOPYSuccess, result.Outcome)
	assert.Equal(t, "appliance-A", result.TargetApplianceID)
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	assert.Nil(t, result.Error)
	mockClient.AssertExpectations(t)
}

func TestVerifyPlacement_ActualFunction_DifferentAppliance(t *testing.T) {
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetVolume", ctx, "vol-67890").Return(gopowerstore.Volume{
		ID:          "vol-67890",
		ApplianceID: "appliance-B",
	}, nil)

	result := verifyPlacement(ctx, mockClient, "vol-67890", "appliance-A")

	assert.Equal(t, PlacementHostCopyFallback, result.Outcome)
	assert.Equal(t, "appliance-B", result.TargetApplianceID)
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	assert.Nil(t, result.Error)
	mockClient.AssertExpectations(t)
}

func TestVerifyPlacement_ActualFunction_QueryFailed(t *testing.T) {
	ctx := context.Background()
	mockClient := new(mocks.Client)

	mockClient.On("GetVolume", ctx, "vol-67890").Return(gopowerstore.Volume{}, errors.New("API error"))

	result := verifyPlacement(ctx, mockClient, "vol-67890", "appliance-A")

	assert.Equal(t, PlacementVerificationFailed, result.Outcome)
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	assert.NotNil(t, result.Error)
	mockClient.AssertExpectations(t)
}

func TestVerifyPlacement_ActualFunction_EmptyTargetVolumeID(t *testing.T) {
	ctx := context.Background()
	mockClient := new(mocks.Client)

	result := verifyPlacement(ctx, mockClient, "", "appliance-A")

	assert.Equal(t, PlacementVerificationFailed, result.Outcome)
	assert.Nil(t, result.Error)
}

func TestVerifyPlacement_ActualFunction_EmptySourceApplianceID(t *testing.T) {
	ctx := context.Background()
	mockClient := new(mocks.Client)

	result := verifyPlacement(ctx, mockClient, "vol-67890", "")

	assert.Equal(t, PlacementVerificationFailed, result.Outcome)
	assert.Nil(t, result.Error)
}

func TestResolveNAAForColocation_ActualFunction_Success(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	// Setup firmware version check
	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(5.1), nil)

	// Setup NAA resolution
	expectedVolumes := []gopowerstore.Volume{
		{
			ID:          "vol-12345",
			ApplianceID: "appliance-A",
		},
	}
	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return(expectedVolumes, nil)

	params := map[string]string{
		KeyAffinitySourceNAA: "naa.68ccf098003ceb5e4577a20be6d11bf9",
	}

	result := resolveNAAForColocation(ctx, params, mockClient, "array-1")

	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, "vol-12345", result.SourceVolumeID)
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	mockClient.AssertExpectations(t)
}

func TestResolveNAAForColocation_ActualFunction_NoLabel(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	params := map[string]string{
		"other-label": "value",
	}

	result := resolveNAAForColocation(ctx, params, mockClient, "array-1")

	assert.Nil(t, result) // No NAA label means nil result (not a failure)
}

func TestResolveNAAForColocation_ActualFunction_EmptyLabel(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	params := map[string]string{
		KeyAffinitySourceNAA: "",
	}

	result := resolveNAAForColocation(ctx, params, mockClient, "array-1")

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "empty NAA ID", result.FailureReason)
}

func TestResolveNAAForColocation_ActualFunction_OldFirmware(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	// Setup firmware version check to return old version
	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(4.9), nil)

	params := map[string]string{
		KeyAffinitySourceNAA: "naa.68ccf098003ceb5e4577a20be6d11bf9",
	}

	result := resolveNAAForColocation(ctx, params, mockClient, "array-1")

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "firmware version too old", result.FailureReason)
	mockClient.AssertExpectations(t)
}

func TestResolveNAAForColocation_ActualFunction_ResolutionFailed(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	// Setup firmware version check
	mockClient.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(5.1), nil)

	// Setup NAA resolution to return not found
	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return([]gopowerstore.Volume{}, nil)

	params := map[string]string{
		KeyAffinitySourceNAA: "naa.68ccf098003ceb5e4577a20be6d11bf9",
	}

	result := resolveNAAForColocation(ctx, params, mockClient, "array-1")

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "NAA ID not found", result.FailureReason)
	mockClient.AssertExpectations(t)
}

// TestResolveNAAToVolumeID_TransientErrorRetry exercises the production retry loop
// with transient errors (HTTP 503) followed by a success, verifying exponential backoff.
func TestResolveNAAToVolumeID_TransientErrorRetry(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	// First two calls return transient 503 error, third call succeeds
	transientErr := gopowerstore.NewAPIError()
	transientErr.StatusCode = 503
	transientErr.Message = "Service Unavailable"

	callCount := 0
	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return(func(_ context.Context, _ map[string]string) []gopowerstore.Volume {
		callCount++
		if callCount < 3 {
			return nil
		}
		return []gopowerstore.Volume{{ID: "vol-retry-ok", ApplianceID: "appliance-A"}}
	}, func(_ context.Context, _ map[string]string) error {
		if callCount < 3 {
			return transientErr
		}
		return nil
	})

	result, err := resolveNAAToVolumeID(ctx, mockClient, "68ccf098003ceb5e4577a20be6d11bf9")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, "vol-retry-ok", result.SourceVolumeID)
	assert.Equal(t, "appliance-A", result.SourceApplianceID)
	assert.Equal(t, 3, callCount, "Expected 3 API calls (2 retries + 1 success)")
}

// TestResolveNAAToVolumeID_TransientErrorExhausted verifies that after exhausting
// all retry attempts with transient errors, the function returns a failure result.
func TestResolveNAAToVolumeID_TransientErrorExhausted(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()
	mockClient := new(mocks.Client)

	transientErr := gopowerstore.NewAPIError()
	transientErr.StatusCode = 503
	transientErr.Message = "Service Unavailable"

	mockClient.On("GetVolumesWithFilter", ctx, mock.MatchedBy(func(filters map[string]string) bool {
		_, hasWWN := filters["wwn"]
		return hasWWN
	})).Return([]gopowerstore.Volume(nil), transientErr)

	result, err := resolveNAAToVolumeID(ctx, mockClient, "68ccf098003ceb5e4577a20be6d11bf9")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	// Should have been called NAAResolutionMaxRetries times
	mockClient.AssertNumberOfCalls(t, "GetVolumesWithFilter", NAAResolutionMaxRetries)
}

// TestCheckFirmwareVersion_PerArrayCaching verifies that firmware version results
// are cached independently per array ID (Comment 3 fix validation).
func TestCheckFirmwareVersion_PerArrayCaching(t *testing.T) {
	ResetNAAConfig()
	ctx := context.Background()

	mockClientA := new(mocks.Client)
	mockClientB := new(mocks.Client)

	// Array A has firmware 5.1 (enabled)
	mockClientA.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(5.1), nil).Once()
	// Array B has firmware 4.9 (disabled)
	mockClientB.On("GetSoftwareMajorMinorVersion", ctx).Return(float32(4.9), nil).Once()

	resultA := CheckFirmwareVersion(ctx, mockClientA, "array-A")
	assert.True(t, resultA, "Array A (firmware 5.1) should be enabled")

	resultB := CheckFirmwareVersion(ctx, mockClientB, "array-B")
	assert.False(t, resultB, "Array B (firmware 4.9) should be disabled")

	// Cached calls should not hit the API again
	resultA2 := CheckFirmwareVersion(ctx, mockClientA, "array-A")
	assert.True(t, resultA2, "Cached result for array A should still be enabled")

	resultB2 := CheckFirmwareVersion(ctx, mockClientB, "array-B")
	assert.False(t, resultB2, "Cached result for array B should still be disabled")

	mockClientA.AssertExpectations(t)
	mockClientB.AssertExpectations(t)
}
