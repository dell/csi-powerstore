package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCoreVariables(t *testing.T) {
	// Check if SemVer is set to a non-default value
	if SemVer != "unknown" {
		assert.NotEqual(t, "unknown", SemVer, "SemVer should not be 'unknown' if set during build")
	} else {
		assert.Equal(t, "unknown", SemVer, "SemVer should be 'unknown' by default")
	}

	// Check if CommitSha7 is set to a non-default value
	if CommitSha7 != "" {
		assert.NotEmpty(t, CommitSha7, "CommitSha7 should not be empty if set during build")
	} else {
		assert.Empty(t, CommitSha7, "CommitSha7 should be empty by default")
	}

	// Check if CommitSha32 is set to a non-default value
	if CommitSha32 != "" {
		assert.NotEmpty(t, CommitSha32, "CommitSha32 should not be empty if set during build")
	} else {
		assert.Empty(t, CommitSha32, "CommitSha32 should be empty by default")
	}

	// Check if CommitTime is set to a non-default value
	if !CommitTime.IsZero() {
		assert.False(t, CommitTime.IsZero(), "CommitTime should not be zero if set during build")
	} else {
		assert.True(t, CommitTime.IsZero(), "CommitTime should be zero by default")
	}

	// Test setting values
	SemVer = "1.0.0"
	CommitSha7 = "abcdefg"
	CommitSha32 = "abcdefg1234567890abcdefg1234567890"
	CommitTime = time.Now()

	assert.Equal(t, "1.0.0", SemVer, "SemVer should be '1.0.0'")
	assert.Equal(t, "abcdefg", CommitSha7, "CommitSha7 should be 'abcdefg'")
	assert.Equal(t, "abcdefg1234567890abcdefg1234567890", CommitSha32, "CommitSha32 should be 'abcdefg1234567890abcdefg1234567890'")
	assert.False(t, CommitTime.IsZero(), "CommitTime should not be zero")
}
