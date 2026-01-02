package uuid

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew tests UUID generation
func TestNew(t *testing.T) {
	tests := []struct {
		name string
		runs int
	}{
		{
			name: "generate single UUID",
			runs: 1,
		},
		{
			name: "generate multiple UUIDs",
			runs: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]bool)

			for i := 0; i < tt.runs; i++ {
				uuid := New()

				// Verify UUID is 16 bytes
				assert.Equal(t, 16, len(uuid))

				// Verify version is 4
				version := (uuid[6] >> 4) & 0x0f
				assert.Equal(t, uint8(4), version, "UUID version should be 4")

				// Verify variant is RFC 4122
				variant := (uuid[8] >> 6) & 0x03
				assert.Equal(t, uint8(2), variant, "UUID variant should be RFC 4122 (10 in binary)")

				// Check uniqueness
				str := uuid.String()
				assert.False(t, seen[str], "UUID should be unique")
				seen[str] = true
			}
		})
	}
}

// TestString tests UUID string formatting
func TestString(t *testing.T) {
	tests := []struct {
		name     string
		uuid     UUID
		expected string
	}{
		{
			name:     "zero UUID",
			uuid:     UUID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: "00000000-0000-0000-0000-000000000000",
		},
		{
			name:     "all ones UUID",
			uuid:     UUID{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
			expected: "ffffffff-ffff-ffff-ffff-ffffffffffff",
		},
		{
			name:     "mixed values UUID",
			uuid:     UUID{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			expected: "12345678-9abc-def0-1122-334455667788",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.uuid.String()
			assert.Equal(t, tt.expected, str)

			// Verify format matches UUID regex
			matched, err := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, str)
			require.NoError(t, err)
			assert.True(t, matched, "UUID string should match standard format")

			// Verify dashes are in correct positions
			assert.Equal(t, "-", string(str[8]))
			assert.Equal(t, "-", string(str[13]))
			assert.Equal(t, "-", string(str[18]))
			assert.Equal(t, "-", string(str[23]))

			// Verify length
			assert.Equal(t, 36, len(str))
		})
	}
}

// TestUUIDFormat tests that generated UUIDs match the standard format
func TestUUIDFormat(t *testing.T) {
	const iterations = 1000

	// Compile regex once for performance
	hexPattern := regexp.MustCompile(`^[0-9a-f]+$`)

	for i := 0; i < iterations; i++ {
		uuid := New()
		str := uuid.String()

		// Test standard UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		parts := strings.Split(str, "-")
		require.Len(t, parts, 5, "UUID should have 5 parts separated by dashes")
		assert.Equal(t, 8, len(parts[0]), "First part should be 8 characters")
		assert.Equal(t, 4, len(parts[1]), "Second part should be 4 characters")
		assert.Equal(t, 4, len(parts[2]), "Third part should be 4 characters")
		assert.Equal(t, 4, len(parts[3]), "Fourth part should be 4 characters")
		assert.Equal(t, 12, len(parts[4]), "Fifth part should be 12 characters")

		// Verify all characters are hexadecimal
		for _, part := range parts {
			assert.True(t, hexPattern.MatchString(part), "UUID parts should only contain hex characters")
		}

		// Verify version bits (4th character of third part should start with 4)
		versionChar := parts[2][0]
		assert.Equal(t, byte('4'), versionChar, "UUID version should be 4")

		// Verify variant bits (first character of fourth part should be 8, 9, a, or b)
		variantChar := parts[3][0]
		assert.Contains(t, []byte{'8', '9', 'a', 'b'}, variantChar, "UUID variant should be RFC 4122")
	}
}

// TestConcurrentGeneration tests that UUID generation is safe for concurrent use
func TestConcurrentGeneration(t *testing.T) {
	const numGoroutines = 100
	const uuidsPerGoroutine = 100

	results := make(chan UUID, numGoroutines*uuidsPerGoroutine)

	// Generate UUIDs concurrently
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < uuidsPerGoroutine; j++ {
				results <- New()
			}
		}()
	}

	// Collect all UUIDs
	seen := make(map[string]bool)
	for i := 0; i < numGoroutines*uuidsPerGoroutine; i++ {
		uuid := <-results
		str := uuid.String()

		// Verify uniqueness
		assert.False(t, seen[str], "UUID should be unique even in concurrent generation")
		seen[str] = true

		// Verify version and variant
		version := (uuid[6] >> 4) & 0x0f
		assert.Equal(t, uint8(4), version)

		variant := (uuid[8] >> 6) & 0x03
		assert.Equal(t, uint8(2), variant)
	}

	// Verify we got all expected UUIDs
	assert.Equal(t, numGoroutines*uuidsPerGoroutine, len(seen))
}

// TestUUIDEquality tests UUID equality
func TestUUIDEquality(t *testing.T) {
	uuid1 := New()
	uuid2 := New()

	// Different UUIDs should not be equal
	assert.NotEqual(t, uuid1, uuid2)
	assert.NotEqual(t, uuid1.String(), uuid2.String())

	// Same UUID should be equal
	uuid3 := uuid1
	assert.Equal(t, uuid1, uuid3)
	assert.Equal(t, uuid1.String(), uuid3.String())
}

// TestUUIDArrayAccess tests that UUID can be accessed as a byte array
func TestUUIDArrayAccess(t *testing.T) {
	uuid := New()

	// Verify we can access all bytes
	for i := 0; i < 16; i++ {
		_ = uuid[i]
	}

	// Verify length
	assert.Equal(t, 16, len(uuid))
}

// BenchmarkNew benchmarks UUID generation
func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New()
	}
}

// BenchmarkString benchmarks UUID string conversion
func BenchmarkString(b *testing.B) {
	uuid := New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = uuid.String()
	}
}
