package uuid

import (
	"crypto/rand"
	"fmt"
)

// UUID represents a UUID (RFC 4122)
type UUID [16]byte

// New generates a random UUID v4
func New() UUID {
	var u UUID
	// Read random bytes
	if _, err := rand.Read(u[:]); err != nil {
		panic(fmt.Sprintf("failed to generate UUID: %v", err))
	}

	// Set version (4) and variant (RFC 4122)
	u[6] = (u[6] & 0x0f) | 0x40 // Version 4
	u[8] = (u[8] & 0x3f) | 0x80 // Variant RFC 4122

	return u
}

// String returns the UUID in standard format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
func (u UUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
