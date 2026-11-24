// Package scanver remembers the version a scanner's CLI reported at its last health check.
package scanver

import (
	"regexp"
	"sync/atomic"
)

var versionToken = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?[0-9A-Za-z.+-]*`)

// Cache holds the last version seen; the zero value reports no version.
type Cache struct {
	v atomic.Pointer[string]
}

// Record stores the first version-like token in a CLI's version output.
func (c *Cache) Record(output string) {
	if tok := versionToken.FindString(output); tok != "" {
		c.v.Store(&tok)
	}
}

// Version returns the recorded version, or "" when none was seen.
func (c *Cache) Version() string {
	if p := c.v.Load(); p != nil {
		return *p
	}
	return ""
}
