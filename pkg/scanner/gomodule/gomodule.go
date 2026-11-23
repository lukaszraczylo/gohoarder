// Package gomodule maps a Go cache key to a module path.
package gomodule

import "strings"

// Path returns the module path of a cache key "module/@v/version.zip", with the module proxy's
// case encoding ("!a" is "A") reversed. A name without "/@v/" is taken as the module path.
func Path(cacheKey string) string {
	module, _, _ := strings.Cut(cacheKey, "/@v/")
	var b strings.Builder
	for i := 0; i < len(module); i++ {
		if module[i] == '!' && i+1 < len(module) {
			i++
			b.WriteString(strings.ToUpper(string(module[i])))
			continue
		}
		b.WriteByte(module[i])
	}
	return b.String()
}
