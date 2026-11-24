package metadata

import (
	"regexp"
	"strings"
)

// advisoryIDPattern matches the advisory ids that scanners report for one issue.
var advisoryIDPattern = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3}|GO-\d{4}-\d{4,}|PYSEC-\d{4}-\d+)`)

// advisoryURLMarkers keep ExtractAdvisoryIDs to links that name the advisory itself,
// not links that merely mention another one.
var advisoryURLMarkers = []string{"/advisories/", "/vuln/detail/", "/vulnerability/", "/vuln/", "/cve/"}

// CanonicalAdvisoryID writes an advisory id in its usual case: CVE and GO ids in
// upper case, GHSA ids as "GHSA-" plus lower-case groups.
func CanonicalAdvisoryID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) >= 5 && strings.EqualFold(id[:5], "GHSA-") {
		return "GHSA-" + strings.ToLower(id[5:])
	}
	return strings.ToUpper(id)
}

// ExtractAdvisoryIDs returns the advisory ids named by advisory links, in order, once each.
func ExtractAdvisoryIDs(urls ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range urls {
		lower := strings.ToLower(u)
		named := false
		for _, marker := range advisoryURLMarkers {
			if strings.Contains(lower, marker) {
				named = true
				break
			}
		}
		if !named {
			continue
		}
		for _, id := range advisoryIDPattern.FindAllString(u, -1) {
			id = CanonicalAdvisoryID(id)
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// NormalizeAliases returns the candidate ids that differ from id, once each (case-insensitive).
func NormalizeAliases(id string, candidates ...string) []string {
	seen := map[string]bool{strings.ToUpper(strings.TrimSpace(id)): true}
	var out []string
	for _, c := range candidates {
		c = CanonicalAdvisoryID(c)
		if c == "" || seen[strings.ToUpper(c)] {
			continue
		}
		seen[strings.ToUpper(c)] = true
		out = append(out, c)
	}
	return out
}

// IDs returns the finding's id and its aliases, upper-cased, once each.
func (v Vulnerability) IDs() []string {
	out := make([]string, 0, 1+len(v.Aliases))
	seen := map[string]bool{}
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		key := strings.ToUpper(strings.TrimSpace(id))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// IsCVE reports whether id is a CVE id.
func IsCVE(id string) bool {
	return len(id) >= 4 && strings.EqualFold(id[:4], "CVE-")
}

// BypassFor returns the bypass that covers the finding under its id or any alias.
// The map is keyed by upper-cased target.
func BypassFor(bypassed map[string]*CVEBypass, v Vulnerability) (*CVEBypass, bool) {
	for _, id := range v.IDs() {
		if b, ok := bypassed[id]; ok {
			return b, true
		}
	}
	return nil, false
}
