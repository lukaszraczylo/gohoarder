package ghsa

import (
	"testing"
)

func TestVersionInRange(t *testing.T) {
	// matched: whether the version satisfies the range expression.
	// ok: whether the parser/comparator could evaluate the inputs.
	cases := []struct {
		name    string
		version string
		expr    string
		matched bool
		ok      bool
	}{
		{"single LT match", "1.2.3", "< 2.0.0", true, true},
		{"single LT no match", "2.5.0", "< 2.0.0", false, true},
		{"single GTE match", "2.5.0", ">= 2.0.0", true, true},
		{"single GTE no match", "1.0.0", ">= 2.0.0", false, true},
		{"range hit", "1.5.0", ">= 1.0.0, < 2.0.0", true, true},
		{"range below", "0.9.0", ">= 1.0.0, < 2.0.0", false, true},
		{"range above", "2.0.0", ">= 1.0.0, < 2.0.0", false, true},
		{"range upper bound exclusive", "2.0.0", ">= 1.0.0, < 2.0.0", false, true},
		{"range lower bound inclusive", "1.0.0", ">= 1.0.0, < 2.0.0", true, true},
		{"equality match", "1.2.3", "= 1.2.3", true, true},
		{"equality miss", "1.2.4", "= 1.2.3", false, true},
		{"with v prefix on bound", "1.2.3", ">= v1.0.0", true, true},
		{"shorter version coerces", "1.0", ">= 1.0.0", true, true},
		{"pre-release lower than release", "1.0.0-rc1", ">= 1.0.0", false, true},
		{"pre-release greater than older", "1.0.0-rc1", ">= 0.9.0", true, true},
		{"malformed operator", "1.0.0", "~ 1.0.0", false, false},
		{"malformed version", "abc", ">= 1.0.0", false, false},
		{"empty bound after op", "1.0.0", ">=", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, ok := versionInRange(tc.version, tc.expr)
			if matched != tc.matched || ok != tc.ok {
				t.Fatalf("versionInRange(%q, %q) = (%v, %v), want (%v, %v)",
					tc.version, tc.expr, matched, ok, tc.matched, tc.ok)
			}
		})
	}
}

func TestAdvisoryAffectsVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		adv     GHSAAdvisory
		want    bool
	}{
		{
			name:    "advisory with no vulnerabilities is conservatively included",
			adv:     GHSAAdvisory{GHSAID: "GHSA-xxxx", Vulnerabilities: nil},
			version: "1.0.0",
			want:    true,
		},
		{
			name: "matching range marks advisory as affecting",
			adv: GHSAAdvisory{
				GHSAID: "GHSA-aaaa",
				Vulnerabilities: []GHSAVulnerability{
					{VulnerableVersions: ">= 1.0.0, < 2.0.0"},
				},
			},
			version: "1.5.0",
			want:    true,
		},
		{
			name: "non-matching range excludes advisory",
			adv: GHSAAdvisory{
				GHSAID: "GHSA-bbbb",
				Vulnerabilities: []GHSAVulnerability{
					{VulnerableVersions: ">= 2.0.0"},
				},
			},
			version: "1.0.0",
			want:    false,
		},
		{
			name: "any matching range across multiple vulns is affecting",
			adv: GHSAAdvisory{
				GHSAID: "GHSA-cccc",
				Vulnerabilities: []GHSAVulnerability{
					{VulnerableVersions: "< 0.5.0"},
					{VulnerableVersions: ">= 1.0.0, < 1.2.0"},
				},
			},
			version: "1.1.0",
			want:    true,
		},
		{
			name: "empty range falls back to affecting (fail-closed)",
			adv: GHSAAdvisory{
				GHSAID:          "GHSA-dddd",
				Vulnerabilities: []GHSAVulnerability{{VulnerableVersions: ""}},
			},
			version: "1.0.0",
			want:    true,
		},
		{
			name: "unparseable range falls back to affecting (fail-closed)",
			adv: GHSAAdvisory{
				GHSAID:          "GHSA-eeee",
				Vulnerabilities: []GHSAVulnerability{{VulnerableVersions: "~> 1.0"}},
			},
			version: "1.0.0",
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := advisoryAffectsVersion(tc.adv, tc.version)
			if got != tc.want {
				t.Fatalf("advisoryAffectsVersion(%q) = %v, want %v",
					tc.version, got, tc.want)
			}
		})
	}
}

func TestFilterAffectedAdvisoriesEmptyVersion(t *testing.T) {
	// Without a target version we can't compare ranges, so all advisories
	// are conservatively included.
	s := &Scanner{}
	in := []GHSAAdvisory{
		{GHSAID: "A", Vulnerabilities: []GHSAVulnerability{{VulnerableVersions: ">= 2.0.0"}}},
		{GHSAID: "B"},
	}
	out := s.filterAffectedAdvisories(in, "")
	if len(out) != len(in) {
		t.Fatalf("expected all advisories with empty version, got %d/%d", len(out), len(in))
	}
}

func TestFilterAffectedAdvisoriesFiltersByRange(t *testing.T) {
	s := &Scanner{}
	in := []GHSAAdvisory{
		{ // matches
			GHSAID: "MATCH",
			Vulnerabilities: []GHSAVulnerability{
				{VulnerableVersions: ">= 1.0.0, < 2.0.0"},
			},
		},
		{ // does not match
			GHSAID: "MISS",
			Vulnerabilities: []GHSAVulnerability{
				{VulnerableVersions: ">= 3.0.0"},
			},
		},
	}
	out := s.filterAffectedAdvisories(in, "1.5.0")
	if len(out) != 1 || out[0].GHSAID != "MATCH" {
		t.Fatalf("expected only MATCH, got %+v", out)
	}
}
