package metadata

import (
	"slices"
	"testing"
)

func TestCanonicalAdvisoryID(t *testing.T) {
	for in, want := range map[string]string{
		"cve-2021-44906":      "CVE-2021-44906",
		"GHSA-XXXX-Yyyy-ZZZZ": "GHSA-xxxx-yyyy-zzzz",
		" go-2022-0001 ":      "GO-2022-0001",
		"":                    "",
		"ghsa-phwq-j96m-2c2q": "GHSA-phwq-j96m-2c2q",
		"PYSEC-2021-1":        "PYSEC-2021-1",
		"npm:1097":            "NPM:1097",
	} {
		if got := CanonicalAdvisoryID(in); got != want {
			t.Errorf("CanonicalAdvisoryID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractAdvisoryIDsKeepsOnlyAdvisoryLinks(t *testing.T) {
	got := ExtractAdvisoryIDs(
		"https://github.com/advisories/GHSA-xvch-5gv4-984h",
		"https://nvd.nist.gov/vuln/detail/CVE-2021-44906",
		"https://github.com/minimistjs/minimist/issues/CVE-2020-9999-discussion",
		"https://avd.aquasec.com/nvd/cve-2021-44906",
		"https://github.com/advisories/GHSA-xvch-5gv4-984h",
	)
	want := []string{"GHSA-xvch-5gv4-984h", "CVE-2021-44906"}
	if !slices.Equal(got, want) {
		t.Errorf("ExtractAdvisoryIDs = %v, want %v", got, want)
	}
}

func TestNormalizeAliasesDropsTheIDAndDuplicates(t *testing.T) {
	got := NormalizeAliases("CVE-2021-44906", "cve-2021-44906", "GHSA-XVCH-5GV4-984H", "ghsa-xvch-5gv4-984h", "")
	want := []string{"GHSA-xvch-5gv4-984h"}
	if !slices.Equal(got, want) {
		t.Errorf("NormalizeAliases = %v, want %v", got, want)
	}
}

func TestVulnerabilityIDsAreUpperCasedOnce(t *testing.T) {
	v := Vulnerability{ID: "ghsa-xvch-5gv4-984h", Aliases: []string{"CVE-2021-44906", "GHSA-XVCH-5GV4-984H"}}
	want := []string{"GHSA-XVCH-5GV4-984H", "CVE-2021-44906"}
	if got := v.IDs(); !slices.Equal(got, want) {
		t.Errorf("IDs = %v, want %v", got, want)
	}
}
