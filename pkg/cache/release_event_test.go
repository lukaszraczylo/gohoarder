package cache

import "testing"

func TestWithReleaseVersion(t *testing.T) {
	with := withReleaseVersion(map[string]interface{}{"version": "six-1.17.0.tar.gz"}, "1.17.0")
	if with["release_version"] != "1.17.0" || with["version"] != "six-1.17.0.tar.gz" {
		t.Errorf("payload = %v", with)
	}
	if _, ok := withReleaseVersion(map[string]interface{}{"version": "1.3.0"}, "")["release_version"]; ok {
		t.Error("empty release version must not be sent")
	}
}
