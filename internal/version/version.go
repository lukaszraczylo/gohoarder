package version

import "runtime"

var (
	// Version is the semantic version (set by linker flags)
	Version = "dev"
	// GitCommit is the git commit hash (set by linker flags)
	GitCommit = "unknown"
	// BuildTime is the build timestamp (set by linker flags)
	BuildTime = "unknown"
	// GoVersion is the Go version used to build
	GoVersion = runtime.Version()
)

// Info contains version information
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the version information
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildTime: BuildTime,
		GoVersion: GoVersion,
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}
