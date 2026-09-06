package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

var (
	// Version can be set at compile time via -ldflags "-X main.Version=v0.1.7".
	Version = "dev"
	// GitCommit can be set at compile time via -ldflags "-X main.GitCommit=abc1234".
	GitCommit = ""
	// BuildDate can be set at compile time via -ldflags "-X main.BuildDate=2026-09-06T08:00:00Z".
	BuildDate = ""
)

func init() {
	if Version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				Version = bi.Main.Version
			}
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if GitCommit == "" {
						GitCommit = s.Value
					}
				case "vcs.time":
					if BuildDate == "" {
						BuildDate = s.Value
					}
				case "vcs.modified":
					if s.Value == "true" && GitCommit != "" && !strings.HasSuffix(GitCommit, "-dirty") {
						GitCommit += "-dirty"
					}
				}
			}
		}
	}
}

// formatVersion returns the full version string including commit, build time, and architecture.
func formatVersion() string {
	commit := GitCommit
	if len(commit) > 7 {
		commit = commit[:7]
	}
	parts := []string{fmt.Sprintf("uulink %s", Version)}
	if commit != "" {
		parts = append(parts, fmt.Sprintf("(commit: %s)", commit))
	}
	if BuildDate != "" {
		parts = append(parts, fmt.Sprintf("built %s", BuildDate))
	}
	parts = append(parts, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
	return strings.Join(parts, " ")
}

// formatVersionShort returns just the version tag.
func formatVersionShort() string {
	return Version
}
