package main

import (
	"strings"
	"testing"
)

func TestFormatVersion(t *testing.T) {
	origVersion, origCommit, origDate := Version, GitCommit, BuildDate
	defer func() {
		Version, GitCommit, BuildDate = origVersion, origCommit, origDate
	}()

	Version = "v0.1.7"
	GitCommit = "1234567890abcdef"
	BuildDate = "2026-09-06T08:00:00Z"

	full := formatVersion()
	if !strings.Contains(full, "uulink v0.1.7") {
		t.Errorf("formatVersion() = %q, expected to contain 'uulink v0.1.7'", full)
	}
	if !strings.Contains(full, "(commit: 1234567)") {
		t.Errorf("formatVersion() = %q, expected short commit 1234567", full)
	}
	if !strings.Contains(full, "built 2026-09-06T08:00:00Z") {
		t.Errorf("formatVersion() = %q, expected build date", full)
	}

	short := formatVersionShort()
	if short != "v0.1.7" {
		t.Errorf("formatVersionShort() = %q, want 'v0.1.7'", short)
	}
}
