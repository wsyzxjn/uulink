package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestFindCommand(t *testing.T) {
	cmd, path, err := findCommand(commands(), []string{"share", "join", "-id", "1"})
	if err != nil || cmd.name != "join" || strings.Join(path, " ") != "share join" {
		t.Fatalf("share join: cmd=%v path=%v err=%v", cmd, path, err)
	}
	cmd, path, err = findCommand(commands(), []string{"share"})
	if err != nil || cmd.name != "share" || cmd.run != nil || len(path) != 1 {
		t.Fatalf("share group: cmd=%v path=%v err=%v", cmd, path, err)
	}
	if _, _, err := findCommand(commands(), []string{"share", "bogus"}); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
	if _, _, err := findCommand(commands(), []string{"bogus"}); err == nil {
		t.Fatal("unknown command accepted")
	}
	cmd, path, err = findCommand(commands(), []string{"serve", "-mapping", "80:80"})
	if err != nil || cmd.name != "serve" || len(path) != 1 {
		t.Fatalf("serve with flags: cmd=%v path=%v err=%v", cmd, path, err)
	}
}

func TestRunUsageAndVersion(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"help"}, &stdout); err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, want := range []string{"Commands:", "login", "serve", "connect", "share", "Global flags"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("root help lacks %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "debug") && strings.Contains(stdout.String(), "guest-test") {
		t.Fatal("hidden debug group is listed in root help")
	}

	stdout.Reset()
	if err := run([]string{"help", "share", "join"}, &stdout); err != nil {
		t.Fatalf("help share join: %v", err)
	}
	if !strings.Contains(stdout.String(), "-id") || strings.Contains(stdout.String(), "room-file") {
		t.Fatalf("share join help should list -id and hide debug flags:\n%s", stdout.String())
	}
	stdout.Reset()
	if err := run([]string{"share", "join", "-help-debug"}, &stdout); err != nil {
		t.Fatalf("share join -help-debug: %v", err)
	}
	if !strings.Contains(stdout.String(), "Debugging flags") || !strings.Contains(stdout.String(), "room-file") {
		t.Fatalf("-help-debug should list debug flags:\n%s", stdout.String())
	}

	stdout.Reset()
	if err := run([]string{"version"}, &stdout); err != nil {
		t.Fatalf("version: %v", err)
	}
	if err := run([]string{"-v"}, &stdout); err != nil {
		t.Fatalf("-v: %v", err)
	}

	var usage *usageError
	if err := run([]string{"bogus"}, &stdout); !errors.As(err, &usage) {
		t.Fatalf("unknown command: err=%v, want usage error", err)
	}
	if err := run([]string{"serve", "extra"}, &stdout); !errors.As(err, &usage) {
		t.Fatalf("stray argument: err=%v, want usage error", err)
	}
	if err := run([]string{"serve", "-transport", "relay"}, &stdout); !errors.As(err, &usage) {
		t.Fatalf("serve -transport: err=%v, want usage error", err)
	}
	if err := run([]string{}, &stdout); !errors.As(err, &usage) {
		t.Fatalf("no command: err=%v, want usage error", err)
	}
	if err := run([]string{"share"}, &stdout); !errors.As(err, &usage) {
		t.Fatalf("bare group: err=%v, want usage error", err)
	}
	// The pre-subcommand flag syntax is gone; it is a plain usage error.
	if err := run([]string{"-serve", "-mapping", "80:80"}, &stdout); !errors.As(err, &usage) || !strings.Contains(err.Error(), "uulink help") {
		t.Fatalf("flag-only syntax: err=%v, want usage error pointing at help", err)
	}
}

// A usage error surfaces before any network call, so a bad mapping on a
// missing config is still reported as usage.
func TestRunReportsMappingErrorsAsUsage(t *testing.T) {
	var stdout bytes.Buffer
	cfg := t.TempDir() + "/config.json"
	err := run([]string{"share", "join", "-config", cfg, "-id", "1", "-code", "ABCDEFGH", "-mapping", "abc"}, &stdout)
	var usage *usageError
	if !errors.As(err, &usage) || !strings.Contains(err.Error(), "invalid mapping spec") {
		t.Fatalf("err = %v, want usage error about the mapping", err)
	}
	err = run([]string{"connect", "-config", cfg, "-local", "8080"}, &stdout)
	if !errors.As(err, &usage) {
		t.Fatalf("connect on a missing config = %v, want usage/config error", err)
	}
}
