package logging

import "testing"

func TestParseLevelAndDefaultFiltering(t *testing.T) {
	if CurrentLevel() != LevelInfo {
		t.Fatalf("default level = %v, want info", CurrentLevel())
	}
	if enabled(LevelDebug) {
		t.Fatal("debug should be disabled at the default info level")
	}
	if !enabled(LevelInfo) || !enabled(LevelError) {
		t.Fatal("info and error should be enabled at the default info level")
	}

	for _, tc := range []struct {
		value string
		want  Level
	}{
		{value: "debug", want: LevelDebug},
		{value: "info", want: LevelInfo},
		{value: "warn", want: LevelWarn},
		{value: "error", want: LevelError},
	} {
		got, err := ParseLevel(tc.value)
		if err != nil {
			t.Fatalf("ParseLevel(%q): %v", tc.value, err)
		}
		if got != tc.want {
			t.Fatalf("ParseLevel(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}

	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("ParseLevel accepted an invalid level")
	}
}
