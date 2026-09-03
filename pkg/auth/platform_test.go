package auth

import "testing"

func TestPlatformParams(t *testing.T) {
	tests := []struct {
		goos         string
		cfgPlatform  int
		platform     string
		versionName  string
		versionCode  string
	}{
		{"darwin", 0, "4", "4.38.0", "616"},
		{"windows", 0, "1", "4.38.3", "9325"},
		{"darwin", 1, "1", "4.38.3", "9325"},
		{"darwin", 4, "4", "4.38.0", "616"},
	}

	for _, test := range tests {
		platform, versionName, versionCode := platformParams(test.goos, test.cfgPlatform)
		if platform != test.platform || versionName != test.versionName || versionCode != test.versionCode {
			t.Fatalf("platformParams(%q, %d) = (%q, %q, %q), want (%q, %q, %q)",
				test.goos, test.cfgPlatform, platform, versionName, versionCode,
				test.platform, test.versionName, test.versionCode)
		}
	}
}
