package auth

import "testing"

func TestPlatformParams(t *testing.T) {
	tests := []struct {
		goos         string
		platform     string
		versionName  string
		versionCode  string
	}{
		{"darwin", "4", "4.38.0", "616"},
		{"windows", "1", "4.38.3", "9325"},
	}

	for _, test := range tests {
		platform, versionName, versionCode := platformParams(test.goos)
		if platform != test.platform || versionName != test.versionName || versionCode != test.versionCode {
			t.Fatalf("platformParams(%q) = (%q, %q, %q), want (%q, %q, %q)",
				test.goos, platform, versionName, versionCode,
				test.platform, test.versionName, test.versionCode)
		}
	}
}
