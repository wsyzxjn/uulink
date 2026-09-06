package auth

import (
	"testing"
)

func TestSign(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		url     string
		headers map[string]string
		body    string
		want    string
	}{
		{
			name:   "GET /message/summary",
			method: "GET",
			url:    "https://api.nrd.nie.163.com/api/v1/message/summary",
			headers: map[string]string{
				"X-Param-CHN":       "gwqd",
				"X-Param-client-id": "283D0DE4-6D90-5DBE-8C6C-5A782CDB9379",
				"X-Param-CNT":       "CN",
				"X-Param-device-id": "aeawqa5txeafoxl4",
				"X-Param-LANG":      "zh-CN",
				"X-Param-OPR":       "None",
				"X-Param-PKGN":      "com.netease.uuremote",
				"X-Param-PLAT":      "4",
				"X-Param-REL":       "prod",
				"X-Param-TS":        "1787999435",
				"X-Param-user-id":   "aebgn7l5nqaar6u7",
				"X-Param-VC":        "616",
				"X-Param-VN":        "4.38.0",
			},
			body: "",
			want: "ae450fed11a5421b01ac8732ecc5cee483c76e5a129aaeb7ae648b3967b2d30a",
		},
		{
			name:   "POST /room/join with body",
			method: "POST",
			url:    "https://api.nrd.nie.163.com/api/v1/room/join/by_device/aeawn7l56uabjgfc",
			headers: map[string]string{
				"X-Param-CHN":       "gwqd",
				"X-Param-client-id": "283D0DE4-6D90-5DBE-8C6C-5A782CDB9379",
				"X-Param-CNT":       "CN",
				"X-Param-device-id": "aeawqa5txeafoxl4",
				"X-Param-LANG":      "zh-CN",
				"X-Param-OPR":       "None",
				"X-Param-PKGN":      "com.netease.uuremote",
				"X-Param-PLAT":      "4",
				"X-Param-REL":       "prod",
				"X-Param-TS":        "1787999435",
				"X-Param-user-id":   "aebgn7l5nqaar6u7",
				"X-Param-VC":        "616",
				"X-Param-VN":        "4.38.0",
			},
			body: `{"force_join":false}`,
			want: "abd3eb55dbd45ddc20d3a74a0c3de40f2d3d3389eb012ae9faceacb5a6af7c90",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sign(tt.method, tt.url, tt.headers, tt.body)
			if got != tt.want {
				t.Errorf("Sign() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildHeadersOmitsEmptyAuthorization(t *testing.T) {
	headers := BuildHeaders(&Config{
		ClientID: "client",
		DeviceID: "device",
	}, "123")

	if _, ok := headers["Authorization"]; ok {
		t.Fatal("BuildHeaders() emitted Authorization for an empty JWT")
	}
	if headers["X-Param-client-id"] != "client" || headers["X-Param-device-id"] != "device" {
		t.Fatalf("BuildHeaders() dropped guest request identifiers: %#v", headers)
	}
}

func TestBuildHeadersVersionOverrides(t *testing.T) {
	cfg := &Config{
		ClientID:    "client",
		DeviceID:    "device",
		VersionName: "4.39.0",
		VersionCode: "9999",
	}
	headers := BuildHeaders(cfg, "123")
	if headers["X-Param-VN"] != "4.39.0" {
		t.Fatalf("expected X-Param-VN to be 4.39.0, got %q", headers["X-Param-VN"])
	}
	if headers["X-Param-VC"] != "9999" {
		t.Fatalf("expected X-Param-VC to be 9999, got %q", headers["X-Param-VC"])
	}

	t.Setenv("UULINK_CLIENT_VN", "4.40.0")
	t.Setenv("UULINK_CLIENT_VC", "10000")
	headersEnv := BuildHeaders(cfg, "123")
	if headersEnv["X-Param-VN"] != "4.40.0" {
		t.Fatalf("expected env override X-Param-VN to be 4.40.0, got %q", headersEnv["X-Param-VN"])
	}
	if headersEnv["X-Param-VC"] != "10000" {
		t.Fatalf("expected env override X-Param-VC to be 10000, got %q", headersEnv["X-Param-VC"])
	}
}
