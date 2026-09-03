package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateSharePassCode(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		code, err := GenerateSharePassCode()
		if err != nil {
			t.Fatalf("GenerateSharePassCode: %v", err)
		}
		if len(code) != 8 {
			t.Fatalf("code length = %d, want 8", len(code))
		}
		for _, r := range code {
			if !strings.ContainsRune(sharePassCodeAlphabet, r) {
				t.Fatalf("code %q contains rune %q outside alphabet", code, r)
			}
		}
		seen[code] = struct{}{}
	}
	if len(seen) < 90 {
		t.Fatalf("generated only %d distinct codes from 100 attempts", len(seen))
	}
}

func TestSharePassCodeSign(t *testing.T) {
	const passCode = "ABCDEFGH"
	const want = "9ac2197d9258257b1ae8463e4214e4cd0a578bc1517f2415928b91be4283fc48"
	if got := SharePassCodeSign(passCode); got != want {
		t.Fatalf("SharePassCodeSign() = %q, want %q", got, want)
	}
	const (
		salt     = "mysalt"
		wantSalt = "e7f622ee88c6023a41ed99de879bf7a640450cbffc23d9b294651f321414f430"
	)
	if got := SharePassCodeSignWithSalt(salt, passCode); got != wantSalt {
		t.Fatalf("SharePassCodeSignWithSalt() = %q, want %q", got, wantSalt)
	}
}

func TestGuestShareConfirmationRequestBody(t *testing.T) {
	body, err := json.Marshal(GuestShareConfirmationRequest{
		ControlID:    "0123456789abcdef0123456789abcdef",
		AllowControl: true,
		NeedPassword: false,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	const want = `{"control_id":"0123456789abcdef0123456789abcdef","allow_control":true,"need_password":false}`
	if string(body) != want {
		t.Fatalf("request body = %s, want %s", body, want)
	}
}

func TestGuestShareUploadControlModeRequestBody(t *testing.T) {
	body, err := json.Marshal(GuestShareUploadControlModeRequest{
		ControlID:    "0123456789abcdef0123456789abcdef",
		AllowControl: true,
		ControlMode:  "by_confirmation",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	const want = `{"control_id":"0123456789abcdef0123456789abcdef","allow_control":true,"control_mode":"by_confirmation"}`
	if string(body) != want {
		t.Fatalf("request body = %s, want %s", body, want)
	}
}

func TestGuestShareUploadSignRequestBody(t *testing.T) {
	body, err := json.Marshal(GuestShareUploadSignRequest{
		CanControl:       true,
		ControlID:        "0123456789abcdef0123456789abcdef",
		Sign:             "0123456789abcdef0123456789abcdef",
		BackupSign:       "",
		ControlMode:      "by_confirmation",
		NeedConfirmation: true,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	const want = `{"can_remote_control":true,"control_id":"0123456789abcdef0123456789abcdef","sign":"0123456789abcdef0123456789abcdef","backup_sign":"","control_mode":"by_confirmation","need_confirmation":true}`
	if string(body) != want {
		t.Fatalf("request body = %s, want %s", body, want)
	}
}

func TestParseShareAuthMode(t *testing.T) {
	for value, want := range map[string]ShareAuthMode{
		"temporary": ShareAuthTemporary,
		"custom":    ShareAuthCustom,
		"both":      ShareAuthBoth,
	} {
		got, err := ParseShareAuthMode(value)
		if err != nil {
			t.Fatalf("ParseShareAuthMode(%q): %v", value, err)
		}
		if got != want {
			t.Fatalf("ParseShareAuthMode(%q) = %q, want %q", value, got, want)
		}
	}
	if _, err := ParseShareAuthMode("by_password"); err == nil {
		t.Fatal("ParseShareAuthMode accepted an official control-mode value as a CLI mode")
	}
}

func TestShareAuthModeOfficialControlMode(t *testing.T) {
	tests := []struct {
		mode ShareAuthMode
		want string
	}{
		{ShareAuthTemporary, "by_password"},
		{ShareAuthCustom, "by_confirmation"},
		{ShareAuthBoth, "password_confirmation"},
	}
	for _, test := range tests {
		if got := test.mode.OfficialControlMode(); got != test.want {
			t.Fatalf("mode %q OfficialControlMode() = %q, want %q", test.mode, got, test.want)
		}
	}
}

func TestShareJoinCode(t *testing.T) {
	const (
		temporary = "ABCDEFGH"
		custom    = "JKLMNPQR"
	)
	tests := []struct {
		mode ShareAuthMode
		want string
	}{
		{ShareAuthTemporary, temporary},
		{ShareAuthCustom, custom},
		{ShareAuthBoth, temporary + custom},
	}
	for _, test := range tests {
		if got := ShareJoinCode(temporary, custom, test.mode); got != test.want {
			t.Fatalf("ShareJoinCode(mode=%q) = %q, want %q", test.mode, got, test.want)
		}
	}
}

func TestNewGuestShareUploadSignRequestModes(t *testing.T) {
	const (
		controlID  = "12345678"
		temporary  = "ABCDEFGH"
		custom     = "JKLMNPQR"
		tempSign   = "9ac2197d9258257b1ae8463e4214e4cd0a578bc1517f2415928b91be4283fc48"
		customSign = "e7ccbaa3a408d10bb093b9bb3e08f568de1947e13ffe894e6ea207bafb5f5cff"
	)
	tests := []struct {
		mode ShareAuthMode
		want string
	}{
		{
			ShareAuthTemporary,
			`{"can_remote_control":true,"control_id":"12345678","sign":"` + tempSign + `","backup_sign":"","control_mode":"by_password","need_confirmation":false}`,
		},
		{
			ShareAuthCustom,
			`{"can_remote_control":true,"control_id":"12345678","sign":"","backup_sign":"` + customSign + `","control_mode":"by_confirmation","need_confirmation":true}`,
		},
		{
			ShareAuthBoth,
			`{"can_remote_control":true,"control_id":"12345678","sign":"` + tempSign + `","backup_sign":"` + customSign + `","control_mode":"password_confirmation","need_confirmation":true}`,
		},
	}
	for _, test := range tests {
		body, err := json.Marshal(NewGuestShareUploadSignRequest(controlID, temporary, custom, test.mode))
		if err != nil {
			t.Fatalf("marshal %q request: %v", test.mode, err)
		}
		if string(body) != test.want {
			t.Fatalf("mode %q request body = %s, want %s", test.mode, body, test.want)
		}
	}
}

func TestNewGuestShareUploadControlModeRequest(t *testing.T) {
	body, err := json.Marshal(NewGuestShareUploadControlModeRequest("12345678", true, ShareAuthTemporary))
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	const want = `{"control_id":"12345678","allow_control":true,"control_mode":"by_password"}`
	if string(body) != want {
		t.Fatalf("request body = %s, want %s", body, want)
	}
}

func TestJoinRoomByShareCodeRequestBody(t *testing.T) {
	body, err := json.Marshal(&JoinRoomByShareCodeRequest{
		ConnectID:   "949918424",
		ConnectCode: "ABCDEFGH",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	const want = `{"connect_id":"949918424","connect_code":"ABCDEFGH"}`
	if string(body) != want {
		t.Fatalf("request body = %s, want %s", body, want)
	}
}

func TestGenerateAndValidateCustomShareCode(t *testing.T) {
	for i := 0; i < 20; i++ {
		code, err := GenerateCustomShareCode()
		if err != nil {
			t.Fatalf("GenerateCustomShareCode: %v", err)
		}
		if err := ValidateCustomShareCode(code); err != nil {
			t.Fatalf("ValidateCustomShareCode(%q): %v", code, err)
		}
	}
	for _, code := range []string{"ABCDEFGH", "12345678", "ABC123", "ABC12345678901234", "ABC 1234"} {
		if err := ValidateCustomShareCode(code); err == nil {
			t.Fatalf("ValidateCustomShareCode(%q) accepted invalid code", code)
		}
	}
}
