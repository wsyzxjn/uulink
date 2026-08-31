package api

import (
	"encoding/base64"
	"testing"
)

func TestJWTSubject(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user","device_id":"device"}`))
	token := "header." + payload + ".signature"

	subject, err := JWTSubject(token)
	if err != nil {
		t.Fatalf("JWTSubject: %v", err)
	}
	if subject != "user" {
		t.Fatalf("subject = %q, want user", subject)
	}
}

func TestJWTSubjectRejectsMalformedToken(t *testing.T) {
	if _, err := JWTSubject("not-a-jwt"); err == nil {
		t.Fatal("JWTSubject accepted a malformed token")
	}
}
