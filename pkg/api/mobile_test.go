package api

import (
	"encoding/json"
	"testing"
)

func TestMobileCodeRequestBody(t *testing.T) {
	body := map[string]any{
		"country_code": "+86",
		"mobile":       "19300000000",
		"type":         "login",
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	const want = `{"country_code":"+86","mobile":"19300000000","type":"login"}`
	if string(data) != want {
		t.Fatalf("got %s, want %s", string(data), want)
	}
}

func TestLoginByMobileRequestBody(t *testing.T) {
	body := map[string]any{
		"country_code": "+86",
		"mobile":       "19300000000",
		"code":         "123456",
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	const want = `{"code":"123456","country_code":"+86","mobile":"19300000000"}`
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["code"] != "123456" || decoded["country_code"] != "+86" || decoded["mobile"] != "19300000000" {
		t.Fatalf("unexpected fields: %v", decoded)
	}
}
