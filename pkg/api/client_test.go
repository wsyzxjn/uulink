package api

import (
	"testing"

	"github.com/user/uulink/pkg/auth"
)

func TestNewClientUsesCookieJar(t *testing.T) {
	client := NewClient(&auth.Config{})
	if client.http.Jar == nil {
		t.Fatal("NewClient() HTTP client has no cookie jar")
	}
}
