package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestNewClientUsesCookieJar(t *testing.T) {
	client := NewClient(&auth.Config{})
	if client.http.Jar == nil {
		t.Fatal("NewClient() HTTP client has no cookie jar")
	}
}

func TestDoContextReturnsResponseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":403,"msg":"denied","data":{}}`))
	}))
	defer server.Close()

	client := NewClientWithOptions(&auth.Config{}, ClientOptions{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	_, err := client.DoContext(context.Background(), http.MethodGet, "/test", nil)
	var responseErr *ResponseError
	if !errors.As(err, &responseErr) {
		t.Fatalf("DoContext() error = %v, want ResponseError", err)
	}
	if responseErr.Code != 403 || responseErr.Message != "denied" {
		t.Fatalf("ResponseError = %+v", responseErr)
	}
}

func TestDoContextReturnsResponseErrorForHTTP400Envelope(t *testing.T) {
	// The production API answers business failures such as an expired token
	// with HTTP 400 and a normal {code,msg} envelope.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":1120,"msg":"token expired","data":{}}`))
	}))
	defer server.Close()

	client := NewClientWithOptions(&auth.Config{}, ClientOptions{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	_, err := client.DoContext(context.Background(), http.MethodGet, "/test", nil)
	var responseErr *ResponseError
	if !errors.As(err, &responseErr) {
		t.Fatalf("DoContext() error = %v, want ResponseError", err)
	}
	if responseErr.Code != 1120 || responseErr.Message != "token expired" {
		t.Fatalf("ResponseError = %+v", responseErr)
	}
}

func TestDoContextReportsHTTPStatusWithoutEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	client := NewClientWithOptions(&auth.Config{}, ClientOptions{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	_, err := client.DoContext(context.Background(), http.MethodGet, "/test", nil)
	if err == nil || !strings.Contains(err.Error(), "unexpected HTTP status 502") {
		t.Fatalf("DoContext() error = %v, want HTTP status error", err)
	}
}

func TestDoContextCancellation(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	client := NewClientWithOptions(&auth.Config{}, ClientOptions{
		BaseURL:    "https://example.invalid",
		HTTPClient: &http.Client{Transport: transport},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.DoContext(ctx, http.MethodGet, "/test", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DoContext() error = %v, want context.Canceled", err)
	}
}

func TestReportRequestUsesConfiguredHTTPClient(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://relay.example/api/v1/ip" {
			t.Fatalf("report URL = %q", request.URL.String())
		}
		if request.Header.Get("x-report-token") != "report-token" {
			t.Fatalf("report token header = %q", request.Header.Get("x-report-token"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"code":0,"data":{}}`)),
			Header:     make(http.Header),
		}, nil
	})
	client := NewClientWithOptions(&auth.Config{}, ClientOptions{
		BaseURL:    "https://api.example",
		HTTPClient: &http.Client{Transport: transport},
	})

	room := &RoomConnectionInfo{ReportURL: "https://relay.example", ReportToken: "report-token"}
	if _, err := client.ReportIP(room); err != nil {
		t.Fatalf("ReportIP(): %v", err)
	}
}

func TestTypedUserAndDeviceResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/user/info":
			_, _ = w.Write([]byte(`{"code":0,"data":{"user_id":"u1","nickname":"tester"}}`))
		case "/api/v1/device/list":
			_, _ = w.Write([]byte(`{"code":0,"data":{"current_device":{"device_id":"d1","alias":"Mac","status":"online","platform":4,"client_id":"c1","version_name":"4.38.0"},"my_binded_devices":[],"others_shared_devices":[]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClientWithOptions(&auth.Config{}, ClientOptions{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	user, err := client.GetUserInfo()
	if err != nil {
		t.Fatalf("GetUserInfo(): %v", err)
	}
	if user.UserID != "u1" || user.Nickname != "tester" {
		t.Fatalf("user = %+v", user)
	}
	devices, err := client.GetDeviceList()
	if err != nil {
		t.Fatalf("GetDeviceList(): %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "d1" || devices[0].Platform != 4 {
		t.Fatalf("devices = %+v", devices)
	}
}
