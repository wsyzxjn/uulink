package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

func TestDoContextRejectsOversizedResponse(t *testing.T) {
	client := NewClientWithOptions(&auth.Config{}, ClientOptions{
		BaseURL: "https://api.example",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := `{"code":0,"data":{"padding":"` + strings.Repeat("x", maxAPIResponseBytes) + `"}}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		})},
	})

	_, err := client.DoContext(context.Background(), http.MethodGet, "/oversized", nil)
	if err == nil || !strings.Contains(err.Error(), "response body exceeds") {
		t.Fatalf("DoContext() error = %v, want oversized response error", err)
	}
}

func TestJoinRoomByShareCodeContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := NewClientWithOptions(&auth.Config{}, ClientOptions{
		BaseURL: "https://api.example",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})},
	})

	_, err := client.JoinRoomByShareCodeContext(ctx, "connect", "code")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("JoinRoomByShareCodeContext() error = %v, want context.Canceled", err)
	}
}
