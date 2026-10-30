package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateEntitlementError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/group/group-id/orgs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":true,"message":"The org group-id is not entitled for api access. Please upgrade your plan."}`))
	}))
	defer server.Close()

	ctx := context.Background()
	s, err := New(ctx, "group-id", "token", []string{}, "", server.URL)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.Validate(ctx)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()

	for _, want := range []string{
		"snyk-connector: failed to validate credentials for group",
		"not entitled for API access",
		"Please upgrade your plan.",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error should contain %q, got: %v", want, msg)
		}
	}
	for _, unwanted := range []string{
		"failed to unmarshal JSON error response",
		"cannot unmarshal bool",
	} {
		if strings.Contains(msg, unwanted) {
			t.Fatalf("error should not contain %q, got: %v", unwanted, msg)
		}
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("status.Code = %v, want PermissionDenied", got)
	}
}
