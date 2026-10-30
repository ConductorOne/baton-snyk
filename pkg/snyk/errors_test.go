package snyk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrorRespUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
		wantMsg string
	}{
		{
			name:    "bool true envelope",
			body:    `{"error":true,"message":"The org 1 is not entitled for api access. Please upgrade your plan."}`,
			wantErr: "",
			wantMsg: "The org 1 is not entitled for api access. Please upgrade your plan.",
		},
		{
			name:    "bool false",
			body:    `{"error":false,"message":"m"}`,
			wantErr: "",
			wantMsg: "m",
		},
		{
			name:    "string error (legacy)",
			body:    `{"error":"boom","message":"m"}`,
			wantErr: "boom",
			wantMsg: "m",
		},
		{
			name:    "null error",
			body:    `{"error":null,"message":"m"}`,
			wantErr: "",
			wantMsg: "m",
		},
		{
			name:    "absent error",
			body:    `{"message":"m"}`,
			wantErr: "",
			wantMsg: "m",
		},
		{
			name:    "empty object",
			body:    `{}`,
			wantErr: "",
			wantMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp ErrorResp
			if err := json.Unmarshal([]byte(tt.body), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Err != tt.wantErr {
				t.Fatalf("Err = %q, want %q", resp.Err, tt.wantErr)
			}
			if resp.Msg != tt.wantMsg {
				t.Fatalf("Msg = %q, want %q", resp.Msg, tt.wantMsg)
			}
		})
	}

	// Exotic types (D7) and malformed JSON still fail to parse.
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "number error (exotic)", body: `{"error":42,"message":"m"}`},
		{name: "malformed JSON", body: `{error`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var resp ErrorResp
			if err := json.Unmarshal([]byte(tc.body), &resp); err == nil {
				t.Fatalf("expected non-nil unmarshal error for %s", tc.body)
			}
		})
	}
}

// TestDoRestRequestEntitlementClassification pins the classification wiring at the
// second transport return (client.go doRestRequest) via a REST API path.
func TestDoRestRequestEntitlementClassification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/orgs/org-id/memberships" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":true,"message":"The org org-id is not entitled for api access. Please upgrade your plan."}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), "group-id", "token", BaseHost, server.URL)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = client.ListOrgMemberships(context.Background(), "org-id", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrNotEntitledForAPI) {
		t.Fatalf("expected ErrNotEntitledForAPI, got: %v", err)
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("status.Code = %v, want PermissionDenied", got)
	}
	msg := err.Error()
	if strings.Contains(msg, "failed to unmarshal JSON error response") || strings.Contains(msg, "cannot unmarshal bool") {
		t.Fatalf("unmarshal fragments must be gone, got: %v", msg)
	}
	if !strings.Contains(msg, "not entitled for API access") || !strings.Contains(msg, "Please upgrade your plan.") {
		t.Fatalf("error should carry the entitlement reason + upstream message, got: %v", msg)
	}
}

func TestErrorRespMessage(t *testing.T) {
	tests := []struct {
		name string
		resp ErrorResp
		want string
	}{
		{
			name: "msg only",
			resp: ErrorResp{Msg: "m"},
			want: "unexpected error from snyk api: m",
		},
		{
			name: "both set",
			resp: ErrorResp{Err: "boom", Msg: "m"},
			want: "unexpected error from snyk api: boom, m",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resp.Message(); got != tt.want {
				t.Fatalf("Message() = %q, want %q", got, tt.want)
			}
		})
	}
}

// recordingCore is a minimal zapcore.Core capturing log entries in memory
// (zaptest/observer is not vendored).
type recordingCore struct {
	entries []zapcore.Entry
	fields  []map[string]interface{}
}

func (c *recordingCore) Enabled(zapcore.Level) bool { return true }
func (c *recordingCore) With([]zapcore.Field) zapcore.Core {
	return c
}
func (c *recordingCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return ce.AddCore(ent, c)
}
func (c *recordingCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	m := make(map[string]interface{}, len(fields))
	for _, f := range fields {
		switch f.Type {
		case zapcore.Int64Type:
			m[f.Key] = f.Integer
		default:
			m[f.Key] = f.String
		}
	}
	c.entries = append(c.entries, ent)
	c.fields = append(c.fields, m)
	return nil
}
func (c *recordingCore) Sync() error { return nil }

func TestClassifyHTTPError(t *testing.T) {
	E := errors.New("sentinel")
	entitlementMsg := "The org 1 is not entitled for api access. Please upgrade your plan."
	tests := []struct {
		name       string
		resp       *http.Response
		errResp    *ErrorResp
		inputErr   error
		checkIsE   bool
		checkEnt   bool
		checkCode  bool
		checkCause bool
		wantCode   codes.Code
	}{
		{
			name:     "nil resp pass-through",
			resp:     nil,
			errResp:  &ErrorResp{Msg: "any"},
			inputErr: E,
			checkIsE: true,
		},
		{
			name:     "nil errResp pass-through",
			resp:     &http.Response{StatusCode: http.StatusForbidden},
			errResp:  nil,
			inputErr: E,
			checkIsE: true,
		},
		{
			name:       "entitlement 403",
			resp:       &http.Response{StatusCode: http.StatusForbidden},
			errResp:    &ErrorResp{Msg: entitlementMsg},
			inputErr:   E,
			checkEnt:   true,
			checkCode:  true,
			wantCode:   codes.PermissionDenied,
			checkCause: true,
		},
		{
			name:     "403 different message",
			resp:     &http.Response{StatusCode: http.StatusForbidden},
			errResp:  &ErrorResp{Msg: "forbidden resource"},
			inputErr: E,
			checkIsE: true,
		},
		{
			name:     "500",
			resp:     &http.Response{StatusCode: http.StatusInternalServerError},
			errResp:  &ErrorResp{Msg: "not entitled"},
			inputErr: E,
			checkIsE: true,
		},
		{
			name:     "200",
			resp:     &http.Response{StatusCode: http.StatusOK},
			errResp:  &ErrorResp{Msg: "not entitled"},
			inputErr: E,
			checkIsE: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{groupID: "group-1"}
			got := c.classifyHTTPError(context.Background(), tt.resp, tt.errResp, tt.inputErr)

			if tt.checkIsE && !errors.Is(got, E) {
				t.Fatalf("expected input error unchanged, got %#v", got)
			}
			if tt.checkEnt {
				if !errors.Is(got, ErrNotEntitledForAPI) {
					t.Fatalf("expected ErrNotEntitledForAPI, got %#v", got)
				}
				var ent *EntitlementError
				if !errors.As(got, &ent) || ent.UpstreamMessage != entitlementMsg {
					t.Fatalf("unexpected EntitlementError: %#v", got)
				}
				if tt.checkCause && !errors.Is(got, E) {
					t.Fatalf("original cause must stay reachable via Unwrap, got %#v", got)
				}
				if got := status.Code(got); got != codes.PermissionDenied {
					t.Fatalf("status.Code = %v, want PermissionDenied", got)
				}
				if tt.errResp.Msg != entitlementMsg {
					t.Fatalf("errResp.Msg mutated: %q", tt.errResp.Msg)
				}
			}
			if tt.checkCode {
				if got := status.Code(got); got != tt.wantCode {
					t.Fatalf("status.Code = %v, want %v", got, tt.wantCode)
				}
			}
		})
	}
}

func TestClassifyHTTPErrorWarnLog(t *testing.T) {
	core := &recordingCore{}
	l := zap.New(core)
	ctx := ctxzap.ToContext(context.Background(), l)

	c := &Client{groupID: "group-1"}
	resp := &http.Response{StatusCode: http.StatusForbidden}
	errResp := &ErrorResp{Msg: "The org 1 is not entitled for api access. Please upgrade your plan."}
	err := c.classifyHTTPError(ctx, resp, errResp, errors.New("orig"))

	if !errors.Is(err, ErrNotEntitledForAPI) {
		t.Fatalf("expected entitlement error, got %#v", err)
	}
	if len(core.entries) != 1 {
		t.Fatalf("expected exactly one log entry, got %d: %#v", len(core.entries), core.entries)
	}
	ent := core.entries[0]
	if ent.Level != zapcore.WarnLevel {
		t.Fatalf("log level = %v, want Warn", ent.Level)
	}
	if ent.Message != "snyk org not entitled for api access" {
		t.Fatalf("log message = %q", ent.Message)
	}
	fields := core.fields[0]
	if fields["status_code"] != int64(403) {
		t.Fatalf("status_code field = %#v", fields["status_code"])
	}
	if fields["group_id"] != "group-1" {
		t.Fatalf("group_id field = %#v", fields["group_id"])
	}
	// I6: no token, no body dump — exactly the two sanctioned fields.
	if len(fields) != 2 {
		t.Fatalf("expected exactly 2 log fields, got %d: %#v", len(fields), fields)
	}
	for _, forbidden := range []string{"token", "authorization", "body", "message"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("log must not contain %q field", forbidden)
		}
	}
	for _, e := range core.entries {
		if e.Level >= zapcore.ErrorLevel {
			t.Fatalf("unexpected error-level log entry: %#v", e)
		}
	}
}

func TestDoRequestEntitlementClassification(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		checkEnt    bool
		checkCode   bool
		wantCode    codes.Code
		notContains []string
		contains    []string
	}{
		{
			name:      "entitlement 403 e2e",
			status:    http.StatusForbidden,
			body:      `{"error":true,"message":"The org group-id is not entitled for api access. Please upgrade your plan."}`,
			checkEnt:  true,
			checkCode: true,
			wantCode:  codes.PermissionDenied,
			notContains: []string{
				"failed to unmarshal JSON error response",
				"cannot unmarshal bool",
			},
			contains: []string{"not entitled for API access", "Please upgrade your plan."},
		},
		{
			name:      "401 invalid credentials",
			status:    http.StatusUnauthorized,
			body:      `{"error":true,"message":"Invalid API token."}`,
			checkCode: true,
			wantCode:  codes.Unauthenticated,
			notContains: []string{
				"not entitled for API access",
			},
		},
		{
			name:     "403 other condition",
			status:   http.StatusForbidden,
			body:     `{"error":true,"message":"Access forbidden for this resource."}`,
			contains: []string{"unexpected error from snyk api"},
		},
		{
			name:      "500 server error",
			status:    http.StatusInternalServerError,
			body:      `{"error":true,"message":"internal"}`,
			checkCode: true,
			wantCode:  codes.Unavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/group/group-id/orgs" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client, err := NewClient(context.Background(), "group-id", "token", BaseHost, server.URL)
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = client.ListOrgs(context.Background(), NewPaginationVars("", 50))
			if err == nil {
				t.Fatal("expected an error")
			}

			if tt.checkEnt {
				if !errors.Is(err, ErrNotEntitledForAPI) {
					t.Fatalf("expected ErrNotEntitledForAPI, got: %v", err)
				}
			} else if errors.Is(err, ErrNotEntitledForAPI) {
				t.Fatalf("did not expect ErrNotEntitledForAPI, got: %v", err)
			}

			if tt.checkCode {
				if got := status.Code(err); got != tt.wantCode {
					t.Fatalf("status.Code = %v, want %v", got, tt.wantCode)
				}
			}

			msg := err.Error()
			for _, s := range tt.notContains {
				if strings.Contains(msg, s) {
					t.Fatalf("error should not contain %q, got: %v", s, msg)
				}
			}
			for _, s := range tt.contains {
				if !strings.Contains(msg, s) {
					t.Fatalf("error should contain %q, got: %v", s, msg)
				}
			}
		})
	}
}
