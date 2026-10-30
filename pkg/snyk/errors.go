package snyk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrNotEntitledForAPI marks the Snyk 403 "org is not entitled for api access" condition.
var ErrNotEntitledForAPI = errors.New("snyk org is not entitled for API access; upgrade your Snyk plan")

// EntitlementError surfaces a Snyk 403 whose body says the org lacks API entitlement.
// It keeps the credentials-valid framing: the token works, the plan does not cover the API.
type EntitlementError struct {
	StatusCode      int
	UpstreamMessage string
}

func (e *EntitlementError) Error() string {
	return fmt.Sprintf("%s (HTTP status %d). Upstream message: %s",
		ErrNotEntitledForAPI.Error(), e.StatusCode, e.UpstreamMessage)
}

// GRPCStatus maps the entitlement 403 to PermissionDenied, matching the vendored
// uhttp mapping GrpcCodeFromHTTPStatus(403) (GO-P-041).
func (e *EntitlementError) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, e.Error())
}

// Is makes errors.Is(err, ErrNotEntitledForAPI) work for any *EntitlementError.
func (e *EntitlementError) Is(target error) bool {
	return target == ErrNotEntitledForAPI
}

// classifyHTTPError reclassifies the transport-level error built by the vendored uhttp
// wrapper. It fires ONLY on HTTP 403 whose parsed error body says the org is not
// entitled for API access; every other input passes through unchanged.
func (c *Client) classifyHTTPError(ctx context.Context, resp *http.Response, errResp *ErrorResp, err error) error {
	if resp == nil || resp.StatusCode != http.StatusForbidden || errResp == nil ||
		!strings.Contains(strings.ToLower(errResp.Msg), "not entitled") {
		return err
	}

	logger := ctxzap.Extract(ctx)
	logger.Warn("snyk org not entitled for api access",
		zap.Int("status_code", resp.StatusCode),
		zap.String("group_id", c.groupID),
	)

	return &EntitlementError{
		StatusCode:      resp.StatusCode,
		UpstreamMessage: errResp.Msg,
	}
}