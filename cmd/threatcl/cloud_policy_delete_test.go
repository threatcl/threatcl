package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudPolicyDeleteRunWithForce(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	httpClient.transport.setResponse("DELETE", "/api/v1/org/org123/policies/pol-1", http.StatusNoContent, "")

	cmd := testCloudPolicyDeleteCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-force"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully deleted policy") {
		t.Errorf("expected success message in output, got %q", out)
	}
}

func TestCloudPolicyDeleteRunMissingPolicyId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyDeleteCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-force"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-policy-id is required") {
		t.Errorf("expected error about -policy-id being required, got %q", out)
	}
}

func TestCloudPolicyDeleteRunNoTokenForOrg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	cmd := testCloudPolicyDeleteCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-policy-id", "pol-1", "-org-id", "different-org", "-force"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no token found for organization") {
		t.Errorf("expected error message about no token for org, got %q", out)
	}
}

func TestCloudPolicyDeleteRunAPIErrors(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		httpErr      error
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "unauthorized",
			statusCode:   http.StatusUnauthorized,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "not found",
			statusCode:   http.StatusNotFound,
			expectedCode: 1,
			expectedOut:  "Error deleting policy",
		},
		{
			name:         "server error",
			statusCode:   http.StatusInternalServerError,
			expectedCode: 1,
			expectedOut:  "Error deleting policy",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error deleting policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			if tt.httpErr != nil {
				httpClient.transport.setError("DELETE", "/api/v1/org/org123/policies/pol-1", tt.httpErr)
			} else {
				httpClient.transport.setResponse("DELETE", "/api/v1/org/org123/policies/pol-1", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudPolicyDeleteCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-force"})
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

func TestCloudPolicyDeletePolicy(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	httpClient.transport.setResponse("DELETE", "/api/v1/org/org123/policies/pol-1", http.StatusNoContent, "")

	err := deletePolicy("token", "org123", "pol-1", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
