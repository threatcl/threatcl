package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudPoliciesRunWithOrgId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	policies := []policy{
		{
			ID:       "pol-1",
			Name:     "Controls Required",
			Slug:     "controls-required",
			Severity: "error",
			Enabled:  true,
			Enforced: true,
		},
		{
			ID:       "pol-2",
			Name:     "Description Required",
			Slug:     "description-required",
			Severity: "warning",
			Enabled:  false,
			Enforced: false,
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies", http.StatusOK, jsonResponse(policies))

	cmd := testCloudPoliciesCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}

	if !strings.Contains(out, "Description Required") {
		t.Errorf("expected 'Description Required' in output, got %q", out)
	}
}

func TestCloudPoliciesRunWithoutOrgId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	whoamiResp := whoamiResponse{
		Organizations: []orgMembership{
			{
				Organization: orgInfo{
					ID:   "org123",
					Name: "Test Org",
				},
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResp))

	policies := []policy{
		{
			ID:   "pol-1",
			Name: "Controls Required",
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies", http.StatusOK, jsonResponse(policies))

	cmd := testCloudPoliciesCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}
}

func TestCloudPoliciesRunNoTokenForOrg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	cmd := testCloudPoliciesCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "different-org"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no token found for organization") {
		t.Errorf("expected error message about no token for org, got %q", out)
	}
}

func TestCloudPoliciesRunEmptyList(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies", http.StatusOK, jsonResponse([]policy{}))

	cmd := testCloudPoliciesCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "No policies found") {
		t.Errorf("expected 'No policies found' message, got %q", out)
	}
}

func TestCloudPoliciesRunEnabledOnly(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	policies := []policy{
		{
			ID:       "pol-1",
			Name:     "Enabled Policy",
			Severity: "error",
			Enabled:  true,
		},
		{
			ID:       "pol-2",
			Name:     "Disabled Policy",
			Severity: "warning",
			Enabled:  false,
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies", http.StatusOK, jsonResponse(policies))

	cmd := testCloudPoliciesCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-enabled-only"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Enabled Policy") {
		t.Errorf("expected 'Enabled Policy' in output, got %q", out)
	}

	if strings.Contains(out, "Disabled Policy") {
		t.Errorf("expected 'Disabled Policy' NOT in output, got %q", out)
	}
}

func TestCloudPoliciesRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	policies := []policy{
		{
			ID:       "pol-1",
			Name:     "Controls Required",
			Severity: "error",
			Enabled:  true,
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies", http.StatusOK, jsonResponse(policies))

	cmd := testCloudPoliciesCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-json"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var result []policy
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 policy in JSON output, got %d", len(result))
	}
}

func TestCloudPoliciesRunAPIErrors(t *testing.T) {
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
			name:         "server error",
			statusCode:   http.StatusInternalServerError,
			expectedCode: 1,
			expectedOut:  "Error fetching policies",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error fetching policies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/org/org123/policies", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudPoliciesCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123"})
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

func TestCloudPoliciesFetchPolicies(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	policies := []policy{
		{
			ID:       "pol-1",
			Name:     "Controls Required",
			Severity: "error",
		},
		{
			ID:       "pol-2",
			Name:     "Description Required",
			Severity: "warning",
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies", http.StatusOK, jsonResponse(policies))

	result, err := fetchPolicies("token", "org123", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 policies, got %d", len(result))
	}

	if result[0].Name != "Controls Required" {
		t.Errorf("expected first policy name %q, got %q", "Controls Required", result[0].Name)
	}
}

func TestCloudPoliciesDisplayPolicies(t *testing.T) {
	policies := []policy{
		{
			ID:        "pol-1",
			Name:      "Controls Required",
			Severity:  "error",
			Enabled:   true,
			Enforced:  true,
			Category:  "completeness",
			UpdatedAt: "2026-03-10T12:00:00Z",
		},
		{
			ID:        "pol-2",
			Name:      "Description Required",
			Severity:  "warning",
			Enabled:   false,
			Enforced:  false,
			UpdatedAt: "2026-03-11T12:00:00Z",
		},
	}

	cmd := testCloudPoliciesCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayPolicies(policies)
	})

	if !strings.Contains(out, "NAME") {
		t.Errorf("expected 'NAME' header in output, got %q", out)
	}

	if !strings.Contains(out, "SEVERITY") {
		t.Errorf("expected 'SEVERITY' header in output, got %q", out)
	}

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}

	if !strings.Contains(out, "Description Required") {
		t.Errorf("expected 'Description Required' in output, got %q", out)
	}
}

func TestCloudPoliciesDisplayPoliciesEmpty(t *testing.T) {
	cmd := testCloudPoliciesCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayPolicies([]policy{})
	})

	if !strings.Contains(out, "No policies found") {
		t.Errorf("expected 'No policies found' message, got %q", out)
	}
}
