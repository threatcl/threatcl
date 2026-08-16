package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

// --- cloud policy (view) tests ---

func TestCloudPolicyRunWithOrgId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	p := policy{
		ID:             "pol-1",
		OrganizationID: "org123",
		Name:           "Controls Required",
		Slug:           "controls-required",
		Description:    "Every threat must have at least one control.",
		RegoSource:     "package threatcl.controls_required\n\nimport rego.v1\n",
		Severity:       "error",
		Category:       "completeness",
		Tags:           []string{"quickstart"},
		Enabled:        true,
		Enforced:       true,
		CreatedBy:      "user-1",
		CreatedAt:      "2026-03-10T12:00:00Z",
		UpdatedAt:      "2026-03-10T12:00:00Z",
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(p))

	cmd := testCloudPolicyCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}

	if !strings.Contains(out, "pol-1") {
		t.Errorf("expected 'pol-1' in output, got %q", out)
	}

	if !strings.Contains(out, "controls-required") {
		t.Errorf("expected 'controls-required' in output, got %q", out)
	}
}

func TestCloudPolicyRunWithoutOrgId(t *testing.T) {
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

	p := policy{
		ID:   "pol-1",
		Name: "Controls Required",
		Slug: "controls-required",
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(p))

	cmd := testCloudPolicyCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-policy-id", "pol-1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}
}

func TestCloudPolicyRunNoPolicyId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-policy-id is required") {
		t.Errorf("expected error message about -policy-id being required, got %q", out)
	}
}

func TestCloudPolicyRunNoTokenForOrg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	cmd := testCloudPolicyCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-policy-id", "pol-1", "-org-id", "different-org"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no token found for organization") {
		t.Errorf("expected error message about no token for org, got %q", out)
	}
}

func TestCloudPolicyRunShowRego(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	p := policy{
		ID:         "pol-1",
		Name:       "Controls Required",
		Slug:       "controls-required",
		Severity:   "error",
		RegoSource: "package threatcl.controls_required\n\nimport rego.v1\n",
		Enabled:    true,
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(p))

	cmd := testCloudPolicyCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-show-rego"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Rego Source") {
		t.Errorf("expected 'Rego Source' in output, got %q", out)
	}

	if !strings.Contains(out, "package threatcl.controls_required") {
		t.Errorf("expected rego source content in output, got %q", out)
	}
}

func TestCloudPolicyRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	p := policy{
		ID:       "pol-1",
		Name:     "Controls Required",
		Severity: "error",
		Enabled:  true,
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(p))

	cmd := testCloudPolicyCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-json"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var result policy
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}

	if result.Name != "Controls Required" {
		t.Errorf("expected policy name 'Controls Required', got %q", result.Name)
	}
}

func TestCloudPolicyRunAPIErrors(t *testing.T) {
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
			expectedOut:  "policy not found",
		},
		{
			name:         "server error",
			statusCode:   http.StatusInternalServerError,
			expectedCode: 1,
			expectedOut:  "Error fetching policy",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error fetching policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/org/org123/policies/pol-1", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies/pol-1", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudPolicyCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1"})
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

func TestCloudPolicyFetchPolicy(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	p := policy{
		ID:       "pol-1",
		Name:     "Controls Required",
		Slug:     "controls-required",
		Severity: "error",
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(p))

	result, err := NewCloudClient("token", "org123", getAPIBaseURL(fsSvc), httpClient).FetchPolicy("pol-1")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatalf("expected policy but got nil")
	}

	if result.Name != "Controls Required" {
		t.Errorf("expected policy name %q, got %q", "Controls Required", result.Name)
	}

	if result.ID != "pol-1" {
		t.Errorf("expected policy ID %q, got %q", "pol-1", result.ID)
	}
}

func TestCloudPolicyDisplayPolicy(t *testing.T) {
	p := &policy{
		ID:          "pol-1",
		Name:        "Controls Required",
		Slug:        "controls-required",
		Description: "Every threat must have at least one control.",
		Severity:    "error",
		Category:    "completeness",
		Tags:        []string{"quickstart"},
		Enabled:     true,
		Enforced:    true,
		CreatedAt:   "2026-03-10T12:00:00Z",
		UpdatedAt:   "2026-03-10T12:00:00Z",
	}

	cmd := testCloudPolicyCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayPolicy(p)
	})

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}

	if !strings.Contains(out, "controls-required") {
		t.Errorf("expected 'controls-required' in output, got %q", out)
	}

	if !strings.Contains(out, "error") {
		t.Errorf("expected 'error' in output, got %q", out)
	}

	if !strings.Contains(out, "completeness") {
		t.Errorf("expected 'completeness' in output, got %q", out)
	}
}

// --- cloud policy create tests ---

func TestCloudPolicyCreateRunSuccess(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n\nimport rego.v1\n"))

	createdPolicy := policy{
		ID:       "pol-new",
		Name:     "Test Policy",
		Severity: "error",
		Enabled:  true,
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies", http.StatusCreated, jsonResponse(createdPolicy))

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-name", "Test Policy", "-severity", "error", "-rego-file", "policy.rego"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully created policy") {
		t.Errorf("expected success message in output, got %q", out)
	}

	if !strings.Contains(out, "Test Policy") {
		t.Errorf("expected policy name in output, got %q", out)
	}
}

func TestCloudPolicyCreateRunWithAllFlags(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n"))

	createdPolicy := policy{
		ID:          "pol-new",
		Name:        "Full Policy",
		Description: "A full policy",
		Severity:    "warning",
		Category:    "completeness",
		Tags:        []string{"tag1", "tag2"},
		Enabled:     false,
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies", http.StatusCreated, jsonResponse(createdPolicy))

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{
			"-org-id", "org123",
			"-name", "Full Policy",
			"-severity", "warning",
			"-rego-file", "policy.rego",
			"-description", "A full policy",
			"-category", "completeness",
			"-tags", "tag1,tag2",
			"-enabled=false",
		})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully created policy") {
		t.Errorf("expected success message in output, got %q", out)
	}
}

func TestCloudPolicyCreateRunMissingName(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-severity", "error", "-rego-file", "policy.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-name is required") {
		t.Errorf("expected error about -name being required, got %q", out)
	}
}

func TestCloudPolicyCreateRunMissingSeverity(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-name", "Test", "-rego-file", "policy.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-severity is required") {
		t.Errorf("expected error about -severity being required, got %q", out)
	}
}

func TestCloudPolicyCreateRunMissingRegoFile(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-name", "Test", "-severity", "error"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-file is required") {
		t.Errorf("expected error about -file being required, got %q", out)
	}
}

func TestCloudPolicyCreateRunInvalidSeverity(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-name", "Test", "-severity", "invalid", "-rego-file", "policy.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-severity must be one of") {
		t.Errorf("expected error about invalid severity, got %q", out)
	}
}

func TestCloudPolicyCreateRunRegoFileNotFound(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	// Don't set any file content - file doesn't exist

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-name", "Test", "-severity", "error", "-rego-file", "nonexistent.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "failed to read file") {
		t.Errorf("expected error about failed to read file, got %q", out)
	}
}

func TestCloudPolicyCreateRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n"))

	createdPolicy := policy{
		ID:       "pol-new",
		Name:     "Test Policy",
		Severity: "error",
		Enabled:  true,
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies", http.StatusCreated, jsonResponse(createdPolicy))

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-name", "Test Policy", "-severity", "error", "-rego-file", "policy.rego", "-json"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var result policy
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}

	if result.Name != "Test Policy" {
		t.Errorf("expected policy name 'Test Policy', got %q", result.Name)
	}
}

func TestCloudPolicyCreateRunAPIErrors(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		responseBody string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "unauthorized",
			statusCode:   http.StatusUnauthorized,
			responseBody: `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "bad request",
			statusCode:   http.StatusBadRequest,
			responseBody: `{"error":"invalid_rego"}`,
			expectedCode: 1,
			expectedOut:  "Error creating policy",
		},
		{
			name:         "forbidden",
			statusCode:   http.StatusForbidden,
			responseBody: `{"error":"policy_limit_reached"}`,
			expectedCode: 1,
			expectedOut:  "Error creating policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")
			fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n"))

			httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies", tt.statusCode, tt.responseBody)

			cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "-name", "Test", "-severity", "error", "-rego-file", "policy.rego"})
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

func TestCloudPolicyCreatePolicy(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	createdPolicy := policy{
		ID:       "pol-new",
		Name:     "Test Policy",
		Severity: "error",
		Enabled:  true,
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies", http.StatusCreated, jsonResponse(createdPolicy))

	enabled := true
	payload := &policyCreateRequest{
		Name:       "Test Policy",
		RegoSource: "package threatcl.test\n",
		Severity:   "error",
		Enabled:    &enabled,
	}

	result, err := NewCloudClient("token", "org123", getAPIBaseURL(fsSvc), httpClient).CreatePolicy(payload)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatalf("expected policy but got nil")
	}

	if result.Name != "Test Policy" {
		t.Errorf("expected policy name %q, got %q", "Test Policy", result.Name)
	}

	if result.ID != "pol-new" {
		t.Errorf("expected policy ID %q, got %q", "pol-new", result.ID)
	}
}

// --- cloud policy update tests ---

func TestCloudPolicyUpdateRunSuccess(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	updatedPolicy := policy{
		ID:       "pol-1",
		Name:     "Controls Required",
		Severity: "warning",
		Enabled:  true,
	}
	httpClient.transport.setResponse("PUT", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(updatedPolicy))

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-severity", "warning"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully updated policy") {
		t.Errorf("expected success message in output, got %q", out)
	}
}

func TestCloudPolicyUpdateRunWithRegoFile(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	fsSvc.SetFileContent("updated.rego", []byte("package threatcl.updated\n\nimport rego.v1\n"))

	updatedPolicy := policy{
		ID:         "pol-1",
		Name:       "Controls Required",
		Severity:   "error",
		RegoSource: "package threatcl.updated\n\nimport rego.v1\n",
		Enabled:    true,
	}
	httpClient.transport.setResponse("PUT", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(updatedPolicy))

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-rego-file", "updated.rego"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully updated policy") {
		t.Errorf("expected success message in output, got %q", out)
	}
}

func TestCloudPolicyUpdateRunMissingPolicyId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-severity", "warning"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-policy-id is required") {
		t.Errorf("expected error about -policy-id being required, got %q", out)
	}
}

func TestCloudPolicyUpdateRunNoUpdates(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-policy-id", "pol-1"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no update fields specified") {
		t.Errorf("expected error about no update fields, got %q", out)
	}
}

func TestCloudPolicyUpdateRunEnabledFlag(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	updatedPolicy := policy{
		ID:       "pol-1",
		Name:     "Controls Required",
		Severity: "error",
		Enabled:  false,
	}
	httpClient.transport.setResponse("PUT", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(updatedPolicy))

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-enabled=false"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully updated policy") {
		t.Errorf("expected success message in output, got %q", out)
	}
}

func TestCloudPolicyUpdateRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	updatedPolicy := policy{
		ID:       "pol-1",
		Name:     "Controls Required",
		Severity: "warning",
		Enabled:  true,
	}
	httpClient.transport.setResponse("PUT", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(updatedPolicy))

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-severity", "warning", "-json"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var result policy
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}

	if result.Severity != "warning" {
		t.Errorf("expected severity 'warning', got %q", result.Severity)
	}
}

func TestCloudPolicyUpdateRunAPIErrors(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		responseBody string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "unauthorized",
			statusCode:   http.StatusUnauthorized,
			responseBody: `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "not found",
			statusCode:   http.StatusNotFound,
			responseBody: `{"error":"not_found"}`,
			expectedCode: 1,
			expectedOut:  "policy not found",
		},
		{
			name:         "bad request",
			statusCode:   http.StatusBadRequest,
			responseBody: `{"error":"invalid_rego"}`,
			expectedCode: 1,
			expectedOut:  "Error updating policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			httpClient.transport.setResponse("PUT", "/api/v1/org/org123/policies/pol-1", tt.statusCode, tt.responseBody)

			cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-severity", "warning"})
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

func TestCloudPolicyUpdatePolicy(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	updatedPolicy := policy{
		ID:       "pol-1",
		Name:     "Controls Required",
		Severity: "warning",
		Enabled:  true,
	}
	httpClient.transport.setResponse("PUT", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(updatedPolicy))

	severity := "warning"
	payload := &policyUpdateRequest{
		Severity: &severity,
	}

	result, err := NewCloudClient("token", "org123", getAPIBaseURL(fsSvc), httpClient).UpdatePolicy("pol-1", payload)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatalf("expected policy but got nil")
	}

	if result.Severity != "warning" {
		t.Errorf("expected severity %q, got %q", "warning", result.Severity)
	}
}

func TestCloudPolicyRunShowSourceInvariant(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	// An invariant policy carries no rego_source - it would fail Rego
	// compilation in an older client - so the source has to be read from
	// the source field.
	p := policy{
		ID:       "pol-1",
		Name:     "threats_have_controls",
		Slug:     "threats_have_controls",
		Engine:   policyEngineInvariant,
		Source:   testInvariantSource,
		Severity: "warning",
		Enabled:  true,
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(p))

	cmd := testCloudPolicyCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-show-source"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	for _, want := range []string{"Engine:      invariant", "Invariant Source:", "target      = \"threat\""} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got %q", want, out)
		}
	}
}

func TestCloudPolicyCreateRunInvariant(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariant.hcl", []byte(testInvariantSource))

	createdPolicy := policy{
		ID:       "pol-new",
		Name:     "threats_have_controls",
		Engine:   policyEngineInvariant,
		Severity: "warning",
		Enabled:  true,
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies", http.StatusCreated, jsonResponse(createdPolicy))

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-engine", "invariant", "-file", "invariant.hcl"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d: %s", code, out)
	}

	bodies := httpClient.transport.getRequestBodies("POST", "/api/v1/org/org123/policies")
	if len(bodies) != 1 {
		t.Fatalf("expected 1 request, got %d", len(bodies))
	}

	body := map[string]any{}
	if err := json.Unmarshal([]byte(bodies[0]), &body); err != nil {
		t.Fatalf("failed to decode request body: %v", err)
	}

	// Name and severity are the block's, without the author repeating them.
	if body["name"] != "threats_have_controls" {
		t.Errorf("expected the name to default to the block label, got %v", body["name"])
	}
	if body["severity"] != "warning" {
		t.Errorf("expected the severity to default to the block's, got %v", body["severity"])
	}
	if body["engine"] != policyEngineInvariant {
		t.Errorf("expected engine invariant, got %v", body["engine"])
	}
	if body["source"] != testInvariantSource {
		t.Errorf("expected the invariant source to be sent, got %v", body["source"])
	}
	if _, ok := body["rego_source"]; ok {
		t.Error("expected no rego_source on an invariant policy")
	}
}

func TestCloudPolicyCreateRunRegoSendsBothSourceFields(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n"))

	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies", http.StatusCreated, jsonResponse(policy{ID: "pol-new", Name: "Test"}))

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	code := 0
	capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-name", "Test", "-severity", "error", "-file", "policy.rego"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	bodies := httpClient.transport.getRequestBodies("POST", "/api/v1/org/org123/policies")
	if len(bodies) != 1 {
		t.Fatalf("expected 1 request, got %d", len(bodies))
	}

	body := map[string]any{}
	if err := json.Unmarshal([]byte(bodies[0]), &body); err != nil {
		t.Fatalf("failed to decode request body: %v", err)
	}

	// The deprecated alias keeps a deployment that predates `source` working.
	if body["source"] != "package threatcl.test\n" || body["rego_source"] != "package threatcl.test\n" {
		t.Errorf("expected both source fields on a rego policy, got %v", body)
	}
	if _, ok := body["engine"]; ok {
		t.Error("expected no engine field for rego - the server defaults to it")
	}
}

func TestCloudPolicyCreateRunInvariantErrors(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		args        []string
		expectedOut string
	}{
		{
			name:        "severity contradicts the block",
			source:      testInvariantSource,
			args:        []string{"-engine", "invariant", "-severity", "error", "-file", "invariant.hcl"},
			expectedOut: "contradicts invariant",
		},
		{
			name:        "info is not an invariant severity",
			source:      testInvariantSource,
			args:        []string{"-engine", "invariant", "-severity", "info", "-file", "invariant.hcl"},
			expectedOut: "-severity must be one of: error, warning",
		},
		{
			name:        "more than one block",
			source:      testTwoInvariantSource,
			args:        []string{"-engine", "invariant", "-file", "invariant.hcl"},
			expectedOut: "sync-invariants",
		},
		{
			name:        "unknown engine",
			source:      testInvariantSource,
			args:        []string{"-engine", "opa", "-file", "invariant.hcl"},
			expectedOut: "-engine must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")
			fsSvc.SetFileContent("invariant.hcl", []byte(tt.source))

			cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(append([]string{"-org-id", "org123"}, tt.args...))
			})

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}

			if bodies := httpClient.transport.getRequestBodies("POST", "/api/v1/org/org123/policies"); len(bodies) != 0 {
				t.Errorf("expected no request to be sent, got %d", len(bodies))
			}
		})
	}
}

func TestCloudPolicyCreateRunFeatureNotEnabled(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariant.hcl", []byte(testInvariantSource))

	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies", http.StatusForbidden,
		`{"error":{"code":"feature_not_enabled","message":"Invariant policies are not enabled","status":403}}`)

	cmd := testCloudPolicyCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-engine", "invariant", "-file", "invariant.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Invariant policies are not enabled") {
		t.Errorf("expected the API message, got %q", out)
	}

	// The deployment doesn't offer the engine, so point at the local fallback.
	if !strings.Contains(out, "threatcl validate -invariants") {
		t.Errorf("expected guidance to fall back to local validation, got %q", out)
	}
}

func TestCloudPolicyUpdateRunWithInvariantFile(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariant.hcl", []byte(testInvariantSource))

	updated := policy{ID: "pol-1", Name: "threats_have_controls", Engine: policyEngineInvariant, Severity: "warning"}
	httpClient.transport.setResponse("PUT", "/api/v1/org/org123/policies/pol-1", http.StatusOK, jsonResponse(updated))

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-engine", "invariant", "-file", "invariant.hcl"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d: %s", code, out)
	}

	bodies := httpClient.transport.getRequestBodies("PUT", "/api/v1/org/org123/policies/pol-1")
	if len(bodies) != 1 {
		t.Fatalf("expected 1 request, got %d", len(bodies))
	}

	body := map[string]any{}
	if err := json.Unmarshal([]byte(bodies[0]), &body); err != nil {
		t.Fatalf("failed to decode request body: %v", err)
	}

	if body["engine"] != policyEngineInvariant {
		t.Errorf("expected engine invariant, got %v", body["engine"])
	}
	if body["source"] != testInvariantSource {
		t.Errorf("expected the invariant source to be sent, got %v", body["source"])
	}
	if _, ok := body["rego_source"]; ok {
		t.Error("expected no rego_source on an invariant update")
	}
}

func TestCloudPolicyUpdateRunInvariantFileInvalid(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariant.hcl", []byte(testTwoInvariantSource))

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-engine", "invariant", "-file", "invariant.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Error parsing invariant file") {
		t.Errorf("expected a local parse error, got %q", out)
	}
}

func TestCloudPolicyUpdateRunInvalidEngine(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-engine", "opa", "-name", "Nope"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-engine must be one of") {
		t.Errorf("expected an engine error, got %q", out)
	}
}

func TestCloudPolicyUpdateRunInvariantSeverityConflict(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariant.hcl", []byte(testInvariantSource))

	cmd := testCloudPolicyUpdateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-policy-id", "pol-1", "-engine", "invariant", "-severity", "error", "-file", "invariant.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "contradicts invariant") {
		t.Errorf("expected a contradiction error, got %q", out)
	}

	if bodies := httpClient.transport.getRequestBodies("PUT", "/api/v1/org/org123/policies/pol-1"); len(bodies) != 0 {
		t.Errorf("expected no request to be sent, got %d", len(bodies))
	}
}
