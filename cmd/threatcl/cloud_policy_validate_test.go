package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudPolicyValidateRunValid(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n\nimport rego.v1\n"))

	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies/validate", http.StatusOK, `{"valid":true}`)

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "policy.rego"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Policy is valid") {
		t.Errorf("expected 'Policy is valid' in output, got %q", out)
	}
}

func TestCloudPolicyValidateRunInvalid(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("policy.rego", []byte("invalid rego content"))

	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies/validate", http.StatusOK, `{"valid":false,"error":"parse error: unexpected token"}`)

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "policy.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Policy is invalid") {
		t.Errorf("expected 'Policy is invalid' in output, got %q", out)
	}

	if !strings.Contains(out, "parse error") {
		t.Errorf("expected 'parse error' in output, got %q", out)
	}
}

func TestCloudPolicyValidateRunMissingFileArg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "policy file path is required") {
		t.Errorf("expected error about file path being required, got %q", out)
	}
}

func TestCloudPolicyValidateRunFileNotFound(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "nonexistent.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "failed to read file") {
		t.Errorf("expected error about failed to read file, got %q", out)
	}
}

func TestCloudPolicyValidateRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n"))

	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies/validate", http.StatusOK, `{"valid":true}`)

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-json", "policy.rego"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var result policyValidateResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid=true in JSON output")
	}
}

func TestCloudPolicyValidateRunJSONInvalid(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("policy.rego", []byte("bad rego"))

	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies/validate", http.StatusOK, `{"valid":false,"error":"parse error"}`)

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-json", "policy.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	var result policyValidateResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}

	if result.Valid {
		t.Errorf("expected valid=false in JSON output")
	}
}

func TestCloudPolicyValidateRunAPIErrors(t *testing.T) {
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
			expectedOut:  "Error validating policy",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error validating policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")
			fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n"))

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/org/org123/policies/validate", tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies/validate", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "policy.rego"})
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

func TestCloudPolicyValidateRego(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies/validate", http.StatusOK, `{"valid":true}`)

	result, err := NewCloudClient("token", "org123", getAPIBaseURL(fsSvc), httpClient).ValidatePolicySource(policyEngineRego, "package threatcl.test\n")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatalf("expected result but got nil")
	}

	if !result.Valid {
		t.Errorf("expected valid=true, got false")
	}
}

func TestCloudPolicyValidateRunNoTokenForOrg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("policy.rego", []byte("package threatcl.test\n"))

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "different-org", "policy.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no token found for organization") {
		t.Errorf("expected error message about no token for org, got %q", out)
	}
}

func TestCloudPolicyValidateRunInvariantEngine(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariant.hcl", []byte(testInvariantSource))

	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies/validate", http.StatusOK, `{"valid":true}`)

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-engine", "invariant", "invariant.hcl"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d: %s", code, out)
	}

	bodies := httpClient.transport.getRequestBodies("POST", "/api/v1/org/org123/policies/validate")
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
		t.Errorf("expected the file contents as source, got %v", body["source"])
	}
	if _, ok := body["rego_source"]; ok {
		t.Error("expected no rego_source for an invariant validation")
	}
}

func TestCloudPolicyValidateRunInvariantInvalid(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariant.hcl", []byte(testInvariantSource))

	// Exemptions resolve server-side against the org's models, so a file that
	// parses locally can still be rejected.
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/policies/validate", http.StatusOK,
		`{"valid":false,"error":"exemption references unknown threatmodel \"Payments Service\""}`)

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-engine", "invariant", "invariant.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "unknown threatmodel") {
		t.Errorf("expected the server's reason in output, got %q", out)
	}
}

func TestCloudPolicyValidateRunInvalidEngine(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyValidateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-engine", "opa", "policy.rego"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-engine must be one of") {
		t.Errorf("expected an engine error, got %q", out)
	}
}
