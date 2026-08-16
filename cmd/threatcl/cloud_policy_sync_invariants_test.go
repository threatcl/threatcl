package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

const syncInvariantsPath = "/api/v1/org/org123/policies/import-invariants"

func TestCloudPolicySyncInvariantsRun(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariants.hcl", []byte(testTwoInvariantSource))

	httpClient.transport.setResponse("POST", syncInvariantsPath, http.StatusOK,
		`{"created":["no_public_unauth"],"updated":["threats_have_controls"],"policies":[]}`)

	cmd := testCloudPolicySyncInvariantsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "invariants.hcl"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	for _, want := range []string{
		"Parsed 2 invariants from invariants.hcl",
		"+ no_public_unauth (created)",
		"~ threats_have_controls (updated)",
		"1 created | 1 updated",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got %q", want, out)
		}
	}

	bodies := httpClient.transport.getRequestBodies("POST", syncInvariantsPath)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 request, got %d", len(bodies))
	}

	var payload importInvariantsRequest
	if err := json.Unmarshal([]byte(bodies[0]), &payload); err != nil {
		t.Fatalf("failed to decode request body: %v", err)
	}
	if payload.Source != testTwoInvariantSource {
		t.Errorf("expected the whole file to be sent, got %q", payload.Source)
	}
}

func TestCloudPolicySyncInvariantsRunNoChanges(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariants.hcl", []byte(testInvariantSource))

	httpClient.transport.setResponse("POST", syncInvariantsPath, http.StatusOK,
		`{"created":[],"updated":[],"policies":[]}`)

	cmd := testCloudPolicySyncInvariantsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "invariants.hcl"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Parsed 1 invariant from") {
		t.Errorf("expected a singular count, got %q", out)
	}

	if !strings.Contains(out, "No policies were created or updated.") {
		t.Errorf("expected the no-change line, got %q", out)
	}
}

func TestCloudPolicySyncInvariantsRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariants.hcl", []byte(testInvariantSource))

	httpClient.transport.setResponse("POST", syncInvariantsPath, http.StatusOK,
		`{"created":["threats_have_controls"],"updated":[],"policies":[{"id":"p1","name":"threats_have_controls","engine":"invariant","severity":"warning"}]}`)

	cmd := testCloudPolicySyncInvariantsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-json", "invariants.hcl"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var result importInvariantsResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v", err)
	}

	if len(result.Created) != 1 || result.Created[0] != "threats_have_controls" {
		t.Errorf("unexpected created list: %v", result.Created)
	}
	if len(result.Policies) != 1 || result.Policies[0].Engine != policyEngineInvariant {
		t.Errorf("unexpected policies: %+v", result.Policies)
	}
}

func TestCloudPolicySyncInvariantsRunMissingFileArg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicySyncInvariantsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "invariants file path is required") {
		t.Errorf("expected error about the file path, got %q", out)
	}
}

func TestCloudPolicySyncInvariantsRunFileNotFound(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	cmd := testCloudPolicySyncInvariantsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "nonexistent.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "failed to read file") {
		t.Errorf("expected error about failing to read the file, got %q", out)
	}
}

func TestCloudPolicySyncInvariantsRunInvalidFile(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariants.hcl", []byte("invariant \"broken\" {\n  target = \"threat\"\n}\n"))

	cmd := testCloudPolicySyncInvariantsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "invariants.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Error parsing invariants file") {
		t.Errorf("expected a local parse error, got %q", out)
	}

	// An all-or-nothing import shouldn't be attempted with a file we already
	// know won't parse.
	if bodies := httpClient.transport.getRequestBodies("POST", syncInvariantsPath); len(bodies) != 0 {
		t.Errorf("expected no request to be sent, got %d", len(bodies))
	}
}

func TestCloudPolicySyncInvariantsRunAPIErrors(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		httpErr      error
		expectedOut  string
		expectedHint string
	}{
		{
			name:         "invariant engine disabled",
			statusCode:   http.StatusForbidden,
			body:         `{"error":{"code":"feature_not_enabled","message":"Invariant policies are not enabled","status":403}}`,
			expectedOut:  "Invariant policies are not enabled",
			expectedHint: "threatcl validate -invariants",
		},
		{
			name:         "unknown exemption model",
			statusCode:   http.StatusBadRequest,
			body:         `{"error":{"code":"unknown_exemption_model","message":"Unknown model \"Payments Service\"","status":400}}`,
			expectedOut:  "Unknown model",
			expectedHint: "display name shown in the cloud UI",
		},
		{
			name:         "slug conflict",
			statusCode:   http.StatusConflict,
			body:         `{"error":{"code":"policy_slug_exists","message":"Policy slug already exists","status":409}}`,
			expectedOut:  "Policy slug already exists",
			expectedHint: "block name label",
		},
		{
			name:        "unauthorized",
			statusCode:  http.StatusUnauthorized,
			body:        `{"error":{"code":"unauthorized","message":"nope","status":401}}`,
			expectedOut: "authentication failed",
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectedOut: "Error importing invariants",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")
			fsSvc.SetFileContent("invariants.hcl", []byte(testInvariantSource))

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", syncInvariantsPath, tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", syncInvariantsPath, tt.statusCode, tt.body)
			}

			cmd := testCloudPolicySyncInvariantsCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "invariants.hcl"})
			})

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}

			if tt.expectedHint != "" && !strings.Contains(out, tt.expectedHint) {
				t.Errorf("expected guidance containing %q, got %q", tt.expectedHint, out)
			}
		})
	}
}

func TestCloudPolicySyncInvariantsRunNoTokenForOrg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent("invariants.hcl", []byte(testInvariantSource))

	cmd := testCloudPolicySyncInvariantsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "different-org", "invariants.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no token found for organization") {
		t.Errorf("expected error about no token for org, got %q", out)
	}
}

func TestCloudPolicySyncInvariantsHelpAndSynopsis(t *testing.T) {
	cmd := &CloudPolicySyncInvariantsCommand{}

	if !strings.Contains(cmd.Help(), "sync-invariants") {
		t.Error("expected the help text to name the command")
	}

	if cmd.Synopsis() == "" {
		t.Error("expected a synopsis")
	}
}
