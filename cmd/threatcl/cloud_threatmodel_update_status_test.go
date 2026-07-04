package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

// tmUpdateStatusTestCommand builds a CloudThreatmodelUpdateStatusCommand with injected mocks
func tmUpdateStatusTestCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudThreatmodelUpdateStatusCommand {
	t.Helper()

	return &CloudThreatmodelUpdateStatusCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func TestCloudThreatmodelUpdateStatusHelp(t *testing.T) {
	cmd := &CloudThreatmodelUpdateStatusCommand{}
	help := cmd.Help()

	for _, want := range []string{"threatcl cloud threatmodel update-status", "-model-id", "-status", "-org-id"} {
		if !strings.Contains(help, want) {
			t.Errorf("Help text should contain %q", want)
		}
	}
}

func TestCloudThreatmodelUpdateStatusSynopsis(t *testing.T) {
	cmd := &CloudThreatmodelUpdateStatusCommand{}
	synopsis := cmd.Synopsis()

	if synopsis == "" {
		t.Error("Synopsis should not be empty")
	}

	if !strings.Contains(strings.ToLower(synopsis), "status") {
		t.Error("Synopsis should mention status")
	}
}

func TestCloudThreatmodelUpdateStatusAutocompleteFlags(t *testing.T) {
	cmd := &CloudThreatmodelUpdateStatusCommand{}

	flags := cmd.AutocompleteFlags()
	if _, ok := flags["-config"]; !ok {
		t.Error("AutocompleteFlags should include -config")
	}
	if _, ok := flags["-status"]; !ok {
		t.Error("AutocompleteFlags should include -status")
	}
}

func TestCloudThreatmodelUpdateStatusArgErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedOut string
	}{
		{
			name:        "missing model-id",
			args:        []string{"-status", "approved"},
			expectedOut: "-model-id is required",
		},
		{
			name:        "missing status",
			args:        []string{"-model-id", "tm1"},
			expectedOut: "-status is required",
		},
		{
			name:        "no args",
			args:        []string{},
			expectedOut: "-model-id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tmUpdateStatusTestCommand(t, newMockHTTPClient(), newMockKeyringService(), newMockFileSystemService())

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

func TestCloudThreatmodelUpdateStatusMissingToken(t *testing.T) {
	keyringSvc := newMockKeyringService()
	keyringSvc.setError(fmt.Errorf("no token"))

	cmd := tmUpdateStatusTestCommand(t, newMockHTTPClient(), keyringSvc, newMockFileSystemService())

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1", "-status", "approved"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no tokens found") {
		t.Errorf("expected error about missing tokens, got %q", out)
	}

	if !strings.Contains(out, ErrPleaseLogin) {
		t.Errorf("expected login hint, got %q", out)
	}
}

func TestCloudThreatmodelUpdateStatusSuccess(t *testing.T) {
	statuses := []string{"draft", "in_review", "approved", "archived"}

	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			statusPath := "/api/v1/org/org123/models/tm1/status"
			httpClient.transport.setResponse("POST", statusPath, http.StatusOK, `{"success":true}`)

			cmd := tmUpdateStatusTestCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-model-id", "tm1", "-status", status})
			})

			if code != 0 {
				t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
			}

			expectedMsg := fmt.Sprintf("Successfully updated threat model status to '%s'", status)
			if !strings.Contains(out, expectedMsg) {
				t.Errorf("expected output to contain %q, got %q", expectedMsg, out)
			}

			// Assert the outgoing payload
			bodies := httpClient.transport.getRequestBodies("POST", statusPath)
			if len(bodies) != 1 {
				t.Fatalf("expected 1 status update request, got %d", len(bodies))
			}

			var payload map[string]string
			if err := json.Unmarshal([]byte(bodies[0]), &payload); err != nil {
				t.Fatalf("failed to parse request body %q: %v", bodies[0], err)
			}

			if payload["status"] != status {
				t.Errorf("expected request payload status %q, got %q", status, payload["status"])
			}
		})
	}
}

func TestCloudThreatmodelUpdateStatusWithOrgIdFlag(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org456", "Other Org")

	httpClient.transport.setResponse("POST", "/api/v1/org/org456/models/my-slug/status", http.StatusOK, `{"success":true}`)

	cmd := tmUpdateStatusTestCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "my-slug", "-status", "approved", "-org-id", "org456"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "Successfully updated threat model status to 'approved'") {
		t.Errorf("expected success message, got %q", out)
	}
}

func TestCloudThreatmodelUpdateStatusAPIErrors(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		httpErr     error
		expectedOut string
	}{
		{
			name:        "unauthorized",
			statusCode:  http.StatusUnauthorized,
			expectedOut: "authentication failed",
		},
		{
			name:        "not found",
			statusCode:  http.StatusNotFound,
			expectedOut: "resource not found",
		},
		{
			name:        "invalid status rejected by server",
			statusCode:  http.StatusBadRequest,
			expectedOut: "api returned status 400",
		},
		{
			name:        "server error",
			statusCode:  http.StatusInternalServerError,
			expectedOut: "api returned status 500",
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectedOut: "network error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			statusPath := "/api/v1/org/org123/models/tm1/status"
			if tt.httpErr != nil {
				httpClient.transport.setError("POST", statusPath, tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", statusPath, tt.statusCode, `{"error":"error"}`)
			}

			cmd := tmUpdateStatusTestCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-model-id", "tm1", "-status", "approved"})
			})

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if !strings.Contains(out, "Error updating threat model status") {
				t.Errorf("expected status update error prefix, got %q", out)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}
