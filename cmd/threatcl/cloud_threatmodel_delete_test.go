package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

// tmDeleteTestCommand builds a CloudThreatmodelDeleteCommand with injected mocks
func tmDeleteTestCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudThreatmodelDeleteCommand {
	t.Helper()

	return &CloudThreatmodelDeleteCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func TestCloudThreatmodelDeleteHelp(t *testing.T) {
	cmd := &CloudThreatmodelDeleteCommand{}
	help := cmd.Help()

	for _, want := range []string{"threatcl cloud threatmodel delete", "-model-id", "-org-id"} {
		if !strings.Contains(help, want) {
			t.Errorf("Help text should contain %q", want)
		}
	}
}

func TestCloudThreatmodelDeleteSynopsis(t *testing.T) {
	cmd := &CloudThreatmodelDeleteCommand{}
	synopsis := cmd.Synopsis()

	if synopsis == "" {
		t.Error("Synopsis should not be empty")
	}

	if !strings.Contains(strings.ToLower(synopsis), "delete") {
		t.Error("Synopsis should mention delete")
	}
}

func TestCloudThreatmodelDeleteAutocompleteFlags(t *testing.T) {
	cmd := &CloudThreatmodelDeleteCommand{}

	flags := cmd.AutocompleteFlags()
	if _, ok := flags["-config"]; !ok {
		t.Error("AutocompleteFlags should include -config")
	}
}

func TestCloudThreatmodelDeleteMissingModelId(t *testing.T) {
	cmd := tmDeleteTestCommand(t, newMockHTTPClient(), newMockKeyringService(), newMockFileSystemService())

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-model-id is required") {
		t.Errorf("expected error about -model-id being required, got %q", out)
	}
}

func TestCloudThreatmodelDeleteMissingToken(t *testing.T) {
	keyringSvc := newMockKeyringService()
	keyringSvc.setError(fmt.Errorf("no token"))

	cmd := tmDeleteTestCommand(t, newMockHTTPClient(), keyringSvc, newMockFileSystemService())

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1"})
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

func TestCloudThreatmodelDeleteNoTokenForOrg(t *testing.T) {
	keyringSvc := newMockKeyringService()
	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	cmd := tmDeleteTestCommand(t, newMockHTTPClient(), keyringSvc, newMockFileSystemService())

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1", "-org-id", "different-org"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no token found for organization") {
		t.Errorf("expected error about no token for org, got %q", out)
	}
}

func TestCloudThreatmodelDeleteSuccess(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		orgId   string
		modelId string
	}{
		{
			name:    "default org with model ID",
			args:    []string{"-model-id", "tm1"},
			orgId:   "org123",
			modelId: "tm1",
		},
		{
			name:    "explicit org with slug",
			args:    []string{"-model-id", "my-model-slug", "-org-id", "org456"},
			orgId:   "org456",
			modelId: "my-model-slug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", tt.orgId, "Test Org")

			// Only the exact expected path returns 204; anything else 404s,
			// so a passing run proves the DELETE hit the right URL.
			deletePath := fmt.Sprintf("/api/v1/org/%s/models/%s", tt.orgId, tt.modelId)
			httpClient.transport.setResponse("DELETE", deletePath, http.StatusNoContent, "")

			cmd := tmDeleteTestCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != 0 {
				t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
			}

			expectedMsg := fmt.Sprintf("Successfully deleted threat model '%s'", tt.modelId)
			if !strings.Contains(out, expectedMsg) {
				t.Errorf("expected output to contain %q, got %q", expectedMsg, out)
			}
		})
	}
}

func TestCloudThreatmodelDeleteAPIErrors(t *testing.T) {
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
			name:        "server error",
			statusCode:  http.StatusInternalServerError,
			expectedOut: "api returned status 500",
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectedOut: ErrFailedToConnect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			deletePath := "/api/v1/org/org123/models/tm1"
			if tt.httpErr != nil {
				httpClient.transport.setError("DELETE", deletePath, tt.httpErr)
			} else {
				httpClient.transport.setResponse("DELETE", deletePath, tt.statusCode, `{"error":"error"}`)
			}

			cmd := tmDeleteTestCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-model-id", "tm1"})
			})

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if !strings.Contains(out, "Error deleting threat model") {
				t.Errorf("expected delete error prefix, got %q", out)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}
