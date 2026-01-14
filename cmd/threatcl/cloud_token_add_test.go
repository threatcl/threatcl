package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func testCloudTokenAddCommand(t *testing.T, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudTokenAddCommand {
	t.Helper()

	global := &GlobalCmdOptions{}

	return &CloudTokenAddCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func TestCloudTokenAddWithApiTokenOrganization(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up whoami response with api_token_organization fields
	whoamiResp := whoamiResponse{
		ID: "user123",
		User: userInfo{
			Email: "test@example.com",
		},
		Organizations: []orgMembership{
			{
				Organization: orgInfo{
					ID:   "org-from-list",
					Name: "Org From List",
				},
			},
		},
		ApiTokenOrganizationID:   "api-token-org-id",
		ApiTokenOrganizationName: "API Token Org",
	}
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResp))

	cmd := testCloudTokenAddCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-token", "test-token"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d, output: %s", code, out)
	}

	// Verify the token was stored with the API token org, not the first org from the list
	if !strings.Contains(out, "api-token-org-id") {
		t.Errorf("expected output to contain api-token-org-id, got %q", out)
	}

	if !strings.Contains(out, "API Token Org") {
		t.Errorf("expected output to contain 'API Token Org', got %q", out)
	}

	// Verify the token was stored for the correct org
	token, err := getTokenForOrg("api-token-org-id", keyringSvc, fsSvc)
	if err != nil {
		t.Errorf("expected token to be stored for api-token-org-id, got error: %v", err)
	}

	if token != "test-token" {
		t.Errorf("expected token 'test-token', got %q", token)
	}

	// Verify the token was NOT stored for the org from the list
	_, err = getTokenForOrg("org-from-list", keyringSvc, fsSvc)
	if err == nil {
		t.Error("expected no token for org-from-list, but found one")
	}
}

func TestCloudTokenAddFallbackToFirstOrg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up whoami response WITHOUT api_token_organization fields (legacy behavior)
	whoamiResp := whoamiResponse{
		ID: "user123",
		User: userInfo{
			Email: "test@example.com",
		},
		Organizations: []orgMembership{
			{
				Organization: orgInfo{
					ID:   "first-org-id",
					Name: "First Org",
				},
			},
			{
				Organization: orgInfo{
					ID:   "second-org-id",
					Name: "Second Org",
				},
			},
		},
		// No ApiTokenOrganizationID - simulate legacy API
	}
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResp))

	cmd := testCloudTokenAddCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-token", "test-token"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d, output: %s", code, out)
	}

	// Verify the token was stored for the first org (legacy behavior)
	if !strings.Contains(out, "first-org-id") {
		t.Errorf("expected output to contain first-org-id, got %q", out)
	}

	token, err := getTokenForOrg("first-org-id", keyringSvc, fsSvc)
	if err != nil {
		t.Errorf("expected token to be stored for first-org-id, got error: %v", err)
	}

	if token != "test-token" {
		t.Errorf("expected token 'test-token', got %q", token)
	}
}

func TestCloudTokenAddNoOrganizations(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up whoami response with no organizations and no api_token_organization
	whoamiResp := whoamiResponse{
		ID: "user123",
		User: userInfo{
			Email: "test@example.com",
		},
		Organizations: []orgMembership{},
	}
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResp))

	cmd := testCloudTokenAddCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-token", "test-token"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no organizations found") {
		t.Errorf("expected error about no organizations, got %q", out)
	}
}

func TestCloudTokenAddNoTokenFlag(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudTokenAddCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		// When no token flag is provided and stdin is empty, it should fail
		code = cmd.Run([]string{})
	})

	// Should fail because it prompts for input but gets EOF
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Error reading input") {
		t.Errorf("expected error about reading input, got %q", out)
	}
}

func TestCloudTokenAddInvalidToken(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up unauthorized response
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusUnauthorized, `{"error":"unauthorized"}`)

	cmd := testCloudTokenAddCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-token", "invalid-token"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "invalid token") {
		t.Errorf("expected error about invalid token, got %q", out)
	}
}
