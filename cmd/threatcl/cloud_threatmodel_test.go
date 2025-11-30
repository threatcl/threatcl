package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func testCloudThreatmodelCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudThreatmodelCommand {
	t.Helper()

	global := &GlobalCmdOptions{}

	return &CloudThreatmodelCommand{
		GlobalCmdOptions: global,
		httpClient:       httpClient,
		keyringSvc:       keyringSvc,
		fsSvc:            fsSvc,
	}
}

func TestCloudThreatmodelRunWithOrgId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up threat model response
	threatModel := threatModel{
		ID:             "tm1",
		OrganizationID: "org123",
		Name:           "Threat Model 1",
		Slug:           "threat-model-1",
		Description:    "A test threat model",
		Status:         "active",
		Version:        "1.0",
		SpecFilePath:   "/path/to/spec.hcl",
		ThreatCount:    5,
		ControlCount:   3,
		DataFlowCount:  2,
		Tags:           []string{"security", "cloud"},
		CreatedBy:      "user123",
		CreatedAt:      "2024-01-01T00:00:00Z",
		UpdatedAt:      "2024-01-02T00:00:00Z",
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1", http.StatusOK, jsonResponse(threatModel))

	cmd := testCloudThreatmodelCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	// Check for threat model information in output
	if !strings.Contains(out, "Threat Model 1") {
		t.Errorf("expected 'Threat Model 1' in output, got %q", out)
	}

	if !strings.Contains(out, "tm1") {
		t.Errorf("expected 'tm1' in output, got %q", out)
	}

	if !strings.Contains(out, "threat-model-1") {
		t.Errorf("expected 'threat-model-1' in output, got %q", out)
	}
}

func TestCloudThreatmodelRunWithoutOrgId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up whoami response with organization
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

	// Set up threat model response
	threatModel := threatModel{
		ID:     "tm1",
		Name:   "Threat Model 1",
		Slug:   "threat-model-1",
		Status: "active",
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1", http.StatusOK, jsonResponse(threatModel))

	cmd := testCloudThreatmodelCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Threat Model 1") {
		t.Errorf("expected 'Threat Model 1' in output, got %q", out)
	}
}

func TestCloudThreatmodelRunNoModelId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudThreatmodelCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-model-id is required") {
		t.Errorf("expected error message about -model-id being required, got %q", out)
	}
}

func TestCloudThreatmodelRunNoOrganizations(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up whoami response with no organizations
	whoamiResp := whoamiResponse{
		Organizations: []orgMembership{},
	}
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResp))

	cmd := testCloudThreatmodelCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "No organizations found") {
		t.Errorf("expected error message about no organizations, got %q", out)
	}
}

func TestCloudThreatmodelRunAPIErrors(t *testing.T) {
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
			expectedOut:  "threat model not found",
		},
		{
			name:         "server error",
			statusCode:   http.StatusInternalServerError,
			expectedCode: 1,
			expectedOut:  "Error fetching threat model",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error fetching threat model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token
			keyringSvc.Set("access_token", map[string]interface{}{
				"access_token": "valid-token",
			})

			// Set up error response
			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/org/org123/models/tm1", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudThreatmodelCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1"})
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

func TestCloudThreatmodelFetchUserInfo(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	whoamiResp := whoamiResponse{
		ID: "user123",
		User: userInfo{
			Email: "test@example.com",
		},
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

	cmd := testCloudThreatmodelCommand(t, httpClient, nil, fsSvc)

	resp, err := cmd.fetchUserInfo("token", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatalf("expected response but got nil")
	}

	if len(resp.Organizations) != 1 {
		t.Errorf("expected 1 organization, got %d", len(resp.Organizations))
	}

	if resp.Organizations[0].Organization.ID != "org123" {
		t.Errorf("expected org ID %q, got %q", "org123", resp.Organizations[0].Organization.ID)
	}
}

func TestCloudThreatmodelFetchThreatModel(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	threatModel := threatModel{
		ID:     "tm1",
		Name:   "Threat Model 1",
		Slug:   "threat-model-1",
		Status: "active",
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1", http.StatusOK, jsonResponse(threatModel))

	cmd := testCloudThreatmodelCommand(t, httpClient, nil, fsSvc)

	model, err := cmd.fetchThreatModel("token", "org123", "tm1", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if model == nil {
		t.Fatalf("expected threat model but got nil")
	}

	if model.Name != "Threat Model 1" {
		t.Errorf("expected model name %q, got %q", "Threat Model 1", model.Name)
	}

	if model.ID != "tm1" {
		t.Errorf("expected model ID %q, got %q", "tm1", model.ID)
	}
}

func TestCloudThreatmodelFetchThreatModelWithSlug(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	threatModel := threatModel{
		ID:     "tm1",
		Name:   "Threat Model 1",
		Slug:   "threat-model-1",
		Status: "active",
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/threat-model-1", http.StatusOK, jsonResponse(threatModel))

	cmd := testCloudThreatmodelCommand(t, httpClient, nil, fsSvc)

	model, err := cmd.fetchThreatModel("token", "org123", "threat-model-1", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if model == nil {
		t.Fatalf("expected threat model but got nil")
	}

	if model.Slug != "threat-model-1" {
		t.Errorf("expected model slug %q, got %q", "threat-model-1", model.Slug)
	}
}

func TestCloudThreatmodelDisplayThreatModel(t *testing.T) {
	threatModel := &threatModel{
		ID:             "tm1-123456789012345678901234567890123456",
		OrganizationID: "org123",
		Name:           "Threat Model 1",
		Slug:           "threat-model-1",
		Description:    "A test threat model",
		Status:         "active",
		Version:        "1.0",
		SpecFilePath:   "/path/to/spec.hcl",
		ThreatCount:    5,
		ControlCount:   3,
		DataFlowCount:  2,
		Tags:           []string{"security", "cloud"},
		CreatedBy:      "user123",
		CreatedAt:      "2024-01-01T00:00:00Z",
		UpdatedAt:      "2024-01-02T00:00:00Z",
	}

	cmd := testCloudThreatmodelCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayThreatModel(threatModel)
	})

	// Check for key fields in output
	if !strings.Contains(out, "Threat Model 1") {
		t.Errorf("expected 'Threat Model 1' in output, got %q", out)
	}

	if !strings.Contains(out, "threat-model-1") {
		t.Errorf("expected 'threat-model-1' in output, got %q", out)
	}

	if !strings.Contains(out, "active") {
		t.Errorf("expected 'active' in output, got %q", out)
	}

	if !strings.Contains(out, "1.0") {
		t.Errorf("expected '1.0' in output, got %q", out)
	}
}
