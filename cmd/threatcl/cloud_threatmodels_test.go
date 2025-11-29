package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudThreatmodelsRunWithOrgId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up threat models response
	threatModels := []threatModel{
		{
			ID:            "tm1",
			Name:          "Threat Model 1",
			Slug:          "threat-model-1",
			Status:        "active",
			Version:       "1.0",
			ThreatCount:   5,
			ControlCount:  3,
			DataFlowCount: 2,
		},
		{
			ID:            "tm2",
			Name:          "Threat Model 2",
			Slug:          "threat-model-2",
			Status:        "draft",
			Version:       "0.5",
			ThreatCount:   2,
			ControlCount:  1,
			DataFlowCount: 1,
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models", http.StatusOK, jsonResponse(threatModels))

	cmd := testCloudThreatmodelsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-orgId", "org123"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	// Check for threat model names in output
	if !strings.Contains(out, "Threat Model 1") {
		t.Errorf("expected 'Threat Model 1' in output, got %q", out)
	}

	if !strings.Contains(out, "Threat Model 2") {
		t.Errorf("expected 'Threat Model 2' in output, got %q", out)
	}
}

func TestCloudThreatmodelsRunWithoutOrgId(t *testing.T) {
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

	// Set up threat models response
	threatModels := []threatModel{
		{
			ID:     "tm1",
			Name:   "Threat Model 1",
			Slug:   "threat-model-1",
			Status: "active",
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models", http.StatusOK, jsonResponse(threatModels))

	cmd := testCloudThreatmodelsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Threat Model 1") {
		t.Errorf("expected 'Threat Model 1' in output, got %q", out)
	}
}

func TestCloudThreatmodelsRunNoOrganizations(t *testing.T) {
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

	cmd := testCloudThreatmodelsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "No organizations found") {
		t.Errorf("expected error message about no organizations, got %q", out)
	}
}

func TestCloudThreatmodelsRunEmptyList(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up empty threat models response
	threatModels := []threatModel{}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models", http.StatusOK, jsonResponse(threatModels))

	cmd := testCloudThreatmodelsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-orgId", "org123"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "No threat models found") {
		t.Errorf("expected 'No threat models found' message, got %q", out)
	}
}

func TestCloudThreatmodelsRunAPIErrors(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		httpErr     error
		expectedCode int
		expectedOut  string
	}{
		{
			name:        "unauthorized",
			statusCode:  http.StatusUnauthorized,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:        "server error",
			statusCode:  http.StatusInternalServerError,
			expectedCode: 1,
			expectedOut:  "Error fetching threat models",
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error fetching threat models",
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
				httpClient.transport.setError("GET", "/api/v1/org/org123/models", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/org/org123/models", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudThreatmodelsCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-orgId", "org123"})
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

func TestCloudThreatmodelsFetchUserInfo(t *testing.T) {
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

	cmd := testCloudThreatmodelsCommand(t, httpClient, nil, fsSvc)

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

func TestCloudThreatmodelsFetchThreatModels(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	threatModels := []threatModel{
		{
			ID:     "tm1",
			Name:   "Threat Model 1",
			Status: "active",
		},
		{
			ID:     "tm2",
			Name:   "Threat Model 2",
			Status: "draft",
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models", http.StatusOK, jsonResponse(threatModels))

	cmd := testCloudThreatmodelsCommand(t, httpClient, nil, fsSvc)

	models, err := cmd.fetchThreatModels("token", "org123", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(models) != 2 {
		t.Errorf("expected 2 threat models, got %d", len(models))
	}

	if models[0].Name != "Threat Model 1" {
		t.Errorf("expected first model name %q, got %q", "Threat Model 1", models[0].Name)
	}
}

func TestCloudThreatmodelsDisplayThreatModels(t *testing.T) {
	threatModels := []threatModel{
		{
			ID:            "tm1-123456789012345678901234567890123456",
			Name:          "Threat Model 1",
			Slug:          "threat-model-1",
			Status:        "active",
			Version:       "1.0",
			ThreatCount:   5,
			ControlCount:  3,
			DataFlowCount: 2,
		},
		{
			ID:            "tm2-123456789012345678901234567890123456",
			Name:          "Threat Model 2",
			Slug:          "threat-model-2",
			Status:        "draft",
			Version:       "0.5",
			ThreatCount:   2,
			ControlCount:  1,
			DataFlowCount: 1,
		},
	}

	cmd := testCloudThreatmodelsCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayThreatModels(threatModels)
	})

	// Check for table headers
	if !strings.Contains(out, "ID") {
		t.Errorf("expected 'ID' header in output, got %q", out)
	}

	if !strings.Contains(out, "Name") {
		t.Errorf("expected 'Name' header in output, got %q", out)
	}

	// Check for threat model data
	if !strings.Contains(out, "Threat Model 1") {
		t.Errorf("expected 'Threat Model 1' in output, got %q", out)
	}

	if !strings.Contains(out, "Threat Model 2") {
		t.Errorf("expected 'Threat Model 2' in output, got %q", out)
	}
}

func TestCloudThreatmodelsDisplayThreatModelsEmpty(t *testing.T) {
	cmd := testCloudThreatmodelsCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayThreatModels([]threatModel{})
	})

	if !strings.Contains(out, "No threat models found") {
		t.Errorf("expected 'No threat models found' message, got %q", out)
	}
}

