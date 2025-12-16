package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func testCloudThreatmodelVersionsCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudThreatmodelVersionsCommand {
	t.Helper()

	global := &GlobalCmdOptions{}

	return &CloudThreatmodelVersionsCommand{
		GlobalCmdOptions: global,
		httpClient:       httpClient,
		keyringSvc:       keyringSvc,
		fsSvc:            fsSvc,
	}
}

func TestCloudThreatmodelVersionsRunWithOrgId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up versions response
	versionsResp := threatModelVersionsResponse{
		Total: 3,
		Versions: []threatModelVersion{
			{
				ID:        "v1",
				Version:   "3.0.0",
				ChangedBy: "user@example.com",
				CreatedAt: "2024-03-01T00:00:00Z",
				IsCurrent: true,
			},
			{
				ID:        "v2",
				Version:   "2.0.0",
				ChangedBy: "user@example.com",
				CreatedAt: "2024-02-01T00:00:00Z",
				IsCurrent: false,
			},
			{
				ID:        "v3",
				Version:   "1.0.0",
				ChangedBy: "admin@example.com",
				CreatedAt: "2024-01-01T00:00:00Z",
				IsCurrent: false,
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions", http.StatusOK, jsonResponse(versionsResp))

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	// Check for versions information in output
	if !strings.Contains(out, "3.0.0") {
		t.Errorf("expected '3.0.0' in output, got %q", out)
	}

	if !strings.Contains(out, "2.0.0") {
		t.Errorf("expected '2.0.0' in output, got %q", out)
	}

	if !strings.Contains(out, "1.0.0") {
		t.Errorf("expected '1.0.0' in output, got %q", out)
	}

	if !strings.Contains(out, "CURRENT VERSION") {
		t.Errorf("expected 'CURRENT VERSION' marker in output, got %q", out)
	}

	if !strings.Contains(out, "Total: 3 version(s)") {
		t.Errorf("expected total count in output, got %q", out)
	}
}

func TestCloudThreatmodelVersionsRunWithoutOrgId(t *testing.T) {
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

	// Set up versions response
	versionsResp := threatModelVersionsResponse{
		Total: 1,
		Versions: []threatModelVersion{
			{
				ID:        "v1",
				Version:   "1.0.0",
				ChangedBy: "user@example.com",
				CreatedAt: "2024-01-01T00:00:00Z",
				IsCurrent: true,
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions", http.StatusOK, jsonResponse(versionsResp))

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "1.0.0") {
		t.Errorf("expected '1.0.0' in output, got %q", out)
	}
}

func TestCloudThreatmodelVersionsRunNoModelId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudThreatmodelVersionsRunNoOrganizations(t *testing.T) {
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

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudThreatmodelVersionsRunAPIErrors(t *testing.T) {
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
			expectedOut:  "Error fetching threat model versions",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error fetching threat model versions",
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
				httpClient.transport.setError("GET", "/api/v1/org/org123/models/tm1/versions", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudThreatmodelVersionsFetchUserInfo(t *testing.T) {
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

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, nil, fsSvc)

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

func TestCloudThreatmodelVersionsFetchThreatModelVersions(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	versionsResp := threatModelVersionsResponse{
		Total: 2,
		Versions: []threatModelVersion{
			{
				ID:        "v1",
				Version:   "2.0.0",
				ChangedBy: "user@example.com",
				CreatedAt: "2024-02-01T00:00:00Z",
				IsCurrent: true,
			},
			{
				ID:        "v2",
				Version:   "1.0.0",
				ChangedBy: "admin@example.com",
				CreatedAt: "2024-01-01T00:00:00Z",
				IsCurrent: false,
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions", http.StatusOK, jsonResponse(versionsResp))

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, nil, fsSvc)

	versions, err := cmd.fetchThreatModelVersions("token", "org123", "tm1", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if versions == nil {
		t.Fatalf("expected versions response but got nil")
	}

	if versions.Total != 2 {
		t.Errorf("expected total 2, got %d", versions.Total)
	}

	if len(versions.Versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions.Versions))
	}

	if versions.Versions[0].Version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got %q", versions.Versions[0].Version)
	}

	if !versions.Versions[0].IsCurrent {
		t.Errorf("expected first version to be current")
	}
}

func TestCloudThreatmodelVersionsFetchThreatModelVersionsWithSlug(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	versionsResp := threatModelVersionsResponse{
		Total: 1,
		Versions: []threatModelVersion{
			{
				ID:        "v1",
				Version:   "1.0.0",
				ChangedBy: "user@example.com",
				CreatedAt: "2024-01-01T00:00:00Z",
				IsCurrent: true,
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/my-model-slug/versions", http.StatusOK, jsonResponse(versionsResp))

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, nil, fsSvc)

	versions, err := cmd.fetchThreatModelVersions("token", "org123", "my-model-slug", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if versions == nil {
		t.Fatalf("expected versions response but got nil")
	}

	if len(versions.Versions) != 1 {
		t.Errorf("expected 1 version, got %d", len(versions.Versions))
	}
}

func TestCloudThreatmodelVersionsDisplayThreatModelVersions(t *testing.T) {
	versionsResp := &threatModelVersionsResponse{
		Total: 3,
		Versions: []threatModelVersion{
			{
				ID:        "v1",
				Version:   "3.0.0",
				ChangedBy: "user@example.com",
				CreatedAt: "2024-03-01T12:30:45Z",
				IsCurrent: true,
			},
			{
				ID:        "v2",
				Version:   "2.0.0",
				ChangedBy: "admin@example.com",
				CreatedAt: "2024-02-01T10:20:30Z",
				IsCurrent: false,
			},
			{
				ID:        "v3",
				Version:   "1.0.0",
				ChangedBy: "dev@example.com",
				CreatedAt: "2024-01-01T08:15:00Z",
				IsCurrent: false,
			},
		},
	}

	cmd := testCloudThreatmodelVersionsCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayThreatModelVersions(versionsResp)
	})

	// Check for key fields in output
	if !strings.Contains(out, "3.0.0") {
		t.Errorf("expected '3.0.0' in output, got %q", out)
	}

	if !strings.Contains(out, "2.0.0") {
		t.Errorf("expected '2.0.0' in output, got %q", out)
	}

	if !strings.Contains(out, "1.0.0") {
		t.Errorf("expected '1.0.0' in output, got %q", out)
	}

	if !strings.Contains(out, "CURRENT VERSION") {
		t.Errorf("expected 'CURRENT VERSION' marker in output, got %q", out)
	}

	if !strings.Contains(out, "user@example.com") {
		t.Errorf("expected 'user@example.com' in output, got %q", out)
	}

	if !strings.Contains(out, "Total: 3 version(s)") {
		t.Errorf("expected total count in output, got %q", out)
	}
}

func TestCloudThreatmodelVersionsDisplayEmptyVersions(t *testing.T) {
	versionsResp := &threatModelVersionsResponse{
		Total:    0,
		Versions: []threatModelVersion{},
	}

	cmd := testCloudThreatmodelVersionsCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayThreatModelVersions(versionsResp)
	})

	if !strings.Contains(out, "No versions found") {
		t.Errorf("expected 'No versions found' in output, got %q", out)
	}
}

func TestCloudThreatmodelVersionsRunWithDownload(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up version file content for download
	fileContent := "threatmodel \"test\" {\n  // version 1.0.0\n}"
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions/1.0.0/download", http.StatusOK, fileContent)

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1", "-download", "output.hcl", "-version", "1.0.0"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	// Verify success message
	if !strings.Contains(out, "Successfully downloaded threat model version 1.0.0 to output.hcl") {
		t.Errorf("expected success message in output, got %q", out)
	}

	// Verify file was written
	writtenContent, exists := fsSvc.files["output.hcl"]
	if !exists {
		t.Errorf("expected file 'output.hcl' to be written")
	}

	if string(writtenContent) != fileContent {
		t.Errorf("expected file content %q, got %q", fileContent, string(writtenContent))
	}

	// Verify that versions display is NOT in output (should return early)
	if strings.Contains(out, "Threat Model Versions") {
		t.Errorf("expected NOT to display versions information when downloading, got %q", out)
	}
}

func TestCloudThreatmodelVersionsRunWithDownloadWithoutOrgId(t *testing.T) {
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

	// Set up download response
	fileContent := "threatmodel \"test\" {\n  version = \"2.0.0\"\n}"
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions/2.0.0/download", http.StatusOK, fileContent)

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1", "-download", "output.hcl", "-version", "2.0.0"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully downloaded") {
		t.Errorf("expected success message in output, got %q", out)
	}

	// Verify file was written
	if _, exists := fsSvc.files["output.hcl"]; !exists {
		t.Errorf("expected file 'output.hcl' to be written")
	}
}

func TestCloudThreatmodelVersionsRunWithDownloadNoVersion(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1", "-download", "output.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-version is required when using -download") {
		t.Errorf("expected error message about -version being required, got %q", out)
	}
}

func TestCloudThreatmodelVersionsRunWithDownloadAPIErrors(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		httpErr      error
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "download not found",
			statusCode:   http.StatusNotFound,
			expectedCode: 1,
			expectedOut:  "Error downloading threat model version file",
		},
		{
			name:         "download unauthorized",
			statusCode:   http.StatusUnauthorized,
			expectedCode: 1,
			expectedOut:  "Error downloading threat model version file",
		},
		{
			name:         "download server error",
			statusCode:   http.StatusInternalServerError,
			expectedCode: 1,
			expectedOut:  "Error downloading threat model version file",
		},
		{
			name:         "download network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error downloading threat model version file",
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

			// Set up error response for download
			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/org/org123/models/tm1/versions/1.0.0/download", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions/1.0.0/download", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1", "-download", "output.hcl", "-version", "1.0.0"})
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}

			// Verify file was NOT written
			if _, exists := fsSvc.files["output.hcl"]; exists {
				t.Errorf("expected file NOT to be written on error")
			}
		})
	}
}

func TestCloudThreatmodelVersionsRunWithDownloadFileWriteError(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up successful download response
	fileContent := "threatmodel \"test\" {}"
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions/1.0.0/download", http.StatusOK, fileContent)

	// Set up file write error
	fsSvc.writeErr = fmt.Errorf("permission denied")

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1", "-download", "output.hcl", "-version", "1.0.0"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Error downloading threat model version file") {
		t.Errorf("expected error message in output, got %q", out)
	}

	if !strings.Contains(out, "permission denied") {
		t.Errorf("expected permission denied error in output, got %q", out)
	}
}

func TestCloudThreatmodelVersionsDownloadThreatModelVersion(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	fileContent := "threatmodel \"test\" {\n  version = \"1.0.0\"\n  description = \"test model\"\n}"
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions/1.0.0/download", http.StatusOK, fileContent)

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, nil, fsSvc)

	err := cmd.downloadThreatModelVersion("token", "org123", "tm1", "1.0.0", "test.hcl", false, httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify file content
	writtenContent, exists := fsSvc.files["test.hcl"]
	if !exists {
		t.Fatalf("expected file to be written")
	}

	if string(writtenContent) != fileContent {
		t.Errorf("expected file content %q, got %q", fileContent, string(writtenContent))
	}
}

func TestCloudThreatmodelVersionsDownloadThreatModelVersionWithSlug(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	fileContent := "threatmodel \"my-model\" {\n  version = \"2.5.0\"\n}"
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/my-model-slug/versions/2.5.0/download", http.StatusOK, fileContent)

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, nil, fsSvc)

	err := cmd.downloadThreatModelVersion("token", "org123", "my-model-slug", "2.5.0", "test.hcl", false, httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	writtenContent, exists := fsSvc.files["test.hcl"]
	if !exists {
		t.Fatalf("expected file to be written")
	}

	if string(writtenContent) != fileContent {
		t.Errorf("expected file content %q, got %q", fileContent, string(writtenContent))
	}
}

func TestCloudThreatmodelVersionsDownloadThreatModelVersionFileExists(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	// Simulate existing file
	fsSvc.files["existing.hcl"] = []byte("old content")

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, nil, fsSvc)

	// Try to download without overwrite flag - should fail
	err := cmd.downloadThreatModelVersion("token", "org123", "tm1", "1.0.0", "existing.hcl", false, httpClient, fsSvc)

	if err == nil {
		t.Errorf("expected error when file exists without overwrite flag")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got %v", err)
	}

	// Verify original file content unchanged
	content := fsSvc.files["existing.hcl"]
	if string(content) != "old content" {
		t.Errorf("expected original content to be preserved, got %q", string(content))
	}
}

func TestCloudThreatmodelVersionsDownloadThreatModelVersionFileExistsWithOverwrite(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	// Simulate existing file
	fsSvc.files["existing.hcl"] = []byte("old content")

	fileContent := "threatmodel \"new\" {\n  version = \"3.0.0\"\n  description = \"new model\"\n}"
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions/3.0.0/download", http.StatusOK, fileContent)

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, nil, fsSvc)

	// Try to download with overwrite flag - should succeed
	err := cmd.downloadThreatModelVersion("token", "org123", "tm1", "3.0.0", "existing.hcl", true, httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error with overwrite flag: %v", err)
	}

	// Verify file was overwritten
	writtenContent := fsSvc.files["existing.hcl"]
	if string(writtenContent) != fileContent {
		t.Errorf("expected file content %q, got %q", fileContent, string(writtenContent))
	}
}

func TestCloudThreatmodelVersionsRunWithDownloadAndOverwrite(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Simulate existing file
	fsSvc.files["output.hcl"] = []byte("old content")

	// Set up download response
	fileContent := "threatmodel \"new\" {\n  version = \"2.0.0\"\n}"
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions/2.0.0/download", http.StatusOK, fileContent)

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1", "-download", "output.hcl", "-version", "2.0.0", "-overwrite"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully downloaded") {
		t.Errorf("expected success message in output, got %q", out)
	}

	// Verify file was overwritten
	writtenContent := fsSvc.files["output.hcl"]
	if string(writtenContent) != fileContent {
		t.Errorf("expected file content %q, got %q", fileContent, string(writtenContent))
	}
}

func TestCloudThreatmodelVersionsRunWithDownloadFileExistsNoOverwrite(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Simulate existing file
	fsSvc.files["output.hcl"] = []byte("old content")

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "tm1", "-download", "output.hcl", "-version", "1.0.0"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Error downloading threat model version file") {
		t.Errorf("expected error message in output, got %q", out)
	}

	if !strings.Contains(out, "already exists") {
		t.Errorf("expected 'already exists' error in output, got %q", out)
	}

	// Verify original file content unchanged
	content := fsSvc.files["output.hcl"]
	if string(content) != "old content" {
		t.Errorf("expected original content to be preserved, got %q", string(content))
	}
}

func TestCloudThreatmodelVersionsDownloadNotFoundError(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/tm1/versions/9.9.9/download", http.StatusNotFound, `{"error":"version not found"}`)

	cmd := testCloudThreatmodelVersionsCommand(t, httpClient, nil, fsSvc)

	err := cmd.downloadThreatModelVersion("token", "org123", "tm1", "9.9.9", "test.hcl", false, httpClient, fsSvc)

	if err == nil {
		t.Errorf("expected error for not found version")
	}

	if !strings.Contains(err.Error(), "threat model version not found") {
		t.Errorf("expected 'threat model version not found' error, got %v", err)
	}

	if !strings.Contains(err.Error(), "9.9.9") {
		t.Errorf("expected version '9.9.9' in error message, got %v", err)
	}
}
