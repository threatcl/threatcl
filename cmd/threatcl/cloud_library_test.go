package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

// Test helper functions for library commands

func testCloudLibraryFoldersCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryFoldersCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryFoldersCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryFolderCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryFolderCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryFolderCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryThreatsCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryThreatsCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryThreatsCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryThreatCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryThreatCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryThreatCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryThreatRefCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryThreatRefCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryThreatRefCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryControlsCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryControlsCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryControlsCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryControlCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryControlCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryControlCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryControlRefCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryControlRefCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryControlRefCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryStatsCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryStatsCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryStatsCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryExportCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryExportCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryExportCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudLibraryImportCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryImportCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryImportCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

// Mock responses for library tests
var (
	mockFoldersResponse = `{
		"data": {
			"libraryFolders": [
				{
					"id": "folder-1",
					"name": "Security Threats",
					"description": "Common security threats",
					"createdAt": "2024-01-01T00:00:00Z",
					"updatedAt": "2024-01-15T00:00:00Z"
				},
				{
					"id": "folder-2",
					"name": "Security Controls",
					"description": "Security controls library",
					"createdAt": "2024-01-01T00:00:00Z",
					"updatedAt": "2024-01-15T00:00:00Z"
				}
			]
		}
	}`

	mockFolderResponse = `{
		"data": {
			"libraryFolder": {
				"id": "folder-1",
				"name": "Security Threats",
				"description": "Common security threats",
				"createdAt": "2024-01-01T00:00:00Z",
				"updatedAt": "2024-01-15T00:00:00Z"
			}
		}
	}`

	mockThreatLibraryItemsResponse = `{
		"data": {
			"threatLibraryItems": [
				{
					"id": "threat-lib-1",
					"referenceId": "THR-001",
					"name": "SQL Injection",
					"status": "PUBLISHED",
					"currentVersion": {
						"version": "1.0.0",
						"name": "SQL Injection",
						"description": "SQL injection vulnerability",
						"severity": "High",
						"stride": ["Tampering"],
						"impacts": ["Integrity", "Confidentiality"],
						"tags": ["injection", "database"]
					},
					"usageCount": 5
				}
			]
		}
	}`

	mockThreatLibraryItemResponse = `{
		"data": {
			"threatLibraryItem": {
				"id": "threat-lib-1",
				"referenceId": "THR-001",
				"name": "SQL Injection",
				"status": "PUBLISHED",
				"currentVersion": {
					"version": "2.0.0",
					"name": "SQL Injection",
					"description": "SQL injection vulnerability",
					"impacts": ["Integrity", "Confidentiality"],
					"stride": ["Tampering", "Information Disclosure"],
					"severity": "High",
					"likelihood": "Medium",
					"cweIds": ["CWE-89"],
					"mitreAttackIds": ["T1190"],
					"tags": ["injection", "database", "owasp"],
					"recommendedControls": [{"referenceId": "CTL-001", "name": "Input Validation"}, {"referenceId": "CTL-002", "name": "Prepared Statements"}]
				},
				"versions": [
					{"version": "2.0.0", "name": "SQL Injection"},
					{"version": "1.0.0", "name": "SQL Injection"}
				],
				"usageCount": 5,
				"usedByModels": [
					{"id": "model-1", "name": "Web Application TM"}
				]
			}
		}
	}`

	mockControlLibraryItemsResponse = `{
		"data": {
			"controlLibraryItems": [
				{
					"id": "control-lib-1",
					"referenceId": "CTL-001",
					"name": "Input Validation",
					"status": "PUBLISHED",
					"currentVersion": {
						"version": "1.0.0",
						"name": "Input Validation",
						"controlType": "Preventive",
						"controlCategory": "Application Security",
						"tags": ["validation", "input"]
					},
					"usageCount": 10
				}
			]
		}
	}`

	mockControlLibraryItemResponse = `{
		"data": {
			"controlLibraryItem": {
				"id": "control-lib-1",
				"referenceId": "CTL-001",
				"name": "Input Validation",
				"status": "PUBLISHED",
				"currentVersion": {
					"version": "1.2.0",
					"name": "Input Validation",
					"description": "Validate and sanitize all user inputs",
					"controlType": "Preventive",
					"controlCategory": "Application Security",
					"implementationGuidance": "Use allowlist validation for all user inputs.",
					"nistControls": ["AC-3", "SI-10"],
					"cisControls": ["5.1", "5.2"],
					"isoControls": ["A.14.2.5"],
					"tags": ["validation", "input", "security"],
					"relatedThreats": [{"referenceId": "THR-001", "name": "SQL Injection"}, {"referenceId": "THR-002", "name": "XSS Attack"}],
					"defaultRiskReduction": 30
				},
				"versions": [
					{"version": "1.2.0", "name": "Input Validation"},
					{"version": "1.0.0", "name": "Input Validation"}
				],
				"usageCount": 10,
				"usedByModels": [
					{"id": "model-1", "name": "Web Application TM"},
					{"id": "model-2", "name": "API Gateway TM"}
				]
			}
		}
	}`

	mockLibraryStatsResponse = `{
		"data": {
			"libraryUsageStats": {
				"totalThreatItems": 45,
				"totalControlItems": 62,
				"publishedThreatItems": 38,
				"publishedControlItems": 55,
				"mostUsedThreats": [
					{"id": "threat-1", "name": "SQL Injection", "usageCount": 12},
					{"id": "threat-2", "name": "XSS", "usageCount": 8}
				],
				"mostUsedControls": [
					{"id": "control-1", "name": "Input Validation", "usageCount": 15}
				]
			}
		}
	}`
)

// ==================== CloudLibraryCommand Tests ====================

func TestCloudLibraryCommand(t *testing.T) {
	cmd := &CloudLibraryCommand{}

	// t.Run("Help", func(t *testing.T) {
	// 	help := cmd.Help()
	// 	expectedText := []string{"folders", "folder", "threats", "threat", "controls", "control", "stats", "export"}
	// 	for _, text := range expectedText {
	// 		if !strings.Contains(help, text) {
	// 			t.Errorf("expected help to contain %q", text)
	// 		}
	// 	}
	// })

	t.Run("Synopsis", func(t *testing.T) {
		synopsis := cmd.Synopsis()
		if !strings.Contains(strings.ToLower(synopsis), "librar") {
			t.Errorf("synopsis should mention 'library' or 'libraries', got %q", synopsis)
		}
	})
}

// ==================== CloudLibraryFoldersCommand Tests ====================

func TestCloudLibraryFoldersRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		useSequence  bool
		orgsStatus   int
		orgsResp     string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful list folders",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockFoldersResponse,
			expectedCode: 0,
			expectedOut:  "Security Threats",
		},
		{
			name:         "successful list with type filter",
			args:         []string{"-org-id", "org-123", "-type", "THREAT"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockFoldersResponse,
			expectedCode: 0,
			expectedOut:  "Found 2 folder",
		},
		{
			name:         "invalid folder type",
			args:         []string{"-type", "INVALID"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid folder type",
		},
		{
			name:         "missing token",
			args:         []string{},
			token:        "",
			expectedCode: 1,
			expectedOut:  "no tokens found",
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockFoldersResponse,
			expectedCode: 0,
			expectedOut:  `"id": "folder-1"`,
		},
		{
			name:         "unauthorized",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusUnauthorized,
			queryResp:    `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryFoldersCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryFolderCommand Tests ====================

func TestCloudLibraryFolderRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful get folder",
			args:         []string{"-org-id", "org-123", "folder-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockFolderResponse,
			expectedCode: 0,
			expectedOut:  "Security Threats",
		},
		{
			name:         "missing folder ID",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "folder ID is required",
		},
		{
			name:         "folder not found",
			args:         []string{"-org-id", "org-123", "nonexistent"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"libraryFolder": null}}`,
			expectedCode: 1,
			expectedOut:  "library folder not found",
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json", "folder-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockFolderResponse,
			expectedCode: 0,
			expectedOut:  `"name": "Security Threats"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryFolderCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryThreatsCommand Tests ====================

func TestCloudLibraryThreatsRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful list threats",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockThreatLibraryItemsResponse,
			expectedCode: 0,
			expectedOut:  "SQL Injection",
		},
		{
			name:         "with status filter",
			args:         []string{"-org-id", "org-123", "-status", "PUBLISHED"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockThreatLibraryItemsResponse,
			expectedCode: 0,
			expectedOut:  "THR-001",
		},
		{
			name:         "invalid status",
			args:         []string{"-status", "INVALID"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid status",
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockThreatLibraryItemsResponse,
			expectedCode: 0,
			expectedOut:  `"referenceId": "THR-001"`,
		},
		{
			name:         "no threats found",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"threatLibraryItems": []}}`,
			expectedCode: 0,
			expectedOut:  "No threat library items found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryThreatsCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryThreatCommand Tests ====================

func TestCloudLibraryThreatRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful get threat",
			args:         []string{"-org-id", "org-123", "threat-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockThreatLibraryItemResponse,
			expectedCode: 0,
			expectedOut:  "SQL Injection",
		},
		{
			name:         "missing threat ID",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "threat library item ID is required",
		},
		{
			name:         "threat not found",
			args:         []string{"-org-id", "org-123", "nonexistent"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"threatLibraryItem": null}}`,
			expectedCode: 1,
			expectedOut:  "threat library item not found",
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json", "threat-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockThreatLibraryItemResponse,
			expectedCode: 0,
			expectedOut:  `"severity": "High"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryThreatCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryThreatRefCommand Tests ====================

func TestCloudLibraryThreatRefRun(t *testing.T) {
	mockResponse := `{
		"data": {
			"threatLibraryItemByRef": {
				"id": "threat-lib-1",
				"referenceId": "THR-001",
				"name": "SQL Injection",
				"status": "PUBLISHED",
				"currentVersion": {
					"version": "2.0.0",
					"name": "SQL Injection",
					"description": "SQL injection vulnerability",
					"impacts": ["Integrity"],
					"stride": ["Tampering"],
					"severity": "High",
					"likelihood": "Medium",
					"cweIds": ["CWE-89"],
					"mitreAttackIds": [],
					"tags": ["injection"],
					"recommendedControls": []
				},
				"versions": [],
				"usageCount": 5,
				"usedByModels": []
			}
		}
	}`

	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful get by reference",
			args:         []string{"-org-id", "org-123", "THR-001"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockResponse,
			expectedCode: 0,
			expectedOut:  "THR-001",
		},
		{
			name:         "missing reference ID",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "reference ID is required",
		},
		{
			name:         "not found",
			args:         []string{"-org-id", "org-123", "THR-999"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"threatLibraryItemByRef": null}}`,
			expectedCode: 1,
			expectedOut:  "threat library item not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryThreatRefCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryControlsCommand Tests ====================

func TestCloudLibraryControlsRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful list controls",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockControlLibraryItemsResponse,
			expectedCode: 0,
			expectedOut:  "Input Validation",
		},
		{
			name:         "with type filter",
			args:         []string{"-org-id", "org-123", "-type", "Preventive"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockControlLibraryItemsResponse,
			expectedCode: 0,
			expectedOut:  "CTL-001",
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockControlLibraryItemsResponse,
			expectedCode: 0,
			expectedOut:  `"referenceId": "CTL-001"`,
		},
		{
			name:         "no controls found",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"controlLibraryItems": []}}`,
			expectedCode: 0,
			expectedOut:  "No control library items found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryControlsCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryControlCommand Tests ====================

func TestCloudLibraryControlRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful get control",
			args:         []string{"-org-id", "org-123", "control-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockControlLibraryItemResponse,
			expectedCode: 0,
			expectedOut:  "Input Validation",
		},
		{
			name:         "missing control ID",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "control library item ID is required",
		},
		{
			name:         "control not found",
			args:         []string{"-org-id", "org-123", "nonexistent"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"controlLibraryItem": null}}`,
			expectedCode: 1,
			expectedOut:  "control library item not found",
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json", "control-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockControlLibraryItemResponse,
			expectedCode: 0,
			expectedOut:  `"controlType": "Preventive"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryControlCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryControlRefCommand Tests ====================

func TestCloudLibraryControlRefRun(t *testing.T) {
	mockResponse := `{
		"data": {
			"controlLibraryItemByRef": {
				"id": "control-lib-1",
				"referenceId": "CTL-001",
				"name": "Input Validation",
				"status": "PUBLISHED",
				"currentVersion": {
					"version": "1.2.0",
					"name": "Input Validation",
					"description": "Validate inputs",
					"controlType": "Preventive",
					"controlCategory": "Application Security",
					"implementationGuidance": "Use allowlist",
					"nistControls": ["AC-3"],
					"cisControls": ["5.1"],
					"isoControls": [],
					"tags": ["validation"],
					"relatedThreats": [{"referenceId": "THR-001", "name": "SQL Injection"}],
					"defaultRiskReduction": 30
				},
				"versions": [],
				"usageCount": 10,
				"usedByModels": []
			}
		}
	}`

	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful get by reference",
			args:         []string{"-org-id", "org-123", "CTL-001"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockResponse,
			expectedCode: 0,
			expectedOut:  "CTL-001",
		},
		{
			name:         "missing reference ID",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "reference ID is required",
		},
		{
			name:         "not found",
			args:         []string{"-org-id", "org-123", "CTL-999"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"controlLibraryItemByRef": null}}`,
			expectedCode: 1,
			expectedOut:  "control library item not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryControlRefCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryStatsCommand Tests ====================

func TestCloudLibraryStatsRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful get stats",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockLibraryStatsResponse,
			expectedCode: 0,
			expectedOut:  "Total Threats",
		},
		{
			name:         "shows published counts",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockLibraryStatsResponse,
			expectedCode: 0,
			expectedOut:  "38 published",
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    mockLibraryStatsResponse,
			expectedCode: 0,
			expectedOut:  `"totalThreatItems": 45`,
		},
		{
			name:         "missing token",
			args:         []string{},
			token:        "",
			expectedCode: 1,
			expectedOut:  "no tokens found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := testCloudLibraryStatsCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== CloudLibraryExportCommand Tests ====================

var mockLibraryExportHCL = `threat_library_item "SQL Injection" {
  reference_id = "THR-001"
  status       = "published"
  description  = "SQL injection vulnerability"
}

control_library_item "Input Validation" {
  reference_id = "CTL-001"
  status       = "published"
  description  = "Validate and sanitize all user inputs"
}
`

func TestCloudLibraryExportRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		apiStatus    int
		apiResp      string
		expectedCode int
		expectedOut  string
		checkFile    string
	}{
		{
			name:         "successful export to stdout",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			apiStatus:    http.StatusOK,
			apiResp:      mockLibraryExportHCL,
			expectedCode: 0,
			expectedOut:  "threat_library_item",
		},
		{
			name:         "successful export to file",
			args:         []string{"-org-id", "org-123", "-output", "/tmp/library-export.hcl"},
			token:        "valid-token",
			apiStatus:    http.StatusOK,
			apiResp:      mockLibraryExportHCL,
			expectedCode: 0,
			expectedOut:  "Library exported to",
			checkFile:    "/tmp/library-export.hcl",
		},
		{
			name:         "successful export to file with -o flag",
			args:         []string{"-org-id", "org-123", "-o", "/tmp/library-export-o.hcl"},
			token:        "valid-token",
			apiStatus:    http.StatusOK,
			apiResp:      mockLibraryExportHCL,
			expectedCode: 0,
			expectedOut:  "Library exported to",
			checkFile:    "/tmp/library-export-o.hcl",
		},
		{
			name:         "export with type filter threats",
			args:         []string{"-org-id", "org-123", "-type", "threats"},
			token:        "valid-token",
			apiStatus:    http.StatusOK,
			apiResp:      mockLibraryExportHCL,
			expectedCode: 0,
			expectedOut:  "threat_library_item",
		},
		{
			name:         "export with type filter controls",
			args:         []string{"-org-id", "org-123", "-type", "controls"},
			token:        "valid-token",
			apiStatus:    http.StatusOK,
			apiResp:      mockLibraryExportHCL,
			expectedCode: 0,
			expectedOut:  "control_library_item",
		},
		{
			name:         "invalid type filter",
			args:         []string{"-type", "invalid"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid export type",
		},
		{
			name:         "missing token",
			args:         []string{},
			token:        "",
			expectedCode: 1,
			expectedOut:  "no tokens found",
		},
		{
			name:         "unauthorized",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			apiStatus:    http.StatusUnauthorized,
			apiResp:      `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "server error",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			apiStatus:    http.StatusInternalServerError,
			apiResp:      `{"error":"export_error"}`,
			expectedCode: 1,
			expectedOut:  "Error exporting library",
		},
		{
			name:         "export with all query parameters",
			args:         []string{"-org-id", "org-123", "-type", "threats", "-status", "PUBLISHED", "-folder", "STRIDE", "-include-drafts", "-include-deprecated", "-tags", "owasp,injection"},
			token:        "valid-token",
			apiStatus:    http.StatusOK,
			apiResp:      mockLibraryExportHCL,
			expectedCode: 0,
			expectedOut:  "threat_library_item",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.apiStatus != 0 {
				httpClient.transport.setResponse("GET", "/api/v1/org/org-123/library/export", tt.apiStatus, tt.apiResp)
			}

			cmd := testCloudLibraryExportCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d (output: %s)", tt.expectedCode, code, out)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}

			if tt.checkFile != "" && tt.expectedCode == 0 {
				data, err := fsSvc.ReadFile(tt.checkFile)
				if err != nil {
					t.Errorf("expected file %s to exist, got error: %v", tt.checkFile, err)
				}
				if !strings.Contains(string(data), "threat_library_item") {
					t.Errorf("expected file content to contain HCL data, got %q", string(data))
				}
			}
		})
	}
}

// ==================== CloudLibraryImportCommand Tests ====================

func TestCloudLibraryImportRun(t *testing.T) {
	mockImportResponse := func(result libraryImportResult) string {
		data, _ := json.Marshal(result)
		return string(data)
	}

	successResult := libraryImportResult{
		FoldersCreated:  5,
		FoldersUpdated:  2,
		ThreatsCreated:  12,
		ThreatsUpdated:  3,
		ThreatsSkipped:  1,
		ControlsCreated: 8,
		ControlsUpdated: 2,
		ControlsSkipped: 0,
	}

	warningResult := libraryImportResult{
		FoldersCreated:  1,
		ThreatsCreated:  2,
		ControlsCreated: 1,
		Warnings:        []string{"Unresolved control reference: CTRL.LEGACY.001 (in threat OWASP.A01.002)", "Duplicate tag: owasp"},
	}

	tests := []struct {
		name         string
		args         []string
		token        string
		fileContent  string
		filePath     string
		apiStatus    int
		apiResp      string
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful import with default mode",
			args:         []string{"-org-id", "org-123", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusOK,
			apiResp:      mockImportResponse(successResult),
			expectedCode: 0,
			expectedOut:  "Import complete (mode: create-only)",
		},
		{
			name:         "successful import shows stats",
			args:         []string{"-org-id", "org-123", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusOK,
			apiResp:      mockImportResponse(successResult),
			expectedCode: 0,
			expectedOut:  "12 created, 3 updated, 1 skipped",
		},
		{
			name:         "successful import with update mode",
			args:         []string{"-org-id", "org-123", "-mode", "update", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusOK,
			apiResp:      mockImportResponse(successResult),
			expectedCode: 0,
			expectedOut:  "Import complete (mode: update)",
		},
		{
			name:         "successful import with -m short flag",
			args:         []string{"-org-id", "org-123", "-m", "replace", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusOK,
			apiResp:      mockImportResponse(successResult),
			expectedCode: 0,
			expectedOut:  "Import complete (mode: replace)",
		},
		{
			name:         "successful import with json output",
			args:         []string{"-org-id", "org-123", "-json", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusOK,
			apiResp:      mockImportResponse(successResult),
			expectedCode: 0,
			expectedOut:  `"threats_created": 12`,
		},
		{
			name:         "missing file argument",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "file path is required",
		},
		{
			name:         "non-hcl file extension",
			args:         []string{"-org-id", "org-123", "/path/to/library.json"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "file must have a .hcl extension",
		},
		{
			name:         "invalid mode",
			args:         []string{"-org-id", "org-123", "-mode", "invalid", "/path/to/library.hcl"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid import mode",
		},
		{
			name:         "file not found",
			args:         []string{"-org-id", "org-123", "/path/to/nonexistent.hcl"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "failed to read file",
		},
		{
			name:         "missing token",
			args:         []string{"/path/to/library.hcl"},
			token:        "",
			expectedCode: 1,
			expectedOut:  "no tokens found",
		},
		{
			name:         "unauthorized",
			args:         []string{"-org-id", "org-123", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusUnauthorized,
			apiResp:      `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "bad request",
			args:         []string{"-org-id", "org-123", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusBadRequest,
			apiResp:      `{"error":"bad_request","message":"invalid HCL syntax"}`,
			expectedCode: 1,
			expectedOut:  "Error importing library",
		},
		{
			name:         "import with warnings",
			args:         []string{"-org-id", "org-123", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusOK,
			apiResp:      mockImportResponse(warningResult),
			expectedCode: 0,
			expectedOut:  "Unresolved control reference",
		},
		{
			name:         "import warnings section header",
			args:         []string{"-org-id", "org-123", "/path/to/library.hcl"},
			token:        "valid-token",
			filePath:     "/path/to/library.hcl",
			fileContent:  mockLibraryExportHCL,
			apiStatus:    http.StatusOK,
			apiResp:      mockImportResponse(warningResult),
			expectedCode: 0,
			expectedOut:  "Warnings:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org-123", "Test Org")
			}

			if tt.filePath != "" && tt.fileContent != "" {
				fsSvc.SetFileContent(tt.filePath, []byte(tt.fileContent))
			}

			if tt.apiStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/org/org-123/library/import", tt.apiStatus, tt.apiResp)
			}

			cmd := testCloudLibraryImportCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d (output: %s)", tt.expectedCode, code, out)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

// ==================== Helper Function Tests ====================

func TestValidateLibraryStatus(t *testing.T) {
	tests := []struct {
		status string
		valid  bool
	}{
		{"DRAFT", true},
		{"PUBLISHED", true},
		{"ARCHIVED", true},
		{"DEPRECATED", true},
		{"", true}, // empty is valid
		{"INVALID", false},
		{"draft", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			if got := validateLibraryStatus(tt.status); got != tt.valid {
				t.Errorf("validateLibraryStatus(%q) = %v, want %v", tt.status, got, tt.valid)
			}
		})
	}
}

func TestValidateFolderType(t *testing.T) {
	tests := []struct {
		folderType string
		valid      bool
	}{
		{"THREAT", true},
		{"CONTROL", true},
		{"", true}, // empty is valid
		{"INVALID", false},
		{"threat", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.folderType, func(t *testing.T) {
			if got := validateFolderType(tt.folderType); got != tt.valid {
				t.Errorf("validateFolderType(%q) = %v, want %v", tt.folderType, got, tt.valid)
			}
		})
	}
}

func TestSplitCommaSeparated(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"one", []string{"one"}},
		{"one,two", []string{"one", "two"}},
		{"one, two, three", []string{"one", "two", "three"}},
		{" one , two ", []string{"one", "two"}},
		{",,,", nil}, // empty parts
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitCommaSeparated(tt.input)
			if tt.expected == nil {
				if got != nil {
					t.Errorf("splitCommaSeparated(%q) = %v, want nil", tt.input, got)
				}
			} else {
				if len(got) != len(tt.expected) {
					t.Errorf("splitCommaSeparated(%q) = %v, want %v", tt.input, got, tt.expected)
				}
				for i := range got {
					if got[i] != tt.expected[i] {
						t.Errorf("splitCommaSeparated(%q)[%d] = %v, want %v", tt.input, i, got[i], tt.expected[i])
					}
				}
			}
		})
	}
}

func TestOutputLibraryJSON(t *testing.T) {
	data := map[string]string{"key": "value"}

	out := capturer.CaptureStdout(func() {
		err := outputLibraryJSON(data)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	// Verify it's valid JSON
	var parsed map[string]string
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Errorf("output is not valid JSON: %v", err)
	}

	if parsed["key"] != "value" {
		t.Errorf("expected key=value, got %v", parsed)
	}
}

// ==================== Help and Synopsis Tests ====================

func TestLibraryCommandsHelp(t *testing.T) {
	tests := []struct {
		name     string
		cmd      interface{ Help() string }
		expected []string
	}{
		{
			name:     "folders",
			cmd:      testCloudLibraryFoldersCommand(t, nil, nil, nil),
			expected: []string{"-type", "-org-id", "-json", "THREAT", "CONTROL"},
		},
		{
			name:     "folder",
			cmd:      testCloudLibraryFolderCommand(t, nil, nil, nil),
			expected: []string{"<id>", "-org-id", "-json"},
		},
		{
			name:     "threats",
			cmd:      testCloudLibraryThreatsCommand(t, nil, nil, nil),
			expected: []string{"-folder", "-status", "-severity", "-stride", "-tags", "-search", "-json"},
		},
		{
			name:     "threat",
			cmd:      testCloudLibraryThreatCommand(t, nil, nil, nil),
			expected: []string{"<id>", "-org-id", "-json"},
		},
		{
			name:     "threat-ref",
			cmd:      testCloudLibraryThreatRefCommand(t, nil, nil, nil),
			expected: []string{"<reference-id>", "-org-id", "-json"},
		},
		{
			name:     "controls",
			cmd:      testCloudLibraryControlsCommand(t, nil, nil, nil),
			expected: []string{"-folder", "-status", "-type", "-category", "-tags", "-search", "-json"},
		},
		{
			name:     "control",
			cmd:      testCloudLibraryControlCommand(t, nil, nil, nil),
			expected: []string{"<id>", "-org-id", "-json"},
		},
		{
			name:     "control-ref",
			cmd:      testCloudLibraryControlRefCommand(t, nil, nil, nil),
			expected: []string{"<reference-id>", "-org-id", "-json"},
		},
		{
			name:     "stats",
			cmd:      testCloudLibraryStatsCommand(t, nil, nil, nil),
			expected: []string{"-org-id", "-json"},
		},
		{
			name:     "export",
			cmd:      testCloudLibraryExportCommand(t, nil, nil, nil),
			expected: []string{"-org-id", "-output", "-type", "-status", "-folder", "-include-drafts", "-include-deprecated", "-tags"},
		},
		{
			name:     "import",
			cmd:      testCloudLibraryImportCommand(t, nil, nil, nil),
			expected: []string{"-org-id", "-mode", "-json", "create-only", "update", "replace", "<file>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			help := tt.cmd.Help()
			for _, exp := range tt.expected {
				if !strings.Contains(help, exp) {
					t.Errorf("expected help to contain %q", exp)
				}
			}
		})
	}
}

func TestLibraryCommandsSynopsis(t *testing.T) {
	tests := []struct {
		name     string
		cmd      interface{ Synopsis() string }
		contains string
	}{
		{"folders", testCloudLibraryFoldersCommand(t, nil, nil, nil), "folder"},
		{"folder", testCloudLibraryFolderCommand(t, nil, nil, nil), "folder"},
		{"threats", testCloudLibraryThreatsCommand(t, nil, nil, nil), "threat"},
		{"threat", testCloudLibraryThreatCommand(t, nil, nil, nil), "threat"},
		{"threat-ref", testCloudLibraryThreatRefCommand(t, nil, nil, nil), "threat"},
		{"controls", testCloudLibraryControlsCommand(t, nil, nil, nil), "control"},
		{"control", testCloudLibraryControlCommand(t, nil, nil, nil), "control"},
		{"control-ref", testCloudLibraryControlRefCommand(t, nil, nil, nil), "control"},
		{"stats", testCloudLibraryStatsCommand(t, nil, nil, nil), "statistic"},
		{"export", testCloudLibraryExportCommand(t, nil, nil, nil), "export"},
		{"import", testCloudLibraryImportCommand(t, nil, nil, nil), "import"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synopsis := tt.cmd.Synopsis()
			if !strings.Contains(strings.ToLower(synopsis), tt.contains) {
				t.Errorf("synopsis should contain %q, got %q", tt.contains, synopsis)
			}
		})
	}
}
