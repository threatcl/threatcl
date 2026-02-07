package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func testCloudSearchCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudSearchCommand {
	t.Helper()

	global := &GlobalCmdOptions{}

	return &CloudSearchCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func TestCloudSearchRun(t *testing.T) {
	orgsResponse := `{
		"data": {
			"myOrganizations": [
				{
					"organization": {"id": "org-123", "name": "Test Org"},
					"role": "admin",
					"joinedAt": "2024-01-01T00:00:00Z"
				}
			]
		}
	}`

	threatsResponse := `{
		"data": {
			"threats": [
				{
					"id": "threat-1",
					"name": "SQL Injection",
					"description": "SQL injection vulnerability",
					"impacts": ["Integrity", "Confidentiality"],
					"stride": ["Tampering"],
					"informationAssets": [
						{
							"id": "asset-1",
							"name": "User Database",
							"description": "Primary user data",
							"informationClassification": "Confidential"
						}
					],
					"threatModel": {
						"id": "tm-1",
						"name": "Web Application",
						"description": "Main web app threat model",
						"status": "active",
						"version": "1.0.0"
					}
				}
			]
		}
	}`

	tests := []struct {
		name         string
		args         []string
		token        string
		useSequence  bool
		orgsStatus   int
		orgsResponse string
		orgsErr      error
		threatStatus int
		threatResp   string
		threatErr    error
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "successful search with results",
			args:         []string{"-impacts", "Integrity"},
			token:        "valid-token",
			useSequence:  true,
			orgsStatus:   http.StatusOK,
			orgsResponse: orgsResponse,
			threatStatus: http.StatusOK,
			threatResp:   threatsResponse,
			expectedCode: 0,
			expectedOut:  "SQL Injection",
		},
		{
			name:         "successful search with specific org",
			args:         []string{"-impacts", "Confidentiality", "-org-id", "org123"},
			token:        "valid-token",
			threatStatus: http.StatusOK,
			threatResp:   threatsResponse,
			expectedCode: 0,
			expectedOut:  "Found 1 threat",
		},
		{
			name:         "successful search with no filters",
			args:         []string{},
			token:        "valid-token",
			useSequence:  true,
			orgsStatus:   http.StatusOK,
			orgsResponse: orgsResponse,
			threatStatus: http.StatusOK,
			threatResp:   threatsResponse,
			expectedCode: 0,
			expectedOut:  "SQL Injection",
		},
		{
			name:         "successful search with stride filter",
			args:         []string{"-stride", "Tampering,Info Disclosure"},
			token:        "valid-token",
			useSequence:  true,
			orgsStatus:   http.StatusOK,
			orgsResponse: orgsResponse,
			threatStatus: http.StatusOK,
			threatResp:   threatsResponse,
			expectedCode: 0,
			expectedOut:  "SQL Injection",
		},
		{
			name:         "successful search with has-controls filter",
			args:         []string{"-has-controls", "true"},
			token:        "valid-token",
			useSequence:  true,
			orgsStatus:   http.StatusOK,
			orgsResponse: orgsResponse,
			threatStatus: http.StatusOK,
			threatResp:   threatsResponse,
			expectedCode: 0,
			expectedOut:  "SQL Injection",
		},
		{
			name:         "invalid impacts value",
			args:         []string{"-impacts", "Invalid"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid impact value",
		},
		{
			name:         "invalid stride value",
			args:         []string{"-stride", "Invalid"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid STRIDE value",
		},
		{
			name:         "invalid type value",
			args:         []string{"-type", "invalid"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid -type value",
		},
		{
			name:         "invalid has-controls value",
			args:         []string{"-has-controls", "maybe"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid -has-controls value",
		},
		{
			name:         "invalid implemented value",
			args:         []string{"-type", "controls", "-implemented", "maybe"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "invalid -implemented value",
		},
		{
			name:         "impacts flag not valid for controls",
			args:         []string{"-type", "controls", "-impacts", "Integrity"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "-impacts flag is not valid when -type=controls",
		},
		{
			name:         "stride flag not valid for controls",
			args:         []string{"-type", "controls", "-stride", "Info Disclosure"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "-stride flag is not valid when -type=controls",
		},
		{
			name:         "has-controls flag not valid for controls",
			args:         []string{"-type", "controls", "-has-controls", "true"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "-has-controls flag is not valid when -type=controls",
		},
		{
			name:         "implemented flag not valid for threats",
			args:         []string{"-type", "threats", "-implemented", "true"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "-implemented flag is not valid when -type=threats",
		},
		{
			name:         "missing token",
			args:         []string{"-impacts", "Integrity"},
			token:        "",
			expectedCode: 1,
			expectedOut:  "no tokens found",
		},
		{
			name:         "unauthorized token",
			args:         []string{"-impacts", "Integrity"},
			token:        "invalid-token",
			orgsStatus:   http.StatusUnauthorized,
			orgsResponse: `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "no organizations",
			args:         []string{"-impacts", "Integrity"},
			token:        "valid-token",
			orgsStatus:   http.StatusOK,
			orgsResponse: `{"data": {"myOrganizations": []}}`,
			expectedCode: 1,
			expectedOut:  "No organizations found",
		},
		{
			name:         "no threats found",
			args:         []string{"-impacts", "Availability"},
			token:        "valid-token",
			useSequence:  true,
			orgsStatus:   http.StatusOK,
			orgsResponse: orgsResponse,
			threatStatus: http.StatusOK,
			threatResp:   `{"data": {"threats": []}}`,
			expectedCode: 0,
			expectedOut:  "No threats found",
		},
		{
			name:         "network error on orgs",
			args:         []string{"-impacts", "Integrity"},
			token:        "valid-token",
			orgsErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error fetching organizations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token in new format
			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "org123", "Test Org")
			}

			// Set up responses
			if tt.orgsErr != nil {
				httpClient.transport.setError("POST", "/api/v1/graphql", tt.orgsErr)
			} else if tt.useSequence && tt.orgsStatus != 0 && tt.threatStatus != 0 {
				// Use sequence for tests that need both orgs and threats responses
				httpClient.transport.setResponseSequence("POST", "/api/v1/graphql", []mockResponseData{
					{statusCode: tt.orgsStatus, body: tt.orgsResponse},
					{statusCode: tt.threatStatus, body: tt.threatResp},
				})
			} else if tt.orgsStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.orgsStatus, tt.orgsResponse)
			} else if tt.threatStatus != 0 {
				// For specific org tests, we skip the orgs call and go straight to threats
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.threatStatus, tt.threatResp)
			}

			cmd := testCloudSearchCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudSearchFetchOrganizationsGraphQL(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		response    string
		httpErr     error
		expectError bool
		expectedLen int
	}{
		{
			name:       "successful fetch",
			statusCode: http.StatusOK,
			response: `{
				"data": {
					"myOrganizations": [
						{"organization": {"id": "org-1", "name": "Org 1"}, "role": "admin", "joinedAt": "2024-01-01"},
						{"organization": {"id": "org-2", "name": "Org 2"}, "role": "member", "joinedAt": "2024-01-02"}
					]
				}
			}`,
			expectError: false,
			expectedLen: 2,
		},
		{
			name:       "empty organizations",
			statusCode: http.StatusOK,
			response: `{
				"data": {"myOrganizations": []}
			}`,
			expectError: false,
			expectedLen: 0,
		},
		{
			name:        "unauthorized",
			statusCode:  http.StatusUnauthorized,
			response:    `{"error":"unauthorized"}`,
			expectError: true,
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
		},
		{
			name:       "graphql error",
			statusCode: http.StatusOK,
			response: `{
				"data": null,
				"errors": [{"message": "Internal error"}]
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/graphql", tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.statusCode, tt.response)
			}

			cmd := testCloudSearchCommand(t, httpClient, nil, fsSvc)

			orgs, err := cmd.fetchOrganizationsGraphQL("test-token", httpClient, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(orgs) != tt.expectedLen {
					t.Errorf("expected %d orgs, got %d", tt.expectedLen, len(orgs))
				}
			}
		})
	}
}

func TestCloudSearchSearchThreatsGraphQL(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		response    string
		httpErr     error
		expectError bool
		expectedLen int
	}{
		{
			name:       "successful search",
			statusCode: http.StatusOK,
			response: `{
				"data": {
					"threats": [
						{
							"id": "threat-1",
							"name": "Threat 1",
							"description": "Description",
							"impacts": ["Integrity"],
							"stride": ["Tampering"],
							"informationAssets": [],
							"threatModel": {"id": "tm-1", "name": "TM 1", "description": "", "status": "active", "version": "1.0"}
						}
					]
				}
			}`,
			expectError: false,
			expectedLen: 1,
		},
		{
			name:       "no threats",
			statusCode: http.StatusOK,
			response: `{
				"data": {"threats": []}
			}`,
			expectError: false,
			expectedLen: 0,
		},
		{
			name:        "unauthorized",
			statusCode:  http.StatusUnauthorized,
			response:    `{"error":"unauthorized"}`,
			expectError: true,
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
		},
		{
			name:       "graphql error",
			statusCode: http.StatusOK,
			response: `{
				"data": null,
				"errors": [{"message": "Organization not found"}]
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/graphql", tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.statusCode, tt.response)
			}

			cmd := testCloudSearchCommand(t, httpClient, nil, fsSvc)

			filter := threatSearchFilter{Impacts: "Integrity"}
			threats, err := cmd.searchThreatsGraphQL("test-token", "org-123", filter, httpClient, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(threats) != tt.expectedLen {
					t.Errorf("expected %d threats, got %d", tt.expectedLen, len(threats))
				}
			}
		})
	}
}

func TestCloudSearchSearchControlsGraphQL(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		response    string
		httpErr     error
		expectError bool
		expectedLen int
	}{
		{
			name:       "successful search",
			statusCode: http.StatusOK,
			response: `{
				"data": {
					"controls": [
						{
							"id": "control-1",
							"name": "Input Validation",
							"description": "Validate user input",
							"implemented": true,
							"threatModel": {"id": "tm-1", "name": "TM 1", "description": "", "status": "active", "version": "1.0"}
						}
					]
				}
			}`,
			expectError: false,
			expectedLen: 1,
		},
		{
			name:       "no controls",
			statusCode: http.StatusOK,
			response: `{
				"data": {"controls": []}
			}`,
			expectError: false,
			expectedLen: 0,
		},
		{
			name:        "unauthorized",
			statusCode:  http.StatusUnauthorized,
			response:    `{"error":"unauthorized"}`,
			expectError: true,
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
		},
		{
			name:       "graphql error",
			statusCode: http.StatusOK,
			response: `{
				"data": null,
				"errors": [{"message": "Organization not found"}]
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/graphql", tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.statusCode, tt.response)
			}

			cmd := testCloudSearchCommand(t, httpClient, nil, fsSvc)

			filter := controlSearchFilter{}
			controls, err := cmd.searchControlsGraphQL("test-token", "org-123", filter, httpClient, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(controls) != tt.expectedLen {
					t.Errorf("expected %d controls, got %d", tt.expectedLen, len(controls))
				}
			}
		})
	}
}

func TestCloudSearchDisplayThreatResults(t *testing.T) {
	threats := []graphQLThreat{
		{
			ID:          "threat-1",
			Name:        "SQL Injection",
			Description: "A SQL injection vulnerability",
			Impacts:     []string{"Integrity", "Confidentiality"},
			Stride:      []string{"Tampering", "Information Disclosure"},
			InformationAssets: []struct {
				ID                        string `json:"id"`
				Name                      string `json:"name"`
				Description               string `json:"description"`
				InformationClassification string `json:"informationClassification"`
			}{
				{ID: "asset-1", Name: "User Database", InformationClassification: "Confidential"},
			},
			ThreatModel: struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Status      string `json:"status"`
				Version     string `json:"version"`
			}{
				ID: "tm-1", Name: "Web App", Status: "active", Version: "1.0.0",
			},
			OrgID:   "org-123",
			OrgName: "Test Organization",
		},
	}

	cmd := testCloudSearchCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayThreatResults(threats, "impacts: Integrity", 2)
	})

	expectedFields := []string{
		"SQL Injection",
		"threat-1",
		"A SQL injection vulnerability",
		"Integrity, Confidentiality",
		"Tampering, Information Disclosure",
		"User Database",
		"Confidential",
		"Web App",
		"active",
		"1.0.0",
		"Found 1 threat(s) over 1 threatmodel(s) in 2 org(s)",
		"Org Name: Test Organization",
		"Org ID:   org-123",
	}

	for _, field := range expectedFields {
		if !strings.Contains(out, field) {
			t.Errorf("expected output to contain %q, got %q", field, out)
		}
	}
}

func TestCloudSearchDisplayThreatResultsEmpty(t *testing.T) {
	cmd := testCloudSearchCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayThreatResults([]graphQLThreat{}, "impacts: Availability", 1)
	})

	if !strings.Contains(out, "No threats found") {
		t.Errorf("expected 'No threats found' message, got %q", out)
	}
}

func TestCloudSearchDisplayControlResults(t *testing.T) {
	controls := []graphQLControl{
		{
			ID:          "control-1",
			Name:        "Input Validation",
			Description: "Validate all user inputs",
			Implemented: true,
			ThreatModel: struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Status      string `json:"status"`
				Version     string `json:"version"`
			}{
				ID: "tm-1", Name: "Web App", Status: "active", Version: "1.0.0",
			},
			OrgID:   "org-123",
			OrgName: "Test Organization",
		},
	}

	cmd := testCloudSearchCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayControlResults(controls, "implemented: true", 1)
	})

	expectedFields := []string{
		"Input Validation",
		"control-1",
		"Validate all user inputs",
		"Implemented: true",
		"Web App",
		"active",
		"1.0.0",
		"Found 1 control(s) over 1 threatmodel(s) in 1 org(s)",
		"Org Name: Test Organization",
		"Org ID:   org-123",
	}

	for _, field := range expectedFields {
		if !strings.Contains(out, field) {
			t.Errorf("expected output to contain %q, got %q", field, out)
		}
	}
}

func TestCloudSearchDisplayControlResultsEmpty(t *testing.T) {
	cmd := testCloudSearchCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayControlResults([]graphQLControl{}, "all", 1)
	})

	if !strings.Contains(out, "No controls found") {
		t.Errorf("expected 'No controls found' message, got %q", out)
	}
}

func TestCloudSearchHelp(t *testing.T) {
	cmd := testCloudSearchCommand(t, nil, nil, nil)
	help := cmd.Help()

	expectedText := []string{
		"threatcl cloud search",
		"-type",
		"-impacts",
		"-stride",
		"-has-controls",
		"-implemented",
		"-threatmodel-id",
		"-org-id",
		"Integrity",
		"Confidentiality",
		"Availability",
		"Spoofing",
		"Tampering",
		"Info Disclosure",
		"Denial Of Service",
		"Elevation Of Privilege",
		"threats",
		"controls",
		"THREATCL_API_URL",
	}

	for _, text := range expectedText {
		if !strings.Contains(help, text) {
			t.Errorf("expected help to contain %q", text)
		}
	}
}

func TestCloudSearchSynopsis(t *testing.T) {
	cmd := testCloudSearchCommand(t, nil, nil, nil)
	synopsis := cmd.Synopsis()

	if synopsis == "" {
		t.Error("synopsis should not be empty")
	}

	if !strings.Contains(synopsis, "Search") {
		t.Errorf("synopsis should mention 'Search', got %q", synopsis)
	}
}
