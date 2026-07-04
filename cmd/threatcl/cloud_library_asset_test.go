package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

// libraryAssetTestCommand builds a CloudLibraryAssetCommand with injected mocks
func libraryAssetTestCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryAssetCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryAssetCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

// libraryAssetTestItemResponse is a full single-asset GraphQL response
var libraryAssetTestItemResponse = `{
	"data": {
		"informationAssetLibraryItem": {
			"id": "asset-lib-1",
			"referenceId": "IA-UDATA",
			"name": "User Data",
			"status": "PUBLISHED",
			"currentVersion": {
				"version": "2.0.0",
				"versionNumber": 2,
				"isPublished": true,
				"name": "User Data",
				"description": "PII collected from users",
				"informationClassification": "Confidential",
				"source": "CRM system",
				"changeSummary": "Updated classification",
				"createdAt": "2024-01-15T00:00:00Z"
			},
			"versions": [
				{"version": "2.0.0", "versionNumber": 2, "isPublished": true, "name": "User Data", "createdAt": "2024-01-15T00:00:00Z"},
				{"version": "1.0.0", "versionNumber": 1, "isPublished": true, "name": "User Data", "createdAt": "2024-01-01T00:00:00Z"}
			],
			"usageCount": 3,
			"usedByModels": [
				{"id": "model-1", "name": "Web Application TM"},
				{"id": "model-2", "name": "API Gateway TM"}
			]
		}
	}
}`

func TestCloudLibraryAssetHelpAndSynopsis(t *testing.T) {
	cmd := &CloudLibraryAssetCommand{}

	t.Run("Help", func(t *testing.T) {
		help := cmd.Help()
		for _, text := range []string{"threatcl cloud library asset", "<id>", "-json", "-org-id"} {
			if !strings.Contains(help, text) {
				t.Errorf("expected help to contain %q", text)
			}
		}
	})

	t.Run("Synopsis", func(t *testing.T) {
		synopsis := cmd.Synopsis()
		if !strings.Contains(strings.ToLower(synopsis), "information asset") {
			t.Errorf("synopsis should mention 'information asset', got %q", synopsis)
		}
	})

	t.Run("AutocompleteFlags", func(t *testing.T) {
		flags := cmd.AutocompleteFlags()
		if _, ok := flags["-config"]; !ok {
			t.Error("expected autocomplete flags to include -config")
		}
	})
}

func TestCloudLibraryAssetRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		queryStatus  int
		queryResp    string
		httpErr      error
		expectedCode int
		expectedOut  []string
	}{
		{
			name:         "successful get asset",
			args:         []string{"-org-id", "org-123", "asset-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    libraryAssetTestItemResponse,
			expectedCode: 0,
			expectedOut: []string{
				"Information Asset Library Item: User Data",
				"Reference ID: IA-UDATA",
				"Status:       PUBLISHED",
				"Usage Count:  3",
				"Current Version (v2.0.0)",
				"PII collected from users",
				"Confidential",
				"CRM system",
				"Updated classification",
				"Versions (2)",
				"v2.0.0 (current)",
				"Used By Models (2)",
				"Web Application TM",
			},
		},
		{
			name:         "missing asset ID",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  []string{"information asset library item ID is required"},
		},
		{
			name:         "asset not found",
			args:         []string{"-org-id", "org-123", "nonexistent"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"informationAssetLibraryItem": null}}`,
			expectedCode: 1,
			expectedOut:  []string{"information asset library item not found: nonexistent"},
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json", "asset-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    libraryAssetTestItemResponse,
			expectedCode: 0,
			expectedOut:  []string{`"referenceId": "IA-UDATA"`, `"informationClassification": "Confidential"`},
		},
		{
			name:         "missing token",
			args:         []string{"asset-lib-1"},
			token:        "",
			expectedCode: 1,
			expectedOut:  []string{"no tokens found"},
		},
		{
			name:         "unauthorized",
			args:         []string{"-org-id", "org-123", "asset-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusUnauthorized,
			queryResp:    `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  []string{"authentication failed"},
		},
		{
			name:         "graphql error",
			args:         []string{"-org-id", "org-123", "asset-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"errors":[{"message":"backend broke"}]}`,
			expectedCode: 1,
			expectedOut:  []string{"GraphQL error: backend broke"},
		},
		{
			name:         "malformed data payload",
			args:         []string{"-org-id", "org-123", "asset-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"informationAssetLibraryItem": ["not", "an", "object"]}}`,
			expectedCode: 1,
			expectedOut:  []string{"failed to parse information asset library item"},
		},
		{
			name:         "malformed response body",
			args:         []string{"-org-id", "org-123", "asset-lib-1"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{not json`,
			expectedCode: 1,
			expectedOut:  []string{"Error fetching information asset library item"},
		},
		{
			name:         "network error",
			args:         []string{"-org-id", "org-123", "asset-lib-1"},
			token:        "valid-token",
			httpErr:      fmt.Errorf("connection refused"),
			expectedCode: 1,
			expectedOut:  []string{"Error fetching information asset library item"},
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

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/graphql", tt.httpErr)
			} else if tt.queryStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", tt.queryStatus, tt.queryResp)
			}

			cmd := libraryAssetTestCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			for _, expected := range tt.expectedOut {
				if !strings.Contains(out, expected) {
					t.Errorf("expected output to contain %q, got %q", expected, out)
				}
			}
		})
	}
}

func TestCloudLibraryAssetRequestBody(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()
	keyringSvc.setMockToken("valid-token", "org-123", "Test Org")
	httpClient.transport.setResponse("POST", "/api/v1/graphql", http.StatusOK, libraryAssetTestItemResponse)

	cmd := libraryAssetTestCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org-123", "asset-lib-1"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	bodies := httpClient.transport.getRequestBodies("POST", "/api/v1/graphql")
	if len(bodies) != 1 {
		t.Fatalf("expected 1 request body, got %d", len(bodies))
	}

	for _, expected := range []string{
		`"id":"asset-lib-1"`,
		`"orgId":"org-123"`,
		`informationAssetLibraryItem(orgId: $orgId, id: $id)`,
	} {
		if !strings.Contains(bodies[0], expected) {
			t.Errorf("expected request body to contain %q, got %q", expected, bodies[0])
		}
	}
}
