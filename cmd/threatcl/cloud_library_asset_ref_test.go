package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

// libraryAssetRefTestCommand builds a CloudLibraryAssetRefCommand with injected mocks
func libraryAssetRefTestCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryAssetRefCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryAssetRefCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

// libraryAssetRefTestItemResponse is a full asset-by-reference GraphQL response
var libraryAssetRefTestItemResponse = `{
	"data": {
		"informationAssetLibraryItemByRef": {
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
				{"version": "2.0.0", "versionNumber": 2, "isPublished": true, "name": "User Data", "createdAt": "2024-01-15T00:00:00Z"}
			],
			"usageCount": 3,
			"usedByModels": [
				{"id": "model-1", "name": "Web Application TM"}
			]
		}
	}
}`

func TestCloudLibraryAssetRefHelpAndSynopsis(t *testing.T) {
	cmd := &CloudLibraryAssetRefCommand{}

	t.Run("Help", func(t *testing.T) {
		help := cmd.Help()
		for _, text := range []string{"threatcl cloud library asset-ref", "<reference-id>", "-json", "-org-id"} {
			if !strings.Contains(help, text) {
				t.Errorf("expected help to contain %q", text)
			}
		}
	})

	t.Run("Synopsis", func(t *testing.T) {
		synopsis := cmd.Synopsis()
		if !strings.Contains(strings.ToLower(synopsis), "reference id") {
			t.Errorf("synopsis should mention 'reference ID', got %q", synopsis)
		}
	})

	t.Run("AutocompleteFlags", func(t *testing.T) {
		flags := cmd.AutocompleteFlags()
		if _, ok := flags["-config"]; !ok {
			t.Error("expected autocomplete flags to include -config")
		}
	})
}

func TestCloudLibraryAssetRefRun(t *testing.T) {
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
			name:         "successful get asset by ref",
			args:         []string{"-org-id", "org-123", "IA-UDATA"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    libraryAssetRefTestItemResponse,
			expectedCode: 0,
			expectedOut: []string{
				"Information Asset Library Item: User Data",
				"Reference ID: IA-UDATA",
				"Current Version (v2.0.0)",
				"Confidential",
				"Used By Models (1)",
			},
		},
		{
			name:         "missing reference ID",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  []string{"reference ID is required"},
		},
		{
			name:         "asset not found by ref",
			args:         []string{"-org-id", "org-123", "IA-MISSING"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"informationAssetLibraryItemByRef": null}}`,
			expectedCode: 1,
			expectedOut:  []string{"information asset library item not found: IA-MISSING"},
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json", "IA-UDATA"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    libraryAssetRefTestItemResponse,
			expectedCode: 0,
			expectedOut:  []string{`"referenceId": "IA-UDATA"`, `"informationClassification": "Confidential"`},
		},
		{
			name:         "missing token",
			args:         []string{"IA-UDATA"},
			token:        "",
			expectedCode: 1,
			expectedOut:  []string{"no tokens found"},
		},
		{
			name:         "unauthorized",
			args:         []string{"-org-id", "org-123", "IA-UDATA"},
			token:        "valid-token",
			queryStatus:  http.StatusUnauthorized,
			queryResp:    `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  []string{"authentication failed"},
		},
		{
			name:         "graphql error",
			args:         []string{"-org-id", "org-123", "IA-UDATA"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"errors":[{"message":"ref lookup failed"}]}`,
			expectedCode: 1,
			expectedOut:  []string{"GraphQL error: ref lookup failed"},
		},
		{
			name:         "malformed data payload",
			args:         []string{"-org-id", "org-123", "IA-UDATA"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"informationAssetLibraryItemByRef": ["not", "an", "object"]}}`,
			expectedCode: 1,
			expectedOut:  []string{"failed to parse information asset library item"},
		},
		{
			name:         "network error",
			args:         []string{"-org-id", "org-123", "IA-UDATA"},
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

			cmd := libraryAssetRefTestCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudLibraryAssetRefRequestBody(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()
	keyringSvc.setMockToken("valid-token", "org-123", "Test Org")
	httpClient.transport.setResponse("POST", "/api/v1/graphql", http.StatusOK, libraryAssetRefTestItemResponse)

	cmd := libraryAssetRefTestCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org-123", "IA-UDATA"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	bodies := httpClient.transport.getRequestBodies("POST", "/api/v1/graphql")
	if len(bodies) != 1 {
		t.Fatalf("expected 1 request body, got %d", len(bodies))
	}

	for _, expected := range []string{
		`"referenceId":"IA-UDATA"`,
		`"orgId":"org-123"`,
		`informationAssetLibraryItemByRef(orgId: $orgId, referenceId: $referenceId)`,
	} {
		if !strings.Contains(bodies[0], expected) {
			t.Errorf("expected request body to contain %q, got %q", expected, bodies[0])
		}
	}
}
