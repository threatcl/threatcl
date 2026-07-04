package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

// libraryAssetsTestCommand builds a CloudLibraryAssetsCommand with injected mocks
func libraryAssetsTestCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLibraryAssetsCommand {
	t.Helper()
	global := &GlobalCmdOptions{}
	return &CloudLibraryAssetsCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

// Mock responses for information asset library list tests
var (
	libraryAssetsTestListResponse = `{
		"data": {
			"informationAssetLibraryItems": [
				{
					"id": "asset-lib-1",
					"referenceId": "IA-UDATA",
					"name": "User Data",
					"status": "PUBLISHED",
					"currentVersion": {
						"version": "1.0.0",
						"name": "User Data",
						"informationClassification": "Confidential"
					},
					"usageCount": 3
				},
				{
					"id": "asset-lib-2",
					"referenceId": "IA-VERY-LONG-REFERENCE-ID",
					"name": "An Extremely Long Information Asset Name Exceeding Limit",
					"status": "DRAFT",
					"currentVersion": {
						"version": "0.1.0",
						"name": "Long asset",
						"informationClassification": "Highly Confidential Restricted"
					},
					"usageCount": 0
				},
				{
					"id": "asset-lib-3",
					"referenceId": "IA-NOVER",
					"name": "No Version Asset",
					"status": "DRAFT",
					"usageCount": 1
				}
			]
		}
	}`

	libraryAssetsTestEmptyResponse = `{"data": {"informationAssetLibraryItems": []}}`
)

func TestCloudLibraryAssetsHelpAndSynopsis(t *testing.T) {
	cmd := &CloudLibraryAssetsCommand{}

	t.Run("Help", func(t *testing.T) {
		help := cmd.Help()
		for _, text := range []string{"threatcl cloud library assets", "-classification", "-status", "-json"} {
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

func TestCloudLibraryAssetsRun(t *testing.T) {
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
			name:         "successful list assets",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    libraryAssetsTestListResponse,
			expectedCode: 0,
			expectedOut:  []string{"Found 3 information asset(s)", "IA-UDATA", "User Data", "Confidential"},
		},
		{
			name:         "long values are truncated",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    libraryAssetsTestListResponse,
			expectedCode: 0,
			expectedOut:  []string{"IA-VERY-LO...", "An Extremely Long Information ...", "Highly Confiden..."},
		},
		{
			name:         "empty list",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    libraryAssetsTestEmptyResponse,
			expectedCode: 0,
			expectedOut:  []string{"No information asset library items found"},
		},
		{
			name:         "json output",
			args:         []string{"-org-id", "org-123", "-json"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    libraryAssetsTestListResponse,
			expectedCode: 0,
			expectedOut:  []string{`"referenceId": "IA-UDATA"`, `"informationClassification": "Confidential"`},
		},
		{
			name:         "invalid status flag",
			args:         []string{"-org-id", "org-123", "-status", "BOGUS"},
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  []string{"invalid status: BOGUS"},
		},
		{
			name:         "missing token",
			args:         []string{},
			token:        "",
			expectedCode: 1,
			expectedOut:  []string{"no tokens found"},
		},
		{
			name:         "unauthorized",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusUnauthorized,
			queryResp:    `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  []string{"authentication failed"},
		},
		{
			name:         "graphql error",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"errors":[{"message":"something exploded"}]}`,
			expectedCode: 1,
			expectedOut:  []string{"GraphQL error: something exploded"},
		},
		{
			name:         "malformed data payload",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{"data": {"informationAssetLibraryItems": {"not": "an array"}}}`,
			expectedCode: 1,
			expectedOut:  []string{"failed to parse information asset library items"},
		},
		{
			name:         "malformed response body",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			queryStatus:  http.StatusOK,
			queryResp:    `{not json`,
			expectedCode: 1,
			expectedOut:  []string{"Error fetching information asset library items"},
		},
		{
			name:         "network error",
			args:         []string{"-org-id", "org-123"},
			token:        "valid-token",
			httpErr:      fmt.Errorf("connection refused"),
			expectedCode: 1,
			expectedOut:  []string{"Error fetching information asset library items"},
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

			cmd := libraryAssetsTestCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudLibraryAssetsRequestBody(t *testing.T) {
	t.Run("filters are sent in request body", func(t *testing.T) {
		httpClient := newMockHTTPClient()
		keyringSvc := newMockKeyringService()
		fsSvc := newMockFileSystemService()
		keyringSvc.setMockToken("valid-token", "org-123", "Test Org")
		httpClient.transport.setResponse("POST", "/api/v1/graphql", http.StatusOK, libraryAssetsTestEmptyResponse)

		cmd := libraryAssetsTestCommand(t, httpClient, keyringSvc, fsSvc)

		var code int
		capturer.CaptureOutput(func() {
			code = cmd.Run([]string{
				"-org-id", "org-123",
				"-folder", "folder-9",
				"-status", "PUBLISHED",
				"-classification", "Confidential",
				"-search", "user",
			})
		})

		if code != 0 {
			t.Fatalf("expected exit code 0, got %d", code)
		}

		bodies := httpClient.transport.getRequestBodies("POST", "/api/v1/graphql")
		if len(bodies) != 1 {
			t.Fatalf("expected 1 request body, got %d", len(bodies))
		}

		for _, expected := range []string{
			`"folderId":"folder-9"`,
			`"status":"PUBLISHED"`,
			`"informationClassification":"Confidential"`,
			`"search":"user"`,
			`"orgId":"org-123"`,
			`informationAssetLibraryItems(orgId: $orgId, filter: $filter)`,
		} {
			if !strings.Contains(bodies[0], expected) {
				t.Errorf("expected request body to contain %q, got %q", expected, bodies[0])
			}
		}
	})

	t.Run("no filter key when no filters set", func(t *testing.T) {
		httpClient := newMockHTTPClient()
		keyringSvc := newMockKeyringService()
		fsSvc := newMockFileSystemService()
		keyringSvc.setMockToken("valid-token", "org-123", "Test Org")
		httpClient.transport.setResponse("POST", "/api/v1/graphql", http.StatusOK, libraryAssetsTestEmptyResponse)

		cmd := libraryAssetsTestCommand(t, httpClient, keyringSvc, fsSvc)

		var code int
		capturer.CaptureOutput(func() {
			code = cmd.Run([]string{"-org-id", "org-123"})
		})

		if code != 0 {
			t.Fatalf("expected exit code 0, got %d", code)
		}

		bodies := httpClient.transport.getRequestBodies("POST", "/api/v1/graphql")
		if len(bodies) != 1 {
			t.Fatalf("expected 1 request body, got %d", len(bodies))
		}

		if strings.Contains(bodies[0], `"filter":`) {
			t.Errorf("expected request body to omit filter variable, got %q", bodies[0])
		}
	})
}
