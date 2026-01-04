package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/threatcl/spec"
)

func TestValidateThreatModel(t *testing.T) {
	tests := []struct {
		name                  string
		fileContent           string
		setupMocks            func(*mockHTTPClient, *mockFileSystemService)
		expectedOrgValid      string
		expectedTMNameValid   string
		expectedTMFileMatches string
		expectedErrContains   string
	}{
		{
			name: "valid organization without threat model specified",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))
			},
			expectedOrgValid:      "org-id",
			expectedTMNameValid:   "",
			expectedTMFileMatches: "",
			expectedErrContains:   "",
		},
		{
			name: "valid organization with threat model matching latest version",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))

				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK, jsonResponse(threatModel{
					ID:   "tm-123",
					Name: "My TM",
					Slug: "my-tm",
				}))

				// Calculate expected file hash
				fileContent := []byte(`
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`)
				hashBytes := sha256.Sum256(fileContent)
				fileHash := hex.EncodeToString(hashBytes[:])

				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/tm-123/versions", http.StatusOK, jsonResponse(threatModelVersionsResponse{
					Versions: []threatModelVersion{
						{
							ID:           "v1",
							Version:      "1.0.0",
							SpecFileHash: fileHash,
							IsCurrent:    true,
						},
					},
					Total: 1,
				}))
			},
			expectedOrgValid:      "org-id",
			expectedTMNameValid:   "my-tm",
			expectedTMFileMatches: "1.0.0",
			expectedErrContains:   "",
		},
		{
			name: "valid organization with threat model matching non-latest version",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))

				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK, jsonResponse(threatModel{
					ID:   "tm-123",
					Name: "My TM",
					Slug: "my-tm",
				}))

				// Calculate expected file hash
				fileContent := []byte(`
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`)
				hashBytes := sha256.Sum256(fileContent)
				fileHash := hex.EncodeToString(hashBytes[:])

				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/tm-123/versions", http.StatusOK, jsonResponse(threatModelVersionsResponse{
					Versions: []threatModelVersion{
						{
							ID:           "v2",
							Version:      "2.0.0",
							SpecFileHash: "different-hash",
							IsCurrent:    true,
						},
						{
							ID:           "v1",
							Version:      "1.0.0",
							SpecFileHash: fileHash,
							IsCurrent:    false,
						},
					},
					Total: 2,
				}))
			},
			expectedOrgValid:      "org-id",
			expectedTMNameValid:   "my-tm",
			expectedTMFileMatches: "",
			expectedErrContains:   "",
		},
		{
			name: "valid organization with threat model but no matching version",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))

				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK, jsonResponse(threatModel{
					ID:   "tm-123",
					Name: "My TM",
					Slug: "my-tm",
				}))

				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/tm-123/versions", http.StatusOK, jsonResponse(threatModelVersionsResponse{
					Versions: []threatModelVersion{
						{
							ID:           "v1",
							Version:      "1.0.0",
							SpecFileHash: "some-other-hash",
							IsCurrent:    true,
						},
					},
					Total: 1,
				}))
			},
			expectedOrgValid:      "org-id",
			expectedTMNameValid:   "my-tm",
			expectedTMFileMatches: "",
			expectedErrContains:   "",
		},
		{
			name: "valid organization but threat model not found",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "nonexistent-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))

				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/nonexistent-tm", http.StatusNotFound, `{"error":"not found"}`)
			},
			expectedOrgValid:      "org-id",
			expectedTMNameValid:   "nonexistent-tm",
			expectedTMFileMatches: "",
			expectedErrContains:   "error: backend threatmodel 'nonexistent-tm' not found",
		},
		{
			name: "user not member of organization",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "different-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))
			},
			expectedOrgValid:      "",
			expectedTMNameValid:   "",
			expectedTMFileMatches: "",
			expectedErrContains:   "not a member of organization",
		},
		{
			name: "no backend block",
			fileContent: `
spec_version = "0.1.10"

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				// No HTTP calls expected
			},
			expectedOrgValid:      "",
			expectedTMNameValid:   "",
			expectedTMFileMatches: "",
			expectedErrContains:   "No backend block found",
		},
		{
			name: "multiple backend blocks",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

backend "other-backend" {
  organization = "other-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				// No HTTP calls expected
			},
			expectedOrgValid:      "",
			expectedTMNameValid:   "",
			expectedTMFileMatches: "",
			expectedErrContains:   "only one backend block is allowed",
		},
		{
			name: "wrong backend name",
			fileContent: `
spec_version = "0.1.10"

backend "other-backend" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				// No HTTP calls expected
			},
			expectedOrgValid:      "",
			expectedTMNameValid:   "",
			expectedTMFileMatches: "",
			expectedErrContains:   "expected 'threatcl-cloud'",
		},
		{
			name: "missing organization in backend",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				// No HTTP calls expected
			},
			expectedOrgValid:      "",
			expectedTMNameValid:   "",
			expectedTMFileMatches: "",
			expectedErrContains:   "organization\" is required",
		},
		{
			name: "error fetching user info",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				httpClient.transport.setError("GET", "/api/v1/users/me", fmt.Errorf("network error"))
			},
			expectedOrgValid:      "",
			expectedTMNameValid:   "",
			expectedTMFileMatches: "",
			expectedErrContains:   "error fetching user information",
		},
		{
			name: "error fetching threat model versions",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			setupMocks: func(httpClient *mockHTTPClient, fsSvc *mockFileSystemService) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))

				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK, jsonResponse(threatModel{
					ID:   "tm-123",
					Name: "My TM",
					Slug: "my-tm",
				}))

				httpClient.transport.setError("GET", "/api/v1/org/org-id/models/tm-123/versions", fmt.Errorf("network error"))
			},
			expectedOrgValid:      "org-id",
			expectedTMNameValid:   "my-tm",
			expectedTMFileMatches: "",
			expectedErrContains:   "error fetching threat model versions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile, err := os.CreateTemp("", "test-*.hcl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write([]byte(tt.fileContent)); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			tmpFile.Close()

			// Set up mocks
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()
			tt.setupMocks(httpClient, fsSvc)

			// Load spec config
			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			// Call validateThreatModel
			orgValid, tmNameValid, tmFileMatches, err := validateThreatModel("test-token", tmpFile.Name(), httpClient, fsSvc, cfg)

			// Check return values
			if orgValid != tt.expectedOrgValid {
				t.Errorf("expected orgValid=%v, got %v", tt.expectedOrgValid, orgValid)
			}

			if tmNameValid != tt.expectedTMNameValid {
				t.Errorf("expected tmNameValid=%v, got %v", tt.expectedTMNameValid, tmNameValid)
			}

			if tmFileMatches != tt.expectedTMFileMatches {
				t.Errorf("expected tmFileMatches=%v, got %v", tt.expectedTMFileMatches, tmFileMatches)
			}

			// Check error
			if tt.expectedErrContains != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.expectedErrContains)
				} else if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.expectedErrContains)) {
					t.Errorf("expected error containing %q, got %q", tt.expectedErrContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestCreateThreatModel(t *testing.T) {
	tests := []struct {
		name        string
		modelName   string
		description string
		statusCode  int
		response    string
		httpErr     error
		expectError bool
		errorMsg    string
	}{
		{
			name:        "successful creation with 201",
			modelName:   "Test Model",
			description: "Test Description",
			statusCode:  http.StatusCreated,
			response:    jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model", Description: "Test Description"}),
			expectError: false,
		},
		{
			name:        "successful creation with 200",
			modelName:   "Test Model",
			description: "",
			statusCode:  http.StatusOK,
			response:    jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model"}),
			expectError: false,
		},
		{
			name:        "unauthorized",
			modelName:   "Test Model",
			description: "",
			statusCode:  http.StatusUnauthorized,
			response:    `{"error":"unauthorized"}`,
			expectError: true,
			errorMsg:    "authentication failed",
		},
		{
			name:        "network error",
			modelName:   "Test Model",
			description: "",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
			errorMsg:    "failed to connect",
		},
		{
			name:        "server error",
			modelName:   "Test Model",
			description: "",
			statusCode:  http.StatusInternalServerError,
			response:    `{"error":"server error"}`,
			expectError: true,
			errorMsg:    "API returned status 500",
		},
		{
			name:        "malformed response",
			modelName:   "Test Model",
			description: "",
			statusCode:  http.StatusCreated,
			response:    `invalid json`,
			expectError: true,
			errorMsg:    "failed to parse response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/org/org123/models", tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", "/api/v1/org/org123/models", tt.statusCode, tt.response)
			}

			tm, err := createThreatModel("token", "org123", tt.modelName, tt.description, httpClient, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tm == nil {
					t.Fatalf("expected threat model but got nil")
				}
				if tm.Name != "Test Model" {
					t.Errorf("expected name %q, got %q", "Test Model", tm.Name)
				}
				if tm.ID != "tm123" {
					t.Errorf("expected ID %q, got %q", "tm123", tm.ID)
				}
				if tm.Slug != "test-model" {
					t.Errorf("expected slug %q, got %q", "test-model", tm.Slug)
				}
			}
		})
	}
}

func TestUpdateHCLBackendThreatmodel(t *testing.T) {
	tests := []struct {
		name            string
		initialContent  string
		slug            string
		expectedContent string
		expectError     bool
		errorMsg        string
	}{
		{
			name: "successful update with indentation",
			initialContent: `spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
}
`,
			slug: "my-new-tm",
			expectedContent: `spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-new-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
}
`,
			expectError: false,
		},
		{
			name: "successful update with tabs",
			initialContent: "spec_version = \"0.1.10\"\n\nbackend \"threatcl-cloud\" {\n\torganization = \"test-org\"\n}\n",
			slug:           "test-slug",
			expectedContent: "spec_version = \"0.1.10\"\n\nbackend \"threatcl-cloud\" {\n\torganization = \"test-org\"\n\tthreatmodel = \"test-slug\"\n}\n",
			expectError:    false,
		},
		{
			name: "threatmodel already set",
			initialContent: `spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "existing-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
}
`,
			slug:        "new-slug",
			expectError: true,
			errorMsg:    "already set",
		},
		{
			name: "no organization found",
			initialContent: `spec_version = "0.1.10"

backend "threatcl-cloud" {
}

threatmodel "Test Model" {
  author = "test@example.com"
}
`,
			slug:        "my-slug",
			expectError: true,
			errorMsg:    "could not find organization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile, err := os.CreateTemp("", "test-*.hcl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write([]byte(tt.initialContent)); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			tmpFile.Close()

			// Note: fsSvc is not used for file operations in updateHCLBackendThreatmodel
			// (it reads/writes directly to disk), but we pass it for API compatibility
			fsSvc := newMockFileSystemService()

			err = updateHCLBackendThreatmodel(tmpFile.Name(), tt.slug, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Read the updated content
				updatedContent, err := os.ReadFile(tmpFile.Name())
				if err != nil {
					t.Fatalf("failed to read updated file: %v", err)
				}

				if string(updatedContent) != tt.expectedContent {
					t.Errorf("expected content:\n%s\ngot:\n%s", tt.expectedContent, string(updatedContent))
				}
			}
		})
	}
}
