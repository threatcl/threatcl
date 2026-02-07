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
	"github.com/zenizh/go-capturer"
)

func TestCloudValidateRun(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tests := []struct {
		name         string
		fileContent  string
		createFile   bool
		token        string
		statusCode   int
		response     string
		httpErr      error
		expectedCode int
		expectedOut  string
	}{
		{
			name:        "successful org validation",
			fileContent: validHCL,
			createFile:  true,
			token:       "valid-token",
			statusCode:  http.StatusOK,
			response: jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}),
			expectedCode: 0,
			expectedOut:  "✓ Organization is valid",
		},
		{
			name:         "no file provided",
			expectedCode: 1,
			expectedOut:  "file path is required",
		},
		{
			name:         "file does not exist",
			createFile:   false,
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "error reading file",
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
			createFile:   true,
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "No backend block found",
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
			createFile:   true,
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "only one backend block is allowed",
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
			createFile:   true,
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "expected 'threatcl-cloud'",
		},
		{
			name: "missing organization",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			createFile:   true,
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "organization\" is required",
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
			createFile: true,
			token:      "valid-token",
			statusCode: http.StatusOK,
			response: jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}),
			expectedCode: 1,
			expectedOut:  "not a member of organization 'different-org'",
		},
		{
			name:         "missing token",
			fileContent:  validHCL,
			createFile:   true,
			token:        "",
			expectedCode: 1,
			expectedOut:  "no tokens found",
		},
		{
			name:         "invalid token",
			fileContent:  validHCL,
			createFile:   true,
			token:        "invalid-token",
			statusCode:   http.StatusUnauthorized,
			response:     `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filePath string

			// Create temporary file if needed
			if tt.createFile {
				tmpFile, err := os.CreateTemp("", "test-*.hcl")
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer os.Remove(tmpFile.Name())
				filePath = tmpFile.Name()

				if tt.fileContent != "" {
					if _, err := tmpFile.Write([]byte(tt.fileContent)); err != nil {
						t.Fatalf("failed to write temp file: %v", err)
					}
					tmpFile.Close()
				} else {
					tmpFile.Close()
				}
			} else if tt.name == "file does not exist" {
				filePath = "nonexistent-file.hcl"
			}

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token in new format
			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "test-org-id", "Test Org")
			}

			// Set up HTTP response
			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/users/me", tt.httpErr)
			} else if tt.statusCode != 0 {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", tt.statusCode, tt.response)
			}

			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			cmd := &CloudValidateCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: &GlobalCmdOptions{},
					httpClient:       httpClient,
					keyringSvc:       keyringSvc,
					fsSvc:            fsSvc,
				},
				specCfg: cfg,
			}

			var args []string
			if tt.name == "no file provided" {
				args = []string{}
			} else {
				args = []string{filePath}
			}

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(args)
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

func TestCloudValidateHelp(t *testing.T) {
	cmd := &CloudValidateCommand{}
	help := cmd.Help()

	if !strings.Contains(help, "threatcl cloud validate") {
		t.Error("Help text should contain command name")
	}

	if !strings.Contains(help, "backend") {
		t.Error("Help text should mention backend validation")
	}
}

func TestCloudValidateSynopsis(t *testing.T) {
	cmd := &CloudValidateCommand{}
	synopsis := cmd.Synopsis()

	if synopsis == "" {
		t.Error("Synopsis should not be empty")
	}

	if !strings.Contains(strings.ToLower(synopsis), "validate") {
		t.Error("Synopsis should mention validation")
	}
}

func TestCloudValidateWithThreatModelShort(t *testing.T) {
	tests := []struct {
		name              string
		fileContent       string
		tmShort           string
		threatModelExists bool
		threatModelID     string
		versionsTotal     int
		versions          []threatModelVersion
		expectedCode      int
		expectedOut       string
	}{
		{
			name: "threat model found with matching latest version",
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
			tmShort:           "my-tm",
			threatModelExists: true,
			threatModelID:     "tm-123",
			versionsTotal:     1,
			versions: []threatModelVersion{
				{
					ID:           "v1",
					Version:      "1.0.0",
					SpecFileHash: "", // Will be set to computed hash in test
					IsCurrent:    true,
				},
			},
			expectedCode: 0,
			expectedOut:  "Threat model file matches the latest version",
		},
		{
			name: "threat model found with matching non-latest version",
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
			tmShort:           "my-tm",
			threatModelExists: true,
			threatModelID:     "tm-123",
			versionsTotal:     2,
			versions: []threatModelVersion{
				{
					ID:           "v2",
					Version:      "2.0.0",
					SpecFileHash: "new-hash",
					IsCurrent:    true,
				},
				{
					ID:           "v1",
					Version:      "1.0.0",
					SpecFileHash: "", // Will be set to computed hash in test
					IsCurrent:    false,
				},
			},
			expectedCode: 0,
			expectedOut:  "Local Threat model file (org-id: org-id, model-id: my-tm) matches a cloud threat model, but doesn't match the latest version",
		},
		{
			name: "threat model not found",
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
			tmShort:           "nonexistent-tm",
			threatModelExists: false,
			expectedCode:      1,
			expectedOut:       "backend threatmodel 'nonexistent-tm' not found",
		},
		{
			name: "threat model exists but no versions",
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
			tmShort:           "my-tm",
			threatModelExists: true,
			threatModelID:     "tm-123",
			versionsTotal:     0,
			versions:          []threatModelVersion{},
			expectedCode:      0,
			expectedOut:       "Local Threat model file (org-id: org-id, model-id: my-tm) matches a cloud threat model, but doesn't match the latest version",
		},
		{
			name: "threat model exists but version hash does not match",
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
			tmShort:           "my-tm",
			threatModelExists: true,
			threatModelID:     "tm-123",
			versionsTotal:     1,
			versions: []threatModelVersion{
				{
					ID:           "v1",
					Version:      "1.0.0",
					SpecFileHash: "some-other-hash-that-wont-match",
					IsCurrent:    true,
				},
			},
			expectedCode: 0,
			expectedOut:  "Local Threat model file (org-id: org-id, model-id: my-tm) matches a cloud threat model, but doesn't match the latest version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "test-*.hcl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write([]byte(tt.fileContent)); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			tmpFile.Close()

			// Calculate the actual file hash
			fileContent := []byte(tt.fileContent)
			hashBytes := sha256.Sum256(fileContent)
			fileHash := hex.EncodeToString(hashBytes[:])

			// Update versions with the computed hash if needed
			for i := range tt.versions {
				if tt.versions[i].SpecFileHash == "" {
					tt.versions[i].SpecFileHash = fileHash
				}
			}

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token in new format
			keyringSvc.setMockToken("valid-token", "test-org-id", "Test Org")

			// Set up whoami response
			whoamiResp := whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}
			httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResp))

			// Set up threat model response
			if tt.threatModelExists {
				tm := threatModel{
					ID:   tt.threatModelID,
					Name: "My TM",
					Slug: tt.tmShort,
				}
				httpClient.transport.setResponse("GET", fmt.Sprintf("/api/v1/org/org-id/models/%s", tt.tmShort), http.StatusOK, jsonResponse(tm))

				// Set up versions response
				versionsResp := threatModelVersionsResponse{
					Versions: tt.versions,
					Total:    tt.versionsTotal,
				}
				httpClient.transport.setResponse("GET", fmt.Sprintf("/api/v1/org/org-id/models/%s/versions", tt.threatModelID), http.StatusOK, jsonResponse(versionsResp))
			} else {
				httpClient.transport.setResponse("GET", fmt.Sprintf("/api/v1/org/org-id/models/%s", tt.tmShort), http.StatusNotFound, `{"error":"not found"}`)
			}

			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			cmd := &CloudValidateCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: &GlobalCmdOptions{},
					httpClient:       httpClient,
					keyringSvc:       keyringSvc,
					fsSvc:            fsSvc,
				},
				specCfg: cfg,
			}

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{tmpFile.Name()})
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d\nOutput: %s", tt.expectedCode, code, out)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

func TestCloudValidateAPIErrors(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tests := []struct {
		name         string
		setupMock    func(*mockHTTPClient)
		expectedCode int
		expectedOut  string
	}{
		{
			name: "fetchThreatModel network error",
			setupMock: func(httpClient *mockHTTPClient) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))
				httpClient.transport.setError("GET", "/api/v1/org/org-id/models/my-tm", fmt.Errorf("network error"))
			},
			expectedCode: 1,
			expectedOut:  "error fetching threat models",
		},
		{
			name: "fetchThreatModel unauthorized",
			setupMock: func(httpClient *mockHTTPClient) {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
					User: userInfo{Email: "test@example.com"},
					Organizations: []orgMembership{
						{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
					},
				}))
				httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusUnauthorized, `{"error":"unauthorized"}`)
			},
			expectedCode: 1,
			expectedOut:  "error fetching threat models",
		},
		{
			name: "fetchThreatModelVersions error",
			setupMock: func(httpClient *mockHTTPClient) {
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
				httpClient.transport.setError("GET", "/api/v1/org/org-id/models/tm-123/versions", fmt.Errorf("versions error"))
			},
			expectedCode: 1,
			expectedOut:  "error fetching threat model versions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "test-*.hcl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			tmpFile.Close()

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "test-org-id", "Test Org")

			tt.setupMock(httpClient)

			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			cmd := &CloudValidateCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: &GlobalCmdOptions{},
					httpClient:       httpClient,
					keyringSvc:       keyringSvc,
					fsSvc:            fsSvc,
				},
				specCfg: cfg,
			}

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{tmpFile.Name()})
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

func TestCloudValidateInvalidHCL(t *testing.T) {
	tests := []struct {
		name         string
		fileContent  string
		expectedCode int
		expectedOut  string
	}{
		{
			name: "invalid HCL syntax",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  // Missing closing brace

threatmodel "Test Model" {
  author = "test@example.com"
}
`,
			expectedCode: 1,
			expectedOut:  "error parsing HCL file",
		},
		{
			name: "missing required backend attribute",
			fileContent: `
spec_version = "0.1.10"

backend "threatcl-cloud" {
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`,
			expectedCode: 1,
			expectedOut:  "organization\" is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "test-*.hcl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write([]byte(tt.fileContent)); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			tmpFile.Close()

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token for tests that need to reach validation logic
			keyringSvc.setMockToken("valid-token", "test-org-id", "Test Org")

			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			cmd := &CloudValidateCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: &GlobalCmdOptions{},
					httpClient:       httpClient,
					keyringSvc:       keyringSvc,
					fsSvc:            fsSvc,
				},
				specCfg: cfg,
			}

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{tmpFile.Name()})
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

func TestCloudValidateWithConfig(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tests := []struct {
		name         string
		configFile   string
		configExists bool
		expectedCode int
		expectedOut  string
	}{
		{
			name: "valid config file",
			configFile: `
initiative_sizes = ["Small", "Medium", "Large"]
default_initiative_size = "Medium"
`,
			configExists: true,
			expectedCode: 0,
			expectedOut:  "Organization is valid",
		},
		{
			name:         "config file does not exist",
			configFile:   "",
			configExists: false,
			expectedCode: 1,
			expectedOut:  "Error loading config file",
		},
		{
			name: "invalid config file",
			configFile: `
invalid syntax {{{
`,
			configExists: true,
			expectedCode: 1,
			expectedOut:  "Error loading config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "test-*.hcl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			tmpFile.Close()

			var configPath string
			if tt.configExists {
				configFile, err := os.CreateTemp("", "config-*.hcl")
				if err != nil {
					t.Fatalf("failed to create config file: %v", err)
				}
				defer os.Remove(configFile.Name())
				configPath = configFile.Name()

				if _, err := configFile.Write([]byte(tt.configFile)); err != nil {
					t.Fatalf("failed to write config file: %v", err)
				}
				configFile.Close()
			} else {
				configPath = "/nonexistent/config.hcl"
			}

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "test-org-id", "Test Org")

			httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}))

			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			cmd := &CloudValidateCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: &GlobalCmdOptions{},
					httpClient:       httpClient,
					keyringSvc:       keyringSvc,
					fsSvc:            fsSvc,
				},
				specCfg: cfg,
			}

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-config", configPath, tmpFile.Name()})
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
