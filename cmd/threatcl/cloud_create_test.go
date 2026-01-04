package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudCreateRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		token        string
		statusCode   int
		response     string
		httpErr      error
		expectedCode int
		expectedOut  string
		expectError  bool
	}{
		{
			name:         "successful creation with name",
			args:         []string{"-name", "Test Model"},
			token:        "valid-token",
			statusCode:   http.StatusCreated,
			response:     jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model"}),
			expectedCode: 0,
			expectedOut:  "Successfully created threat model 'Test Model'",
		},
		{
			name:         "successful creation with name and description",
			args:         []string{"-name", "Test Model", "-description", "This is a test"},
			token:        "valid-token",
			statusCode:   http.StatusCreated,
			response:     jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model", Description: "This is a test"}),
			expectedCode: 0,
			expectedOut:  "Successfully created threat model 'Test Model'",
		},
		{
			name:         "successful creation with org-id",
			args:         []string{"-name", "Test Model", "-org-id", "org456"},
			token:        "valid-token",
			statusCode:   http.StatusCreated,
			response:     jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model"}),
			expectedCode: 0,
			expectedOut:  "Successfully created threat model 'Test Model'",
		},
		{
			name:         "missing name flag",
			args:         []string{},
			expectedCode: 1,
			expectedOut:  "Error: -name is required",
		},
		{
			name:         "missing token",
			args:         []string{"-name", "Test Model"},
			token:        "",
			expectedCode: 1,
			expectedOut:  "error retrieving token",
		},
		{
			name:         "invalid token",
			args:         []string{"-name", "Test Model"},
			token:        "invalid-token",
			statusCode:   http.StatusUnauthorized,
			response:     `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "network error",
			args:         []string{"-name", "Test Model"},
			token:        "token",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectError:  true,
		},
		{
			name:         "API error",
			args:         []string{"-name", "Test Model"},
			token:        "token",
			statusCode:   http.StatusBadRequest,
			response:     `{"error":"bad request"}`,
			expectedCode: 1,
			expectedOut:  "Error creating threat model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token
			if tt.token != "" {
				keyringSvc.Set("access_token", map[string]interface{}{
					"access_token": tt.token,
				})
			} else {
				keyringSvc.setError(fmt.Errorf("no token"))
			}

			// Set up whoami response for automatic org-id
			if tt.token != "" && !contains(tt.args, "-org-id") {
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
			}

			// Set up HTTP response for create
			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/org/org123/models", tt.httpErr)
				httpClient.transport.setError("POST", "/api/v1/org/org456/models", tt.httpErr)
			} else if tt.statusCode != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/org/org123/models", tt.statusCode, tt.response)
				httpClient.transport.setResponse("POST", "/api/v1/org/org456/models", tt.statusCode, tt.response)
			}

			cmd := testCloudCreateCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudCreateRunWithoutOrgId(t *testing.T) {
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

	// Set up create response
	threatModel := threatModel{
		ID:   "tm1",
		Name: "Test Model",
		Slug: "test-model",
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models", http.StatusCreated, jsonResponse(threatModel))

	cmd := testCloudCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-name", "Test Model"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully created threat model 'Test Model'") {
		t.Errorf("expected success message in output, got %q", out)
	}
}

func TestCloudCreateRunNoOrganizations(t *testing.T) {
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

	cmd := testCloudCreateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-name", "Test Model"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "No organizations found") {
		t.Errorf("expected error message about no organizations, got %q", out)
	}
}

func TestCloudCreateFetchUserInfo(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		statusCode  int
		response    string
		httpErr     error
		expectError bool
	}{
		{
			name:        "successful fetch",
			token:       "valid-token",
			statusCode:  http.StatusOK,
			response:    jsonResponse(whoamiResponse{ID: "user123", User: userInfo{Email: "test@example.com"}}),
			expectError: false,
		},
		{
			name:        "unauthorized",
			token:       "invalid-token",
			statusCode:  http.StatusUnauthorized,
			response:    `{"error":"unauthorized"}`,
			expectError: true,
		},
		{
			name:        "network error",
			token:       "token",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
		},
		{
			name:        "server error",
			token:       "token",
			statusCode:  http.StatusInternalServerError,
			response:    `{"error":"server error"}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/users/me", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", tt.statusCode, tt.response)
			}

			_ = testCloudCreateCommand(t, httpClient, nil, fsSvc)

			resp, err := fetchUserInfo(tt.token, httpClient, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if resp == nil {
					t.Fatalf("expected response but got nil")
				}
				if resp.User.Email != "test@example.com" {
					t.Errorf("expected email %q, got %q", "test@example.com", resp.User.Email)
				}
			}
		})
	}
}

func TestCloudCreateCreateThreatModel(t *testing.T) {
	tests := []struct {
		name        string
		modelName   string
		description string
		statusCode  int
		response    string
		httpErr     error
		expectError bool
	}{
		{
			name:        "successful creation",
			modelName:   "Test Model",
			description: "Test Description",
			statusCode:  http.StatusCreated,
			response:    jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model", Description: "Test Description"}),
			expectError: false,
		},
		{
			name:        "successful creation with OK status",
			modelName:   "Test Model",
			description: "Test Description",
			statusCode:  http.StatusOK,
			response:    jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model", Description: "Test Description"}),
			expectError: false,
		},
		{
			name:        "unauthorized",
			modelName:   "Test Model",
			description: "Test Description",
			statusCode:  http.StatusUnauthorized,
			response:    `{"error":"unauthorized"}`,
			expectError: true,
		},
		{
			name:        "network error",
			modelName:   "Test Model",
			description: "Test Description",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
		},
		{
			name:        "server error",
			modelName:   "Test Model",
			description: "Test Description",
			statusCode:  http.StatusInternalServerError,
			response:    `{"error":"server error"}`,
			expectError: true,
		},
		{
			name:        "bad request",
			modelName:   "Test Model",
			description: "Test Description",
			statusCode:  http.StatusBadRequest,
			response:    `{"error":"bad request"}`,
			expectError: true,
		},
		{
			name:        "malformed JSON response",
			modelName:   "Test Model",
			description: "Test Description",
			statusCode:  http.StatusCreated,
			response:    `invalid json`,
			expectError: true,
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

			_ = testCloudCreateCommand(t, httpClient, nil, fsSvc)

			tm, err := createThreatModel("token", "org123", tt.modelName, tt.description, httpClient, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
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

func TestCloudCreateDisplayOutput(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up whoami response
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

	// Set up create response with description
	threatModel := threatModel{
		ID:          "tm1-123456789012345678901234567890123456",
		Name:        "Test Model",
		Slug:        "test-model",
		Description: "This is a test description",
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models", http.StatusCreated, jsonResponse(threatModel))

	cmd := testCloudCreateCommand(t, httpClient, keyringSvc, fsSvc)

	out := capturer.CaptureOutput(func() {
		cmd.Run([]string{"-name", "Test Model", "-description", "This is a test description"})
	})

	// Check for expected output fields
	expectedFields := []string{
		"Successfully created threat model 'Test Model'",
		"ID: tm1-123456789012345678901234567890123456",
		"Slug: test-model",
		"Description: This is a test description",
	}

	for _, field := range expectedFields {
		if !strings.Contains(out, field) {
			t.Errorf("expected output to contain %q, got %q", field, out)
		}
	}
}

func TestCloudCreateDisplayOutputNoDescription(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Set up token
	keyringSvc.Set("access_token", map[string]interface{}{
		"access_token": "valid-token",
	})

	// Set up whoami response
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

	// Set up create response without description
	threatModel := threatModel{
		ID:   "tm1",
		Name: "Test Model",
		Slug: "test-model",
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models", http.StatusCreated, jsonResponse(threatModel))

	cmd := testCloudCreateCommand(t, httpClient, keyringSvc, fsSvc)

	out := capturer.CaptureOutput(func() {
		cmd.Run([]string{"-name", "Test Model"})
	})

	// Should display success message and ID/Slug but not Description
	if !strings.Contains(out, "Successfully created threat model 'Test Model'") {
		t.Errorf("expected success message in output, got %q", out)
	}
	if !strings.Contains(out, "ID: tm1") {
		t.Errorf("expected ID in output, got %q", out)
	}
	if !strings.Contains(out, "Slug: test-model") {
		t.Errorf("expected slug in output, got %q", out)
	}
	// Should not display Description line when empty
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Description:") {
			t.Errorf("should not display Description line when empty, got: %q", line)
		}
	}
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestCloudCreateWithUpload(t *testing.T) {
	validHCL := `spec_version = "0.1.15"

threatmodel "Test Model" {
  author = "test@example.com"
  description = "A test model"
  
  threat "Test threat" {
    description = "Test threat"
  }
}
`

	tests := []struct {
		name             string
		token            string
		hclContent       string
		createStatus     int
		createResponse   string
		uploadStatus     int
		uploadResponse   string
		createErr        error
		uploadErr        error
		expectedCode     int
		expectedOut      string
		expectedErrorOut string
	}{
		{
			name:           "successful creation and upload",
			token:          "valid-token",
			hclContent:     validHCL,
			createStatus:   http.StatusCreated,
			createResponse: jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model"}),
			uploadStatus:   http.StatusOK,
			uploadResponse: `{"success":true}`,
			expectedCode:   0,
			expectedOut:    "Successfully created threat model 'Test Model'",
		},
		{
			name:             "invalid HCL file",
			token:            "valid-token",
			hclContent:       "invalid hcl content",
			expectedCode:     1,
			expectedErrorOut: "Error parsing HCL file",
		},
		{
			name:  "HCL file with multiple threat models",
			token: "valid-token",
			hclContent: `spec_version = "0.1.15"

threatmodel "Model 1" {
  author = "test@example.com"
}

threatmodel "Model 2" {
  author = "test@example.com"
}
`,
			expectedCode:     1,
			expectedErrorOut: "file must contain exactly one threat model",
		},
		{
			name:  "HCL file with zero threat models",
			token: "valid-token",
			hclContent: `spec_version = "0.1.15"

# Just a comment
`,
			expectedCode:     1,
			expectedErrorOut: "file must contain exactly one threat model",
		},
		{
			name:             "upload fails after successful creation",
			token:            "valid-token",
			hclContent:       validHCL,
			createStatus:     http.StatusCreated,
			createResponse:   jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model"}),
			uploadStatus:     http.StatusBadRequest,
			uploadResponse:   `{"error":"upload failed"}`,
			expectedCode:     1,
			expectedOut:      "Successfully created threat model 'Test Model'",
			expectedErrorOut: "Note: The threat model was created successfully, but the upload failed",
		},
		{
			name:             "upload network error after creation",
			token:            "valid-token",
			hclContent:       validHCL,
			createStatus:     http.StatusCreated,
			createResponse:   jsonResponse(threatModel{ID: "tm123", Name: "Test Model", Slug: "test-model"}),
			uploadErr:        fmt.Errorf("network error"),
			expectedCode:     1,
			expectedOut:      "Successfully created threat model 'Test Model'",
			expectedErrorOut: "Error uploading file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file for the HCL content
			tmpFile, err := os.CreateTemp("", "test-*.hcl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if tt.hclContent != "" {
				if _, err := tmpFile.Write([]byte(tt.hclContent)); err != nil {
					t.Fatalf("failed to write temp file: %v", err)
				}
				tmpFile.Close()
			} else {
				tmpFile.Close()
			}

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token
			if tt.token != "" {
				keyringSvc.Set("access_token", map[string]interface{}{
					"access_token": tt.token,
				})
			} else {
				keyringSvc.setError(fmt.Errorf("no token"))
			}

			// Set up file content for upload (the upload uses fsSvc.ReadFile)
			if tt.hclContent != "" {
				fsSvc.SetFileContent(tmpFile.Name(), []byte(tt.hclContent))
			}

			// Set up whoami response for automatic org-id
			if tt.token != "" {
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
			}

			// Set up HTTP response for create
			if tt.createErr != nil {
				httpClient.transport.setError("POST", "/api/v1/org/org123/models", tt.createErr)
			} else if tt.createStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/org/org123/models", tt.createStatus, tt.createResponse)
			}

			// Set up HTTP response for upload
			if tt.uploadErr != nil {
				httpClient.transport.setError("POST", "/api/v1/org/org123/models/test-model/upload", tt.uploadErr)
			} else if tt.uploadStatus != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/test-model/upload", tt.uploadStatus, tt.uploadResponse)
			}

			cmd := testCloudCreateCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			args := []string{"-name", "Test Model", "-upload", tmpFile.Name()}
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}

			if tt.expectedErrorOut != "" && !strings.Contains(out, tt.expectedErrorOut) {
				t.Errorf("expected output to contain error %q, got %q", tt.expectedErrorOut, out)
			}
		})
	}
}

func TestCloudCreateUploadFile(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		fileContent string
		statusCode  int
		response    string
		httpErr     error
		expectError bool
		errorMsg    string
	}{
		{
			name:        "successful upload",
			filePath:    "test.hcl",
			fileContent: "threatmodel content",
			statusCode:  http.StatusOK,
			response:    `{"success":true}`,
			expectError: false,
		},
		{
			name:        "file not found",
			filePath:    "nonexistent.hcl",
			expectError: true,
			errorMsg:    "failed to read file",
		},
		{
			name:        "unauthorized",
			filePath:    "test.hcl",
			fileContent: "threatmodel content",
			statusCode:  http.StatusUnauthorized,
			response:    `{"error":"unauthorized"}`,
			expectError: true,
			errorMsg:    "authentication failed",
		},
		{
			name:        "threat model not found",
			filePath:    "test.hcl",
			fileContent: "threatmodel content",
			statusCode:  http.StatusNotFound,
			response:    `{"error":"not found"}`,
			expectError: true,
			errorMsg:    "threat model not found",
		},
		{
			name:        "network error",
			filePath:    "test.hcl",
			fileContent: "threatmodel content",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
			errorMsg:    "failed to connect",
		},
		{
			name:        "server error",
			filePath:    "test.hcl",
			fileContent: "threatmodel content",
			statusCode:  http.StatusInternalServerError,
			response:    `{"error":"server error"}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			// Set up file content if provided
			if tt.fileContent != "" {
				fsSvc.SetFileContent(tt.filePath, []byte(tt.fileContent))
			}

			// Set up HTTP response
			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/org/org123/models/test-model/upload", tt.httpErr)
			} else if tt.statusCode != 0 {
				httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/test-model/upload", tt.statusCode, tt.response)
			}

			_ = testCloudCreateCommand(t, httpClient, nil, fsSvc)

			err := uploadFile("token", "org123", "test-model", tt.filePath, httpClient, fsSvc)

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
			}
		})
	}
}
