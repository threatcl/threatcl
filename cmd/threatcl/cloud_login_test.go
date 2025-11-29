package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zenizh/go-capturer"
)

func TestCloudLoginRunAlreadyAuthenticated(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		validToken   bool
		validateErr  error
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "valid existing token",
			token:        "valid-token",
			validToken:   true,
			expectedCode: 1,
			expectedOut:  "already authenticated",
		},
		{
			name:         "invalid existing token",
			token:        "invalid-token",
			validToken:   false,
			expectedCode: 0, // Should proceed with login
		},
		{
			name:         "validation network error",
			token:        "token",
			validateErr:  fmt.Errorf("network error"),
			expectedCode: 0, // Should proceed with warning
			expectedOut:  "Warning",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token in keyring
			if tt.token != "" {
				keyringSvc.Set("access_token", map[string]interface{}{
					"access_token": tt.token,
				})
			}

			// Set up token validation response
			if tt.validateErr != nil {
				httpClient.transport.setError("GET", "/api/v1/users/me", tt.validateErr)
			} else {
				statusCode := http.StatusUnauthorized
				if tt.validToken {
					statusCode = http.StatusOK
				}
				httpClient.transport.setResponse("GET", "/api/v1/users/me", statusCode, `{"id":"user123"}`)
			}

			// If login should proceed (invalid token or network error), set up device flow
			if !tt.validToken || tt.validateErr != nil {
				// Device code response
				deviceResp := deviceCodeResponse{
					DeviceCode:      "device-code-123",
					ExpiresIn:       600,
					Interval:        1, // Fast for testing
					UserCode:        "ABC-123",
					VerificationURL: "https://example.com/verify",
				}
				httpClient.transport.setResponse("POST", "/api/v1/auth/device", http.StatusOK, jsonResponse(deviceResp))

				// Token poll response
				tokenResp := tokenResponse{
					AccessToken: "access-token-123",
					TokenType:   "Bearer",
				}
				httpClient.transport.setResponse("POST", "/api/v1/auth/device/poll", http.StatusOK, jsonResponse(tokenResp))

				// Set up file system for token save
				fsSvc.setEnv("HOME", "/tmp")
				fsSvc.MkdirAll("/tmp/.config/threatcl", 0755)
			}

			cmd := testCloudLoginCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{})
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

func TestCloudLoginRunSuccessfulFlow(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// No existing token (don't set any token, Get will fail naturally)

	// Set up file system for token save
	fsSvc.setEnv("HOME", "/tmp")
	fsSvc.MkdirAll("/tmp/.config/threatcl", 0755)

	// Device code response
	deviceResp := deviceCodeResponse{
		DeviceCode:      "device-code-123",
		ExpiresIn:       600,
		Interval:        1, // Fast for testing
		UserCode:        "ABC-123",
		VerificationURL: "https://example.com/verify",
	}
	httpClient.transport.setResponse("POST", "/api/v1/auth/device", http.StatusOK, jsonResponse(deviceResp))

	// Token poll response (success on first try)
	tokenResp := tokenResponse{
		AccessToken: "access-token-123",
		TokenType:   "Bearer",
		ExpiresIn:   intPtr(3600),
	}
	httpClient.transport.setResponse("POST", "/api/v1/auth/device/poll", http.StatusOK, jsonResponse(tokenResp))

	cmd := testCloudLoginCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Successfully authenticated") {
		t.Errorf("expected success message, got %q", out)
	}

	// Verify token was saved to keyring
	token, err := keyringSvc.Get("access_token")
	if err != nil {
		t.Errorf("token should be saved to keyring: %v", err)
	}
	if token != "access-token-123" {
		t.Errorf("expected token %q, got %q", "access-token-123", token)
	}
}

func TestCloudLoginRunDeviceCodeFailure(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// No existing token
	keyringSvc.setError(fmt.Errorf("no token"))

	// Device code request fails
	httpClient.transport.setError("POST", "/api/v1/auth/device", fmt.Errorf("API error"))

	cmd := testCloudLoginCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Error requesting device code") {
		t.Errorf("expected error message, got %q", out)
	}
}

func TestCloudLoginRunPollingTimeout(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// No existing token
	keyringSvc.setError(fmt.Errorf("no token"))

	// Device code response with short expiration
	deviceResp := deviceCodeResponse{
		DeviceCode:      "device-code-123",
		ExpiresIn:       1, // 1 second expiration
		Interval:        1,
		UserCode:        "ABC-123",
		VerificationURL: "https://example.com/verify",
	}
	httpClient.transport.setResponse("POST", "/api/v1/auth/device", http.StatusOK, jsonResponse(deviceResp))

	// Polling returns authorization_pending
	errResp := errorResponse{}
	errResp.Error.Code = "authorization_pending"
	errResp.Error.Message = "Authorization pending"
	httpClient.transport.setResponse("POST", "/api/v1/auth/device/poll", http.StatusBadRequest, jsonResponse(errResp))

	cmd := testCloudLoginCommand(t, httpClient, keyringSvc, fsSvc)

	// Wait for timeout
	time.Sleep(2 * time.Second)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "timed out") {
		t.Errorf("expected timeout error, got %q", out)
	}
}

func TestCloudLoginRunKeyringFallback(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// No existing token
	keyringSvc.setError(fmt.Errorf("no token"))

	// Device code response
	deviceResp := deviceCodeResponse{
		DeviceCode:      "device-code-123",
		ExpiresIn:       600,
		Interval:        5,
		UserCode:        "ABC-123",
		VerificationURL: "https://example.com/verify",
	}
	httpClient.transport.setResponse("POST", "/api/v1/auth/device", http.StatusOK, jsonResponse(deviceResp))

	// Token poll response
	tokenResp := tokenResponse{
		AccessToken: "access-token-123",
		TokenType:   "Bearer",
	}
	httpClient.transport.setResponse("POST", "/api/v1/auth/device/poll", http.StatusOK, jsonResponse(tokenResp))

	// Keyring save fails
	keyringSvc.setError(fmt.Errorf("keyring error"))

	// Set up file system
	fsSvc.setEnv("HOME", "/tmp")
	fsSvc.MkdirAll("/tmp/.config/threatcl", 0755)

	cmd := testCloudLoginCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "falling back to file storage") {
		t.Errorf("expected fallback message, got %q", out)
	}

	// Verify token was saved to file
	settingsPath := filepath.Join("/tmp", ".config", "threatcl", "settings.json")
	data, err := fsSvc.ReadFile(settingsPath)
	if err != nil {
		t.Errorf("token should be saved to file: %v", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("failed to parse settings: %v", err)
	}

	if settings["access_token"] != "access-token-123" {
		t.Errorf("expected token in file, got %v", settings)
	}
}

func TestCloudLoginRequestDeviceCode(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		response    string
		httpErr     error
		expectError bool
	}{
		{
			name:        "successful request",
			statusCode:  http.StatusOK,
			response:    jsonResponse(deviceCodeResponse{DeviceCode: "code", UserCode: "123"}),
			expectError: false,
		},
		{
			name:        "API error",
			statusCode:  http.StatusInternalServerError,
			response:    `{"error":"server error"}`,
			expectError: true,
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/auth/device", tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", "/api/v1/auth/device", tt.statusCode, tt.response)
			}

			cmd := testCloudLoginCommand(t, httpClient, nil, fsSvc)

			resp, err := cmd.requestDeviceCode(httpClient, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if resp == nil {
					t.Errorf("expected response but got nil")
				}
			}
		})
	}
}

func TestCloudLoginPollForToken(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	deviceResp := &deviceCodeResponse{
		DeviceCode: "device-code-123",
		ExpiresIn:  600,
		Interval:   1, // 1 second for faster testing
	}

	// First poll: authorization_pending
	errResp1 := errorResponse{}
	errResp1.Error.Code = "authorization_pending"
	httpClient.transport.setResponse("POST", "/api/v1/auth/device/poll", http.StatusBadRequest, jsonResponse(errResp1))

	// Second poll: success
	tokenResp := tokenResponse{
		AccessToken: "access-token-123",
		TokenType:   "Bearer",
	}
	httpClient.transport.setResponse("POST", "/api/v1/auth/device/poll", http.StatusOK, jsonResponse(tokenResp))

	cmd := testCloudLoginCommand(t, httpClient, nil, fsSvc)

	// Poll should succeed on second attempt
	resp, err := cmd.pollForToken(deviceResp, httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatalf("expected token response but got nil")
	}

	if resp.AccessToken != "access-token-123" {
		t.Errorf("expected token %q, got %q", "access-token-123", resp.AccessToken)
	}
}

func TestCloudLoginSaveToken(t *testing.T) {
	tokenResp := &tokenResponse{
		AccessToken: "access-token-123",
		TokenType:   "Bearer",
		ExpiresIn:   intPtr(3600),
	}

	t.Run("save to keyring", func(t *testing.T) {
		keyringSvc := newMockKeyringService()
		fsSvc := newMockFileSystemService()

		cmd := testCloudLoginCommand(t, nil, keyringSvc, fsSvc)

		err := cmd.saveToken(tokenResp, keyringSvc, fsSvc)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify token was saved
		token, err := keyringSvc.Get("access_token")
		if err != nil {
			t.Errorf("token should be saved: %v", err)
		}
		if token != "access-token-123" {
			t.Errorf("expected token %q, got %q", "access-token-123", token)
		}
	})

	t.Run("fallback to file when keyring fails", func(t *testing.T) {
		keyringSvc := newMockKeyringService()
		keyringSvc.setError(fmt.Errorf("keyring error"))
		fsSvc := newMockFileSystemService()
		fsSvc.setEnv("HOME", "/tmp")
		fsSvc.MkdirAll("/tmp/.config/threatcl", 0755)

		cmd := testCloudLoginCommand(t, nil, keyringSvc, fsSvc)

		err := cmd.saveToken(tokenResp, keyringSvc, fsSvc)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify token was saved to file
		settingsPath := filepath.Join("/tmp", ".config", "threatcl", "settings.json")
		data, err := fsSvc.ReadFile(settingsPath)
		if err != nil {
			t.Errorf("token should be saved to file: %v", err)
		}

		var settings map[string]interface{}
		if err := json.Unmarshal(data, &settings); err != nil {
			t.Fatalf("failed to parse settings: %v", err)
		}

		if settings["access_token"] != "access-token-123" {
			t.Errorf("expected token in file, got %v", settings)
		}
	})
}

func TestCloudLoginDisplayVerificationInstructions(t *testing.T) {
	deviceResp := &deviceCodeResponse{
		VerificationURL: "https://example.com/verify",
		UserCode:        "ABC-123",
	}

	cmd := testCloudLoginCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayVerificationInstructions(deviceResp)
	})

	if !strings.Contains(out, "https://example.com/verify") {
		t.Errorf("expected verification URL in output, got %q", out)
	}

	if !strings.Contains(out, "ABC-123") {
		t.Errorf("expected user code in output, got %q", out)
	}
}

// Helper function
func intPtr(i int) *int {
	return &i
}
