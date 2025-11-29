package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudWhoamiRun(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		statusCode   int
		response     string
		httpErr      error
		expectedCode int
		expectedOut  string
		expectError  bool
	}{
		{
			name:         "successful user info",
			token:        "valid-token",
			statusCode:   http.StatusOK,
			response:     jsonResponse(whoamiResponse{User: userInfo{Email: "test@example.com", FullName: "Test User"}}),
			expectedCode: 0,
			expectedOut:  "test@example.com",
		},
		{
			name:         "missing token",
			token:        "",
			expectedCode: 1,
			expectedOut:  "Error retrieving token",
		},
		{
			name:         "invalid token",
			token:        "invalid-token",
			statusCode:   http.StatusUnauthorized,
			response:     `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "network error",
			token:        "token",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectError:  true,
		},
		{
			name:         "malformed JSON",
			token:        "token",
			statusCode:   http.StatusOK,
			response:     `invalid json`,
			expectedCode: 1,
			expectError:  true,
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

			// Set up HTTP response
			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/users/me", tt.httpErr)
			} else if tt.statusCode != 0 {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", tt.statusCode, tt.response)
			}

			cmd := testCloudWhoamiCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudWhoamiFetchUserInfo(t *testing.T) {
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

			cmd := testCloudWhoamiCommand(t, httpClient, nil, fsSvc)

			resp, err := cmd.fetchUserInfo(tt.token, httpClient, fsSvc)

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

func TestCloudWhoamiDisplayUserInfo(t *testing.T) {
	resp := &whoamiResponse{
		ID: "user123",
		User: userInfo{
			ID:            "user123",
			Email:         "test@example.com",
			EmailVerified: true,
			FullName:      "Test User",
			AvatarURL:     "https://example.com/avatar.jpg",
			CreatedAt:     "2024-01-01T00:00:00Z",
			UpdatedAt:     "2024-01-02T00:00:00Z",
		},
		Organizations: []orgMembership{
			{
				Organization: orgInfo{
					ID:               "org123",
					Name:             "Test Org",
					Slug:             "test-org",
					SubscriptionTier: "pro",
					MaxUsers:         10,
					MaxThreatModels:  100,
					MaxStorageMB:     1000,
				},
				Role:     "admin",
				JoinedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	cmd := testCloudWhoamiCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayUserInfo(resp)
	})

	// Check for key information
	expectedFields := []string{
		"test@example.com",
		"Test User",
		"Test Org",
		"test-org",
		"admin",
		"pro",
	}

	for _, field := range expectedFields {
		if !strings.Contains(out, field) {
			t.Errorf("expected output to contain %q, got %q", field, out)
		}
	}
}

func TestCloudWhoamiDisplayUserInfoNoOrgs(t *testing.T) {
	resp := &whoamiResponse{
		ID: "user123",
		User: userInfo{
			Email:    "test@example.com",
			FullName: "Test User",
		},
		Organizations: []orgMembership{},
	}

	cmd := testCloudWhoamiCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayUserInfo(resp)
	})

	// Should still display user info
	if !strings.Contains(out, "test@example.com") {
		t.Errorf("expected user email in output, got %q", out)
	}

	// Should not display organizations section
	if strings.Contains(out, "Organizations:") {
		t.Errorf("should not display organizations section when empty")
	}
}

func TestCloudWhoamiDisplayUserInfoEmailNotVerified(t *testing.T) {
	resp := &whoamiResponse{
		User: userInfo{
			Email:         "test@example.com",
			EmailVerified: false,
		},
	}

	cmd := testCloudWhoamiCommand(t, nil, nil, nil)

	out := capturer.CaptureStdout(func() {
		cmd.displayUserInfo(resp)
	})

	// Should display email without checkmark
	if !strings.Contains(out, "test@example.com") {
		t.Errorf("expected email in output, got %q", out)
	}

	// Should not have checkmark
	if strings.Contains(out, "✓") {
		t.Errorf("should not display checkmark for unverified email")
	}
}
