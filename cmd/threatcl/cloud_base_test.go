package main

import (
	"net/http"
	"testing"
)

func TestResolveOrgId(t *testing.T) {
	tests := []struct {
		name          string
		flagOrgId     string
		envOrgId      string
		userOrgs      []orgMembership
		expectedOrgId string
		expectError   bool
		errorContains string
	}{
		{
			name:          "flag takes priority over env and user orgs",
			flagOrgId:     "flag-org-id",
			envOrgId:      "env-org-id",
			userOrgs:      []orgMembership{{Organization: orgInfo{ID: "user-org-id"}}},
			expectedOrgId: "flag-org-id",
			expectError:   false,
		},
		{
			name:          "env var used when flag is empty",
			flagOrgId:     "",
			envOrgId:      "env-org-id",
			userOrgs:      []orgMembership{{Organization: orgInfo{ID: "user-org-id"}}},
			expectedOrgId: "env-org-id",
			expectError:   false,
		},
		{
			name:          "first user org used when flag and env are empty",
			flagOrgId:     "",
			envOrgId:      "",
			userOrgs:      []orgMembership{{Organization: orgInfo{ID: "user-org-id"}}},
			expectedOrgId: "user-org-id",
			expectError:   false,
		},
		{
			name:      "first user org from multiple orgs",
			flagOrgId: "",
			envOrgId:  "",
			userOrgs: []orgMembership{
				{Organization: orgInfo{ID: "first-org"}},
				{Organization: orgInfo{ID: "second-org"}},
			},
			expectedOrgId: "first-org",
			expectError:   false,
		},
		{
			name:          "error when no orgs and no flag/env",
			flagOrgId:     "",
			envOrgId:      "",
			userOrgs:      []orgMembership{},
			expectError:   true,
			errorContains: "No organizations found",
		},
		{
			name:          "env var works even when user has no orgs",
			flagOrgId:     "",
			envOrgId:      "env-org-id",
			userOrgs:      []orgMembership{},
			expectedOrgId: "env-org-id",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			// Set env var if provided
			if tt.envOrgId != "" {
				fsSvc.setEnv("THREATCL_CLOUD_ORG", tt.envOrgId)
			}

			// Setup whoami response (only needed when falling back to user orgs)
			whoamiResp := whoamiResponse{
				ID:            "user-123",
				User:          userInfo{ID: "user-123", Email: "test@example.com"},
				Organizations: tt.userOrgs,
			}
			httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResp))

			// Create command base
			base := &CloudCommandBase{
				GlobalCmdOptions: &GlobalCmdOptions{},
				httpClient:       httpClient,
				fsSvc:            fsSvc,
			}

			// Call resolveOrgId
			orgId, err := base.resolveOrgId("test-token", tt.flagOrgId, httpClient, fsSvc)

			// Check results
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorContains != "" && !containsString(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if orgId != tt.expectedOrgId {
					t.Errorf("expected org ID %q, got %q", tt.expectedOrgId, orgId)
				}
			}
		})
	}
}

func TestGetTokenAndOrgId(t *testing.T) {
	tests := []struct {
		name           string
		envToken       string
		envOrgId       string
		flagOrgId      string
		storeToken     bool // whether to set up a token in the store
		storeOrgId     string
		storeOrgToken  string
		expectedToken  string
		expectedOrgId  string
		expectError    bool
	}{
		{
			name:          "env token bypasses token store",
			envToken:      "env-api-token",
			storeToken:    true,
			storeOrgId:    "store-org",
			storeOrgToken: "store-token",
			expectedToken: "env-api-token",
			expectedOrgId: "",
		},
		{
			name:          "env token with flag org-id",
			envToken:      "env-api-token",
			flagOrgId:     "flag-org-id",
			expectedToken: "env-api-token",
			expectedOrgId: "flag-org-id",
		},
		{
			name:          "env token with THREATCL_CLOUD_ORG",
			envToken:      "env-api-token",
			envOrgId:      "env-org-id",
			expectedToken: "env-api-token",
			expectedOrgId: "env-org-id",
		},
		{
			name:          "env token with flag org-id takes priority over env org",
			envToken:      "env-api-token",
			flagOrgId:     "flag-org-id",
			envOrgId:      "env-org-id",
			expectedToken: "env-api-token",
			expectedOrgId: "flag-org-id",
		},
		{
			name:          "env token with no org returns empty orgId",
			envToken:      "env-api-token",
			expectedToken: "env-api-token",
			expectedOrgId: "",
		},
		{
			name:          "no env token falls through to token store",
			storeToken:    true,
			storeOrgId:    "store-org",
			storeOrgToken: "store-token",
			expectedToken: "store-token",
			expectedOrgId: "store-org",
		},
		{
			name:        "no env token and no store returns error",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set env vars
			if tt.envToken != "" {
				fsSvc.setEnv("THREATCL_API_TOKEN", tt.envToken)
			}
			if tt.envOrgId != "" {
				fsSvc.setEnv("THREATCL_CLOUD_ORG", tt.envOrgId)
			}

			// Set up token store if requested
			if tt.storeToken {
				err := setTokenForOrg(tt.storeOrgId, tt.storeOrgToken, "bearer", "Test Org", nil, keyringSvc, fsSvc)
				if err != nil {
					t.Fatalf("failed to set up token store: %v", err)
				}
			}

			base := &CloudCommandBase{
				GlobalCmdOptions: &GlobalCmdOptions{},
			}

			token, orgId, err := base.getTokenAndOrgId(tt.flagOrgId, keyringSvc, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if token != tt.expectedToken {
					t.Errorf("expected token %q, got %q", tt.expectedToken, token)
				}
				if orgId != tt.expectedOrgId {
					t.Errorf("expected org ID %q, got %q", tt.expectedOrgId, orgId)
				}
			}
		})
	}
}

// containsString checks if s contains substr
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
