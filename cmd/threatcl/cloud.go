package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/mitchellh/cli"
)

type CloudCommand struct {
}

func (c *CloudCommand) Help() string {
	helpText := `
Usage: threatcl cloud <subcommand>

	This command is used to interact with ThreatCL Cloud services

Subcommands:
	login        Authenticate with ThreatCL Cloud
	whoami       Display current authenticated user information
	threatmodels List threat models for an organization

`
	return strings.TrimSpace(helpText)
}

func (c *CloudCommand) Run(args []string) int {
	return cli.RunResultHelp
}

func (c *CloudCommand) Synopsis() string {
	return "Interact with ThreatCL Cloud services"
}

// JSON type definitions for API responses

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   *int   `json:"expires_in,omitempty"`
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Status  int    `json:"status"`
	} `json:"error"`
}

type whoamiResponse struct {
	ID            string          `json:"id"`
	User          userInfo        `json:"user"`
	Organizations []orgMembership `json:"organizations"`
}

type userInfo struct {
	ID                  string                 `json:"id"`
	Email               string                 `json:"email"`
	EmailVerified       bool                   `json:"email_verified"`
	FullName            string                 `json:"full_name"`
	AvatarURL           string                 `json:"avatar_url"`
	FailedLoginAttempts int                    `json:"failed_login_attempts"`
	Settings            map[string]interface{} `json:"settings"`
	CreatedAt           string                 `json:"created_at"`
	UpdatedAt           string                 `json:"updated_at"`
}

type orgMembership struct {
	Organization orgInfo `json:"organization"`
	Role         string  `json:"role"`
	JoinedAt     string  `json:"joined_at"`
}

type orgInfo struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Slug             string                 `json:"slug"`
	SubscriptionTier string                 `json:"subscription_tier"`
	MaxUsers         int                    `json:"max_users"`
	MaxThreatModels  int                    `json:"max_threat_models"`
	MaxStorageMB     int                    `json:"max_storage_mb"`
	Settings         map[string]interface{} `json:"settings"`
	CreatedAt        string                 `json:"created_at"`
	UpdatedAt        string                 `json:"updated_at"`
}

type threatModel struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organization_id"`
	Name           string   `json:"name"`
	Slug           string   `json:"slug"`
	Description    string   `json:"description"`
	Status         string   `json:"status"`
	Version        string   `json:"version"`
	SpecFilePath   string   `json:"spec_file_path"`
	ThreatCount    int      `json:"threat_count"`
	ControlCount   int      `json:"control_count"`
	DataFlowCount  int      `json:"data_flow_count"`
	Tags           []string `json:"tags"`
	CreatedBy      string   `json:"created_by"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

// Helper functions

// getAPIBaseURL returns the API base URL from environment variable or default
func getAPIBaseURL() string {
	apiURL := os.Getenv("THREATCL_API_URL")
	if apiURL != "" {
		// Remove trailing slash if present
		return strings.TrimSuffix(apiURL, "/")
	}
	return "https://api.threatcl.com"
}

// getToken retrieves the access token from keyring or file
func getToken() (string, error) {
	// Try keyring first
	token, err := getTokenFromKeyring()
	if err == nil {
		return token, nil
	}

	// Fall back to file
	return getTokenFromFile()
}

// validateToken checks if a token is valid by making a lightweight API call
// Returns true if token is valid, false if invalid/expired, and error for network issues
func validateToken(token string) (bool, error) {
	url := fmt.Sprintf("%s/api/v1/users/me", getAPIBaseURL())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		// Network error - unable to validate, not necessarily invalid
		return false, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// Token is invalid or expired
		return false, nil
	}

	// Other status codes - treat as unable to validate
	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func getTokenFromKeyring() (string, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: "threatcl",
	})
	if err != nil {
		return "", fmt.Errorf("failed to open keyring: %w", err)
	}

	item, err := ring.Get("access_token")
	if err != nil {
		return "", fmt.Errorf("failed to get token from keyring: %w", err)
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(item.Data, &tokenData); err != nil {
		return "", fmt.Errorf("failed to parse token data: %w", err)
	}

	accessToken, ok := tokenData["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token format in keyring")
	}

	return accessToken, nil
}

func getTokenFromFile() (string, error) {
	// Determine config directory
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			return "", fmt.Errorf("could not determine home directory")
		}
		configDir = filepath.Join(homeDir, ".config")
	}

	settingsPath := filepath.Join(configDir, "threatcl", "settings.json")

	// Check if file exists
	if _, err := os.Stat(settingsPath); os.IsNotExist(err) {
		return "", fmt.Errorf("no token found - please run 'threatcl cloud login' first")
	}

	// Read file
	settingsJSON, err := os.ReadFile(settingsPath)
	if err != nil {
		return "", fmt.Errorf("failed to read settings file: %w", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(settingsJSON, &settings); err != nil {
		return "", fmt.Errorf("failed to parse settings file: %w", err)
	}

	accessToken, ok := settings["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token format in settings file")
	}

	return accessToken, nil
}
