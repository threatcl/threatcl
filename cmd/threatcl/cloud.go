package main

import (
	"encoding/json"
	"fmt"
	"io"
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
	MaxStorageKB     int                    `json:"max_storage_kb"`
	CurUsers         int                    `json:"cur_users"`
	CurThreatModels  int                    `json:"cur_threat_models"`
	CurStorageKB     int                    `json:"cur_storage_kb"`
	Settings         map[string]interface{} `json:"settings"`
	CreatedAt        string                 `json:"created_at"`
	UpdatedAt        string                 `json:"updated_at"`
}

type threatModel struct {
	ID                        string   `json:"id"`
	OrganizationID            string   `json:"organization_id"`
	Name                      string   `json:"name"`
	Slug                      string   `json:"slug"`
	Description               string   `json:"description"`
	Status                    string   `json:"status"`
	Version                   string   `json:"version"`
	SpecFilePath              string   `json:"spec_file_path"`
	AssetCount                int      `json:"asset_count"`
	ThreatCount               int      `json:"threat_count"`
	ControlCount              int      `json:"control_count"`
	DataFlowCount             int      `json:"data_flow_count"`
	UseCaseCount              int      `json:"use_case_count"`
	ExclusionCount            int      `json:"exclusion_count"`
	ThirdPartyDependencyCount int      `json:"tpd_count"`
	Tags                      []string `json:"tags"`
	CreatedBy                 string   `json:"created_by"`
	CreatedAt                 string   `json:"created_at"`
	UpdatedAt                 string   `json:"updated_at"`
}

type threatModelVersion struct {
	ID                        string `json:"id"`
	IsCurrent                 bool   `json:"is_current"`
	ThreatModelID             string `json:"threat_model_id"`
	Version                   string `json:"version"`
	SpecFilePath              string `json:"spec_file_path"`
	SpecFileSizeBytes         int    `json:"spec_file_size_bytes"`
	SpecFileHash              string `json:"spec_file_hash"`
	AssetCount                int    `json:"asset_count"`
	ThreatCount               int    `json:"threat_count"`
	ControlCount              int    `json:"control_count"`
	DataFlowCount             int    `json:"data_flow_count"`
	UseCaseCount              int    `json:"use_case_count"`
	ExclusionCount            int    `json:"exclusion_count"`
	ThirdPartyDependencyCount int    `json:"tpd_count"`
	CreatedAt                 string `json:"created_at"`
	ChangedBy                 string `json:"changed_by"`
}

type threatModelVersionsResponse struct {
	Versions []threatModelVersion `json:"versions"`
	Total    int                  `json:"total"`
}

// Interfaces for dependency injection (testing)

// HTTPClient interface for HTTP operations
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

// KeyringService interface for keyring operations
type KeyringService interface {
	Get(key string) (string, error)
	Set(key string, data map[string]interface{}) error
}

// FileSystemService interface for file system operations
type FileSystemService interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Stat(path string) (os.FileInfo, error)
	Getenv(key string) string
}

// Default implementations

// defaultHTTPClient wraps http.Client to implement HTTPClient interface
type defaultHTTPClient struct {
	client *http.Client
}

func (d *defaultHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return d.client.Do(req)
}

func (d *defaultHTTPClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return http.Post(url, contentType, body)
}

// defaultKeyringService wraps keyring to implement KeyringService interface
type defaultKeyringService struct{}

func (d *defaultKeyringService) Get(key string) (string, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName:  "threatcl",
		KeychainName: "threatcl",
	})
	if err != nil {
		return "", fmt.Errorf("failed to open keyring: %w", err)
	}

	item, err := ring.Get(key)
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

func (d *defaultKeyringService) Set(key string, data map[string]interface{}) error {
	ring, err := keyring.Open(keyring.Config{
		ServiceName:  "threatcl",
		KeychainName: "threatcl",
	})
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	tokenJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	err = ring.Set(keyring.Item{
		Key:  key,
		Data: tokenJSON,
	})
	if err != nil {
		return fmt.Errorf("failed to save to keyring: %w", err)
	}

	return nil
}

// defaultFileSystemService wraps os operations to implement FileSystemService interface
type defaultFileSystemService struct{}

func (d *defaultFileSystemService) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (d *defaultFileSystemService) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (d *defaultFileSystemService) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (d *defaultFileSystemService) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (d *defaultFileSystemService) Getenv(key string) string {
	return os.Getenv(key)
}

// Helper functions

// getAPIBaseURL returns the API base URL from environment variable or default
// If fsSvc is nil, uses default implementation for backward compatibility
func getAPIBaseURL(fsSvc FileSystemService) string {
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}
	apiURL := fsSvc.Getenv("THREATCL_API_URL")
	if apiURL != "" {
		// Remove trailing slash if present
		return strings.TrimSuffix(apiURL, "/")
	}
	return "https://api.threatcl.com"
}

// getToken retrieves the access token from keyring or file
// If services are nil, uses default implementations for backward compatibility
func getToken(keyringSvc KeyringService, fsSvc FileSystemService) (string, error) {
	// Use default implementations if not provided
	if keyringSvc == nil {
		keyringSvc = &defaultKeyringService{}
	}
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}

	// Try keyring first
	token, err := getTokenFromKeyring(keyringSvc)
	if err == nil {
		return token, nil
	}

	// Fall back to file
	return getTokenFromFile(fsSvc)
}

// validateToken checks if a token is valid by making a lightweight API call
// Returns true if token is valid, false if invalid/expired, and error for network issues
// If httpClient is nil, uses default implementation for backward compatibility
func validateToken(token string, httpClient HTTPClient, fsSvc FileSystemService) (bool, error) {
	// Use default implementations if not provided
	if httpClient == nil {
		httpClient = &defaultHTTPClient{
			client: &http.Client{
				Timeout: 5 * time.Second,
			},
		}
	}
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}

	url := fmt.Sprintf("%s/api/v1/users/me", getAPIBaseURL(fsSvc))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
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

func getTokenFromKeyring(keyringSvc KeyringService) (string, error) {
	return keyringSvc.Get("access_token")
}

func getTokenFromFile(fsSvc FileSystemService) (string, error) {
	// Determine config directory
	configDir := fsSvc.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		homeDir := fsSvc.Getenv("HOME")
		if homeDir == "" {
			return "", fmt.Errorf("could not determine home directory")
		}
		configDir = filepath.Join(homeDir, ".config")
	}

	settingsPath := filepath.Join(configDir, "threatcl", "settings.json")

	// Check if file exists
	if _, err := fsSvc.Stat(settingsPath); os.IsNotExist(err) {
		return "", fmt.Errorf("no token found - please run 'threatcl cloud login' first")
	}

	// Read file
	settingsJSON, err := fsSvc.ReadFile(settingsPath)
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
