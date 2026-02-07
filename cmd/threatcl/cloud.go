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
	AccessToken    string `json:"access_token"`
	TokenType      string `json:"token_type"`
	OrganizationID string `json:"organization_id"`
	ExpiresAt      *int64 `json:"expires_at,omitempty"`
}

// Token store types for multi-org token management

// tokenStore holds all tokens and configuration for multi-org support
type tokenStore struct {
	Version    int                     `json:"version"`
	DefaultOrg string                  `json:"default_org,omitempty"`
	Tokens     map[string]orgTokenData `json:"tokens"`
}

// orgTokenData holds token data for a specific organization
type orgTokenData struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresAt   *int64 `json:"expires_at,omitempty"`
	OrgName     string `json:"org_name,omitempty"`
}

// tokenStoreVersion is the current version of the token store format
const tokenStoreVersion = 2

// tokenStoreKeyringKey is the key used to store the token store in keyring
const tokenStoreKeyringKey = "token_store"

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Status  int    `json:"status"`
	} `json:"error"`
}

type whoamiResponse struct {
	ID                       string          `json:"id"`
	User                     userInfo        `json:"user"`
	Organizations            []orgMembership `json:"organizations"`
	ApiTokenOrganizationID   string          `json:"api_token_organization_id,omitempty"`
	ApiTokenOrganizationName string          `json:"api_token_organization_name,omitempty"`
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
	GetRaw(key string) ([]byte, error)
	Set(key string, data map[string]interface{}) error
	SetRaw(key string, data []byte) error
	Delete(key string) error
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

func (d *defaultKeyringService) openKeyring() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName: "threatcl",
	})
}

func (d *defaultKeyringService) Get(key string) (string, error) {
	ring, err := d.openKeyring()
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

func (d *defaultKeyringService) GetRaw(key string) ([]byte, error) {
	ring, err := d.openKeyring()
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	item, err := ring.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get data from keyring: %w", err)
	}

	return item.Data, nil
}

func (d *defaultKeyringService) Set(key string, data map[string]interface{}) error {
	tokenJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	return d.SetRaw(key, tokenJSON)
}

func (d *defaultKeyringService) SetRaw(key string, data []byte) error {
	ring, err := d.openKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	err = ring.Set(keyring.Item{
		Key:         key,
		Label:       "ThreatCL Cloud Credentials",
		Description: "ThreatCL Cloud API tokens",
		Data:        data,
	})
	if err != nil {
		return fmt.Errorf("failed to save to keyring: %w", err)
	}

	return nil
}

func (d *defaultKeyringService) Delete(key string) error {
	ring, err := d.openKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	err = ring.Remove(key)
	if err != nil {
		return fmt.Errorf("failed to delete from keyring: %w", err)
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

// Token store management functions

// getConfigPath returns the path to the threatcl config directory
func getConfigPath(fsSvc FileSystemService) (string, error) {
	configDir := fsSvc.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		homeDir := fsSvc.Getenv("HOME")
		if homeDir == "" {
			return "", fmt.Errorf("could not determine home directory")
		}
		configDir = filepath.Join(homeDir, ".config")
	}
	return filepath.Join(configDir, "threatcl"), nil
}

// getTokenStorePath returns the path to the token store file
func getTokenStorePath(fsSvc FileSystemService) (string, error) {
	configPath, err := getConfigPath(fsSvc)
	if err != nil {
		return "", err
	}
	return filepath.Join(configPath, "tokens.json"), nil
}

// loadTokenStore loads the token store from keyring or file
// Returns an empty store if no tokens exist yet
func loadTokenStore(keyringSvc KeyringService, fsSvc FileSystemService) (*tokenStore, error) {
	if keyringSvc == nil {
		keyringSvc = &defaultKeyringService{}
	}
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}

	// Try keyring first
	store, err := loadTokenStoreFromKeyring(keyringSvc)
	if err == nil {
		return store, nil
	}

	// Fall back to file
	store, err = loadTokenStoreFromFile(fsSvc)
	if err == nil {
		return store, nil
	}

	// Check if old format exists (for migration error message)
	if hasOldTokenFormat(keyringSvc, fsSvc) {
		return nil, fmt.Errorf("token format has changed - please run 'threatcl cloud login' to re-authenticate")
	}

	// No store exists yet - return empty store
	return &tokenStore{
		Version: tokenStoreVersion,
		Tokens:  make(map[string]orgTokenData),
	}, nil
}

// loadTokenStoreFromKeyring loads the token store from keyring
func loadTokenStoreFromKeyring(keyringSvc KeyringService) (*tokenStore, error) {
	data, err := keyringSvc.GetRaw(tokenStoreKeyringKey)
	if err != nil {
		return nil, err
	}

	var store tokenStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse token store: %w", err)
	}

	// Validate version
	if store.Version != tokenStoreVersion {
		return nil, fmt.Errorf("unsupported token store version: %d", store.Version)
	}

	// Ensure Tokens map is initialized
	if store.Tokens == nil {
		store.Tokens = make(map[string]orgTokenData)
	}

	return &store, nil
}

// loadTokenStoreFromFile loads the token store from file
func loadTokenStoreFromFile(fsSvc FileSystemService) (*tokenStore, error) {
	storePath, err := getTokenStorePath(fsSvc)
	if err != nil {
		return nil, err
	}

	data, err := fsSvc.ReadFile(storePath)
	if err != nil {
		return nil, err
	}

	var store tokenStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse token store: %w", err)
	}

	// Validate version
	if store.Version != tokenStoreVersion {
		return nil, fmt.Errorf("unsupported token store version: %d", store.Version)
	}

	// Ensure Tokens map is initialized
	if store.Tokens == nil {
		store.Tokens = make(map[string]orgTokenData)
	}

	return &store, nil
}

// hasOldTokenFormat checks if old single-token format exists
func hasOldTokenFormat(keyringSvc KeyringService, fsSvc FileSystemService) bool {
	// Check keyring for old format
	_, err := keyringSvc.Get("access_token")
	if err == nil {
		return true
	}

	// Check file for old format
	configPath, err := getConfigPath(fsSvc)
	if err != nil {
		return false
	}
	oldPath := filepath.Join(configPath, "settings.json")
	if _, err := fsSvc.Stat(oldPath); err == nil {
		// File exists, check if it has old format
		data, err := fsSvc.ReadFile(oldPath)
		if err == nil {
			var oldSettings map[string]interface{}
			if json.Unmarshal(data, &oldSettings) == nil {
				// Old format has access_token at root level, not version field
				if _, hasAccessToken := oldSettings["access_token"]; hasAccessToken {
					if _, hasVersion := oldSettings["version"]; !hasVersion {
						return true
					}
				}
			}
		}
	}

	return false
}

// saveTokenStore saves the token store to keyring or file
func saveTokenStore(store *tokenStore, keyringSvc KeyringService, fsSvc FileSystemService) error {
	if keyringSvc == nil {
		keyringSvc = &defaultKeyringService{}
	}
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}

	// Ensure version is set
	store.Version = tokenStoreVersion

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token store: %w", err)
	}

	// Try keyring first
	err = keyringSvc.SetRaw(tokenStoreKeyringKey, data)
	if err == nil {
		return nil
	}

	// Fall back to file
	return saveTokenStoreToFile(store, fsSvc)
}

// saveTokenStoreToFile saves the token store to file
func saveTokenStoreToFile(store *tokenStore, fsSvc FileSystemService) error {
	configPath, err := getConfigPath(fsSvc)
	if err != nil {
		return err
	}

	// Create directory if needed
	if err := fsSvc.MkdirAll(configPath, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	storePath, err := getTokenStorePath(fsSvc)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token store: %w", err)
	}

	return fsSvc.WriteFile(storePath, data, 0600)
}

// getTokenForOrg retrieves the token for a specific organization
func getTokenForOrg(orgId string, keyringSvc KeyringService, fsSvc FileSystemService) (string, error) {
	store, err := loadTokenStore(keyringSvc, fsSvc)
	if err != nil {
		return "", err
	}

	tokenData, ok := store.Tokens[orgId]
	if !ok {
		return "", fmt.Errorf("no token found for organization %s", orgId)
	}

	return tokenData.AccessToken, nil
}

// setTokenForOrg stores a token for a specific organization
func setTokenForOrg(orgId, token, tokenType, orgName string, expiresAt *int64, keyringSvc KeyringService, fsSvc FileSystemService) error {
	store, err := loadTokenStore(keyringSvc, fsSvc)
	if err != nil {
		// If we can't load (e.g., old format), create new store
		store = &tokenStore{
			Version: tokenStoreVersion,
			Tokens:  make(map[string]orgTokenData),
		}
	}

	store.Tokens[orgId] = orgTokenData{
		AccessToken: token,
		TokenType:   tokenType,
		ExpiresAt:   expiresAt,
		OrgName:     orgName,
	}

	// Set as default if no default exists
	if store.DefaultOrg == "" {
		store.DefaultOrg = orgId
	}

	return saveTokenStore(store, keyringSvc, fsSvc)
}

// removeTokenForOrg removes a token for a specific organization
func removeTokenForOrg(orgId string, keyringSvc KeyringService, fsSvc FileSystemService) error {
	store, err := loadTokenStore(keyringSvc, fsSvc)
	if err != nil {
		return err
	}

	if _, ok := store.Tokens[orgId]; !ok {
		return fmt.Errorf("no token found for organization %s", orgId)
	}

	delete(store.Tokens, orgId)

	// Clear default if it was the removed org
	if store.DefaultOrg == orgId {
		store.DefaultOrg = ""
		// Set new default if only one token remains
		if len(store.Tokens) == 1 {
			for id := range store.Tokens {
				store.DefaultOrg = id
				break
			}
		}
	}

	return saveTokenStore(store, keyringSvc, fsSvc)
}

// removeAllTokens removes all tokens from the store
func removeAllTokens(keyringSvc KeyringService, fsSvc FileSystemService) error {
	if keyringSvc == nil {
		keyringSvc = &defaultKeyringService{}
	}
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}

	// Try to delete from keyring
	_ = keyringSvc.Delete(tokenStoreKeyringKey)

	// Try to delete file
	storePath, err := getTokenStorePath(fsSvc)
	if err == nil {
		// We don't have a Delete method on FileSystemService, so we'll write an empty store
		emptyStore := &tokenStore{
			Version: tokenStoreVersion,
			Tokens:  make(map[string]orgTokenData),
		}
		data, _ := json.MarshalIndent(emptyStore, "", "  ")
		_ = fsSvc.WriteFile(storePath, data, 0600)
	}

	return nil
}

// getDefaultOrg returns the default organization ID
func getDefaultOrg(keyringSvc KeyringService, fsSvc FileSystemService) (string, error) {
	store, err := loadTokenStore(keyringSvc, fsSvc)
	if err != nil {
		return "", err
	}

	if store.DefaultOrg != "" {
		return store.DefaultOrg, nil
	}

	// If no default but only one token, return that
	if len(store.Tokens) == 1 {
		for orgId := range store.Tokens {
			return orgId, nil
		}
	}

	if len(store.Tokens) == 0 {
		return "", fmt.Errorf("no tokens found - please run 'threatcl cloud login' first")
	}

	return "", fmt.Errorf("multiple organizations configured but no default set - use 'threatcl cloud token default <org-id>' or --org-id flag")
}

// setDefaultOrg sets the default organization ID
func setDefaultOrg(orgId string, keyringSvc KeyringService, fsSvc FileSystemService) error {
	store, err := loadTokenStore(keyringSvc, fsSvc)
	if err != nil {
		return err
	}

	// Verify the org has a token
	if _, ok := store.Tokens[orgId]; !ok {
		return fmt.Errorf("no token found for organization %s", orgId)
	}

	store.DefaultOrg = orgId
	return saveTokenStore(store, keyringSvc, fsSvc)
}

// listTokens returns all stored tokens (for display, not the actual token values)
func listTokens(keyringSvc KeyringService, fsSvc FileSystemService) (map[string]orgTokenData, string, error) {
	store, err := loadTokenStore(keyringSvc, fsSvc)
	if err != nil {
		return nil, "", err
	}

	return store.Tokens, store.DefaultOrg, nil
}
