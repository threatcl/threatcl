package main

import (
	"bytes"
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

Subcommands:
	login    Authenticate with ThreatCL Cloud
	whoami   Display current authenticated user information

`
	return strings.TrimSpace(helpText)
}

func (c *CloudCommand) Run(args []string) int {
	return cli.RunResultHelp
}

func (c *CloudCommand) Synopsis() string {
	return "Interact with ThreatCL Cloud services"
}

type CloudLoginCommand struct {
	*GlobalCmdOptions
}

func (c *CloudLoginCommand) Help() string {
	helpText := `
Usage: threatcl cloud login

	Authenticate with ThreatCL Cloud using device flow authentication.

	This command will:
	1. Request a device code from the ThreatCL API
	2. Display a verification URL and user code
	3. Wait for you to authorize the device in your browser
	4. Save the access token securely to your OS keychain (or settings file)

Options:

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud login

`
	return strings.TrimSpace(helpText)
}

func (c *CloudLoginCommand) Synopsis() string {
	return "Authenticate with ThreatCL Cloud"
}

func (c *CloudLoginCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud login")
	flagSet.Parse(args)

	// Step 1: Request device code
	deviceResp, err := c.requestDeviceCode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error requesting device code: %s\n", err)
		return 1
	}

	// Step 2: Display user instructions
	c.displayVerificationInstructions(deviceResp)

	// Step 3: Poll for token
	tokenResp, err := c.pollForToken(deviceResp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during authentication: %s\n", err)
		return 1
	}

	// Step 4: Save token
	err = c.saveToken(tokenResp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %s\n", err)
		return 1
	}

	fmt.Println("\n✓ Successfully authenticated and saved token!")
	return 0
}

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

// getAPIBaseURL returns the API base URL from environment variable or default
func getAPIBaseURL() string {
	apiURL := os.Getenv("THREATCL_API_URL")
	if apiURL != "" {
		// Remove trailing slash if present
		return strings.TrimSuffix(apiURL, "/")
	}
	return "https://api.threatcl.com"
}

func (c *CloudLoginCommand) requestDeviceCode() (*deviceCodeResponse, error) {
	url := fmt.Sprintf("%s/api/v1/auth/device", getAPIBaseURL())

	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var deviceResp deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &deviceResp, nil
}

func (c *CloudLoginCommand) displayVerificationInstructions(deviceResp *deviceCodeResponse) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  ThreatCL Cloud Authentication")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	fmt.Println("To complete authentication, please:")
	fmt.Println()
	fmt.Printf("  1. Visit: %s\n", deviceResp.VerificationURL)
	fmt.Println()
	fmt.Printf("  2. Enter this code: %s\n", deviceResp.UserCode)
	fmt.Println()
	fmt.Println("Waiting for authorization...")
	fmt.Println()
}

func (c *CloudLoginCommand) pollForToken(deviceResp *deviceCodeResponse) (*tokenResponse, error) {
	url := fmt.Sprintf("%s/api/v1/auth/device/poll", getAPIBaseURL())

	expiresAt := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	interval := time.Duration(deviceResp.Interval) * time.Second

	// Ensure minimum interval of 1 second
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Do initial poll immediately
	for {
		// Check if we've exceeded the expiration time
		if time.Now().After(expiresAt) {
			return nil, fmt.Errorf("authentication timed out after %d seconds", deviceResp.ExpiresIn)
		}

		// Create request body
		reqBody := map[string]string{
			"device_code": deviceResp.DeviceCode,
		}
		jsonBody, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Make polling request
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
		if err != nil {
			// Network error - continue polling
			fmt.Print(".")
			<-ticker.C
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			fmt.Print(".")
			<-ticker.C
			continue
		}

		// Check if we got a token
		if resp.StatusCode == http.StatusOK {
			var tokenResp tokenResponse
			if err := json.Unmarshal(body, &tokenResp); err != nil {
				return nil, fmt.Errorf("failed to parse token response: %w", err)
			}
			return &tokenResp, nil
		}

		// Check if it's an authorization_pending error (expected)
		var errResp errorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			if errResp.Error.Code == "authorization_pending" {
				// This is expected - user hasn't authorized yet
				fmt.Print(".")
				<-ticker.C
				continue
			}
			// Some other error
			return nil, fmt.Errorf("API error: %s (code: %s)", errResp.Error.Message, errResp.Error.Code)
		}

		// Unexpected response
		fmt.Print(".")
		<-ticker.C
	}
}

func (c *CloudLoginCommand) saveToken(tokenResp *tokenResponse) error {
	// Try to save to keyring first
	err := c.saveTokenToKeyring(tokenResp)
	if err == nil {
		return nil
	}

	// If keyring fails, fall back to file
	fmt.Fprintf(os.Stderr, "Warning: Could not save to keyring (%s), falling back to file storage\n", err)
	return c.saveTokenToFile(tokenResp)
}

func (c *CloudLoginCommand) saveTokenToKeyring(tokenResp *tokenResponse) error {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: "threatcl",
	})
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	// Create token data structure
	tokenData := map[string]interface{}{
		"access_token": tokenResp.AccessToken,
		"token_type":   tokenResp.TokenType,
	}
	if tokenResp.ExpiresIn != nil {
		tokenData["expires_in"] = *tokenResp.ExpiresIn
		tokenData["expires_at"] = time.Now().Add(time.Duration(*tokenResp.ExpiresIn) * time.Second).Unix()
	}

	// Marshal to JSON for storage
	tokenJSON, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	err = ring.Set(keyring.Item{
		Key:  "access_token",
		Data: tokenJSON,
	})
	if err != nil {
		return fmt.Errorf("failed to save to keyring: %w", err)
	}

	return nil
}

func (c *CloudLoginCommand) saveTokenToFile(tokenResp *tokenResponse) error {
	// Determine config directory
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			return fmt.Errorf("could not determine home directory")
		}
		configDir = filepath.Join(homeDir, ".config")
	}

	threatclDir := filepath.Join(configDir, "threatcl")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(threatclDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create settings structure
	settings := map[string]interface{}{
		"access_token": tokenResp.AccessToken,
		"token_type":   tokenResp.TokenType,
	}
	if tokenResp.ExpiresIn != nil {
		settings["expires_in"] = *tokenResp.ExpiresIn
		settings["expires_at"] = time.Now().Add(time.Duration(*tokenResp.ExpiresIn) * time.Second).Unix()
	}

	// Marshal to JSON
	settingsJSON, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Write to file
	settingsPath := filepath.Join(threatclDir, "settings.json")
	if err := os.WriteFile(settingsPath, settingsJSON, 0600); err != nil {
		return fmt.Errorf("failed to write settings file: %w", err)
	}

	return nil
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

type CloudWhoamiCommand struct {
	*GlobalCmdOptions
}

func (c *CloudWhoamiCommand) Help() string {
	helpText := `
Usage: threatcl cloud whoami

	Display information about the currently authenticated user.

	This command retrieves your saved authentication token and displays
	your user profile, including email, organizations, and subscription details.

Options:

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud whoami

`
	return strings.TrimSpace(helpText)
}

func (c *CloudWhoamiCommand) Synopsis() string {
	return "Display current authenticated user information"
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

func (c *CloudWhoamiCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud whoami")
	flagSet.Parse(args)

	// Step 1: Retrieve token
	token, err := getToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving token: %s\n", err)
		fmt.Fprintf(os.Stderr, "Please run 'threatcl cloud login' to authenticate.\n")
		return 1
	}

	// Step 2: Make API request
	whoamiResp, err := c.fetchUserInfo(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching user information: %s\n", err)
		return 1
	}

	// Step 3: Display results
	c.displayUserInfo(whoamiResp)

	return 0
}

func (c *CloudWhoamiCommand) fetchUserInfo(token string) (*whoamiResponse, error) {
	url := fmt.Sprintf("%s/api/v1/users/me", getAPIBaseURL())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("authentication failed - token may be invalid or expired. Please run 'threatcl cloud login' again")
		}
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var whoamiResp whoamiResponse
	if err := json.NewDecoder(resp.Body).Decode(&whoamiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &whoamiResp, nil
}

func (c *CloudWhoamiCommand) displayUserInfo(resp *whoamiResponse) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  ThreatCL Cloud - User Information")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// User Information
	fmt.Println("User:")
	fmt.Printf("  ID:        %s\n", resp.User.ID)
	fmt.Printf("  Email:     %s", resp.User.Email)
	if resp.User.EmailVerified {
		fmt.Print(" ✓")
	}
	fmt.Println()
	fmt.Printf("  Name:      %s\n", resp.User.FullName)
	if resp.User.AvatarURL != "" {
		fmt.Printf("  Avatar:    %s\n", resp.User.AvatarURL)
	}
	fmt.Println()

	// Organizations
	if len(resp.Organizations) > 0 {
		fmt.Println("Organizations:")
		for i, org := range resp.Organizations {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("  Name:              %s\n", org.Organization.Name)
			fmt.Printf("  Slug:              %s\n", org.Organization.Slug)
			fmt.Printf("  Role:              %s\n", org.Role)
			fmt.Printf("  Subscription Tier: %s\n", org.Organization.SubscriptionTier)
			fmt.Printf("  Max Users:         %d\n", org.Organization.MaxUsers)
			fmt.Printf("  Max Threat Models: %d\n", org.Organization.MaxThreatModels)
			fmt.Printf("  Max Storage:       %d MB\n", org.Organization.MaxStorageMB)
		}
		fmt.Println()
	}

	// Timestamps
	fmt.Println("Timestamps:")
	fmt.Printf("  User Created:  %s\n", resp.User.CreatedAt)
	fmt.Printf("  User Updated:  %s\n", resp.User.UpdatedAt)
	if len(resp.Organizations) > 0 {
		fmt.Printf("  Joined Org:    %s\n", resp.Organizations[0].JoinedAt)
	}
}
