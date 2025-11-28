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
)

type CloudLoginCommand struct {
	*GlobalCmdOptions
}

func (c *CloudLoginCommand) Help() string {
	helpText := `
Usage: threatcl cloud login

	Authenticate with ThreatCL Cloud using device flow authentication.

	This command will:
	1. Check if you are already authenticated (if a token exists, it will be validated)
	2. Request a device code from the ThreatCL API
	3. Display a verification URL and user code
	4. Wait for you to authorize the device in your browser
	5. Save the access token securely to your OS keychain (or settings file)

	If you are already authenticated with a valid token, this command will exit
	with an error. Use 'threatcl cloud whoami' to verify your current session.
	If your token is invalid or expired, login will proceed and replace it.

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

	// Check if user is already authenticated
	token, err := getToken()
	if err == nil {
		// Token exists, validate it
		isValid, validateErr := validateToken(token)
		if validateErr != nil {
			// Network error - unable to validate, but allow login to proceed with warning
			fmt.Fprintf(os.Stderr, "Warning: Could not validate existing token (%s). Proceeding with login...\n\n", validateErr)
		} else if isValid {
			// Valid token exists - prevent login
			fmt.Fprintf(os.Stderr, "Error: You are already authenticated. Use 'threatcl cloud whoami' to verify your session.\n")
			return 1
		}
		// Token exists but is invalid/expired - allow login to proceed (will replace token)
	}

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
