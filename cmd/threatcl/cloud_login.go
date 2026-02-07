package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type CloudLoginCommand struct {
	CloudCommandBase
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

	Tokens are scoped to organizations. You can authenticate with multiple
	organizations by running login multiple times and selecting different
	organizations in the web interface.

	Use 'threatcl cloud token list' to see all authenticated organizations.
	Use 'threatcl cloud token default <org-id>' to set the default organization.

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

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(5 * time.Second)

	// Step 1: Request device code
	deviceResp, err := c.requestDeviceCode(httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error requesting device code: %s\n", err)
		return 1
	}

	// Step 2: Display user instructions
	c.displayVerificationInstructions(deviceResp)

	// Step 3: Poll for token
	tokenResp, err := c.pollForToken(deviceResp, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during authentication: %s\n", err)
		return 1
	}

	// Step 4: Fetch org name for display
	orgName := c.fetchOrgName(tokenResp.AccessToken, tokenResp.OrganizationID, httpClient, fsSvc)

	// Step 5: Save token
	err = c.saveToken(tokenResp, orgName, keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %s\n", err)
		return 1
	}

	fmt.Println()
	if orgName != "" {
		fmt.Printf("✓ Successfully authenticated with organization: %s\n", orgName)
	} else {
		fmt.Printf("✓ Successfully authenticated with organization: %s\n", tokenResp.OrganizationID)
	}
	return 0
}

func (c *CloudLoginCommand) requestDeviceCode(httpClient HTTPClient, fsSvc FileSystemService) (*deviceCodeResponse, error) {
	url := fmt.Sprintf("%s/api/v1/auth/device", getAPIBaseURL(fsSvc))

	resp, err := httpClient.Post(url, "application/json", nil)
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

func (c *CloudLoginCommand) pollForToken(deviceResp *deviceCodeResponse, httpClient HTTPClient, fsSvc FileSystemService) (*tokenResponse, error) {
	url := fmt.Sprintf("%s/api/v1/auth/device/poll", getAPIBaseURL(fsSvc))

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
		resp, err := httpClient.Post(url, "application/json", bytes.NewBuffer(jsonBody))
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

func (c *CloudLoginCommand) fetchOrgName(token, orgId string, httpClient HTTPClient, fsSvc FileSystemService) string {
	// Try to fetch user info to get org name
	whoamiResp, err := fetchUserInfo(token, httpClient, fsSvc)
	if err != nil {
		return ""
	}

	// Find the org in the response
	for _, org := range whoamiResp.Organizations {
		if org.Organization.ID == orgId {
			return org.Organization.Name
		}
	}

	return ""
}

func (c *CloudLoginCommand) saveToken(tokenResp *tokenResponse, orgName string, keyringSvc KeyringService, fsSvc FileSystemService) error {
	return setTokenForOrg(
		tokenResp.OrganizationID,
		tokenResp.AccessToken,
		tokenResp.TokenType,
		orgName,
		tokenResp.ExpiresAt,
		keyringSvc,
		fsSvc,
	)
}
