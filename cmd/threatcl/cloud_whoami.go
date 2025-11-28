package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

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
