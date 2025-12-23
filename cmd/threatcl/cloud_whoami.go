package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudWhoamiCommand struct {
	CloudCommandBase
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

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Step 1: Retrieve token
	token, err := c.getTokenWithDeps(keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Step 2: Make API request
	whoamiResp, err := fetchUserInfo(token, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching user information: %s\n", err)
		return 1
	}

	// Step 3: Display results
	c.displayUserInfo(whoamiResp)

	return 0
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
			fmt.Printf("  ID:                %s\n", org.Organization.ID)
			fmt.Printf("  Slug:              %s\n", org.Organization.Slug)
			fmt.Printf("  Role:              %s\n", org.Role)
			fmt.Printf("  Subscription Tier: %s\n", org.Organization.SubscriptionTier)
			fmt.Printf("  Users:             %d/%d\n", org.Organization.CurUsers, org.Organization.MaxUsers)
			fmt.Printf("  Threat Models:     %d/%d\n", org.Organization.CurThreatModels, org.Organization.MaxThreatModels)
			fmt.Printf("  Storage:           %d KB/%d KB\n", org.Organization.CurStorageKB, org.Organization.MaxStorageKB)
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
