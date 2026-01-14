package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudLogoutCommand struct {
	CloudCommandBase
}

func (c *CloudLogoutCommand) Help() string {
	helpText := `
Usage: threatcl cloud logout [options]

	Remove authentication tokens from the local token store.

	By default, removes the token for the current/default organization.
	Use --org-id to remove a specific organization's token, or --all to
	remove all tokens.

Options:

 -org-id=<id>
   Remove the token for this specific organization ID

 -all
   Remove all tokens (logout from all organizations)

 -config=<file>
   Optional config file

Examples:

	# Logout from the default organization
	threatcl cloud logout

	# Logout from a specific organization
	threatcl cloud logout -org-id=550e8400-e29b-41d4-a716-446655440000

	# Logout from all organizations
	threatcl cloud logout -all

`
	return strings.TrimSpace(helpText)
}

func (c *CloudLogoutCommand) Synopsis() string {
	return "Remove authentication tokens"
}

func (c *CloudLogoutCommand) Run(args []string) int {
	var orgIdFlag string
	var allFlag bool

	flagSet := c.GetFlagset("cloud logout")
	flagSet.StringVar(&orgIdFlag, "org-id", "", "Organization ID to logout from")
	flagSet.BoolVar(&allFlag, "all", false, "Logout from all organizations")
	flagSet.Parse(args)

	// Initialize dependencies
	_, keyringSvc, fsSvc := c.initDependencies(5 * time.Second)

	if allFlag {
		return c.logoutAll(keyringSvc, fsSvc)
	}

	if orgIdFlag != "" {
		return c.logoutOrg(orgIdFlag, keyringSvc, fsSvc)
	}

	// Default: logout from default org
	return c.logoutDefault(keyringSvc, fsSvc)
}

func (c *CloudLogoutCommand) logoutAll(keyringSvc KeyringService, fsSvc FileSystemService) int {
	// Get count before removing
	tokens, _, err := listTokens(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving tokens: %s\n", err)
		return 1
	}

	if len(tokens) == 0 {
		fmt.Println("No tokens to remove.")
		return 0
	}

	err = removeAllTokens(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error removing tokens: %s\n", err)
		return 1
	}

	fmt.Printf("Removed %d token(s). You are now logged out from all organizations.\n", len(tokens))
	return 0
}

func (c *CloudLogoutCommand) logoutOrg(orgId string, keyringSvc KeyringService, fsSvc FileSystemService) int {
	// Get token info before removing (for display)
	tokens, _, err := listTokens(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving tokens: %s\n", err)
		return 1
	}

	tokenData, exists := tokens[orgId]
	if !exists {
		fmt.Fprintf(os.Stderr, "Error: no token found for organization %s\n", orgId)
		return 1
	}

	err = removeTokenForOrg(orgId, keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error removing token: %s\n", err)
		return 1
	}

	if tokenData.OrgName != "" {
		fmt.Printf("Logged out from organization: %s (%s)\n", tokenData.OrgName, orgId)
	} else {
		fmt.Printf("Logged out from organization: %s\n", orgId)
	}

	return 0
}

func (c *CloudLogoutCommand) logoutDefault(keyringSvc KeyringService, fsSvc FileSystemService) int {
	// Get default org
	defaultOrg, err := getDefaultOrg(keyringSvc, fsSvc)
	if err != nil {
		// Check if it's a "no tokens" error
		tokens, _, listErr := listTokens(keyringSvc, fsSvc)
		if listErr == nil && len(tokens) == 0 {
			fmt.Println("No tokens to remove.")
			return 0
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}

	return c.logoutOrg(defaultOrg, keyringSvc, fsSvc)
}
