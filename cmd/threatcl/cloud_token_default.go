package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudTokenDefaultCommand struct {
	CloudCommandBase
}

func (c *CloudTokenDefaultCommand) Help() string {
	helpText := `
Usage: threatcl cloud token default [org-id]

	Get or set the default organization.

	When called without arguments, displays the current default organization.
	When called with an organization ID, sets that organization as the default.

	The default organization is used when no --org-id flag is provided and
	the THREATCL_CLOUD_ORG environment variable is not set.

Arguments:

	[org-id]   The organization ID to set as default (optional)

Options:

 -config=<file>
   Optional config file

Examples:

	# Show current default
	threatcl cloud token default

	# Set a new default
	threatcl cloud token default 550e8400-e29b-41d4-a716-446655440000

	# List tokens to see available org IDs
	threatcl cloud token list

`
	return strings.TrimSpace(helpText)
}

func (c *CloudTokenDefaultCommand) Synopsis() string {
	return "Get or set the default organization"
}

func (c *CloudTokenDefaultCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud token default")
	flagSet.Parse(args)

	// Initialize dependencies
	_, keyringSvc, fsSvc := c.initDependencies(5 * time.Second)

	// Get remaining args after flags
	remainingArgs := flagSet.Args()

	if len(remainingArgs) == 0 {
		// Show current default
		return c.showDefault(keyringSvc, fsSvc)
	}

	// Set new default
	orgId := remainingArgs[0]
	return c.setDefault(orgId, keyringSvc, fsSvc)
}

func (c *CloudTokenDefaultCommand) showDefault(keyringSvc KeyringService, fsSvc FileSystemService) int {
	tokens, defaultOrg, err := listTokens(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving tokens: %s\n", err)
		return 1
	}

	if len(tokens) == 0 {
		fmt.Println("No tokens stored. Use 'threatcl cloud login' to authenticate.")
		return 0
	}

	if defaultOrg == "" {
		if len(tokens) == 1 {
			// Single token, it's implicitly the default
			for orgId, tokenData := range tokens {
				if tokenData.OrgName != "" {
					fmt.Printf("Default organization: %s (%s)\n", tokenData.OrgName, orgId)
				} else {
					fmt.Printf("Default organization: %s\n", orgId)
				}
				return 0
			}
		}
		fmt.Println("No default organization set.")
		fmt.Println("Use 'threatcl cloud token default <org-id>' to set one.")
		return 0
	}

	tokenData, exists := tokens[defaultOrg]
	if !exists {
		fmt.Printf("Default organization: %s (token not found)\n", defaultOrg)
		return 0
	}

	if tokenData.OrgName != "" {
		fmt.Printf("Default organization: %s (%s)\n", tokenData.OrgName, defaultOrg)
	} else {
		fmt.Printf("Default organization: %s\n", defaultOrg)
	}

	return 0
}

func (c *CloudTokenDefaultCommand) setDefault(orgId string, keyringSvc KeyringService, fsSvc FileSystemService) int {
	// Verify the org has a token
	tokens, _, err := listTokens(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving tokens: %s\n", err)
		return 1
	}

	tokenData, exists := tokens[orgId]
	if !exists {
		fmt.Fprintf(os.Stderr, "Error: no token found for organization %s\n", orgId)
		fmt.Fprintf(os.Stderr, "Use 'threatcl cloud token list' to see available organizations.\n")
		return 1
	}

	// Set the default
	err = setDefaultOrg(orgId, keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting default: %s\n", err)
		return 1
	}

	if tokenData.OrgName != "" {
		fmt.Printf("Default organization set to: %s (%s)\n", tokenData.OrgName, orgId)
	} else {
		fmt.Printf("Default organization set to: %s\n", orgId)
	}

	return 0
}
