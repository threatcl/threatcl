package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudTokenRemoveCommand struct {
	CloudCommandBase
}

func (c *CloudTokenRemoveCommand) Help() string {
	helpText := `
Usage: threatcl cloud token remove <org-id>

	Remove a token for a specific organization.

	If the removed organization was set as the default, the default will be
	cleared. If only one token remains after removal, it will automatically
	become the new default.

Arguments:

	<org-id>   The organization ID to remove the token for (required)

Options:

 -config=<file>
   Optional config file

Examples:

	# Remove a token for a specific organization
	threatcl cloud token remove 550e8400-e29b-41d4-a716-446655440000

	# List tokens first to see org IDs
	threatcl cloud token list

`
	return strings.TrimSpace(helpText)
}

func (c *CloudTokenRemoveCommand) Synopsis() string {
	return "Remove a token for a specific organization"
}

func (c *CloudTokenRemoveCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud token remove")
	flagSet.Parse(args)

	// Get remaining args after flags
	remainingArgs := flagSet.Args()
	if len(remainingArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Error: organization ID is required\n")
		fmt.Fprintf(os.Stderr, "Usage: threatcl cloud token remove <org-id>\n")
		return 1
	}

	orgId := remainingArgs[0]

	// Initialize dependencies
	_, keyringSvc, fsSvc := c.initDependencies(5 * time.Second)

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

	// Remove the token
	err = removeTokenForOrg(orgId, keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error removing token: %s\n", err)
		return 1
	}

	orgName := tokenData.OrgName
	if orgName != "" {
		fmt.Printf("Token removed for organization: %s (%s)\n", orgName, orgId)
	} else {
		fmt.Printf("Token removed for organization: %s\n", orgId)
	}

	return 0
}
