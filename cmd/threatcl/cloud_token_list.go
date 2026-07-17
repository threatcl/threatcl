package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudTokenListCommand struct {
	CloudCommandBase
}

func (c *CloudTokenListCommand) Help() string {
	helpText := `
Usage: threatcl cloud token list

	List all stored authentication tokens.

	Displays organization ID, organization name, the API endpoint each
	token authenticates against, token expiry status, and indicates which
	organization is set as the default.

Options:

 -config=<file>
   Optional config file
` + cloudEnvVarHelpNoOrg()
	return strings.TrimSpace(helpText)
}

func (c *CloudTokenListCommand) Synopsis() string {
	return "List all stored tokens"
}

func (c *CloudTokenListCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudTokenListCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud token list")
	flagSet.Parse(args)

	// Initialize dependencies
	_, keyringSvc, fsSvc := c.initDependencies(5 * time.Second)

	// Get all tokens
	tokens, defaultOrg, err := listTokens(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving tokens: %s\n", err)
		return 1
	}

	if len(tokens) == 0 {
		fmt.Println("No tokens stored. Use 'threatcl cloud login' to authenticate.")
		return 0
	}

	// Print header
	fmt.Println()
	fmt.Printf("%-36s  %-20s  %-32s  %-10s  %s\n", "ORG ID", "ORG NAME", "ENDPOINT", "STATUS", "DEFAULT")
	fmt.Println(strings.Repeat("-", 110))

	// Print each token
	for orgId, tokenData := range tokens {
		orgName := tokenData.OrgName
		if orgName == "" {
			orgName = "(unknown)"
		}
		if len(orgName) > 20 {
			orgName = orgName[:17] + "..."
		}

		endpoint := tokenData.ApiURL
		if endpoint == "" {
			endpoint = "(default)"
		}
		if len(endpoint) > 32 {
			endpoint = endpoint[:29] + "..."
		}

		status := "Valid"
		if tokenData.ExpiresAt != nil {
			expiresAt := time.Unix(*tokenData.ExpiresAt, 0)
			if time.Now().After(expiresAt) {
				status = "Expired"
			}
		}

		defaultMarker := ""
		if orgId == defaultOrg {
			defaultMarker = "*"
		}

		fmt.Printf("%-36s  %-20s  %-32s  %-10s  %s\n", orgId, orgName, endpoint, status, defaultMarker)
	}

	fmt.Println()
	if defaultOrg != "" {
		fmt.Printf("Default organization: %s\n", defaultOrg)
	} else if len(tokens) > 1 {
		fmt.Println("No default organization set. Use 'threatcl cloud token default <org-id>' to set one.")
	}

	return 0
}
