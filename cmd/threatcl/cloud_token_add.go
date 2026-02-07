package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudTokenAddCommand struct {
	CloudCommandBase
}

func (c *CloudTokenAddCommand) Help() string {
	helpText := `
Usage: threatcl cloud token add [options]

	Add a token manually to the local token store.

	This is useful when you have generated a token via the web interface
	and want to use it with the CLI. The command will auto-detect which
	organization the token belongs to by querying the API.

Options:

 -token=<token>
   The API token to add. If not provided, you will be prompted to enter it.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)

Examples:

	# Add a token interactively
	threatcl cloud token add

	# Add a token directly
	threatcl cloud token add -token=tcl_xxxxx

`
	return strings.TrimSpace(helpText)
}

func (c *CloudTokenAddCommand) Synopsis() string {
	return "Add a token manually"
}

func (c *CloudTokenAddCommand) Run(args []string) int {
	var tokenFlag string

	flagSet := c.GetFlagset("cloud token add")
	flagSet.StringVar(&tokenFlag, "token", "", "The API token to add")
	flagSet.Parse(args)

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Get token from flag or prompt
	token := tokenFlag
	if token == "" {
		fmt.Print("Enter your API token: ")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %s\n", err)
			return 1
		}
		token = strings.TrimSpace(input)
	}

	if token == "" {
		fmt.Fprintf(os.Stderr, "Error: token cannot be empty\n")
		return 1
	}

	// Validate token and get user info
	fmt.Println("Validating token...")
	whoamiResp, err := fetchUserInfo(token, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid token or unable to connect to API: %s\n", err)
		return 1
	}

	// Determine which organization this token belongs to
	var orgID, orgName string

	// If the API returns the token's organization directly, use that
	if whoamiResp.ApiTokenOrganizationID != "" {
		orgID = whoamiResp.ApiTokenOrganizationID
		orgName = whoamiResp.ApiTokenOrganizationName
	} else if len(whoamiResp.Organizations) > 0 {
		// Fall back to first organization (legacy behavior)
		org := whoamiResp.Organizations[0].Organization
		orgID = org.ID
		orgName = org.Name
	} else {
		fmt.Fprintf(os.Stderr, "Error: no organizations found for this token\n")
		return 1
	}

	// Save the token
	err = setTokenForOrg(orgID, token, "Bearer", orgName, nil, keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %s\n", err)
		return 1
	}

	fmt.Printf("\n")
	fmt.Printf("Token added for organization: %s (%s)\n", orgName, orgID)
	return 0
}
