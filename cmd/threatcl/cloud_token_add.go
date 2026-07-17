package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
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

	The API endpoint used to validate the token is saved with it, and
	subsequent cloud commands use that endpoint for the token's
	organization.

Options:

 -token=<token>
   The API token to add. If not provided, you will be prompted to enter it.

 -target=<host>
   ThreatCL Cloud deployment the token belongs to, given as its web host
   (e.g. beta.threatcl.com). The API endpoint is derived automatically
   (e.g. beta-api.threatcl.com).

 -api-url=<url>
   Exact API endpoint the token belongs to (e.g.
   https://beta-api.threatcl.com). Use this when the -target mapping
   doesn't fit. Cannot be combined with -target.

 -config=<file>
   Optional config file
` + cloudEnvVarHelpNoOrg()
	return strings.TrimSpace(helpText)
}

func (c *CloudTokenAddCommand) Synopsis() string {
	return "Add a token manually"
}

func (c *CloudTokenAddCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":  predictHCL,
		"-target":  complete.PredictAnything,
		"-api-url": complete.PredictAnything,
	}
}

func (c *CloudTokenAddCommand) Run(args []string) int {
	var tokenFlag, flagTarget, flagAPIURL string

	flagSet := c.GetFlagset("cloud token add")
	flagSet.StringVar(&tokenFlag, "token", "", "The API token to add")
	flagSet.StringVar(&flagTarget, "target", "", "ThreatCL Cloud web host the token belongs to")
	flagSet.StringVar(&flagAPIURL, "api-url", "", "Exact API endpoint the token belongs to")
	flagSet.Parse(args)

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Resolve the API endpoint the token belongs to; it is saved with the
	// token so subsequent commands talk to the same deployment
	apiURL, err := resolveLoginAPIBaseURL(flagAPIURL, flagTarget, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving API endpoint: %s\n", err)
		return 1
	}

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

	// Validate token and get user info (org-agnostic call)
	fmt.Printf("Validating token against %s...\n", apiURL)
	whoamiResp, err := NewCloudClient(token, "", apiURL, httpClient).FetchUserInfo()
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
	err = setTokenForOrg(orgID, token, "Bearer", orgName, nil, apiURL, keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %s\n", err)
		return 1
	}

	fmt.Printf("\n")
	fmt.Printf("Token added for organization: %s (%s)\n", orgName, orgID)
	return 0
}
