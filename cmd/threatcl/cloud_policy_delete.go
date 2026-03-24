package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudPolicyDeleteCommand struct {
	CloudCommandBase
	flagOrgId    string
	flagPolicyId string
	flagForce    bool
}

func (c *CloudPolicyDeleteCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy delete -policy-id=<uuid> [-org-id=<orgId>] [-force]

	Delete a policy from ThreatCL Cloud.

	The -policy-id flag is required.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -policy-id=<uuid>
   Required. The policy ID to delete.

 -force
   Skip confirmation prompt.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)

 THREATCL_CLOUD_ORG
   Default organization ID to use when -org-id is not specified.

 THREATCL_API_TOKEN
   Provide an API token directly, bypassing the local token store.
   Useful for CI/CD pipelines and automation.

`
	return strings.TrimSpace(helpText)
}

func (c *CloudPolicyDeleteCommand) Synopsis() string {
	return "Delete a policy from ThreatCL Cloud"
}

func (c *CloudPolicyDeleteCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudPolicyDeleteCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy delete")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagPolicyId, "policy-id", "", "Policy ID (required)")
	flagSet.BoolVar(&c.flagForce, "force", false, "Skip confirmation prompt")
	flagSet.Parse(args)

	if c.flagPolicyId == "" {
		fmt.Fprintf(os.Stderr, "Error: -policy-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy delete -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Confirmation prompt unless -force is set
	if !c.flagForce {
		// Fetch the policy first to show the name in the prompt
		p, err := fetchPolicy(token, orgId, c.flagPolicyId, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching policy: %s\n", err)
			return 1
		}

		fmt.Printf("Delete policy \"%s\"? This cannot be undone. [y/N] ", p.Name)
		var response string
		fmt.Scanln(&response)
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Cancelled.")
			return 0
		}
	}

	// Delete policy
	err = deletePolicy(token, orgId, c.flagPolicyId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting policy: %s\n", err)
		return 1
	}

	fmt.Printf("Successfully deleted policy '%s'\n", c.flagPolicyId)
	return 0
}
