package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudThreatmodelDeleteCommand struct {
	CloudCommandBase
	flagOrgId   string
	flagModelId string
}

func (c *CloudThreatmodelDeleteCommand) Help() string {
	helpText := `
Usage: threatcl cloud threatmodel delete -model-id=<modelId_or_slug> [-org-id=<orgId>]

	Delete a threat model from ThreatCL Cloud.

	The -model-id flag is required and can be either a threat model ID or slug.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -model-id=<modelId_or_slug>
   Required. The threat model ID or slug to delete.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: ` + defaultAPIBaseURL + `)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud threatmodel delete -model-id=my-model

 THREATCL_CLOUD_ORG
   Default organization ID to use when -org-id is not specified.

 THREATCL_API_TOKEN
   Provide an API token directly, bypassing the local token store.
   Useful for CI/CD pipelines and automation.

`
	return strings.TrimSpace(helpText)
}

func (c *CloudThreatmodelDeleteCommand) Synopsis() string {
	return "Delete a threat model from ThreatCL Cloud"
}

func (c *CloudThreatmodelDeleteCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudThreatmodelDeleteCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud threatmodel delete")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID or slug (required)")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud threatmodel delete -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Step 1: Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Step 2: Delete threat model
	err = deleteThreatModel(token, orgId, c.flagModelId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting threat model: %s\n", err)
		return 1
	}

	fmt.Printf("Successfully deleted threat model '%s'\n", c.flagModelId)
	return 0
}
