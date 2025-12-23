package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudThreatmodelUpdateStatusCommand struct {
	CloudCommandBase
	flagOrgId   string
	flagModelId string
	flagStatus  string
}

func (c *CloudThreatmodelUpdateStatusCommand) Help() string {
	helpText := `
Usage: threatcl cloud threatmodel update-status -model-id=<modelId_or_slug> -status=<status> [-org-id=<orgId>]

	Update the status of a threat model.

	The -status flag is required and can be either "draft", "in_review", "approved" or "archived".

	The -model-id flag is required and can be either a threat model ID or slug.

	If -org-id is not provided, the command will automatically use the
	first organization from your user profile.

Options:

 -model-id=<modelId_or_slug>
   Required. The threat model ID or slug to update the status of.

 -status=<status>
   Required. The status to update the threat model to. Can be "draft", "in_review", "approved" or "archived".

 -org-id=<orgId>
   Optional organization ID. If not provided, uses the first organization
   from your user profile.

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud threatmodel update-status -model-id=my-model -status=approved
`
	return strings.TrimSpace(helpText)
}

func (c *CloudThreatmodelUpdateStatusCommand) Synopsis() string {
	return "Update the status of a threat model"
}

func (c *CloudThreatmodelUpdateStatusCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud threatmodel update-status")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID or slug (required)")
	flagSet.StringVar(&c.flagStatus, "status", "", "Status to update the threat model to (required)")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud threatmodel update-status -help' for usage information.\n")
		return 1
	}

	if c.flagStatus == "" {
		fmt.Fprintf(os.Stderr, "Error: -status is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud threatmodel update-status -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Step 1: Retrieve token
	token, err := c.getTokenWithDeps(keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Step 2: Get organization ID
	orgId, err := c.resolveOrgId(token, c.flagOrgId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	// Step 3: Update threat model status
	err = updateThreatmodelStatus(token, orgId, c.flagModelId, c.flagStatus, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error updating threat model status: %s\n", err)
		return 1
	}

	fmt.Printf("Successfully updated threat model status to '%s'\n", c.flagStatus)
	return 0
}
