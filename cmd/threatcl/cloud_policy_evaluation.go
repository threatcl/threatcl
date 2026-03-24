package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudPolicyEvaluationCommand struct {
	CloudCommandBase
	flagOrgId   string
	flagModelId string
	flagEvalId  string
	flagJSON    bool
}

func (c *CloudPolicyEvaluationCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy evaluation -model-id=<modelId> -eval-id=<evalId> [-org-id=<orgId>] [-json]

	View details of a single past policy evaluation.

	The -model-id and -eval-id flags are required.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -model-id=<modelId>
   Required. The threat model ID.

 -eval-id=<evalId>
   Required. The evaluation ID to view.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -json
   Output as JSON.

 -config=<file>
   Optional config file

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

func (c *CloudPolicyEvaluationCommand) Synopsis() string {
	return "View details of a policy evaluation"
}

func (c *CloudPolicyEvaluationCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudPolicyEvaluationCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy evaluation")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID (required)")
	flagSet.StringVar(&c.flagEvalId, "eval-id", "", "Evaluation ID (required)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy evaluation -help' for usage information.\n")
		return 1
	}

	if c.flagEvalId == "" {
		fmt.Fprintf(os.Stderr, "Error: -eval-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy evaluation -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch evaluation
	eval, err := fetchPolicyEvaluation(token, orgId, c.flagModelId, c.flagEvalId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching evaluation: %s\n", err)
		return 1
	}

	// Output
	if c.flagJSON {
		output, err := json.MarshalIndent(eval, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling JSON: %s\n", err)
			return 1
		}
		fmt.Println(string(output))
		return 0
	}

	displayEvaluation(eval)
	return 0
}
