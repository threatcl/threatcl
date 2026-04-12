package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudPolicyEvaluationsCommand struct {
	CloudCommandBase
	flagOrgId   string
	flagModelId string
	flagLimit   int
	flagJSON    bool
}

func (c *CloudPolicyEvaluationsCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy evaluations -model-id=<modelId> [-org-id=<orgId>] [-limit=20] [-json]

	List past policy evaluation runs for a threat model.

	The -model-id flag is required.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -model-id=<modelId>
   Required. The threat model ID to list evaluations for.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -limit=<n>
   Maximum number of evaluations to display. Default is 20.

 -json
   Output as JSON.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: ` + defaultAPIBaseURL + `)

 THREATCL_CLOUD_ORG
   Default organization ID to use when -org-id is not specified.

 THREATCL_API_TOKEN
   Provide an API token directly, bypassing the local token store.
   Useful for CI/CD pipelines and automation.

`
	return strings.TrimSpace(helpText)
}

func (c *CloudPolicyEvaluationsCommand) Synopsis() string {
	return "List past policy evaluations for a threat model"
}

func (c *CloudPolicyEvaluationsCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudPolicyEvaluationsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy evaluations")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID (required)")
	flagSet.IntVar(&c.flagLimit, "limit", 20, "Maximum number of evaluations to display")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy evaluations -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch evaluations
	evals, err := fetchPolicyEvaluations(token, orgId, c.flagModelId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching evaluations: %s\n", err)
		return 1
	}

	// Apply limit
	if c.flagLimit > 0 && len(evals) > c.flagLimit {
		evals = evals[:c.flagLimit]
	}

	// Output
	if c.flagJSON {
		output, err := json.MarshalIndent(evals, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling JSON: %s\n", err)
			return 1
		}
		fmt.Println(string(output))
		return 0
	}

	c.displayEvaluations(evals)
	return 0
}

func (c *CloudPolicyEvaluationsCommand) displayEvaluations(evals []policyEvaluation) {
	if len(evals) == 0 {
		fmt.Println("No evaluations found.")
		return
	}

	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Policy Evaluations")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()
	fmt.Printf("%-20s %-12s %-8s %-8s %-8s %-12s %s\n", "ID", "STATUS", "PASSED", "FAILED", "ERRORS", "DURATION", "DATE")
	fmt.Println(strings.Repeat("-", 100))

	for _, e := range evals {
		date := ""
		if len(e.CreatedAt) >= 10 {
			date = e.CreatedAt[:10]
		}
		fmt.Printf("%-20s %-12s %-8d %-8d %-8d %-12s %s\n",
			truncateString(e.ID, 19),
			e.Status,
			e.PassedCount,
			e.FailedCount,
			e.ErrorCount,
			fmt.Sprintf("%dms", e.DurationMs),
			date,
		)
	}
	fmt.Println()
}
