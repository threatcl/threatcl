package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudPolicyEvaluateCommand struct {
	CloudCommandBase
	flagOrgId         string
	flagModelId       string
	flagFailOnError   bool
	flagFailOnWarning bool
	flagJSON          bool
}

func (c *CloudPolicyEvaluateCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy evaluate -model-id=<modelId> [-org-id=<orgId>] [-fail-on-error] [-fail-on-warning] [-json]

	Trigger policy evaluation against a threat model.

	This command is designed for CI/CD integration. Use -fail-on-error or
	-fail-on-warning to control exit codes based on evaluation results.

	The -model-id flag is required.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -model-id=<modelId>
   Required. The threat model ID to evaluate policies against.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -fail-on-error
   Exit with code 1 if any policy with severity "error" fails.

 -fail-on-warning
   Exit with code 1 if any policy with severity "warning" or "error" fails.

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

func (c *CloudPolicyEvaluateCommand) Synopsis() string {
	return "Evaluate policies against a threat model"
}

func (c *CloudPolicyEvaluateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudPolicyEvaluateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy evaluate")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID (required)")
	flagSet.BoolVar(&c.flagFailOnError, "fail-on-error", false, "Exit 1 if error-severity policy fails")
	flagSet.BoolVar(&c.flagFailOnWarning, "fail-on-warning", false, "Exit 1 if warning+ severity policy fails")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy evaluate -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Evaluate policies
	eval, err := evaluatePolicies(token, orgId, c.flagModelId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error evaluating policies: %s\n", err)
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
	} else {
		displayEvaluation(eval)
	}

	// Check exit code based on flags
	if c.flagFailOnWarning {
		for _, r := range eval.Results {
			if !r.Passed && (r.PolicySeverity == "error" || r.PolicySeverity == "warning") {
				return 1
			}
		}
	} else if c.flagFailOnError {
		for _, r := range eval.Results {
			if !r.Passed && r.PolicySeverity == "error" {
				return 1
			}
		}
	}

	return 0
}

// displayEvaluation displays a policy evaluation with results table
func displayEvaluation(eval *policyEvaluation) {
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Policy Evaluation")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()

	fmt.Printf("ID:        %s\n", eval.ID)
	fmt.Printf("Status:    %s\n", eval.Status)
	fmt.Printf("Duration:  %dms\n", eval.DurationMs)
	if eval.CreatedAt != "" {
		fmt.Printf("Date:      %s\n", eval.CreatedAt)
	}
	fmt.Println()

	if len(eval.Results) > 0 {
		fmt.Printf("%-32s %-10s %-8s %s\n", "POLICY", "SEVERITY", "RESULT", "MESSAGE")
		fmt.Println(strings.Repeat("-", 100))

		for _, r := range eval.Results {
			result := "PASS"
			if !r.Passed {
				result = "FAIL"
			}
			fmt.Printf("%-32s %-10s %-8s %s\n",
				truncateString(r.PolicyName, 31),
				r.PolicySeverity,
				result,
				truncateString(r.Message, 40),
			)
		}
		fmt.Println()
	}

	fmt.Printf("%d/%d passed | %d failed | %d errors\n",
		eval.PassedCount, eval.TotalPolicies, eval.FailedCount, eval.ErrorCount)
	fmt.Println()
}
