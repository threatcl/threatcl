package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudPoliciesCommand struct {
	CloudCommandBase
	flagOrgId       string
	flagEnabledOnly bool
	flagEngine      string
	flagJSON        bool
}

func (c *CloudPoliciesCommand) Help() string {
	helpText := `
Usage: threatcl cloud policies [-org-id=<orgId>] [-enabled-only] [-engine=<engine>] [-json]

	List policies for an organization.

	Policies are either Rego modules (engine "rego") or single threatcl
	invariant blocks (engine "invariant").

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -enabled-only
   Filter to enabled policies only.

 -engine=<engine>
   Filter to one engine: rego or invariant.

 -json
   Output as JSON.

 -config=<file>
   Optional config file
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudPoliciesCommand) Synopsis() string {
	return "List policies for an organization"
}

func (c *CloudPoliciesCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
		"-engine": complete.PredictSet(policyEngineRego, policyEngineInvariant),
	}
}

func (c *CloudPoliciesCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policies")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagEnabledOnly, "enabled-only", false, "Filter to enabled policies only")
	flagSet.StringVar(&c.flagEngine, "engine", "", "Filter to one engine: rego or invariant")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	parseFlags(flagSet, args)

	if c.flagEngine != "" && !validPolicyEngine(c.flagEngine) {
		fmt.Fprintf(os.Stderr, "Error: -engine must be one of: %s, %s\n", policyEngineRego, policyEngineInvariant)
		return 1
	}

	// Build the cloud client (resolves token + org)
	client, _, err := c.newCloudClient(c.flagOrgId, 10*time.Second)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch policies
	policies, err := client.FetchPolicies()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching policies: %s\n", err)
		return 1
	}

	// Client-side filtering: the endpoint returns the org's full policy list
	if c.flagEnabledOnly || c.flagEngine != "" {
		var filtered []policy
		for _, p := range policies {
			if c.flagEnabledOnly && !p.Enabled {
				continue
			}
			if c.flagEngine != "" && p.engineName() != c.flagEngine {
				continue
			}
			filtered = append(filtered, p)
		}
		policies = filtered
	}

	// Output
	if c.flagJSON {
		output, err := json.MarshalIndent(policies, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling JSON: %s\n", err)
			return 1
		}
		fmt.Println(string(output))
		return 0
	}

	c.displayPolicies(policies)
	return 0
}

func (c *CloudPoliciesCommand) displayPolicies(policies []policy) {
	if len(policies) == 0 {
		fmt.Println("No policies found.")
		return
	}

	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Policies")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()
	fmt.Printf("%-30s %-10s %-9s %-8s %-9s %-15s %s\n", "NAME", "ENGINE", "SEVERITY", "ENABLED", "ENFORCED", "CATEGORY", "UPDATED")
	fmt.Println(strings.Repeat("-", 100))

	for _, p := range policies {
		category := p.Category
		if category == "" {
			category = "-"
		}
		updated := ""
		if len(p.UpdatedAt) >= 10 {
			updated = p.UpdatedAt[:10]
		}
		fmt.Printf("%-30s %-10s %-9s %-8v %-9v %-15s %s\n",
			truncateString(p.Name, 29),
			p.engineName(),
			p.Severity,
			p.Enabled,
			p.Enforced,
			truncateString(category, 14),
			updated,
		)
	}
	fmt.Println()
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
