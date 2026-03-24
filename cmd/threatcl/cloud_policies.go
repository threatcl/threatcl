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
	flagJSON        bool
}

func (c *CloudPoliciesCommand) Help() string {
	helpText := `
Usage: threatcl cloud policies [-org-id=<orgId>] [-enabled-only] [-json]

	List policies for an organization.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -enabled-only
   Filter to enabled policies only.

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

func (c *CloudPoliciesCommand) Synopsis() string {
	return "List policies for an organization"
}

func (c *CloudPoliciesCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudPoliciesCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policies")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagEnabledOnly, "enabled-only", false, "Filter to enabled policies only")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	flagSet.Parse(args)

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch policies
	policies, err := fetchPolicies(token, orgId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching policies: %s\n", err)
		return 1
	}

	// Client-side filtering for enabled-only
	if c.flagEnabledOnly {
		var filtered []policy
		for _, p := range policies {
			if p.Enabled {
				filtered = append(filtered, p)
			}
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
	fmt.Printf("%-32s %-10s %-8s %-10s %-17s %s\n", "NAME", "SEVERITY", "ENABLED", "ENFORCED", "CATEGORY", "UPDATED")
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
		fmt.Printf("%-32s %-10s %-8v %-10v %-17s %s\n",
			truncateString(p.Name, 31),
			p.Severity,
			p.Enabled,
			p.Enforced,
			truncateString(category, 16),
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
