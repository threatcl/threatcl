package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

// policy represents a policy object from the API
type policy struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organization_id"`
	Name           string   `json:"name"`
	Slug           string   `json:"slug"`
	Description    string   `json:"description"`
	RegoSource     string   `json:"rego_source"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Tags           []string `json:"tags"`
	Enabled        bool     `json:"enabled"`
	Enforced       bool     `json:"enforced"`
	CreatedBy      string   `json:"created_by"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

type CloudPolicyCommand struct {
	CloudCommandBase
	flagOrgId    string
	flagPolicyId string
	flagShowRego bool
	flagJSON     bool
}

func (c *CloudPolicyCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy -policy-id=<uuid> [-org-id=<orgId>] [-show-rego] [-json]

	Display information about a single policy.

	The -policy-id flag is required.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -policy-id=<uuid>
   Required. The policy ID to display.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -show-rego
   Include full Rego source in output.

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

func (c *CloudPolicyCommand) Synopsis() string {
	return "Display information about a single policy"
}

func (c *CloudPolicyCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudPolicyCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagPolicyId, "policy-id", "", "Policy ID (required)")
	flagSet.BoolVar(&c.flagShowRego, "show-rego", false, "Include full Rego source in output")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	flagSet.Parse(args)

	if c.flagPolicyId == "" {
		fmt.Fprintf(os.Stderr, "Error: -policy-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch policy
	p, err := fetchPolicy(token, orgId, c.flagPolicyId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching policy: %s\n", err)
		return 1
	}

	// Output
	if c.flagJSON {
		output, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling JSON: %s\n", err)
			return 1
		}
		fmt.Println(string(output))
		return 0
	}

	c.displayPolicy(p)
	return 0
}

func (c *CloudPolicyCommand) displayPolicy(p *policy) {
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Policy")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()

	fmt.Printf("Name:        %s\n", p.Name)
	fmt.Printf("ID:          %s\n", p.ID)
	fmt.Printf("Slug:        %s\n", p.Slug)
	fmt.Printf("Severity:    %s\n", p.Severity)
	if p.Category != "" {
		fmt.Printf("Category:    %s\n", p.Category)
	}
	if len(p.Tags) > 0 {
		fmt.Printf("Tags:        %s\n", strings.Join(p.Tags, ", "))
	}
	fmt.Printf("Enabled:     %v\n", p.Enabled)
	fmt.Printf("Enforced:    %v\n", p.Enforced)
	if p.Description != "" {
		fmt.Printf("Description: %s\n", p.Description)
	}
	if p.CreatedAt != "" {
		fmt.Printf("Created:     %s\n", p.CreatedAt)
	}
	if p.UpdatedAt != "" {
		fmt.Printf("Updated:     %s\n", p.UpdatedAt)
	}

	if c.flagShowRego && p.RegoSource != "" {
		fmt.Println()
		fmt.Println("Rego Source:")
		for _, line := range strings.Split(p.RegoSource, "\n") {
			fmt.Printf("  %s\n", line)
		}
	}

	fmt.Println()
}
