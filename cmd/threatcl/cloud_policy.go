package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

// policy represents a policy object from the API.
//
// RegoSource is the deprecated alias of Source. It is absent on invariant
// policies - their source is HCL, which an older client would try to compile
// as Rego - so read the source through sourceText().
type policy struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organization_id"`
	Name           string   `json:"name"`
	Slug           string   `json:"slug"`
	Description    string   `json:"description"`
	Engine         string   `json:"engine"`
	Source         string   `json:"source"`
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

// engineName is the policy's engine, defaulting to rego for a response from a
// deployment that predates the field.
func (p *policy) engineName() string {
	return policyEngineOrDefault(p.Engine)
}

// sourceText is the policy's rule text, falling back to the deprecated
// rego_source for a deployment that predates the source field.
func (p *policy) sourceText() string {
	if p.Source != "" {
		return p.Source
	}
	return p.RegoSource
}

type CloudPolicyCommand struct {
	CloudCommandBase
	flagOrgId      string
	flagPolicyId   string
	flagShowSource bool
	flagShowRego   bool
	flagJSON       bool
}

func (c *CloudPolicyCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy -policy-id=<uuid> [-org-id=<orgId>] [-show-source] [-json]

	Display information about a single policy.

	A policy is either a Rego module (engine "rego") or a single threatcl
	invariant block (engine "invariant"); the Engine field says which.

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

 -show-source
   Include the full policy source in output.

 -show-rego
   Deprecated alias for -show-source.

 -json
   Output as JSON.

 -config=<file>
   Optional config file
` + cloudEnvVarHelp()
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
	flagSet.BoolVar(&c.flagShowSource, "show-source", false, "Include the full policy source in output")
	flagSet.BoolVar(&c.flagShowRego, "show-rego", false, "Deprecated alias for -show-source")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	parseFlags(flagSet, args)

	if c.flagPolicyId == "" {
		fmt.Fprintf(os.Stderr, "Error: -policy-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy -help' for usage information.\n")
		return 1
	}

	// Build the cloud client (resolves token + org)
	client, _, err := c.newCloudClient(c.flagOrgId, 10*time.Second)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch policy
	p, err := client.FetchPolicy(c.flagPolicyId)
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
	fmt.Printf("Engine:      %s\n", p.engineName())
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

	if source := p.sourceText(); (c.flagShowSource || c.flagShowRego) && source != "" {
		heading := "Rego Source:"
		if p.engineName() == policyEngineInvariant {
			heading = "Invariant Source:"
		}
		fmt.Println()
		fmt.Println(heading)
		for _, line := range strings.Split(source, "\n") {
			fmt.Printf("  %s\n", line)
		}
	}

	fmt.Println()
}
