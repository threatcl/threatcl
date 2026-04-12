package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudPolicyUpdateCommand struct {
	CloudCommandBase
	flagOrgId       string
	flagPolicyId    string
	flagName        string
	flagDescription string
	flagSeverity    string
	flagRegoFile    string
	flagCategory    string
	flagTags        string
	flagEnabled     string
	flagEnforced    string
	flagJSON        bool
}

func (c *CloudPolicyUpdateCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy update -policy-id=<uuid> [-org-id=<orgId>] [-json]

	Update an existing policy. Only specified fields will be updated.

	The -policy-id flag is required.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -policy-id=<uuid>
   Required. The policy ID to update.

 -name=<name>
   New policy name.

 -description=<description>
   New description.

 -severity=<severity>
   New severity: error, warning, or info.

 -rego-file=<file>
   Path to updated .rego file.

 -category=<category>
   New category.

 -tags=<tags>
   Comma-separated tags (replaces existing).

 -enabled=<true|false>
   Toggle enabled.

 -enforced=<true|false>
   Toggle enforced.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

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

func (c *CloudPolicyUpdateCommand) Synopsis() string {
	return "Update an existing policy"
}

func (c *CloudPolicyUpdateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":    predictHCL,
		"-rego-file": complete.PredictFiles("*.rego"),
		"-severity":  complete.PredictSet("error", "warning", "info"),
		"-enabled":   complete.PredictSet("true", "false"),
		"-enforced":  complete.PredictSet("true", "false"),
	}
}

func (c *CloudPolicyUpdateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy update")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagPolicyId, "policy-id", "", "Policy ID (required)")
	flagSet.StringVar(&c.flagName, "name", "", "New policy name")
	flagSet.StringVar(&c.flagDescription, "description", "", "New description")
	flagSet.StringVar(&c.flagSeverity, "severity", "", "New severity: error, warning, or info")
	flagSet.StringVar(&c.flagRegoFile, "rego-file", "", "Path to updated .rego file")
	flagSet.StringVar(&c.flagCategory, "category", "", "New category")
	flagSet.StringVar(&c.flagTags, "tags", "", "Comma-separated tags (replaces existing)")
	flagSet.StringVar(&c.flagEnabled, "enabled", "", "Toggle enabled (true/false)")
	flagSet.StringVar(&c.flagEnforced, "enforced", "", "Toggle enforced (true/false)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	flagSet.Parse(args)

	if c.flagPolicyId == "" {
		fmt.Fprintf(os.Stderr, "Error: -policy-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy update -help' for usage information.\n")
		return 1
	}

	if c.flagSeverity != "" {
		validSeverities := map[string]bool{"error": true, "warning": true, "info": true}
		if !validSeverities[c.flagSeverity] {
			fmt.Fprintf(os.Stderr, "Error: -severity must be one of: error, warning, info\n")
			return 1
		}
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Build request payload - only include fields that were set
	payload := policyUpdateRequest{}
	hasUpdates := false

	if c.flagName != "" {
		payload.Name = &c.flagName
		hasUpdates = true
	}
	if c.flagDescription != "" {
		payload.Description = &c.flagDescription
		hasUpdates = true
	}
	if c.flagSeverity != "" {
		payload.Severity = &c.flagSeverity
		hasUpdates = true
	}
	if c.flagCategory != "" {
		payload.Category = &c.flagCategory
		hasUpdates = true
	}
	if c.flagTags != "" {
		tags := strings.Split(c.flagTags, ",")
		for i, t := range tags {
			tags[i] = strings.TrimSpace(t)
		}
		payload.Tags = tags
		hasUpdates = true
	}
	if c.flagEnabled != "" {
		enabled := c.flagEnabled == "true"
		payload.Enabled = &enabled
		hasUpdates = true
	}
	if c.flagEnforced != "" {
		enforced := c.flagEnforced == "true"
		payload.Enforced = &enforced
		hasUpdates = true
	}

	// Read rego file if provided
	if c.flagRegoFile != "" {
		regoBytes, err := fsSvc.ReadFile(c.flagRegoFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToReadFile, err)
			return 1
		}
		regoSource := string(regoBytes)
		payload.RegoSource = &regoSource
		hasUpdates = true
	}

	if !hasUpdates {
		fmt.Fprintf(os.Stderr, "Error: no update fields specified\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy update -help' for usage information.\n")
		return 1
	}

	// Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Update policy
	p, err := updatePolicy(token, orgId, c.flagPolicyId, &payload, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error updating policy: %s\n", err)
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

	fmt.Printf("Successfully updated policy '%s' (%s)\n", p.Name, p.ID)
	return 0
}
