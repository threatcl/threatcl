package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudPolicyCreateCommand struct {
	CloudCommandBase
	flagOrgId       string
	flagName        string
	flagSeverity    string
	flagRegoFile    string
	flagDescription string
	flagCategory    string
	flagTags        string
	flagEnabled     bool
	flagJSON        bool
}

func (c *CloudPolicyCreateCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy create -name="Policy Name" -severity=error -rego-file=./policy.rego [-org-id=<orgId>] [-json]

	Create a new policy.

	The -name, -severity, and -rego-file flags are required.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -name=<name>
   Required. The policy name.

 -severity=<severity>
   Required. Policy severity: error, warning, or info.

 -rego-file=<file>
   Required. Path to a local .rego file containing the policy source.

 -description=<description>
   Optional description.

 -category=<category>
   Optional category.

 -tags=<tags>
   Optional comma-separated tags.

 -enabled
   Enable the policy on creation. Default is true.

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

func (c *CloudPolicyCreateCommand) Synopsis() string {
	return "Create a new policy"
}

func (c *CloudPolicyCreateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":    predictHCL,
		"-rego-file": complete.PredictFiles("*.rego"),
		"-severity":  complete.PredictSet("error", "warning", "info"),
	}
}

func (c *CloudPolicyCreateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy create")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagName, "name", "", "Policy name (required)")
	flagSet.StringVar(&c.flagSeverity, "severity", "", "Policy severity: error, warning, or info (required)")
	flagSet.StringVar(&c.flagRegoFile, "rego-file", "", "Path to .rego file (required)")
	flagSet.StringVar(&c.flagDescription, "description", "", "Optional description")
	flagSet.StringVar(&c.flagCategory, "category", "", "Optional category")
	flagSet.StringVar(&c.flagTags, "tags", "", "Comma-separated tags")
	flagSet.BoolVar(&c.flagEnabled, "enabled", true, "Enable the policy on creation")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	flagSet.Parse(args)

	// Validate required flags
	if c.flagName == "" {
		fmt.Fprintf(os.Stderr, "Error: -name is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy create -help' for usage information.\n")
		return 1
	}

	if c.flagSeverity == "" {
		fmt.Fprintf(os.Stderr, "Error: -severity is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy create -help' for usage information.\n")
		return 1
	}

	validSeverities := map[string]bool{"error": true, "warning": true, "info": true}
	if !validSeverities[c.flagSeverity] {
		fmt.Fprintf(os.Stderr, "Error: -severity must be one of: error, warning, info\n")
		return 1
	}

	if c.flagRegoFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -rego-file is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy create -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Read rego file
	regoBytes, err := fsSvc.ReadFile(c.flagRegoFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToReadFile, err)
		return 1
	}
	regoSource := string(regoBytes)

	// Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Build request payload
	payload := policyCreateRequest{
		Name:       c.flagName,
		RegoSource: regoSource,
		Severity:   c.flagSeverity,
		Enabled:    &c.flagEnabled,
	}

	if c.flagDescription != "" {
		payload.Description = &c.flagDescription
	}
	if c.flagCategory != "" {
		payload.Category = &c.flagCategory
	}
	if c.flagTags != "" {
		tags := strings.Split(c.flagTags, ",")
		for i, t := range tags {
			tags[i] = strings.TrimSpace(t)
		}
		payload.Tags = tags
	}

	// Create policy
	p, err := createPolicy(token, orgId, &payload, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating policy: %s\n", err)
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

	fmt.Printf("Successfully created policy '%s' (%s)\n", p.Name, p.ID)
	return 0
}
