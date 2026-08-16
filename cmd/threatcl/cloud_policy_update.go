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
	flagEngine      string
	flagSeverity    string
	flagFile        string
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

	A policy's engine is fixed when it is created, so -engine is only needed to
	tell this command how to read a replacement source file: pass
	-engine=invariant when updating an invariant policy so the file is parsed
	as an invariant block before it is sent.

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

 -engine=<engine>
   The engine of the policy being updated: rego or invariant. Only affects how
   -file is read and sent.

 -severity=<severity>
   New severity: error, warning, or info. Invariant policies take their
   severity from the block and have no "info" level.

 -file=<file>
   Path to an updated policy source file: a .rego module, or an .hcl file with
   a single invariant block when -engine=invariant.

 -rego-file=<file>
   Deprecated alias for -file.

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
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudPolicyUpdateCommand) Synopsis() string {
	return "Update an existing policy"
}

func (c *CloudPolicyUpdateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":    predictHCL,
		"-file":      complete.PredictFiles("*.rego"),
		"-rego-file": complete.PredictFiles("*.rego"),
		"-engine":    complete.PredictSet(policyEngineRego, policyEngineInvariant),
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
	flagSet.StringVar(&c.flagEngine, "engine", "", "Engine of the policy being updated: rego or invariant")
	flagSet.StringVar(&c.flagSeverity, "severity", "", "New severity: error, warning, or info")
	flagSet.StringVar(&c.flagFile, "file", "", "Path to an updated policy source file")
	flagSet.StringVar(&c.flagRegoFile, "rego-file", "", "Deprecated alias for -file")
	flagSet.StringVar(&c.flagCategory, "category", "", "New category")
	flagSet.StringVar(&c.flagTags, "tags", "", "Comma-separated tags (replaces existing)")
	flagSet.StringVar(&c.flagEnabled, "enabled", "", "Toggle enabled (true/false)")
	flagSet.StringVar(&c.flagEnforced, "enforced", "", "Toggle enforced (true/false)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	parseFlags(flagSet, args)

	if c.flagPolicyId == "" {
		fmt.Fprintf(os.Stderr, "Error: -policy-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy update -help' for usage information.\n")
		return 1
	}

	if c.flagEngine != "" && !validPolicyEngine(c.flagEngine) {
		fmt.Fprintf(os.Stderr, "Error: -engine must be one of: %s, %s\n", policyEngineRego, policyEngineInvariant)
		return 1
	}

	if c.flagSeverity != "" && !validPolicySeverity(c.flagEngine, c.flagSeverity) {
		fmt.Fprintf(os.Stderr, "Error: -severity must be one of: %s\n", strings.Join(policySeverities(c.flagEngine), ", "))
		return 1
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

	// Read the replacement source file if provided
	sourceFile := c.flagFile
	if sourceFile == "" {
		sourceFile = c.flagRegoFile
	}
	if sourceFile != "" {
		sourceBytes, err := fsSvc.ReadFile(sourceFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToReadFile, err)
			return 1
		}

		if c.flagEngine == policyEngineInvariant {
			inv, err := parseSingleInvariant(sourceBytes, sourceFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing invariant file %s: %s\n", sourceFile, err)
				return 1
			}

			// The block is authoritative for severity, so a -severity that
			// disagrees with the file being uploaded is a local error.
			if _, _, err := invariantPolicyIdentity(inv, "", c.flagSeverity); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err)
				return 1
			}
		}

		payload.setSource(c.flagEngine, string(sourceBytes))
		hasUpdates = true
	}

	if !hasUpdates {
		fmt.Fprintf(os.Stderr, "Error: no update fields specified\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy update -help' for usage information.\n")
		return 1
	}

	// Retrieve token and org ID
	token, orgId, apiURL, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Update policy
	client := NewCloudClient(token, orgId, apiURL, httpClient)
	p, err := client.UpdatePolicy(c.flagPolicyId, &payload)
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
