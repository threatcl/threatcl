package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
	"github.com/threatcl/spec/invariants"
)

type CloudPolicyCreateCommand struct {
	CloudCommandBase
	flagOrgId       string
	flagName        string
	flagEngine      string
	flagSeverity    string
	flagFile        string
	flagRegoFile    string
	flagDescription string
	flagCategory    string
	flagTags        string
	flagEnabled     bool
	flagJSON        bool
}

func (c *CloudPolicyCreateCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy create -name="Policy Name" -severity=error -file=./policy.rego [-engine=<engine>] [-org-id=<orgId>] [-json]

	Create a new policy.

	A policy is either a Rego module (-engine=rego, the default) or a single
	threatcl invariant block (-engine=invariant), evaluated by the same engine
	'threatcl validate -invariants' uses.

	The -name, -severity, and -file flags are required for a Rego policy. For an
	invariant policy the block is authoritative, so -name and -severity are
	optional and default to the block's name label and severity attribute.

	To import a whole invariants file - one policy per invariant block - use
	'threatcl cloud policy sync-invariants' instead.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -name=<name>
   The policy name. Required for Rego policies; defaults to the block's name
   label for invariant policies.

 -engine=<engine>
   Policy engine: rego (default) or invariant.

 -severity=<severity>
   Policy severity: error, warning, or info. Required for Rego policies. For
   invariant policies it defaults to the block's severity, and must match it
   when given; "info" is not a valid invariant severity.

 -file=<file>
   Required. Path to a local file holding the policy source: a .rego module,
   or an .hcl file with a single invariant block.

 -rego-file=<file>
   Deprecated alias for -file.

 -description=<description>
   Optional description. Invariant policies fall back to the block's
   description.

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
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudPolicyCreateCommand) Synopsis() string {
	return "Create a new policy"
}

func (c *CloudPolicyCreateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":    predictHCL,
		"-file":      complete.PredictFiles("*.rego"),
		"-rego-file": complete.PredictFiles("*.rego"),
		"-engine":    complete.PredictSet(policyEngineRego, policyEngineInvariant),
		"-severity":  complete.PredictSet("error", "warning", "info"),
	}
}

func (c *CloudPolicyCreateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy create")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagName, "name", "", "Policy name")
	flagSet.StringVar(&c.flagEngine, "engine", policyEngineRego, "Policy engine: rego or invariant")
	flagSet.StringVar(&c.flagSeverity, "severity", "", "Policy severity: error, warning, or info")
	flagSet.StringVar(&c.flagFile, "file", "", "Path to the policy source file (required)")
	flagSet.StringVar(&c.flagRegoFile, "rego-file", "", "Deprecated alias for -file")
	flagSet.StringVar(&c.flagDescription, "description", "", "Optional description")
	flagSet.StringVar(&c.flagCategory, "category", "", "Optional category")
	flagSet.StringVar(&c.flagTags, "tags", "", "Comma-separated tags")
	flagSet.BoolVar(&c.flagEnabled, "enabled", true, "Enable the policy on creation")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	parseFlags(flagSet, args)

	if !validPolicyEngine(c.flagEngine) {
		fmt.Fprintf(os.Stderr, "Error: -engine must be one of: %s, %s\n", policyEngineRego, policyEngineInvariant)
		return 1
	}

	// A Rego policy carries no metadata of its own, so name and severity have
	// to come from the flags. An invariant policy takes both from its block.
	if c.flagEngine != policyEngineInvariant {
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
	}

	if c.flagSeverity != "" && !validPolicySeverity(c.flagEngine, c.flagSeverity) {
		fmt.Fprintf(os.Stderr, "Error: -severity must be one of: %s\n", strings.Join(policySeverities(c.flagEngine), ", "))
		return 1
	}

	sourceFile := c.flagFile
	if sourceFile == "" {
		sourceFile = c.flagRegoFile
	}
	if sourceFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy create -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Read the policy source file
	sourceBytes, err := fsSvc.ReadFile(sourceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToReadFile, err)
		return 1
	}
	source := string(sourceBytes)

	name := c.flagName
	severity := c.flagSeverity

	if c.flagEngine == policyEngineInvariant {
		// The block is authoritative for the policy's identity and severity, so
		// parse it here: it fills in the flags the author didn't need to repeat,
		// and a contradiction becomes a local error rather than a 400.
		inv, err := parseSingleInvariant(sourceBytes, sourceFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing invariant file %s: %s\n", sourceFile, err)
			return 1
		}

		name, severity, err = invariantPolicyIdentity(inv, name, severity)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}

	// Retrieve token and org ID
	token, orgId, apiURL, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Build request payload
	payload := policyCreateRequest{
		Name:     name,
		Severity: severity,
		Enabled:  &c.flagEnabled,
	}
	payload.setSource(c.flagEngine, source)

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
	client := NewCloudClient(token, orgId, apiURL, httpClient)
	p, err := client.CreatePolicy(&payload)
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

// policySeverities lists the severities an engine accepts. Invariants have no
// "info" level upstream, so the cloud has none for them either.
func policySeverities(engine string) []string {
	if engine == policyEngineInvariant {
		return []string{string(invariants.SeverityError), string(invariants.SeverityWarning)}
	}
	return []string{"error", "warning", "info"}
}

func validPolicySeverity(engine, severity string) bool {
	for _, s := range policySeverities(engine) {
		if s == severity {
			return true
		}
	}
	return false
}

// invariantPolicyIdentity resolves the name and severity of an invariant
// policy. Both come from the block unless the caller supplied them, and a
// supplied severity that contradicts the block is an error rather than a
// silent override - the block is what the evaluator reads.
func invariantPolicyIdentity(inv *invariants.Invariant, name, severity string) (string, string, error) {
	if name == "" {
		name = inv.Name
	}

	blockSeverity := string(inv.Severity)
	if severity == "" {
		return name, blockSeverity, nil
	}
	if severity != blockSeverity {
		return "", "", fmt.Errorf(
			"-severity=%s contradicts invariant %q, which declares severity %q: change the block's severity attribute, or drop the flag",
			severity, inv.Name, blockSeverity,
		)
	}

	return name, severity, nil
}
