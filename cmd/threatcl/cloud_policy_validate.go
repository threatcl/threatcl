package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudPolicyValidateCommand struct {
	CloudCommandBase
	flagOrgId  string
	flagEngine string
	flagJSON   bool
}

func (c *CloudPolicyValidateCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy validate <file> [-engine=<engine>] [-org-id=<orgId>] [-json]

	Validate a local policy source file against the ThreatCL Cloud API: a .rego
	module (-engine=rego, the default), or an .hcl file holding a single
	threatcl invariant block (-engine=invariant).

	Invariant validation is organization-scoped. The server resolves the
	block's exemption references against the threat model identities your org's
	models declare, so it can fail for reasons a local parse would not catch.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -engine=<engine>
   Policy engine: rego (default) or invariant.

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

func (c *CloudPolicyValidateCommand) Synopsis() string {
	return "Validate a policy source file"
}

func (c *CloudPolicyValidateCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictFiles("*.rego")
}

func (c *CloudPolicyValidateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":    predictHCL,
		"-engine":    complete.PredictSet(policyEngineRego, policyEngineInvariant),
		"-rego-file": complete.PredictFiles("*.rego"),
	}
}

func (c *CloudPolicyValidateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy validate")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagEngine, "engine", policyEngineRego, "Policy engine: rego or invariant")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	parseFlags(flagSet, args)

	if !validPolicyEngine(c.flagEngine) {
		fmt.Fprintf(os.Stderr, "Error: -engine must be one of: %s, %s\n", policyEngineRego, policyEngineInvariant)
		return 1
	}

	// Get remaining args (the file path)
	remainingArgs := flagSet.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: policy file path is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy validate -help' for usage information.\n")
		return 1
	}

	filePath := remainingArgs[0]

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Read the policy source file
	sourceBytes, err := fsSvc.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToReadFile, err)
		return 1
	}

	// Retrieve token and org ID
	token, orgId, apiURL, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Validate the source. The server is the authority here - it is the only
	// side that can resolve an invariant's exemptions against the org's models
	// - so the file is sent as-is rather than pre-parsed locally.
	client := NewCloudClient(token, orgId, apiURL, httpClient)
	result, err := client.ValidatePolicySource(c.flagEngine, string(sourceBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error validating policy: %s\n", err)
		return 1
	}

	// Output
	if c.flagJSON {
		output, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling JSON: %s\n", err)
			return 1
		}
		fmt.Println(string(output))
		if !result.Valid {
			return 1
		}
		return 0
	}

	if result.Valid {
		fmt.Println("Policy is valid")
		return 0
	}

	fmt.Fprintf(os.Stderr, "Policy is invalid: %s\n", result.Error)
	return 1
}
