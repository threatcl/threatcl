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
	flagOrgId string
	flagJSON  bool
}

func (c *CloudPolicyValidateCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy validate <file.rego> [-org-id=<orgId>] [-json]

	Validate a local .rego file against the ThreatCL Cloud API.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

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

func (c *CloudPolicyValidateCommand) Synopsis() string {
	return "Validate a .rego policy file"
}

func (c *CloudPolicyValidateCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictFiles("*.rego")
}

func (c *CloudPolicyValidateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudPolicyValidateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy validate")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	flagSet.Parse(args)

	// Get remaining args (the file path)
	remainingArgs := flagSet.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: .rego file path is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy validate -help' for usage information.\n")
		return 1
	}

	filePath := remainingArgs[0]

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Read rego file
	regoBytes, err := fsSvc.ReadFile(filePath)
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

	// Validate rego
	result, err := validateRego(token, orgId, regoSource, httpClient, fsSvc)
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
