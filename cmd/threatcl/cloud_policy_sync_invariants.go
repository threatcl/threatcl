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

type CloudPolicySyncInvariantsCommand struct {
	CloudCommandBase
	flagOrgId string
	flagJSON  bool
}

func (c *CloudPolicySyncInvariantsCommand) Help() string {
	helpText := `
Usage: threatcl cloud policy sync-invariants <file.hcl> [-org-id=<orgId>] [-json]

	Import a whole threatcl invariants file into ThreatCL Cloud, creating one
	policy per invariant block and upserting by slug. The slug is the block's
	name label, so re-running this after editing the file updates the same
	policies rather than creating new ones.

	The import is all-or-nothing: if any block fails to parse or validate,
	nothing is imported and the error names the offending invariant. Cloud-side
	metadata - enabled, enforced, category and tags - is preserved across an
	update, and new policies default to enabled and not enforced.

	Exemption references resolve against the threatmodel identities your model
	files declare - each segment's threatmodel block label and its dotted id -
	not the display names shown in the cloud UI.

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
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudPolicySyncInvariantsCommand) Synopsis() string {
	return "Import an invariants file as cloud policies"
}

func (c *CloudPolicySyncInvariantsCommand) AutocompleteArgs() complete.Predictor {
	return predictHCL
}

func (c *CloudPolicySyncInvariantsCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudPolicySyncInvariantsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud policy sync-invariants")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")
	parseFlags(flagSet, args)

	remainingArgs := flagSet.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: invariants file path is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud policy sync-invariants -help' for usage information.\n")
		return 1
	}

	filePath := remainingArgs[0]

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	sourceBytes, err := fsSvc.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToReadFile, err)
		return 1
	}

	// Parse locally first. The server validates every block again - and only it
	// can resolve exemptions against the org's models - but a syntax error is
	// worth catching before an all-or-nothing import round-trip.
	invs, err := invariants.ParseHCLRaw(sourceBytes, filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing invariants file %s: %s\n", filePath, err)
		return 1
	}

	// Retrieve token and org ID
	token, orgId, apiURL, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	client := NewCloudClient(token, orgId, apiURL, httpClient)
	result, err := client.ImportInvariants(string(sourceBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error importing invariants: %s\n", err)
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
		return 0
	}

	displayInvariantImport(filePath, len(invs), result)
	return 0
}

// displayInvariantImport reports what the import changed, one line per
// invariant, so a re-run reads as a diff rather than a wall of policies.
func displayInvariantImport(filePath string, parsed int, result *importInvariantsResponse) {
	fmt.Printf("Parsed %d %s from %s\n", parsed, pluralise("invariant", parsed), filePath)

	if len(result.Created) == 0 && len(result.Updated) == 0 {
		fmt.Println("No policies were created or updated.")
		return
	}

	fmt.Println()
	for _, slug := range result.Created {
		fmt.Printf("  + %s (created)\n", slug)
	}
	for _, slug := range result.Updated {
		fmt.Printf("  ~ %s (updated)\n", slug)
	}
	fmt.Println()
	fmt.Printf("%d created | %d updated\n", len(result.Created), len(result.Updated))
}

func pluralise(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
