package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

// CloudLibraryAssetRefCommand gets an information asset library item by reference ID
type CloudLibraryAssetRefCommand struct {
	CloudCommandBase
	flagOrgId string
	flagJSON  bool
}

func (c *CloudLibraryAssetRefCommand) Help() string {
	helpText := `
Usage: threatcl cloud library asset-ref [options] <reference-id>

  Get an information asset library item by its reference ID from ThreatCL Cloud.

  Note: Options must be specified before the positional argument.

Arguments:

  <reference-id>
      The information asset library item reference ID (e.g., "IA-UDATA") (required)

Options:

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # Get an information asset by reference ID
  threatcl cloud library asset-ref IA-UDATA

  # Output as JSON
  threatcl cloud library asset-ref -json IA-UDATA
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryAssetRefCommand) Synopsis() string {
	return "Get an information asset library item by reference ID"
}

func (c *CloudLibraryAssetRefCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudLibraryAssetRefCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library asset-ref")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Get reference ID from positional argument
	remainingArgs := flagSet.Args()
	if len(remainingArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Error: reference ID is required\n")
		fmt.Fprintf(os.Stderr, "Usage: threatcl cloud library asset-ref <reference-id> [options]\n")
		return 1
	}
	refId := remainingArgs[0]

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Get token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch asset by reference ID
	asset, err := fetchInformationAssetLibraryItemByRef(token, orgId, refId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching information asset library item: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(asset); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	displayInformationAsset(asset)
	return 0
}
