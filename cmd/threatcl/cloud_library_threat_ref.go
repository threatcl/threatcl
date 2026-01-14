package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// CloudLibraryThreatRefCommand gets a threat library item by reference ID
type CloudLibraryThreatRefCommand struct {
	CloudCommandBase
	flagOrgId string
	flagJSON  bool
}

func (c *CloudLibraryThreatRefCommand) Help() string {
	helpText := `
Usage: threatcl cloud library threat-ref [options] <reference-id>

  Get a threat library item by its reference ID from ThreatCL Cloud.

  Note: Options must be specified before the positional argument.

Arguments:

  <reference-id>
      The threat library item reference ID (e.g., "THR-001") (required)

Options:

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # Get a threat by reference ID
  threatcl cloud library threat-ref THR-001

  # Output as JSON
  threatcl cloud library threat-ref -json THR-001
`
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryThreatRefCommand) Synopsis() string {
	return "Get a threat library item by reference ID"
}

func (c *CloudLibraryThreatRefCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library threat-ref")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Get reference ID from positional argument
	remainingArgs := flagSet.Args()
	if len(remainingArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Error: reference ID is required\n")
		fmt.Fprintf(os.Stderr, "Usage: threatcl cloud library threat-ref <reference-id> [options]\n")
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

	// Fetch threat by reference ID
	threat, err := fetchThreatLibraryItemByRef(token, orgId, refId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching threat library item: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(threat); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	c.displayThreat(threat)
	return 0
}

func (c *CloudLibraryThreatRefCommand) displayThreat(threat *threatLibraryItem) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Threat Library Item: %s\n", threat.Name)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Printf("ID:           %s\n", threat.ID)
	fmt.Printf("Reference ID: %s\n", threat.ReferenceID)
	fmt.Printf("Name:         %s\n", threat.Name)
	fmt.Printf("Status:       %s\n", threat.Status)
	fmt.Printf("Usage Count:  %d\n", threat.UsageCount)

	if threat.CurrentVersion != nil {
		v := threat.CurrentVersion
		fmt.Printf("\nCurrent Version (v%s):\n", v.Version)
		if v.Description != "" {
			fmt.Printf("  Description:  %s\n", v.Description)
		}
		if v.Severity != "" {
			fmt.Printf("  Severity:     %s\n", v.Severity)
		}
		if v.Likelihood != "" {
			fmt.Printf("  Likelihood:   %s\n", v.Likelihood)
		}
		if len(v.Impacts) > 0 {
			fmt.Printf("  Impacts:      %s\n", strings.Join(v.Impacts, ", "))
		}
		if len(v.Stride) > 0 {
			fmt.Printf("  STRIDE:       %s\n", strings.Join(v.Stride, ", "))
		}
		if len(v.CWEIds) > 0 {
			fmt.Printf("  CWE IDs:      %s\n", strings.Join(v.CWEIds, ", "))
		}
		if len(v.MitreAttackIds) > 0 {
			fmt.Printf("  MITRE ATT&CK: %s\n", strings.Join(v.MitreAttackIds, ", "))
		}
		if len(v.Tags) > 0 {
			fmt.Printf("  Tags:         %s\n", strings.Join(v.Tags, ", "))
		}
		if len(v.RecommendedControls) > 0 {
			fmt.Println()
			fmt.Println("  Recommended Controls:")
			for _, ctrl := range v.RecommendedControls {
				fmt.Printf("    - %s (%s)\n", ctrl.ReferenceID, ctrl.Name)
			}
		}
	}

	if len(threat.Versions) > 0 {
		fmt.Printf("\nVersions (%d):\n", len(threat.Versions))
		for i, v := range threat.Versions {
			current := ""
			if i == 0 {
				current = " (current)"
			}
			fmt.Printf("  - v%s%s\n", v.Version, current)
		}
	}

	if len(threat.UsedByModels) > 0 {
		fmt.Printf("\nUsed By Models (%d):\n", len(threat.UsedByModels))
		for _, model := range threat.UsedByModels {
			fmt.Printf("  - %s\n", model.Name)
		}
	}

	fmt.Println()
}
