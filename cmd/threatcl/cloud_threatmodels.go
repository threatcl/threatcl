package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

type CloudThreatmodelsCommand struct {
	CloudCommandBase
	flagOrgId string
}

func (c *CloudThreatmodelsCommand) Help() string {
	helpText := `
Usage: threatcl cloud threatmodels [-org-id=<orgId>]

	List threat models for an organization.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -config=<file>
   Optional config file
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudThreatmodelsCommand) Synopsis() string {
	return "List threat models for an organization"
}

func (c *CloudThreatmodelsCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudThreatmodelsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud threatmodels")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.Parse(args)

	// Build the cloud client (resolves token + org)
	client, _, err := c.newCloudClient(c.flagOrgId, 10*time.Second)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch threat models
	threatModels, err := client.FetchThreatModels()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching threat models: %s\n", err)
		return 1
	}

	// Step 3: Display results
	c.displayThreatModels(threatModels)

	return 0
}

func (c *CloudThreatmodelsCommand) displayThreatModels(threatModels []threatModel) {
	if len(threatModels) == 0 {
		fmt.Println("No threat models found.")
		return
	}

	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Threat Models")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()
	fmt.Printf("%-36s %-30s %-20s %-10s %-10s\n", "ID", "Name", "Slug", "Status", "Version")
	fmt.Println(strings.Repeat("-", 100))

	for _, tm := range threatModels {
		fmt.Printf("%-36s %-30s %-20s %-10s %-10s\n", tm.ID, tm.Name, tm.Slug, tm.Status, tm.Version)
	}
	fmt.Println()
}
