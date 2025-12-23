package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudThreatmodelsCommand struct {
	CloudCommandBase
	flagOrgId string
}

func (c *CloudThreatmodelsCommand) Help() string {
	helpText := `
Usage: threatcl cloud threatmodels [-org-id=<orgId>]

	List threat models for an organization.

	If -org-id is not provided, the command will automatically use the
	first organization from your user profile.

Options:

 -org-id=<orgId>
   Optional organization ID. If not provided, uses the first organization
   from your user profile.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud threatmodels

`
	return strings.TrimSpace(helpText)
}

func (c *CloudThreatmodelsCommand) Synopsis() string {
	return "List threat models for an organization"
}

func (c *CloudThreatmodelsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud threatmodels")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.Parse(args)

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Step 1: Retrieve token
	token, err := c.getTokenWithDeps(keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Step 2: Get organization ID
	orgId, err := c.resolveOrgId(token, c.flagOrgId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	// Step 3: Fetch threat models
	threatModels, err := fetchThreatModels(token, orgId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching threat models: %s\n", err)
		return 1
	}

	// Step 4: Display results
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
