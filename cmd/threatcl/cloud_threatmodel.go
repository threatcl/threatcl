package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudThreatmodelCommand struct {
	CloudCommandBase
	flagOrgId     string
	flagModelId   string
	flagDownload  string
	flagOverwrite bool
}

func (c *CloudThreatmodelCommand) Help() string {
	helpText := `
Usage: threatcl cloud threatmodel -model-id=<modelId_or_slug> [-org-id=<orgId>] [-download=<file>] [-overwrite]

	Display information about a single threat model.

	The -model-id flag is required and can be either a threat model ID or slug.

	If -org-id is not provided, the command will automatically use the
	first organization from your user profile.

Options:

 -model-id=<modelId_or_slug>
   Required. The threat model ID or slug to display.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses the first organization
   from your user profile.

 -download=<file>
   Optionally, download the threat model file to the specified file.

 -overwrite
   When downloading, overwrite the file if it already exists. Default is false.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud threatmodel -model-id=my-model

`
	return strings.TrimSpace(helpText)
}

func (c *CloudThreatmodelCommand) Synopsis() string {
	return "Display information about a single threat model"
}

func (c *CloudThreatmodelCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud threatmodel")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID or slug (required)")
	flagSet.StringVar(&c.flagDownload, "download", "", "Download the threat model file to the specified file")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite the file if it already exists when downloading")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud threatmodel -help' for usage information.\n")
		return 1
	}

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

	// Step 3: Fetch threat model
	threatModel, err := fetchThreatModel(token, orgId, c.flagModelId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching threat model: %s\n", err)
		return 1
	}

	// Step 4: Download threat model file
	if c.flagDownload != "" {
		url := fmt.Sprintf("%s/api/v1/org/%s/models/%s/download", getAPIBaseURL(fsSvc), orgId, c.flagModelId)
		err = downloadFile(url, token, c.flagDownload, c.flagOverwrite, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading threat model file: %s\n", err)
			return 1
		}
		fmt.Printf("Successfully downloaded threat model file to %s\n", c.flagDownload)
		return 0
	}

	// Step 5: Display result
	c.displayThreatModel(threatModel)

	return 0
}

func (c *CloudThreatmodelCommand) displayThreatModel(tm *threatModel) {
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Threat Model")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()

	fmt.Printf("ID:              %s\n", tm.ID)
	fmt.Printf("Name:            %s\n", tm.Name)
	fmt.Printf("Slug:            %s\n", tm.Slug)
	if tm.Description != "" {
		fmt.Printf("Description:     %s\n", tm.Description)
	}
	fmt.Printf("Status:          %s\n", tm.Status)
	fmt.Printf("Version:         %s\n", tm.Version)
	if tm.SpecFilePath != "" {
		fmt.Printf("Spec File Path:  %s\n", tm.SpecFilePath)
	}
	fmt.Printf("Organization ID: %s\n", tm.OrganizationID)
	fmt.Printf("Asset Count:     %d\n", tm.AssetCount)
	fmt.Printf("Threat Count:    %d\n", tm.ThreatCount)
	fmt.Printf("Control Count:   %d\n", tm.ControlCount)
	fmt.Printf("Data Flow Count: %d\n", tm.DataFlowCount)
	fmt.Printf("Use Case Count:  %d\n", tm.UseCaseCount)
	fmt.Printf("Exclusion Count: %d\n", tm.ExclusionCount)
	fmt.Printf("Third Party Dependency Count: %d\n", tm.ThirdPartyDependencyCount)
	if len(tm.Tags) > 0 {
		fmt.Printf("Tags:            %s\n", strings.Join(tm.Tags, ", "))
	}
	if tm.CreatedBy != "" {
		fmt.Printf("Created By:      %s\n", tm.CreatedBy)
	}
	if tm.CreatedAt != "" {
		fmt.Printf("Created At:      %s\n", tm.CreatedAt)
	}
	if tm.UpdatedAt != "" {
		fmt.Printf("Updated At:      %s\n", tm.UpdatedAt)
	}
	fmt.Println()
}
