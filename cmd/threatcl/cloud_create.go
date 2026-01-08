package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/threatcl/spec"
)

type CloudCreateCommand struct {
	CloudCommandBase
	flagOrgId       string
	flagName        string
	flagDescription string
	flagUpload      string
	specCfg         *spec.ThreatmodelSpecConfig
}

func (c *CloudCreateCommand) Help() string {
	helpText := `
Usage: threatcl cloud create -name=<name> [-description=<description>] [-upload=<file>] [-org-id=<orgId>]

	Create a new threat model in ThreatCL Cloud.

	The -name flag is required and will be the name of the new threat model.

	The -description flag is optional and provides a description for the threat model.

	The -upload flag is optional and allows uploading a threat model HCL file immediately
	after creating the threat model.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -name=<name>
   Required. The name of the threat model to create.

 -description=<description>
   Optional. A description for the threat model.

 -upload=<file>
   Optional. Path to an HCL file to upload immediately after creating the threat model.
   The file must contain exactly one threat model.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud create -name="My Model"

 THREATCL_CLOUD_ORG
   Default organization ID to use when -org-id is not specified.
   Example: THREATCL_CLOUD_ORG=your-org-id threatcl cloud create -name="My Model"

`
	return strings.TrimSpace(helpText)
}

func (c *CloudCreateCommand) Synopsis() string {
	return "Create a new threat model in ThreatCL Cloud"
}

func (c *CloudCreateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud create")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagName, "name", "", "Threat model name (required)")
	flagSet.StringVar(&c.flagDescription, "description", "", "Threat model description (optional)")
	flagSet.StringVar(&c.flagUpload, "upload", "", "HCL file to upload (optional)")
	flagSet.Parse(args)

	if c.flagName == "" {
		fmt.Fprintf(os.Stderr, "Error: -name is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud create -help' for usage information.\n")
		return 1
	}

	// If upload flag is provided, validate the file exists and is parseable
	if c.flagUpload != "" {
		// Load config if provided
		if c.flagConfig != "" {
			err := c.specCfg.LoadSpecConfigFile(c.flagConfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config file: %s\n", err)
				return 1
			}
		}

		// Validate and parse the HCL file
		tmParser := spec.NewThreatmodelParser(c.specCfg)
		err := tmParser.ParseFile(c.flagUpload, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing HCL file: %s\n", err)
			return 1
		}

		// Constraint check
		constraintMsg, err := spec.VersionConstraints(tmParser.GetWrapped(), false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking constraints: %s\n", err)
			return 1
		}
		if constraintMsg != "" {
			fmt.Fprintf(os.Stderr, "Warning: %s Found in %s\n", constraintMsg, c.flagUpload)
		}

		// Check that exactly one threat model exists
		tmCount := len(tmParser.GetWrapped().Threatmodels)
		if tmCount != 1 {
			fmt.Fprintf(os.Stderr, "Error: file must contain exactly one threat model, found %d\n", tmCount)
			return 1
		}
	}

	// Initialize dependencies - use longer timeout if uploading
	timeout := 10 * time.Second
	if c.flagUpload != "" {
		timeout = 30 * time.Second
	}
	httpClient, keyringSvc, fsSvc := c.initDependencies(timeout)

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

	// Step 3: Create the threat model
	threatModel, err := createThreatModel(token, orgId, c.flagName, c.flagDescription, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating threat model: %s\n", err)
		return 1
	}

	fmt.Printf("Successfully created threat model '%s'\n", threatModel.Name)
	fmt.Printf("  ID: %s\n", threatModel.ID)
	fmt.Printf("  Slug: %s\n", threatModel.Slug)
	if threatModel.Description != "" {
		fmt.Printf("  Description: %s\n", threatModel.Description)
	}

	// Step 4: Upload file if provided
	if c.flagUpload != "" {
		fmt.Printf("\nUploading file %s...\n", c.flagUpload)
		err := uploadFile(token, orgId, threatModel.Slug, c.flagUpload, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error uploading file: %s\n", err)
			fmt.Fprintf(os.Stderr, "Note: The threat model was created successfully, but the upload failed.\n")
			return 1
		}
		fmt.Printf("Successfully uploaded threat model from %s\n", c.flagUpload)
	}

	return 0
}
