package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/threatcl/spec"
)

type CloudUploadCommand struct {
	CloudCommandBase
	flagOrgId   string
	flagModelId string
	specCfg     *spec.ThreatmodelSpecConfig
}

func (c *CloudUploadCommand) Help() string {
	helpText := `
Usage: threatcl cloud upload <file> -model-id=<modelId_or_slug> [-org-id=<orgId>]

	Upload a threat model HCL file to ThreatCL Cloud.

	The file argument is required and must be a valid HCL threat model file.
	The file must contain exactly one threat model.

	The -model-id flag is required and can be either a threat model ID or slug.

	If -org-id is not provided, the command will automatically use the
	first organization from your user profile.

Options:

 -model-id=<modelId_or_slug>
   Required. The threat model ID or slug to upload to.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses the first organization
   from your user profile.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud upload mymodel.hcl -model-id=my-model

`
	return strings.TrimSpace(helpText)
}

func (c *CloudUploadCommand) Synopsis() string {
	return "Upload a threat model HCL file to ThreatCL Cloud"
}

func (c *CloudUploadCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud upload")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID or slug (required)")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud upload -help' for usage information.\n")
		return 1
	}

	// Get file path from remaining args
	remainingArgs := flagSet.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: file path is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud upload -help' for usage information.\n")
		return 1
	}
	if len(remainingArgs) > 1 {
		fmt.Fprintf(os.Stderr, "Error: only one file can be uploaded at a time\n")
		return 1
	}

	filePath := remainingArgs[0]

	// Load config if provided
	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %s\n", err)
			return 1
		}
	}

	// Initialize dependencies - use longer timeout for file uploads
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Step 1: Validate and parse the HCL file
	tmParser := spec.NewThreatmodelParser(c.specCfg)
	err := tmParser.ParseFile(filePath, false)
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
		fmt.Fprintf(os.Stderr, "Warning: %s Found in %s\n", constraintMsg, filePath)
	}

	// Check that exactly one threat model exists
	tmCount := len(tmParser.GetWrapped().Threatmodels)
	if tmCount != 1 {
		fmt.Fprintf(os.Stderr, "Error: file must contain exactly one threat model, found %d\n", tmCount)
		return 1
	}

	// Step 2: Retrieve token
	token, err := c.getTokenWithDeps(keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Step 3: Get organization ID
	orgId, err := c.resolveOrgId(token, c.flagOrgId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	// Step 4: Upload the file
	err = uploadFile(token, orgId, c.flagModelId, filePath, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error uploading file: %s\n", err)
		return 1
	}

	fmt.Printf("Successfully uploaded threat model from %s\n", filePath)
	return 0
}
