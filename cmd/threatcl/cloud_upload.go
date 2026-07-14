package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/posener/complete"
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

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Multi-file models:

	A cloud model may be split across several files, keyed by each file's
	threatmodel 'id': the file declaring the un-dotted root id (e.g.
	id = "app") is the model's default file, and each additional file
	declares a dotted id beneath it (e.g. id = "app.frontend") and may
	'extends' the root. Upload the root file first, then the children. The
	server validates each uploaded file against the model's other stored
	files, so a child's extends target doesn't need to be in the same file.
	(The backend block's 'segment' attribute from earlier specs no longer
	exists - the threatmodel id alone keys each file.)

Options:

 -model-id=<modelId_or_slug>
   Required. The threat model ID or slug to upload to.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -config=<file>
   Optional config file
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudUploadCommand) Synopsis() string {
	return "Upload a threat model HCL file to ThreatCL Cloud"
}

func (c *CloudUploadCommand) AutocompleteArgs() complete.Predictor { return predictHCLOrJSON }
func (c *CloudUploadCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
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

	// Step 1: Validate and parse the HCL file. The file may be a single
	// segment of a multi-file cloud model whose extends target lives in
	// another file; the server validates the whole set, so parse
	// file-faithfully and leave extends unresolved.
	tmParser := spec.NewThreatmodelParser(c.specCfg)
	tmParser.SetSkipExtendsResolution(true)
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

	// Retrieve token and org ID, then build the cloud client
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}
	client := NewCloudClient(token, orgId, getAPIBaseURL(fsSvc), httpClient)

	// Upload the file. The caller reads it so the client stays filesystem-free.
	content, uploadErr := fsSvc.ReadFile(filePath)
	if uploadErr == nil {
		uploadErr = client.Upload(c.flagModelId, filepath.Base(filePath), content, false)
	} else {
		uploadErr = fmt.Errorf("%s: %w", ErrFailedToReadFile, uploadErr)
	}
	if uploadErr != nil {
		fmt.Fprintf(os.Stderr, "Error uploading file: %s\n", uploadErr)
		return 1
	}

	fmt.Printf("Successfully uploaded threat model from %s\n", filePath)
	return 0
}
