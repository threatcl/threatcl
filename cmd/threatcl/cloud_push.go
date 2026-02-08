package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/threatcl/spec"
)

type CloudPushCommand struct {
	CloudCommandBase
	flagNoCreate             bool
	flagNoUpdateLocal        bool
	flagIgnoreLinkedControls bool
	specCfg                  *spec.ThreatmodelSpecConfig
}

func (c *CloudPushCommand) Help() string {
	helpText := `
Usage: threatcl cloud push <file> [-no-create] [-no-update-local] [-ignore-linked-controls]

	Push a threat model HCL file to ThreatCL Cloud.

	This command validates, creates (if needed), and uploads a threat model
	to ThreatCL Cloud in a single operation.

	The file must contain exactly one threat model and have a valid backend
	block configured for threatcl-cloud with an organization specified.

	If the threat model doesn't exist in the cloud yet, it will be created
	automatically (unless -no-create is specified).

Options:

 -no-create
   If the threat model doesn't exist in the cloud, don't create it.
   Default: false (will create if needed)

 -no-update-local
   If a new threat model is created, don't update the local HCL file
   with the threatmodel slug. Default: false (will update)

 -ignore-linked-controls
   If set, the cloud will not attempt to link controls to reference threats
   from the control library during upload. Default: false

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)

 THREATCL_API_TOKEN
   Provide an API token directly, bypassing the local token store.
   Useful for CI/CD pipelines and automation.

`
	return strings.TrimSpace(helpText)
}

func (c *CloudPushCommand) Synopsis() string {
	return "Push a threat model HCL file to ThreatCL Cloud"
}

func (c *CloudPushCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud push")
	flagSet.BoolVar(&c.flagNoCreate, "no-create", false, "Don't create threat model if it doesn't exist")
	flagSet.BoolVar(&c.flagNoUpdateLocal, "no-update-local", false, "Don't update local HCL file with threatmodel slug")
	flagSet.BoolVar(&c.flagIgnoreLinkedControls, "ignore-linked-controls", false, "Don't link controls from the control library during upload")
	flagSet.Parse(args)

	// Get file path from remaining args
	remainingArgs := flagSet.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: file path is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud push -help' for usage information.\n")
		return 1
	}
	if len(remainingArgs) > 1 {
		fmt.Fprintf(os.Stderr, "Error: only one file can be pushed at a time\n")
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

	// Initialize dependencies - use longer timeout for upload
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Step 1: Retrieve token (org will be determined from file content)
	token, _, err := c.getTokenAndOrgId("", keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		fmt.Fprintf(os.Stderr, "   %s\n", ErrPleaseLogin)
		return 1
	}

	// Step 2: Run validateThreatModel on the original file
	// Note: validateThreatModel handles preprocessing internally for HCL parsing,
	// while using the original content for hash calculation
	wrapped, orgValid, tmNameValid, tmFileMatchesVersion, validateErr := validateThreatModel(token, filePath, httpClient, fsSvc, c.specCfg)

	// Step 4: Handle validation results
	if validateErr != nil {
		// Check for the specific case: valid org, tmName specified in HCL but not found in cloud
		errStr := validateErr.Error()
		if orgValid != "" && tmNameValid != "" && strings.Contains(errStr, fmt.Sprintf("backend threatmodel '%s' not found", tmNameValid)) {
			fmt.Fprintf(os.Stderr, "❌ HCL file has valid organization but threatmodel '%s' was not found in the cloud.\n", tmNameValid)
			fmt.Fprintf(os.Stderr, "   Either create the threatmodel first, or update the HCL file to use a valid threatmodel slug.\n")
			return 1
		}
		fmt.Fprintf(os.Stderr, "❌ %s\n", validateErr)
		return 1
	}

	// Check if organization is valid
	if orgValid == "" {
		fmt.Fprintf(os.Stderr, "❌ Invalid organization\n")
		return 1
	}

	// Case: tmNameValid and tmFileMatchesVersion - version already matches
	if tmNameValid != "" && tmFileMatchesVersion != "" {
		fmt.Printf("✓ Cloud version matches local version (v%s), not pushing\n", tmFileMatchesVersion)
		return 0
	}

	// Case: tmNameValid but no version match - upload new version
	if tmNameValid != "" && tmFileMatchesVersion == "" {
		fmt.Printf("Uploading new version to threat model '%s'...\n", tmNameValid)
		err = uploadFile(token, orgValid, tmNameValid, filePath, c.flagIgnoreLinkedControls, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error uploading file: %s\n", err)
			return 1
		}
		fmt.Printf("✓ Successfully pushed threat model from %s\n", filePath)
		return 0
	}

	// Case: orgValid but no tmNameValid - need to create threat model
	if orgValid != "" && tmNameValid == "" && tmFileMatchesVersion == "" {
		if c.flagNoCreate {
			fmt.Println("Cloud Threatmodel not created due to -no-create flag")
			return 0
		}

		// Use the already-parsed wrapped threatmodel from validateThreatModel
		if wrapped == nil || len(wrapped.Threatmodels) != 1 {
			fmt.Fprintf(os.Stderr, "Error: file must contain exactly one threat model, found %d\n", len(wrapped.Threatmodels))
			return 1
		}

		tmName := wrapped.Threatmodels[0].Name
		tmDescription := wrapped.Threatmodels[0].Description

		// Create the threat model
		fmt.Printf("Creating new threat model '%s'...\n", tmName)
		newTM, err := createThreatModel(token, orgValid, tmName, tmDescription, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating threat model: %s\n", err)
			return 1
		}

		fmt.Printf("✓ Created threat model '%s' (slug: %s)\n", newTM.Name, newTM.Slug)

		if c.flagNoUpdateLocal {
			fmt.Printf("\nCloud Threat model created. Update your HCL file backend block with:\n")
			fmt.Printf("  threatmodel = \"%s\"\n", newTM.Slug)
			fmt.Printf("Then run 'threatcl cloud push' again to upload.\n")
			return 0
		}

		// Backup original file
		backupPath := filePath + ".bak"
		backupContent, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not read file for backup: %s\n", err)
			fmt.Printf("Cloud Threat model created. Update your HCL file backend block with:\n")
			fmt.Printf("  threatmodel = \"%s\"\n", newTM.Slug)
			return 0
		}

		err = os.WriteFile(backupPath, backupContent, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not create backup file: %s\n", err)
			fmt.Printf("Cloud Threat model created. Update your HCL file backend block with:\n")
			fmt.Printf("  threatmodel = \"%s\"\n", newTM.Slug)
			return 0
		}

		// Update the HCL file with the threatmodel slug
		err = updateHCLBackendThreatmodel(filePath, newTM.Slug, fsSvc)
		if err != nil {
			// Restore from backup
			restoreErr := os.WriteFile(filePath, backupContent, 0644)
			if restoreErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not restore from backup: %s\n", restoreErr)
			}
			os.Remove(backupPath)
			fmt.Fprintf(os.Stderr, "Warning: Could not update HCL file: %s\n", err)
			fmt.Printf("Cloud Threat model created. Update your HCL file backend block with:\n")
			fmt.Printf("  threatmodel = \"%s\"\n", newTM.Slug)
			return 0
		}

		// Remove backup
		os.Remove(backupPath)
		fmt.Printf("✓ Updated %s with threatmodel = \"%s\"\n", filePath, newTM.Slug)

		// Upload the updated file
		fmt.Printf("Uploading threat model...\n")
		err = uploadFile(token, orgValid, newTM.Slug, filePath, c.flagIgnoreLinkedControls, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error uploading file: %s\n", err)
			fmt.Fprintf(os.Stderr, "Note: The threat model was created and local file updated, but the upload failed.\n")
			return 1
		}

		fmt.Printf("✓ Successfully pushed threat model from %s\n", filePath)
		return 0
	}

	// Fallback - should not reach here
	fmt.Fprintf(os.Stderr, "Unexpected state during push operation\n")
	return 1
}
