package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/threatcl/spec"
)

type CloudValidateCommand struct {
	CloudCommandBase
	specCfg *spec.ThreatmodelSpecConfig
}

func (c *CloudValidateCommand) Help() string {
	helpText := `
Usage: threatcl cloud validate <file>

	Validate that a threat model HCL file is properly configured for ThreatCL Cloud.

	This command performs the following validations:
	  1. The threat model file contains exactly one backend block
	  2. The backend has backend_name set to "threatcl-cloud"
	  3. The backend has exactly one organization specified
	  4. The authenticated user is a member of the specified organization

	The file will also be parsed to ensure it is valid HCL.

Options:

 -config=<file>
   Optional config file

Examples:

 # Validate a threat model file
 threatcl cloud validate my-threatmodel.hcl

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)

`
	return strings.TrimSpace(helpText)
}

func (c *CloudValidateCommand) Synopsis() string {
	return "Validate a threat model file for ThreatCL Cloud"
}

func (c *CloudValidateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud validate")
	flagSet.Parse(args)

	// Get remaining args (the file path)
	remainingArgs := flagSet.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: file path is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud validate -help' for usage information.\n")
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

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)
	token, _, err := c.getTokenAndOrgId("", keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		fmt.Fprintf(os.Stderr, "   %s\n", ErrPleaseLogin)
		return 1
	}

	wrapped, orgValid, tmNameValid, tmFileMatchesVersion, err := validateThreatModel(token, filePath, httpClient, fsSvc, c.specCfg)

	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		return 1
	}

	if tmFileMatchesVersion != "" {
		fmt.Printf("✓ Local Threat model file matches the latest version of the cloud threat model at org-id: %s, model-id: %s, version: %s\n", orgValid, tmNameValid, tmFileMatchesVersion)
	} else if tmNameValid != "" {
		fmt.Printf("✓ Local Threat model file (org-id: %s, model-id: %s) matches a cloud threat model, but doesn't match the latest version\nConsider running 'threatcl cloud push' to update the local file to the latest version.\n", orgValid, tmNameValid)
	} else if orgValid != "" {
		fmt.Println("✓ Organization is valid")
	} else {
		fmt.Println("Invalid organization")
		return 1
	}

	// Validate control refs if we have a valid org
	if orgValid != "" && wrapped != nil {
		refs := extractControlRefs(wrapped)
		if len(refs) > 0 {
			found, missing, refErr := validateControlRefs(token, orgValid, refs, httpClient, fsSvc)
			if refErr != nil {
				fmt.Fprintf(os.Stderr, "⚠ Warning: could not validate control refs: %s\n", refErr)
			} else {
				if len(missing) > 0 {
					fmt.Fprintf(os.Stderr, "⚠ Warning: unknown control refs: %v\n", missing)
				}
				// Check for non-PUBLISHED controls
				var nonPublished []string
				for ref, item := range found {
					if item != nil && item.Status != "PUBLISHED" {
						nonPublished = append(nonPublished, fmt.Sprintf("%s (%s)", ref, item.Status))
					}
				}
				if len(nonPublished) > 0 {
					fmt.Fprintf(os.Stderr, "⚠ Warning: non-PUBLISHED control refs: %v\n", nonPublished)
				}
				publishedCount := len(found) - len(nonPublished)
				if publishedCount > 0 {
					fmt.Printf("✓ %d control ref(s) validated (PUBLISHED)\n", publishedCount)
				}
			}
		}
	}

	// Validate threat refs if we have a valid org
	if orgValid != "" && wrapped != nil {
		refs := extractThreatRefs(wrapped)
		if len(refs) > 0 {
			found, missing, refErr := validateThreatRefs(token, orgValid, refs, httpClient, fsSvc)
			if refErr != nil {
				fmt.Fprintf(os.Stderr, "⚠ Warning: could not validate threat refs: %s\n", refErr)
			} else {
				if len(missing) > 0 {
					fmt.Fprintf(os.Stderr, "⚠ Warning: unknown threat refs: %v\n", missing)
				}
				// Check for non-PUBLISHED threats
				var nonPublished []string
				for ref, item := range found {
					if item != nil && item.Status != "PUBLISHED" {
						nonPublished = append(nonPublished, fmt.Sprintf("%s (%s)", ref, item.Status))
					}
				}
				if len(nonPublished) > 0 {
					fmt.Fprintf(os.Stderr, "⚠ Warning: non-PUBLISHED threat refs: %v\n", nonPublished)
				}
				publishedCount := len(found) - len(nonPublished)
				if publishedCount > 0 {
					fmt.Printf("✓ %d threat ref(s) validated (PUBLISHED)\n", publishedCount)
				}
			}
		}
	}

	return 0

}
