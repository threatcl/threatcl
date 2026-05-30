package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
	"github.com/threatcl/spec"
)

type CloudValidateCommand struct {
	CloudCommandBase
	specCfg  *spec.ThreatmodelSpecConfig
	flagDiff bool
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

 -diff
   When the local file does not match the latest cloud version of the
   threat model, download the cloud version and print a semantic summary
   of the differences followed by a unified (git-style) text diff.

Examples:

 # Validate a threat model file
 threatcl cloud validate my-threatmodel.hcl

 # Validate and show a diff against the latest cloud version
 threatcl cloud validate -diff my-threatmodel.hcl

` + cloudEnvVarHelpNoOrg()
	return strings.TrimSpace(helpText)
}

func (c *CloudValidateCommand) Synopsis() string {
	return "Validate a threat model file for ThreatCL Cloud"
}

func (c *CloudValidateCommand) AutocompleteArgs() complete.Predictor { return predictHCLOrJSON }
func (c *CloudValidateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
		"-diff":   complete.PredictNothing,
	}
}

func (c *CloudValidateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud validate")
	flagSet.BoolVar(&c.flagDiff, "diff", false, "Show a semantic + unified diff when the local file doesn't match the latest cloud version")
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
		if c.flagDiff {
			fmt.Println("  (-diff: local file already matches the latest version; nothing to diff)")
		}
	} else if tmNameValid != "" {
		fmt.Printf("✓ Local Threat model file (org-id: %s, model-id: %s) matches a cloud threat model, but doesn't match the latest version\nConsider running 'threatcl cloud push' to update the local file to the latest version.\n", orgValid, tmNameValid)
		if c.flagDiff {
			if diffErr := runCloudValidateDiff(token, orgValid, tmNameValid, filePath, wrapped, httpClient, fsSvc, c.specCfg); diffErr != nil {
				// Non-fatal: the validation result itself is unchanged.
				fmt.Fprintf(os.Stderr, "⚠ Warning: could not produce diff: %s\n", diffErr)
			}
		}
	} else if orgValid != "" {
		fmt.Println("✓ Organization is valid")
		if c.flagDiff {
			fmt.Println("  (-diff: no 'threatmodel' slug in the backend block — nothing to diff against)")
		}
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
			found, missing, refErr := validateThreatRefs(token, orgValid, refs, false, httpClient, fsSvc)
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

	// Validate information asset refs if we have a valid org
	if orgValid != "" && wrapped != nil {
		refs := extractInformationAssetRefs(wrapped)
		if len(refs) > 0 {
			found, missing, refErr := validateInformationAssetRefs(token, orgValid, refs, httpClient, fsSvc)
			if refErr != nil {
				fmt.Fprintf(os.Stderr, "⚠ Warning: could not validate information asset refs: %s\n", refErr)
			} else {
				if len(missing) > 0 {
					fmt.Fprintf(os.Stderr, "⚠ Warning: unknown information asset refs: %v\n", missing)
				}
				// Check for non-PUBLISHED information assets
				var nonPublished []string
				for ref, item := range found {
					if item != nil && item.Status != "PUBLISHED" {
						nonPublished = append(nonPublished, fmt.Sprintf("%s (%s)", ref, item.Status))
					}
				}
				if len(nonPublished) > 0 {
					fmt.Fprintf(os.Stderr, "⚠ Warning: non-PUBLISHED information asset refs: %v\n", nonPublished)
				}
				publishedCount := len(found) - len(nonPublished)
				if publishedCount > 0 {
					fmt.Printf("✓ %d information asset ref(s) validated (PUBLISHED)\n", publishedCount)
				}
			}
		}
	}

	return 0

}
