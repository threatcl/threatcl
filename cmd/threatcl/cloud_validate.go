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
	flagWith string
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

Multi-file models:

	A cloud model may be split across several files, keyed by each file's
	threatmodel 'id': the file declaring the un-dotted root id (e.g.
	id = "app") is the model's default file, and each additional file
	declares a dotted id beneath it (e.g. id = "app.frontend") and may
	'extends' the root. When the validated file declares an id or extends,
	the server also validates it against the model's other stored files and
	this command reports the server-derived id and segment. (The backend
	block's 'segment' attribute from earlier specs no longer exists - the
	threatmodel id alone keys each file.)

Options:

 -config=<file>
   Optional config file

 -diff
   When the local file does not match the latest cloud version of the
   threat model, download the cloud version and print a semantic summary
   of the differences followed by a unified (git-style) text diff.

 -with=<glob>
   Optional glob of the model's other .hcl files (e.g. -with='models/*.hcl').
   Before contacting the server, parses the validated file together with the
   matched files as one set and runs the same whole-set validation the
   server applies (extends resolution, name/id uniqueness, namespace rules,
   backend agreement), failing fast on errors.

Examples:

 # Validate a threat model file
 threatcl cloud validate my-threatmodel.hcl

 # Validate and show a diff against the latest cloud version
 threatcl cloud validate -diff my-threatmodel.hcl

 # Validate one segment of a multi-file model with a local set preflight
 threatcl cloud validate -with='models/*.hcl' models/frontend.hcl

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
		"-with":   predictHCL,
	}
}

func (c *CloudValidateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud validate")
	flagSet.BoolVar(&c.flagDiff, "diff", false, "Show a semantic + unified diff when the local file doesn't match the latest cloud version")
	flagSet.StringVar(&c.flagWith, "with", "", "Glob of the model's other .hcl files for a local whole-set preflight")
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

	// Optional local whole-set preflight before any network work: parse the
	// validated file together with its sibling segment files the way the
	// server will, and fail fast on set-level errors.
	if c.flagWith != "" {
		if !runSetPreflight(filePath, c.flagWith, c.specCfg) {
			return 1
		}
	}

	// Build the cloud client. The org is resolved from the file's backend
	// block, so start org-agnostic and re-scope with WithOrg once known.
	client, _, err := c.newCloudClient("", 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		fmt.Fprintf(os.Stderr, "   %s\n", ErrPleaseLogin)
		return 1
	}

	wrapped, orgValid, tmNameValid, tmFileMatchesVersion, err := validateThreatModel(client, filePath, c.specCfg)

	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		return 1
	}

	// Scope a client to the resolved org for the ref-library lookups below.
	orgClient := client.WithOrg(orgValid)

	// A dotted id or extends marks this file as one segment of a multi-file
	// model; point at the local preflight when it wasn't requested.
	if c.flagWith == "" {
		if hint := multiFileHint(wrapped); hint != "" {
			fmt.Fprintf(os.Stderr, "ℹ %s\n", hint)
		}
	}

	if tmFileMatchesVersion != "" {
		fmt.Printf("✓ Local Threat model file matches the latest version of the cloud threat model at org-id: %s, model-id: %s, version: %s\n", orgValid, tmNameValid, tmFileMatchesVersion)
		if c.flagDiff {
			fmt.Println("  (-diff: local file already matches the latest version; nothing to diff)")
		}
	} else if tmNameValid != "" {
		fmt.Printf("✓ Local Threat model file (org-id: %s, model-id: %s) matches a cloud threat model, but doesn't match the latest version\nConsider running 'threatcl cloud push' to update the local file to the latest version.\n", orgValid, tmNameValid)
		if c.flagDiff {
			if diffErr := runCloudValidateDiff(orgClient, tmNameValid, filePath, wrapped, c.specCfg); diffErr != nil {
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

	// Server-side set validation for multi-file models: when the file
	// declares an id or extends, the server assembles it with the model's
	// other stored files and validates the whole set — it is authoritative
	// there — and reports the parsed id and derived segment. Files with
	// neither (plain single-file models) skip this, keeping their output
	// unchanged.
	if tmNameValid != "" && wrapped != nil && len(wrapped.Threatmodels) == 1 &&
		(wrapped.Threatmodels[0].Id != "" || wrapped.Threatmodels[0].Extends != "") {
		content, readErr := os.ReadFile(filePath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "⚠ Warning: could not read file for server-side validation: %s\n", readErr)
		} else if validateResp, vErr := orgClient.ValidateHCLContent(tmNameValid, content); vErr != nil {
			// Best effort: an older server without the endpoint (or a
			// transient failure) doesn't invalidate the checks above.
			fmt.Fprintf(os.Stderr, "⚠ Warning: could not run server-side validation: %s\n", vErr)
		} else if validateResp.Valid {
			if validateResp.Id != "" {
				fmt.Printf("✓ Server-side validation passed (id: %s, segment: %s)\n", validateResp.Id, validateResp.Segment)
			} else {
				fmt.Printf("✓ Server-side validation passed (segment: %s)\n", validateResp.Segment)
			}
		} else {
			fmt.Fprintf(os.Stderr, "❌ Server-side validation failed:\n")
			renderValidateHCLErrors(os.Stderr, validateResp.Errors)
			return 1
		}
	}

	// Validate control refs if we have a valid org
	if orgValid != "" && wrapped != nil {
		refs := extractControlRefs(wrapped)
		if len(refs) > 0 {
			found, missing, refErr := orgClient.ValidateControlRefs(refs)
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
			found, missing, refErr := orgClient.ValidateThreatRefs(refs, false)
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
			found, missing, refErr := orgClient.ValidateInformationAssetRefs(refs)
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
