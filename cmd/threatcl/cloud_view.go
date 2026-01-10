package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/threatcl/spec"
)

// CloudViewCommand renders a threat model with enriched control data from ThreatCL Cloud
type CloudViewCommand struct {
	CloudCommandBase
	specCfg    *spec.ThreatmodelSpecConfig
	flagRawOut bool
	testEnv    bool
}

func (c *CloudViewCommand) Help() string {
	helpText := `
Usage: threatcl cloud view [options] <file>

  View a threat model HCL file with enriched control data from ThreatCL Cloud.

  This command renders the threat model to markdown, enriching any controls
  that reference the cloud control library with their descriptions,
  implementation guidance, and risk reduction values.

  If the control has local values set (e.g., description, risk_reduction),
  those local values are preserved and the cloud data is not used to
  overwrite them.

Options:

  -config=<file>
    Optional config file

  -debug
    If set, will output debugging information

  -raw
    If set, will output raw markdown instead of formatted terminal output

Examples:

  # View a threat model with enriched controls
  threatcl cloud view my-threatmodel.hcl

  # Output raw markdown
  threatcl cloud view -raw my-threatmodel.hcl

Environment Variables:

  THREATCL_API_URL
    Override the API base URL (default: https://api.threatcl.com)

`
	return strings.TrimSpace(helpText)
}

func (c *CloudViewCommand) Synopsis() string {
	return "View a threat model with enriched cloud control data"
}

func (c *CloudViewCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud view")
	flagSet.BoolVar(&c.flagRawOut, "raw", false, "Output raw markdown")
	flagSet.Parse(args)

	// Get remaining args (the file path)
	remainingArgs := flagSet.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: file path is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud view -help' for usage information.\n")
		return 1
	}

	filePath := remainingArgs[0]

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: file %s does not exist\n", filePath)
		return 1
	}

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
	token, err := c.getTokenWithDeps(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		fmt.Fprintf(os.Stderr, "   %s\n", ErrPleaseLogin)
		return 1
	}

	// Validate threat model (reuse existing validateThreatModel)
	wrapped, orgValid, _, _, err := validateThreatModel(token, filePath, httpClient, fsSvc, c.specCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}

	// If org is valid, check for control refs and enrich if needed
	if orgValid != "" && wrapped != nil {
		refs := extractControlRefs(wrapped)
		if len(refs) > 0 {
			// Fetch control data from cloud
			found, missing, refErr := validateControlRefs(token, orgValid, refs, httpClient, fsSvc)
			if refErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not fetch control refs: %s\n", refErr)
			} else {
				if len(missing) > 0 {
					fmt.Fprintf(os.Stderr, "Warning: unknown control refs (using local data): %v\n", missing)
				}
				// Enrich the controls with cloud data (only PUBLISHED controls)
				skipped := enrichControlsWithCloudData(wrapped, found)
				for _, s := range skipped {
					fmt.Fprintf(os.Stderr, "Warning: control ref %q has status %s (not PUBLISHED), using local data\n", s.Ref, s.Status)
				}
			}
		}
	}

	// Render markdown
	output, err := c.renderThreatmodels(wrapped)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}

	// Output (raw or formatted)
	if c.flagRawOut {
		fmt.Println(output)
	} else {
		formatted, err := c.RenderMd(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		fmt.Println(formatted)
	}

	return 0
}

// skippedControl represents a control that was skipped during enrichment
type skippedControl struct {
	Ref    string
	Status string
}

// enrichControlsWithCloudData enriches Control structs with data from the cloud library.
// Only PUBLISHED controls are enriched. Returns a list of skipped controls (non-PUBLISHED).
// For controls with a ref:
//   - Name is always overridden by the cloud library name (canonical name)
//   - Description/RiskReduction/ImplementationNotes are only enriched if local is empty
func enrichControlsWithCloudData(wrapped *spec.ThreatmodelWrapped, cloudControls map[string]*controlLibraryItem) []skippedControl {
	var skipped []skippedControl

	if wrapped == nil || cloudControls == nil {
		return skipped
	}

	for i := range wrapped.Threatmodels {
		tm := &wrapped.Threatmodels[i]
		for _, threat := range tm.Threats {
			for _, control := range threat.Controls {
				if control.Ref == "" {
					continue
				}

				cloudItem, found := cloudControls[control.Ref]
				if !found || cloudItem == nil || cloudItem.CurrentVersion == nil {
					continue
				}

				// Only enrich from PUBLISHED controls
				if cloudItem.Status != "PUBLISHED" {
					skipped = append(skipped, skippedControl{
						Ref:    control.Ref,
						Status: cloudItem.Status,
					})
					continue
				}

				cv := cloudItem.CurrentVersion

				// Always use cloud library name as the canonical name for referenced controls
				if cv.Name != "" {
					control.Name = cv.Name
				}

				// Enrich Description only if local is empty
				if control.Description == "" && cv.Description != "" {
					control.Description = cv.Description
				}

				// Enrich RiskReduction only if local is 0 (unset)
				if control.RiskReduction == 0 && cv.DefaultRiskReduction > 0 {
					control.RiskReduction = cv.DefaultRiskReduction
				}

				// Append ImplementationGuidance to ImplementationNotes if not already present
				if cv.ImplementationGuidance != "" {
					if control.ImplementationNotes == "" {
						control.ImplementationNotes = cv.ImplementationGuidance
					} else if !strings.Contains(control.ImplementationNotes, cv.ImplementationGuidance) {
						// Append cloud guidance to existing notes
						control.ImplementationNotes = control.ImplementationNotes + "\n\n---\n_Implementation Guidance (from library):_\n" + cv.ImplementationGuidance
					}
				}
			}
		}
	}

	return skipped
}

// renderThreatmodels renders all threatmodels in the wrapped struct to markdown
func (c *CloudViewCommand) renderThreatmodels(wrapped *spec.ThreatmodelWrapped) (string, error) {
	mdBuffer := new(strings.Builder)

	for _, tm := range wrapped.Threatmodels {
		tmBuffer, err := tm.RenderMarkdown(spec.TmMDTemplate)
		if err != nil {
			return "", err
		}

		_, err = io.Copy(mdBuffer, tmBuffer)
		if err != nil {
			return "", fmt.Errorf("failed to copy threatmodel buffer: %w", err)
		}
	}

	return mdBuffer.String(), nil
}

// RenderMd renders markdown using glamour for terminal output
func (c *CloudViewCommand) RenderMd(md string) (string, error) {
	var mdRenderer *glamour.TermRenderer
	var err error
	if !c.testEnv {
		mdRenderer, err = glamour.NewTermRenderer(
			glamour.WithAutoStyle(),
			glamour.WithWordWrap(80),
		)
	} else {
		// For testing - WithAutoStyle() can cause hangs in go test
		mdRenderer, err = glamour.NewTermRenderer(
			glamour.WithWordWrap(80),
		)
	}
	if err != nil {
		return "", err
	}
	return mdRenderer.Render(md)
}
