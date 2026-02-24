package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/threatcl/spec"
)

// CloudViewCommand renders a threat model with enriched control data from ThreatCL Cloud
type CloudViewCommand struct {
	CloudCommandBase
	specCfg                  *spec.ThreatmodelSpecConfig
	flagRawOut               bool
	flagIgnoreLinkedControls bool
	flagModelId              string
	flagOrgId                string
	testEnv                  bool
}

func (c *CloudViewCommand) Help() string {
	helpText := `
Usage: threatcl cloud view [options] [<file>]

  View a threat model HCL file with enriched control data from ThreatCL Cloud.

  This command renders the threat model to markdown, enriching any controls
  that reference the cloud control library with their descriptions,
  implementation guidance, and risk reduction values.

  If the control has local values set (e.g., description, risk_reduction),
  those local values are preserved and the cloud data is not used to
  overwrite them.

  By default, threats that reference the threat library will also include
  their recommended controls from the library.

  Use -model-id to fetch and view a threat model directly from ThreatCL Cloud
  without needing a local copy of the HCL file.

Options:

  -config=<file>
    Optional config file

  -debug
    If set, will output debugging information

  -raw
    If set, will output raw markdown instead of formatted terminal output

  -ignore-linked-controls
    If set, will not fetch or display recommended controls linked to threats
    from the threat library. Default: false

  -model-id=<modelId_or_slug>
    Fetch and view the threat model from ThreatCL Cloud by ID or slug.
    When set, the <file> argument is not required.

  -org-id=<orgId>
    Optional organization ID. Used with -model-id to specify which org
    to download from. If not provided, uses THREATCL_CLOUD_ORG env var
    or the default from your token store.

Examples:

  # View a threat model with enriched controls
  threatcl cloud view my-threatmodel.hcl

  # Output raw markdown
  threatcl cloud view -raw my-threatmodel.hcl

  # View without fetching linked controls from threats
  threatcl cloud view -ignore-linked-controls my-threatmodel.hcl

  # View a cloud threat model by ID or slug
  threatcl cloud view -model-id=my-threat-model

  # View with org override
  threatcl cloud view -model-id=my-threat-model -org-id=<orgId>

Environment Variables:

  THREATCL_API_URL
    Override the API base URL (default: https://api.threatcl.com)

  THREATCL_API_TOKEN
    Provide an API token directly, bypassing the local token store.
    Useful for CI/CD pipelines and automation.

  THREATCL_CLOUD_ORG
    Default organization ID to use when -org-id is not specified.

`
	return strings.TrimSpace(helpText)
}

func (c *CloudViewCommand) Synopsis() string {
	return "View a threat model with enriched cloud control data"
}

func (c *CloudViewCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud view")
	flagSet.BoolVar(&c.flagRawOut, "raw", false, "Output raw markdown")
	flagSet.BoolVar(&c.flagIgnoreLinkedControls, "ignore-linked-controls", false, "Don't fetch recommended controls linked to threats")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID or slug (fetch from cloud)")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional, used with -model-id)")
	flagSet.Parse(args)

	// Get remaining args (the file path)
	remainingArgs := flagSet.Args()

	// Validate: need either -model-id or a file argument, but not both
	if c.flagModelId != "" && len(remainingArgs) > 0 {
		fmt.Fprintf(os.Stderr, "Error: cannot specify both -model-id and a file argument\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud view -help' for usage information.\n")
		return 1
	}

	if c.flagModelId == "" && len(remainingArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: either -model-id or a file path is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud view -help' for usage information.\n")
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
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		fmt.Fprintf(os.Stderr, "   %s\n", ErrPleaseLogin)
		return 1
	}

	// Resolve file path
	var filePath string
	var tmpDir string

	if c.flagModelId != "" {
		// Download from cloud to a temp file
		apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s/download", getAPIBaseURL(fsSvc), url.PathEscape(orgId), url.PathEscape(c.flagModelId))
		resp, dlErr := makeAuthenticatedRequest("GET", apiURL, token, nil, httpClient)
		if dlErr != nil {
			fmt.Fprintf(os.Stderr, "Error downloading threat model: %s\n", dlErr)
			return 1
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			errResp := handleAPIErrorResponse(resp)
			fmt.Fprintf(os.Stderr, "Error downloading threat model: %s\n", errResp)
			return 1
		}

		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "Error reading download response: %s\n", readErr)
			return 1
		}

		tmpDir, err = os.MkdirTemp("", "threatcl-cloud-view-")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating temp directory: %s\n", err)
			return 1
		}
		defer os.RemoveAll(tmpDir)

		filePath = filepath.Join(tmpDir, "model.hcl")
		if writeErr := os.WriteFile(filePath, body, 0600); writeErr != nil {
			fmt.Fprintf(os.Stderr, "Error writing temp file: %s\n", writeErr)
			return 1
		}
	} else {
		filePath = remainingArgs[0]

		// Check if file exists
		if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) {
			fmt.Fprintf(os.Stderr, "Error: file %s does not exist\n", filePath)
			return 1
		}
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

		// Check for threat refs and enrich if needed
		threatRefs := extractThreatRefs(wrapped)
		if len(threatRefs) > 0 {
			// Fetch threat data from cloud (include recommended controls unless flag is set)
			includeLinkedControls := !c.flagIgnoreLinkedControls
			foundThreats, missingThreats, threatErr := validateThreatRefs(token, orgValid, threatRefs, includeLinkedControls, httpClient, fsSvc)
			if threatErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not fetch threat refs: %s\n", threatErr)
			} else {
				if len(missingThreats) > 0 {
					fmt.Fprintf(os.Stderr, "Warning: unknown threat refs (using local data): %v\n", missingThreats)
				}
				// Enrich the threats with cloud data (only PUBLISHED threats)
				skippedThreats := enrichThreatsWithCloudData(wrapped, foundThreats)
				for _, s := range skippedThreats {
					fmt.Fprintf(os.Stderr, "Warning: threat ref %q has status %s (not PUBLISHED), using local data\n", s.Ref, s.Status)
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

// skippedThreat represents a threat that was skipped during enrichment
type skippedThreat struct {
	Ref    string
	Status string
}

// enrichThreatsWithCloudData enriches Threat structs with data from the cloud library.
// Only PUBLISHED threats are enriched. Returns a list of skipped threats (non-PUBLISHED).
// For threats with a ref:
//   - Name is always overridden by the cloud library name (canonical name)
//   - Description/ImpactType/Stride are only enriched if local is empty
//   - RecommendedControls from the library are added to the threat's Controls list
func enrichThreatsWithCloudData(wrapped *spec.ThreatmodelWrapped, cloudThreats map[string]*threatLibraryItem) []skippedThreat {
	var skipped []skippedThreat

	if wrapped == nil || cloudThreats == nil {
		return skipped
	}

	for i := range wrapped.Threatmodels {
		tm := &wrapped.Threatmodels[i]
		for _, threat := range tm.Threats {
			if threat.Ref == "" {
				continue
			}

			cloudItem, found := cloudThreats[threat.Ref]
			if !found || cloudItem == nil || cloudItem.CurrentVersion == nil {
				continue
			}

			// Only enrich from PUBLISHED threats
			if cloudItem.Status != "PUBLISHED" {
				skipped = append(skipped, skippedThreat{
					Ref:    threat.Ref,
					Status: cloudItem.Status,
				})
				continue
			}

			tv := cloudItem.CurrentVersion

			// Always use cloud library name as the canonical name for referenced threats
			if tv.Name != "" {
				threat.Name = tv.Name
			}

			// Enrich Description only if local is empty
			if threat.Description == "" && tv.Description != "" {
				threat.Description = tv.Description
			}

			// Enrich ImpactType only if local is empty
			if len(threat.ImpactType) == 0 && len(tv.Impacts) > 0 {
				threat.ImpactType = tv.Impacts
			}

			// Enrich Stride only if local is empty
			if len(threat.Stride) == 0 && len(tv.Stride) > 0 {
				threat.Stride = tv.Stride
			}

			// Add recommended controls from the library (only PUBLISHED controls)
			if len(tv.RecommendedControls) > 0 {
				// Build a set of existing control refs to avoid duplicates
				existingRefs := make(map[string]bool)
				for _, ctrl := range threat.Controls {
					if ctrl.Ref != "" {
						existingRefs[ctrl.Ref] = true
					}
				}

				for _, recCtrl := range tv.RecommendedControls {
					if recCtrl == nil || recCtrl.CurrentVersion == nil {
						continue
					}
					// Only add PUBLISHED controls
					if recCtrl.Status != "PUBLISHED" {
						continue
					}
					// Skip if already exists
					if existingRefs[recCtrl.ReferenceID] {
						continue
					}

					cv := recCtrl.CurrentVersion
					newControl := &spec.Control{
						Name:                cv.Name,
						Ref:                 recCtrl.ReferenceID,
						Description:         cv.Description,
						ImplementationNotes: cv.ImplementationGuidance,
						RiskReduction:       cv.DefaultRiskReduction,
					}
					threat.Controls = append(threat.Controls, newControl)
					existingRefs[recCtrl.ReferenceID] = true
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
