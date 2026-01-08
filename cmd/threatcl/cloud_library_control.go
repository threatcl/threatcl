package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// CloudLibraryControlCommand gets a specific control library item by ID
type CloudLibraryControlCommand struct {
	CloudCommandBase
	flagOrgId string
	flagJSON  bool
}

func (c *CloudLibraryControlCommand) Help() string {
	helpText := `
Usage: threatcl cloud library control [options] <id>

  Get a specific control library item by ID from ThreatCL Cloud.

  Note: Options must be specified before the positional argument.

Arguments:

  <id>
      The control library item ID (required)

Options:

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # Get a specific control library item
  threatcl cloud library control def-456

  # Output as JSON
  threatcl cloud library control -json def-456
`
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryControlCommand) Synopsis() string {
	return "Get a specific control library item by ID"
}

func (c *CloudLibraryControlCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library control")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Get control ID from positional argument
	remainingArgs := flagSet.Args()
	if len(remainingArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Error: control library item ID is required\n")
		fmt.Fprintf(os.Stderr, "Usage: threatcl cloud library control <id> [options]\n")
		return 1
	}
	controlId := remainingArgs[0]

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Get token
	token, err := c.getTokenWithDeps(keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Resolve org ID
	orgId, err := c.resolveOrgId(token, c.flagOrgId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	// Fetch control
	control, err := c.fetchControlLibraryItem(token, orgId, controlId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching control library item: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(control); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	c.displayControl(control)
	return 0
}

func (c *CloudLibraryControlCommand) fetchControlLibraryItem(token, orgId, controlId string, httpClient HTTPClient, fsSvc FileSystemService) (*controlLibraryItem, error) {
	query := `query controlLibraryItem($orgId: ID!, $id: ID!) {
  controlLibraryItem(orgId: $orgId, id: $id) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      description
      controlType
      controlCategory
      implementationGuidance
      nistControls
      cisControls
      isoControls
      tags
      relatedThreats {
        referenceId
        name
      }
      defaultRiskReduction
    }
    versions {
      version
      name
    }
    usageCount
    usedByModels {
      id
      name
    }
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]interface{}{
			"orgId": orgId,
			"id":    controlId,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/graphql", getAPIBaseURL(fsSvc))
	resp, err := makeAuthenticatedRequest("POST", url, token, bytes.NewReader(jsonData), httpClient)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var gqlResp graphQLResponse
	if err := decodeJSONResponse(resp, &gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	var data struct {
		ControlLibraryItem *controlLibraryItem `json:"controlLibraryItem"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse control library item: %w", err)
	}

	if data.ControlLibraryItem == nil {
		return nil, fmt.Errorf(ErrLibraryControlNotFound, controlId)
	}

	return data.ControlLibraryItem, nil
}

func (c *CloudLibraryControlCommand) displayControl(control *controlLibraryItem) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Control Library Item: %s\n", control.Name)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Printf("ID:           %s\n", control.ID)
	fmt.Printf("Reference ID: %s\n", control.ReferenceID)
	fmt.Printf("Name:         %s\n", control.Name)
	fmt.Printf("Status:       %s\n", control.Status)
	fmt.Printf("Usage Count:  %d\n", control.UsageCount)

	if control.CurrentVersion != nil {
		v := control.CurrentVersion
		fmt.Printf("\nCurrent Version (v%s):\n", v.Version)
		if v.Description != "" {
			fmt.Printf("  Description:       %s\n", v.Description)
		}
		if v.ControlType != "" {
			fmt.Printf("  Control Type:      %s\n", v.ControlType)
		}
		if v.ControlCategory != "" {
			fmt.Printf("  Control Category:  %s\n", v.ControlCategory)
		}
		if v.DefaultRiskReduction > 0 {
			fmt.Printf("  Risk Reduction:    %d%%\n", v.DefaultRiskReduction)
		}

		if v.ImplementationGuidance != "" {
			fmt.Println()
			fmt.Println("  Implementation Guidance:")
			// Word wrap the guidance at ~70 chars
			words := strings.Fields(v.ImplementationGuidance)
			line := "    "
			for _, word := range words {
				if len(line)+len(word)+1 > 74 {
					fmt.Println(line)
					line = "    "
				}
				if line == "    " {
					line += word
				} else {
					line += " " + word
				}
			}
			if line != "    " {
				fmt.Println(line)
			}
		}

		// Framework mappings
		hasFrameworks := len(v.NISTControls) > 0 || len(v.CISControls) > 0 || len(v.ISOControls) > 0
		if hasFrameworks {
			fmt.Println()
			fmt.Println("  Framework Mappings:")
			if len(v.NISTControls) > 0 {
				fmt.Printf("    NIST:  %s\n", strings.Join(v.NISTControls, ", "))
			}
			if len(v.CISControls) > 0 {
				fmt.Printf("    CIS:   %s\n", strings.Join(v.CISControls, ", "))
			}
			if len(v.ISOControls) > 0 {
				fmt.Printf("    ISO:   %s\n", strings.Join(v.ISOControls, ", "))
			}
		}

		if len(v.Tags) > 0 {
			fmt.Printf("\n  Tags:           %s\n", strings.Join(v.Tags, ", "))
		}
		if len(v.RelatedThreats) > 0 {
			fmt.Println()
			fmt.Println("  Related Threats:")
			for _, threat := range v.RelatedThreats {
				fmt.Printf("    - %s (%s)\n", threat.ReferenceID, threat.Name)
			}
		}
	}

	if len(control.Versions) > 0 {
		fmt.Printf("\nVersions (%d):\n", len(control.Versions))
		for i, v := range control.Versions {
			current := ""
			if i == 0 {
				current = " (current)"
			}
			fmt.Printf("  - v%s%s\n", v.Version, current)
		}
	}

	if len(control.UsedByModels) > 0 {
		fmt.Printf("\nUsed By Models (%d):\n", len(control.UsedByModels))
		for _, model := range control.UsedByModels {
			fmt.Printf("  - %s\n", model.Name)
		}
	}

	fmt.Println()
}
