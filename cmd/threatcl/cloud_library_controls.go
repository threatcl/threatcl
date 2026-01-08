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

// CloudLibraryControlsCommand lists control library items
type CloudLibraryControlsCommand struct {
	CloudCommandBase
	flagFolder   string
	flagStatus   string
	flagType     string
	flagCategory string
	flagTags     string
	flagSearch   string
	flagOrgId    string
	flagJSON     bool
}

func (c *CloudLibraryControlsCommand) Help() string {
	helpText := `
Usage: threatcl cloud library controls [options]

  List control library items from ThreatCL Cloud.

Options:

  -folder=<id>
      Filter by folder ID

  -status=<status>
      Filter by status: DRAFT, PUBLISHED, ARCHIVED, or DEPRECATED

  -type=<type>
      Filter by control type (e.g., Preventive, Detective, Corrective)

  -category=<category>
      Filter by control category

  -tags=<tags>
      Filter by tags (comma-separated)
      Example: -tags=encryption,access-control

  -search=<text>
      Free-text search

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # List all control library items
  threatcl cloud library controls

  # List published preventive controls
  threatcl cloud library controls -status=PUBLISHED -type=Preventive

  # Search for encryption-related controls
  threatcl cloud library controls -search=encryption

  # Output as JSON
  threatcl cloud library controls -json
`
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryControlsCommand) Synopsis() string {
	return "List control library items"
}

func (c *CloudLibraryControlsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library controls")
	flagSet.StringVar(&c.flagFolder, "folder", "", "Filter by folder ID")
	flagSet.StringVar(&c.flagStatus, "status", "", "Filter by status (DRAFT, PUBLISHED, ARCHIVED, DEPRECATED)")
	flagSet.StringVar(&c.flagType, "type", "", "Filter by control type")
	flagSet.StringVar(&c.flagCategory, "category", "", "Filter by control category")
	flagSet.StringVar(&c.flagTags, "tags", "", "Filter by tags (comma-separated)")
	flagSet.StringVar(&c.flagSearch, "search", "", "Free-text search")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Validate status if provided
	if c.flagStatus != "" && !validateLibraryStatus(c.flagStatus) {
		fmt.Fprintf(os.Stderr, "Error: "+ErrInvalidLibraryStatus+"\n", c.flagStatus)
		return 1
	}

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

	// Build filter
	filter := c.buildFilter()

	// Fetch controls
	controls, err := c.fetchControlLibraryItems(token, orgId, filter, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching control library items: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(controls); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	c.displayControls(controls)
	return 0
}

func (c *CloudLibraryControlsCommand) buildFilter() map[string]interface{} {
	filter := make(map[string]interface{})

	if c.flagFolder != "" {
		filter["folderId"] = c.flagFolder
	}
	if c.flagStatus != "" {
		filter["status"] = c.flagStatus
	}
	if c.flagType != "" {
		filter["controlType"] = c.flagType
	}
	if c.flagCategory != "" {
		filter["controlCategory"] = c.flagCategory
	}
	if tags := splitCommaSeparated(c.flagTags); tags != nil {
		filter["tags"] = tags
	}
	if c.flagSearch != "" {
		filter["search"] = c.flagSearch
	}

	return filter
}

func (c *CloudLibraryControlsCommand) fetchControlLibraryItems(token, orgId string, filter map[string]interface{}, httpClient HTTPClient, fsSvc FileSystemService) ([]controlLibraryItem, error) {
	query := `query controlLibraryItems($orgId: ID!, $filter: ControlLibraryFilter) {
  controlLibraryItems(orgId: $orgId, filter: $filter) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      controlType
      controlCategory
      tags
    }
    usageCount
  }
}`

	variables := map[string]interface{}{
		"orgId": orgId,
	}
	if len(filter) > 0 {
		variables["filter"] = filter
	}

	reqBody := graphQLRequest{
		Query:     query,
		Variables: variables,
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
		ControlLibraryItems []controlLibraryItem `json:"controlLibraryItems"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse control library items: %w", err)
	}

	return data.ControlLibraryItems, nil
}

func (c *CloudLibraryControlsCommand) displayControls(controls []controlLibraryItem) {
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Control Library Items")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()

	if len(controls) == 0 {
		fmt.Println("No control library items found.")
		return
	}

	fmt.Printf("Found %d control(s):\n\n", len(controls))
	fmt.Printf("%-15s %-35s %-12s %-15s %s\n", "REF ID", "NAME", "STATUS", "TYPE", "USAGE")
	fmt.Println(strings.Repeat("-", 100))

	for _, control := range controls {
		name := control.Name
		if len(name) > 33 {
			name = name[:30] + "..."
		}
		refId := control.ReferenceID
		if len(refId) > 13 {
			refId = refId[:10] + "..."
		}
		controlType := ""
		if control.CurrentVersion != nil {
			controlType = control.CurrentVersion.ControlType
			if len(controlType) > 13 {
				controlType = controlType[:10] + "..."
			}
		}
		fmt.Printf("%-15s %-35s %-12s %-15s %d\n", refId, name, control.Status, controlType, control.UsageCount)
	}
	fmt.Println()
}
