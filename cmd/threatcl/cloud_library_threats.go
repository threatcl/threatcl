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

// CloudLibraryThreatsCommand lists threat library items
type CloudLibraryThreatsCommand struct {
	CloudCommandBase
	flagFolder   string
	flagStatus   string
	flagSeverity string
	flagStride   string
	flagTags     string
	flagSearch   string
	flagOrgId    string
	flagJSON     bool
}

func (c *CloudLibraryThreatsCommand) Help() string {
	helpText := `
Usage: threatcl cloud library threats [options]

  List threat library items from ThreatCL Cloud.

Options:

  -folder=<id>
      Filter by folder ID

  -status=<status>
      Filter by status: DRAFT, PUBLISHED, ARCHIVED, or DEPRECATED

  -severity=<level>
      Filter by severity level

  -stride=<categories>
      Filter by STRIDE categories (comma-separated)
      Example: -stride=Spoofing,Tampering

  -tags=<tags>
      Filter by tags (comma-separated)
      Example: -tags=owasp,injection

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

  # List all threat library items
  threatcl cloud library threats

  # List published threats with high severity
  threatcl cloud library threats -status=PUBLISHED -severity=High

  # Search for injection-related threats
  threatcl cloud library threats -search=injection

  # Output as JSON
  threatcl cloud library threats -json

Environment Variables:

  THREATCL_API_URL
    Override the API base URL (default: https://api.threatcl.com)

  THREATCL_CLOUD_ORG
    Default organization ID to use when -org-id is not specified.

  THREATCL_API_TOKEN
    Provide an API token directly, bypassing the local token store.
    Useful for CI/CD pipelines and automation.

`
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryThreatsCommand) Synopsis() string {
	return "List threat library items"
}

func (c *CloudLibraryThreatsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library threats")
	flagSet.StringVar(&c.flagFolder, "folder", "", "Filter by folder ID")
	flagSet.StringVar(&c.flagStatus, "status", "", "Filter by status (DRAFT, PUBLISHED, ARCHIVED, DEPRECATED)")
	flagSet.StringVar(&c.flagSeverity, "severity", "", "Filter by severity level")
	flagSet.StringVar(&c.flagStride, "stride", "", "Filter by STRIDE categories (comma-separated)")
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

	// Get token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Build filter
	filter := c.buildFilter()

	// Fetch threats
	threats, err := c.fetchThreatLibraryItems(token, orgId, filter, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching threat library items: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(threats); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	c.displayThreats(threats)
	return 0
}

func (c *CloudLibraryThreatsCommand) buildFilter() map[string]interface{} {
	filter := make(map[string]interface{})

	if c.flagFolder != "" {
		filter["folderId"] = c.flagFolder
	}
	if c.flagStatus != "" {
		filter["status"] = c.flagStatus
	}
	if c.flagSeverity != "" {
		filter["severity"] = c.flagSeverity
	}
	if stride := splitCommaSeparated(c.flagStride); stride != nil {
		filter["stride"] = stride
	}
	if tags := splitCommaSeparated(c.flagTags); tags != nil {
		filter["tags"] = tags
	}
	if c.flagSearch != "" {
		filter["search"] = c.flagSearch
	}

	return filter
}

func (c *CloudLibraryThreatsCommand) fetchThreatLibraryItems(token, orgId string, filter map[string]interface{}, httpClient HTTPClient, fsSvc FileSystemService) ([]threatLibraryItem, error) {
	query := `query threatLibraryItems($orgId: ID!, $filter: ThreatLibraryFilter) {
  threatLibraryItems(orgId: $orgId, filter: $filter) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      description
      severity
      stride
      impacts
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
		ThreatLibraryItems []threatLibraryItem `json:"threatLibraryItems"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse threat library items: %w", err)
	}

	return data.ThreatLibraryItems, nil
}

func (c *CloudLibraryThreatsCommand) displayThreats(threats []threatLibraryItem) {
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Threat Library Items")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()

	if len(threats) == 0 {
		fmt.Println("No threat library items found.")
		return
	}

	fmt.Printf("Found %d threat(s):\n\n", len(threats))
	fmt.Printf("%-15s %-35s %-12s %-12s %s\n", "REF ID", "NAME", "STATUS", "SEVERITY", "USAGE")
	fmt.Println(strings.Repeat("-", 100))

	for _, threat := range threats {
		name := threat.Name
		if len(name) > 33 {
			name = name[:30] + "..."
		}
		refId := threat.ReferenceID
		if len(refId) > 13 {
			refId = refId[:10] + "..."
		}
		severity := ""
		if threat.CurrentVersion != nil {
			severity = threat.CurrentVersion.Severity
		}
		fmt.Printf("%-15s %-35s %-12s %-12s %d\n", refId, name, threat.Status, severity, threat.UsageCount)
	}
	fmt.Println()
}
