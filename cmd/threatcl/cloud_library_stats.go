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

// CloudLibraryStatsCommand gets library usage statistics
type CloudLibraryStatsCommand struct {
	CloudCommandBase
	flagOrgId string
	flagJSON  bool
}

func (c *CloudLibraryStatsCommand) Help() string {
	helpText := `
Usage: threatcl cloud library stats [options]

  Get library usage statistics from ThreatCL Cloud.

Options:

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # Get library statistics
  threatcl cloud library stats

  # Output as JSON
  threatcl cloud library stats -json
`
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryStatsCommand) Synopsis() string {
	return "Get library usage statistics"
}

func (c *CloudLibraryStatsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library stats")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")

	if err := flagSet.Parse(args); err != nil {
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

	// Fetch stats
	stats, err := c.fetchLibraryUsageStats(token, orgId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching library usage statistics: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(stats); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	c.displayStats(stats)
	return 0
}

func (c *CloudLibraryStatsCommand) fetchLibraryUsageStats(token, orgId string, httpClient HTTPClient, fsSvc FileSystemService) (*libraryUsageStats, error) {
	query := `query libraryUsageStats($orgId: ID!) {
  libraryUsageStats(orgId: $orgId) {
    totalThreatItems
    totalControlItems
    publishedThreatItems
    publishedControlItems
    mostUsedThreats {
      id
      name
      usageCount
    }
    mostUsedControls {
      id
      name
      usageCount
    }
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]interface{}{
			"orgId": orgId,
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
		LibraryUsageStats *libraryUsageStats `json:"libraryUsageStats"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse library usage statistics: %w", err)
	}

	if data.LibraryUsageStats == nil {
		// Return empty stats if none available
		return &libraryUsageStats{}, nil
	}

	return data.LibraryUsageStats, nil
}

func (c *CloudLibraryStatsCommand) displayStats(stats *libraryUsageStats) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  Library Usage Statistics")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Println("Overview:")
	fmt.Printf("  Total Threats:      %d (%d published)\n", stats.TotalThreatItems, stats.PublishedThreatItems)
	fmt.Printf("  Total Controls:     %d (%d published)\n", stats.TotalControlItems, stats.PublishedControlItems)

	if len(stats.MostUsedThreats) > 0 {
		fmt.Println()
		fmt.Println("Most Used Threats:")
		for i, threat := range stats.MostUsedThreats {
			name := threat.Name
			if len(name) > 35 {
				name = name[:32] + "..."
			}
			fmt.Printf("  %d. %-38s - used in %d model(s)\n", i+1, name, threat.UsageCount)
		}
	}

	if len(stats.MostUsedControls) > 0 {
		fmt.Println()
		fmt.Println("Most Used Controls:")
		for i, control := range stats.MostUsedControls {
			name := control.Name
			if len(name) > 35 {
				name = name[:32] + "..."
			}
			fmt.Printf("  %d. %-38s - used in %d model(s)\n", i+1, name, control.UsageCount)
		}
	}

	fmt.Println()
}
