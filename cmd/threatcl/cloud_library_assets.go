package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/posener/complete"
)

// CloudLibraryAssetsCommand lists information asset library items
type CloudLibraryAssetsCommand struct {
	CloudCommandBase
	flagFolder         string
	flagStatus         string
	flagClassification string
	flagSearch         string
	flagOrgId          string
	flagJSON           bool
}

func (c *CloudLibraryAssetsCommand) Help() string {
	helpText := `
Usage: threatcl cloud library assets [options]

  List information asset library items from ThreatCL Cloud.

Options:

  -folder=<id>
      Filter by folder ID

  -status=<status>
      Filter by status: DRAFT, PUBLISHED, ARCHIVED, or DEPRECATED

  -classification=<value>
      Filter by information classification (e.g. Confidential, Restricted)

  -search=<text>
      Free-text search across name and description

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # List all information asset library items
  threatcl cloud library assets

  # List published assets classified as Confidential
  threatcl cloud library assets -status=PUBLISHED -classification=Confidential

  # Search for assets containing "user"
  threatcl cloud library assets -search=user

  # Output as JSON
  threatcl cloud library assets -json
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryAssetsCommand) Synopsis() string {
	return "List information asset library items"
}

func (c *CloudLibraryAssetsCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudLibraryAssetsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library assets")
	flagSet.StringVar(&c.flagFolder, "folder", "", "Filter by folder ID")
	flagSet.StringVar(&c.flagStatus, "status", "", "Filter by status (DRAFT, PUBLISHED, ARCHIVED, DEPRECATED)")
	flagSet.StringVar(&c.flagClassification, "classification", "", "Filter by information classification")
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
	token, orgId, apiURL, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Build filter
	filter := c.buildFilter()

	// Fetch assets
	assets, err := c.fetchInformationAssetLibraryItems(token, orgId, filter, httpClient, apiURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching information asset library items: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(assets); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	c.displayInformationAssets(assets)
	return 0
}

func (c *CloudLibraryAssetsCommand) buildFilter() map[string]interface{} {
	filter := make(map[string]interface{})

	if c.flagFolder != "" {
		filter["folderId"] = c.flagFolder
	}
	if c.flagStatus != "" {
		filter["status"] = c.flagStatus
	}
	if c.flagClassification != "" {
		filter["informationClassification"] = c.flagClassification
	}
	if c.flagSearch != "" {
		filter["search"] = c.flagSearch
	}

	return filter
}

func (c *CloudLibraryAssetsCommand) fetchInformationAssetLibraryItems(token, orgId string, filter map[string]interface{}, httpClient HTTPClient, apiURL string) ([]informationAssetLibraryItem, error) {
	query := `query informationAssetLibraryItems($orgId: ID!, $filter: InformationAssetLibraryFilter) {
  informationAssetLibraryItems(orgId: $orgId, filter: $filter) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      informationClassification
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

	url := fmt.Sprintf("%s/api/v1/graphql", apiURL)
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
		InformationAssetLibraryItems []informationAssetLibraryItem `json:"informationAssetLibraryItems"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse information asset library items: %w", err)
	}

	return data.InformationAssetLibraryItems, nil
}

func (c *CloudLibraryAssetsCommand) displayInformationAssets(assets []informationAssetLibraryItem) {
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Information Asset Library Items")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()

	if len(assets) == 0 {
		fmt.Println("No information asset library items found.")
		return
	}

	fmt.Printf("Found %d information asset(s):\n\n", len(assets))
	fmt.Printf("%-15s %-35s %-12s %-20s %s\n", "REF ID", "NAME", "STATUS", "CLASSIFICATION", "USAGE")
	fmt.Println(strings.Repeat("-", 100))

	for _, asset := range assets {
		name := asset.Name
		if len(name) > 33 {
			name = name[:30] + "..."
		}
		refId := asset.ReferenceID
		if len(refId) > 13 {
			refId = refId[:10] + "..."
		}
		classification := ""
		if asset.CurrentVersion != nil {
			classification = asset.CurrentVersion.InformationClassification
		}
		if len(classification) > 18 {
			classification = classification[:15] + "..."
		}
		fmt.Printf("%-15s %-35s %-12s %-20s %d\n", refId, name, asset.Status, classification, asset.UsageCount)
	}
	fmt.Println()
}
