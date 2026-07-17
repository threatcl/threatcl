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

// CloudLibraryAssetCommand gets a specific information asset library item by ID
type CloudLibraryAssetCommand struct {
	CloudCommandBase
	flagOrgId string
	flagJSON  bool
}

func (c *CloudLibraryAssetCommand) Help() string {
	helpText := `
Usage: threatcl cloud library asset [options] <id>

  Get a specific information asset library item by ID from ThreatCL Cloud.

  Note: Options must be specified before the positional argument.

Arguments:

  <id>
      The information asset library item ID (required)

Options:

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # Get a specific information asset library item
  threatcl cloud library asset abc-123

  # Output as JSON
  threatcl cloud library asset -json abc-123
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryAssetCommand) Synopsis() string {
	return "Get a specific information asset library item by ID"
}

func (c *CloudLibraryAssetCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
	}
}

func (c *CloudLibraryAssetCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library asset")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Get asset ID from positional argument
	remainingArgs := flagSet.Args()
	if len(remainingArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Error: information asset library item ID is required\n")
		fmt.Fprintf(os.Stderr, "Usage: threatcl cloud library asset <id> [options]\n")
		return 1
	}
	assetId := remainingArgs[0]

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Get token and org ID
	token, orgId, apiURL, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch asset
	asset, err := c.fetchInformationAssetLibraryItem(token, orgId, assetId, httpClient, apiURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching information asset library item: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(asset); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	displayInformationAsset(asset)
	return 0
}

func (c *CloudLibraryAssetCommand) fetchInformationAssetLibraryItem(token, orgId, assetId string, httpClient HTTPClient, apiURL string) (*informationAssetLibraryItem, error) {
	query := `query informationAssetLibraryItem($orgId: ID!, $id: ID!) {
  informationAssetLibraryItem(orgId: $orgId, id: $id) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      versionNumber
      isPublished
      name
      description
      informationClassification
      source
      changeSummary
      createdAt
    }
    versions {
      version
      versionNumber
      isPublished
      name
      createdAt
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
			"id":    assetId,
		},
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
		InformationAssetLibraryItem *informationAssetLibraryItem `json:"informationAssetLibraryItem"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse information asset library item: %w", err)
	}

	if data.InformationAssetLibraryItem == nil {
		return nil, fmt.Errorf(ErrLibraryAssetNotFound, assetId)
	}

	return data.InformationAssetLibraryItem, nil
}

// displayInformationAsset renders an information asset library item to stdout
// in human-readable form. Shared with cloud library asset-ref.
func displayInformationAsset(asset *informationAssetLibraryItem) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Information Asset Library Item: %s\n", asset.Name)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Printf("ID:           %s\n", asset.ID)
	fmt.Printf("Reference ID: %s\n", asset.ReferenceID)
	fmt.Printf("Name:         %s\n", asset.Name)
	fmt.Printf("Status:       %s\n", asset.Status)
	fmt.Printf("Usage Count:  %d\n", asset.UsageCount)

	if asset.CurrentVersion != nil {
		v := asset.CurrentVersion
		fmt.Printf("\nCurrent Version (v%s):\n", v.Version)
		if v.Description != "" {
			fmt.Printf("  Description:               %s\n", v.Description)
		}
		if v.InformationClassification != "" {
			fmt.Printf("  Information Classification: %s\n", v.InformationClassification)
		}
		if v.Source != "" {
			fmt.Printf("  Source:                    %s\n", v.Source)
		}
		if v.ChangeSummary != "" {
			fmt.Printf("  Change Summary:            %s\n", v.ChangeSummary)
		}
		if v.CreatedAt != "" {
			fmt.Printf("  Created At:                %s\n", v.CreatedAt)
		}
		fmt.Printf("  Published:                 %t\n", v.IsPublished)
	}

	if len(asset.Versions) > 0 {
		fmt.Printf("\nVersions (%d):\n", len(asset.Versions))
		for i, v := range asset.Versions {
			current := ""
			if i == 0 {
				current = " (current)"
			}
			fmt.Printf("  - v%s%s\n", v.Version, current)
		}
	}

	if len(asset.UsedByModels) > 0 {
		fmt.Printf("\nUsed By Models (%d):\n", len(asset.UsedByModels))
		for _, model := range asset.UsedByModels {
			fmt.Printf("  - %s\n", model.Name)
		}
	}

	fmt.Println()
}
