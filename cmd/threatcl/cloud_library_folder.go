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

// CloudLibraryFolderCommand gets a specific library folder by ID
type CloudLibraryFolderCommand struct {
	CloudCommandBase
	flagOrgId string
	flagJSON  bool
}

func (c *CloudLibraryFolderCommand) Help() string {
	helpText := `
Usage: threatcl cloud library folder [options] <id>

  Get a specific library folder by ID from ThreatCL Cloud.

  Note: Options must be specified before the positional argument.

Arguments:

  <id>
      The library folder ID (required)

Options:

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # Get a specific folder
  threatcl cloud library folder abc-123

  # Output as JSON
  threatcl cloud library folder -json abc-123

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

func (c *CloudLibraryFolderCommand) Synopsis() string {
	return "Get a specific library folder by ID"
}

func (c *CloudLibraryFolderCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library folder")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Get folder ID from positional argument
	remainingArgs := flagSet.Args()
	if len(remainingArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Error: folder ID is required\n")
		fmt.Fprintf(os.Stderr, "Usage: threatcl cloud library folder <id> [options]\n")
		return 1
	}
	folderId := remainingArgs[0]

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Get token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch folder
	folder, err := c.fetchLibraryFolder(token, orgId, folderId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching library folder: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(folder); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	c.displayFolder(folder)
	return 0
}

func (c *CloudLibraryFolderCommand) fetchLibraryFolder(token, orgId, folderId string, httpClient HTTPClient, fsSvc FileSystemService) (*libraryFolder, error) {
	query := `query libraryFolder($orgId: ID!, $id: ID!) {
  libraryFolder(orgId: $orgId, id: $id) {
    id
    name
    description
    createdAt
    updatedAt
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]interface{}{
			"orgId": orgId,
			"id":    folderId,
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
		LibraryFolder *libraryFolder `json:"libraryFolder"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse folder data: %w", err)
	}

	if data.LibraryFolder == nil {
		return nil, fmt.Errorf(ErrLibraryFolderNotFound, folderId)
	}

	return data.LibraryFolder, nil
}

func (c *CloudLibraryFolderCommand) displayFolder(folder *libraryFolder) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Library Folder: %s\n", folder.Name)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Printf("ID:          %s\n", folder.ID)
	fmt.Printf("Name:        %s\n", folder.Name)
	if folder.Description != "" {
		fmt.Printf("Description: %s\n", folder.Description)
	}
	fmt.Printf("Created:     %s\n", folder.CreatedAt)
	fmt.Printf("Updated:     %s\n", folder.UpdatedAt)
	fmt.Println()
}
