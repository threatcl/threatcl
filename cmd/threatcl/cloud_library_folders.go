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

// CloudLibraryFoldersCommand lists library folders
type CloudLibraryFoldersCommand struct {
	CloudCommandBase
	flagType  string
	flagOrgId string
	flagJSON  bool
}

func (c *CloudLibraryFoldersCommand) Help() string {
	helpText := `
Usage: threatcl cloud library folders [options]

  List library folders from ThreatCL Cloud.

Options:

  -type=<type>
      Filter by folder type: THREAT or CONTROL

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -json
      Output as JSON for scripting/automation

  -config=<file>
      Optional config file

Examples:

  # List all library folders
  threatcl cloud library folders

  # List only threat folders
  threatcl cloud library folders -type=THREAT

  # Output as JSON
  threatcl cloud library folders -json

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

func (c *CloudLibraryFoldersCommand) Synopsis() string {
	return "List library folders"
}

func (c *CloudLibraryFoldersCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library folders")
	flagSet.StringVar(&c.flagType, "type", "", "Filter by folder type (THREAT or CONTROL)")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output as JSON")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Validate folder type if provided
	if c.flagType != "" && !validateFolderType(c.flagType) {
		fmt.Fprintf(os.Stderr, "Error: "+ErrInvalidLibraryFolderType+"\n", c.flagType)
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Get token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Fetch folders
	folders, err := c.fetchLibraryFolders(token, orgId, c.flagType, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching library folders: %s\n", err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(folders); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	c.displayFolders(folders)
	return 0
}

func (c *CloudLibraryFoldersCommand) fetchLibraryFolders(token, orgId, folderType string, httpClient HTTPClient, fsSvc FileSystemService) ([]libraryFolder, error) {
	query := `query libraryFolders($orgId: ID!, $type: LibraryFolderType) {
  libraryFolders(orgId: $orgId, type: $type) {
    id
    name
    description
    createdAt
    updatedAt
  }
}`

	variables := map[string]interface{}{
		"orgId": orgId,
	}
	if folderType != "" {
		variables["type"] = folderType
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
		LibraryFolders []libraryFolder `json:"libraryFolders"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse folders data: %w", err)
	}

	return data.LibraryFolders, nil
}

func (c *CloudLibraryFoldersCommand) displayFolders(folders []libraryFolder) {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("  Library Folders")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	if len(folders) == 0 {
		fmt.Println("No library folders found.")
		return
	}

	fmt.Printf("Found %d folder(s):\n\n", len(folders))
	fmt.Printf("%-36s %s\n", "ID", "NAME")
	fmt.Println(strings.Repeat("-", 80))

	for _, folder := range folders {
		name := folder.Name
		if len(name) > 40 {
			name = name[:37] + "..."
		}
		fmt.Printf("%-36s %s\n", folder.ID, name)
	}
	fmt.Println()
}
