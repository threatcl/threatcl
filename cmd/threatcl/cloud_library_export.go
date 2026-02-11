package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// CloudLibraryExportCommand exports the organization's library as HCL
type CloudLibraryExportCommand struct {
	CloudCommandBase
	flagOrgId             string
	flagOutput            string
	flagType              string
	flagStatus            string
	flagFolder            string
	flagIncludeDrafts     bool
	flagIncludeDeprecated bool
	flagTags              string
}

// Valid export types
var validExportTypes = map[string]bool{
	"threats":  true,
	"controls": true,
}

func (c *CloudLibraryExportCommand) Help() string {
	helpText := `
Usage: threatcl cloud library export [options]

  Export the organization's threat and control library as HCL from ThreatCL Cloud.

Options:

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -output=<file>, -o=<file>
      Output file path (default: stdout)

  -type=<type>
      Filter by type: "threats" or "controls" (default: all)

  -status=<status>
      Filter by status (e.g. PUBLISHED, DRAFT)

  -folder=<path>
      Filter by folder path

  -include-drafts
      Include draft items in the export

  -include-deprecated
      Include deprecated items in the export

  -tags=<tags>
      Comma-separated tag filter (e.g. "owasp,injection")

  -config=<file>
      Optional config file

Examples:

  # Export all published library items to stdout
  threatcl cloud library export

  # Export to a file
  threatcl cloud library export -o library.hcl

  # Export only threats
  threatcl cloud library export -type threats -o threats.hcl

  # Export controls with specific tags
  threatcl cloud library export -type controls -tags "owasp,injection" -o controls.hcl

  # Export including drafts
  threatcl cloud library export -include-drafts -o full-library.hcl

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

func (c *CloudLibraryExportCommand) Synopsis() string {
	return "Export library as HCL"
}

func (c *CloudLibraryExportCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library export")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagOutput, "output", "", "Output file path (default: stdout)")
	flagSet.StringVar(&c.flagOutput, "o", "", "Output file path (default: stdout)")
	flagSet.StringVar(&c.flagType, "type", "", "Filter by type: threats or controls")
	flagSet.StringVar(&c.flagStatus, "status", "", "Filter by status")
	flagSet.StringVar(&c.flagFolder, "folder", "", "Filter by folder path")
	flagSet.BoolVar(&c.flagIncludeDrafts, "include-drafts", false, "Include draft items")
	flagSet.BoolVar(&c.flagIncludeDeprecated, "include-deprecated", false, "Include deprecated items")
	flagSet.StringVar(&c.flagTags, "tags", "", "Comma-separated tag filter")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Validate type if provided
	if c.flagType != "" && !validExportTypes[c.flagType] {
		fmt.Fprintf(os.Stderr, "Error: invalid export type %q (must be \"threats\" or \"controls\")\n", c.flagType)
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Get token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Build the API URL
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/library/export", getAPIBaseURL(fsSvc), url.PathEscape(orgId))

	// Build query parameters
	params := url.Values{}
	if c.flagType != "" {
		params.Set("type", c.flagType)
	}
	if c.flagStatus != "" {
		params.Set("status", c.flagStatus)
	}
	if c.flagFolder != "" {
		params.Set("folder", c.flagFolder)
	}
	if c.flagIncludeDrafts {
		params.Set("include-drafts", "true")
	}
	if c.flagIncludeDeprecated {
		params.Set("include-deprecated", "true")
	}
	if c.flagTags != "" {
		params.Set("tags", c.flagTags)
	}

	if len(params) > 0 {
		apiURL += "?" + params.Encode()
	}

	// Make the API request
	resp, err := makeAuthenticatedRequest("GET", apiURL, token, nil, httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		apiErr := handleAPIErrorResponse(resp)
		fmt.Fprintf(os.Stderr, "Error exporting library: %s\n", apiErr)
		return 1
	}

	// Read the response body (raw HCL text)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %s\n", err)
		return 1
	}

	// Output to file or stdout
	if c.flagOutput != "" {
		if err := fsSvc.WriteFile(c.flagOutput, body, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %s\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Library exported to %s\n", c.flagOutput)
	} else {
		fmt.Print(string(body))
	}

	return 0
}
