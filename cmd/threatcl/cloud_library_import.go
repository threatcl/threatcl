package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxImportFileSize = 10 * 1024 * 1024 // 10MB

// Valid import modes
var validImportModes = map[string]bool{
	"create-only": true,
	"update":      true,
	"replace":     true,
}

// libraryImportResult represents the API response for a library import
type libraryImportResult struct {
	FoldersCreated  int      `json:"folders_created"`
	FoldersUpdated  int      `json:"folders_updated"`
	ThreatsCreated  int      `json:"threats_created"`
	ThreatsUpdated  int      `json:"threats_updated"`
	ThreatsSkipped  int      `json:"threats_skipped"`
	ControlsCreated int      `json:"controls_created"`
	ControlsUpdated int      `json:"controls_updated"`
	ControlsSkipped int      `json:"controls_skipped"`
	Warnings        []string `json:"warnings"`
}

// CloudLibraryImportCommand imports a local HCL file into the cloud library
type CloudLibraryImportCommand struct {
	CloudCommandBase
	flagOrgId string
	flagMode  string
	flagJSON  bool
}

func (c *CloudLibraryImportCommand) Help() string {
	helpText := `
Usage: threatcl cloud library import [options] <file>

  Import a local HCL library file into ThreatCL Cloud.

  The file must have a .hcl extension and be no larger than 10MB.

Options:

  -org-id=<id>
      Organization ID (optional, uses THREATCL_CLOUD_ORG env var or defaults
      to your first organization)

  -mode=<mode>, -m=<mode>
      Import mode: "create-only" (default), "update", or "replace"
        create-only: Only create new items, skip existing ones
        update:      Create new items and update existing ones
        replace:     Replace entire library with imported content

  -json
      Output results as JSON

  -config=<file>
      Optional config file

Examples:

  # Import a library file with default mode (create-only)
  threatcl cloud library import library.hcl

  # Import with update mode
  threatcl cloud library import -mode update library.hcl

  # Import and output results as JSON
  threatcl cloud library import -json library.hcl

  # Import with replace mode to a specific org
  threatcl cloud library import -org-id org-123 -mode replace library.hcl

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

func (c *CloudLibraryImportCommand) Synopsis() string {
	return "Import library from HCL file"
}

func (c *CloudLibraryImportCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud library import")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagMode, "mode", "", "Import mode: create-only (default), update, or replace")
	flagSet.StringVar(&c.flagMode, "m", "", "Import mode: create-only (default), update, or replace")
	flagSet.BoolVar(&c.flagJSON, "json", false, "Output results as JSON")

	if err := flagSet.Parse(args); err != nil {
		return 1
	}

	// Validate positional argument (file path)
	remainingArgs := flagSet.Args()
	if len(remainingArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Error: file path is required\n\n")
		fmt.Fprintf(os.Stderr, "Usage: threatcl cloud library import [options] <file>\n")
		return 1
	}
	filePath := remainingArgs[0]

	// Validate import mode
	mode := c.flagMode
	if mode == "" {
		mode = "create-only"
	}
	if !validImportModes[mode] {
		fmt.Fprintf(os.Stderr, "Error: invalid import mode %q (must be \"create-only\", \"update\", or \"replace\")\n", mode)
		return 1
	}

	// Validate file extension
	if !strings.HasSuffix(strings.ToLower(filePath), ".hcl") {
		fmt.Fprintf(os.Stderr, "Error: file must have a .hcl extension\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Get token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Read the file
	fileData, err := fsSvc.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToReadFile, err)
		return 1
	}

	// Check file size
	if len(fileData) > maxImportFileSize {
		fmt.Fprintf(os.Stderr, "Error: file size exceeds maximum of 10MB\n")
		return 1
	}

	// Build multipart form
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Add file field
	fileWriter, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create form file: %s\n", err)
		return 1
	}

	_, err = fileWriter.Write(fileData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to write file data: %s\n", err)
		return 1
	}

	// Add mode field
	err = writer.WriteField("mode", mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to write mode field: %s\n", err)
		return 1
	}

	// Close the multipart writer
	err = writer.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to close multipart writer: %s\n", err)
		return 1
	}

	// Build the API URL
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/library/import", getAPIBaseURL(fsSvc), url.PathEscape(orgId))

	// Create request manually (can't use makeAuthenticatedRequest because it sets Content-Type to application/json)
	req, err := http.NewRequest("POST", apiURL, &requestBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToCreateReq, err)
		return 1
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToConnect, err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		apiErr := handleAPIErrorResponse(resp)
		fmt.Fprintf(os.Stderr, "Error importing library: %s\n", apiErr)
		return 1
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %s\n", err)
		return 1
	}

	var result libraryImportResult
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", ErrFailedToParseResp, err)
		return 1
	}

	// Output results
	if c.flagJSON {
		if err := outputLibraryJSON(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}

	// Formatted output
	fmt.Printf("Import complete (mode: %s):\n", mode)
	fmt.Printf("  Folders:  %d created, %d updated\n", result.FoldersCreated, result.FoldersUpdated)
	fmt.Printf("  Threats:  %d created, %d updated, %d skipped\n", result.ThreatsCreated, result.ThreatsUpdated, result.ThreatsSkipped)
	fmt.Printf("  Controls: %d created, %d updated, %d skipped\n", result.ControlsCreated, result.ControlsUpdated, result.ControlsSkipped)

	if len(result.Warnings) > 0 {
		fmt.Println()
		fmt.Println("Warnings:")
		for _, w := range result.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	return 0
}
