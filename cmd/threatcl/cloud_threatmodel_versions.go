package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CloudThreatmodelVersionsCommand struct {
	CloudCommandBase
	flagOrgId     string
	flagModelId   string
	flagDownload  string
	flagOverwrite bool
	flagVersion   string
}

func (c *CloudThreatmodelVersionsCommand) Help() string {
	helpText := `
Usage: threatcl cloud threatmodel versions -model-id=<modelId_or_slug> [-org-id=<orgId>] [-download=<file>] [-version=<version>] [-overwrite]

	Display information about the versions of a single threat model.

	The -model-id flag is required and can be either a threat model ID or slug.

	If -org-id is not provided, the command will check the THREATCL_CLOUD_ORG
	environment variable. If that is also not set, it will use the first
	organization from your user profile.

Options:

 -model-id=<modelId_or_slug>
   Required. The threat model ID or slug to display.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG env var
   or the first organization from your user profile.

 -download=<file>
   Optionally, download a specific version of the threat model file to the specified file.

 -version=<version>
   Required when using -download. The version number to download (e.g., 1.0.0).

 -overwrite
   When downloading, overwrite the file if it already exists. Default is false.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud threatmodel versions -model-id=my-model

 THREATCL_CLOUD_ORG
   Default organization ID to use when -org-id is not specified.

`
	return strings.TrimSpace(helpText)
}

func (c *CloudThreatmodelVersionsCommand) Synopsis() string {
	return "Display information about the versions of a single threat model"
}

func (c *CloudThreatmodelVersionsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud threatmodel versions")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID or slug (required)")
	flagSet.StringVar(&c.flagDownload, "download", "", "Download a specific version of the threat model file to the specified file")
	flagSet.StringVar(&c.flagVersion, "version", "", "Version number to download (required when using -download)")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite the file if it already exists when downloading")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud threatmodel versions -help' for usage information.\n")
		return 1
	}

	// Validate that if -download is set, -version must also be set
	if c.flagDownload != "" && c.flagVersion == "" {
		fmt.Fprintf(os.Stderr, "Error: -version is required when using -download\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud threatmodel versions -help' for usage information.\n")
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(10 * time.Second)

	// Step 1: Retrieve token and org ID
	token, orgId, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Step 2: Download threat model version file (if requested)
	if c.flagDownload != "" {
		url := fmt.Sprintf("%s/api/v1/org/%s/models/%s/versions/%s/download", getAPIBaseURL(fsSvc), orgId, c.flagModelId, c.flagVersion)
		err = downloadFile(url, token, c.flagDownload, c.flagOverwrite, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading threat model version file: %s\n", err)
			return 1
		}
		fmt.Printf("Successfully downloaded threat model version %s to %s\n", c.flagVersion, c.flagDownload)
		return 0
	}

	// Step 4: Fetch threat model versions
	threatModelVersionsResponse, err := fetchThreatModelVersions(token, orgId, c.flagModelId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching threat model versions: %s\n", err)
		return 1
	}

	// Step 5: Display result
	c.displayThreatModelVersions(threatModelVersionsResponse)

	return 0
}

func (c *CloudThreatmodelVersionsCommand) displayThreatModelVersions(threatModelVersionsResponse *threatModelVersionsResponse) {
	fmt.Println("\n📋 Threat Model Versions")
	fmt.Println(strings.Repeat("─", 100))

	if len(threatModelVersionsResponse.Versions) == 0 {
		fmt.Println("No versions found.")
		return
	}

	for i, version := range threatModelVersionsResponse.Versions {
		if i > 0 {
			fmt.Println()
		}

		// Highlight current version
		if version.IsCurrent {
			fmt.Println("▶ CURRENT VERSION")
		}

		fmt.Printf("  Version:    %s\n", version.Version)
		fmt.Printf("  Created:    %s\n", formatTimestamp(version.CreatedAt))
		fmt.Printf("  Changed by: %s\n", version.ChangedBy)
		fmt.Printf("  ID:         %s\n", version.ID)
	}

	fmt.Println(strings.Repeat("─", 100))
	fmt.Printf("Total: %d version(s)\n\n", threatModelVersionsResponse.Total)
}

// formatTimestamp formats ISO 8601 timestamps into a more readable format
func formatTimestamp(timestamp string) string {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		// Try alternative formats or return truncated string
		if len(timestamp) > 19 {
			return timestamp[:19]
		}
		return timestamp
	}
	// Format as: "2006-01-02 15:04:05"
	return t.Format("2006-01-02 15:04:05")
}

// func (c *CloudThreatmodelVersionsCommand) fetchThreatModel(token string, orgId string, modelIdOrSlug string, httpClient HTTPClient, fsSvc FileSystemService) (*threatModel, error) {
// 	url := fmt.Sprintf("%s/api/v1/org/%s/models/%s", getAPIBaseURL(fsSvc), orgId, modelIdOrSlug)

// 	req, err := http.NewRequest("GET", url, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create request: %w", err)
// 	}

// 	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
// 	req.Header.Set("Content-Type", "application/json")

// 	resp, err := httpClient.Do(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to connect to API: %w", err)
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		body, _ := io.ReadAll(resp.Body)
// 		if resp.StatusCode == http.StatusUnauthorized {
// 			return nil, fmt.Errorf("authentication failed - token may be invalid or expired. Please run 'threatcl cloud login' again")
// 		}
// 		if resp.StatusCode == http.StatusNotFound {
// 			return nil, fmt.Errorf("threat model not found: %s", modelIdOrSlug)
// 		}
// 		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
// 	}

// 	var threatModel threatModel
// 	if err := json.NewDecoder(resp.Body).Decode(&threatModel); err != nil {
// 		return nil, fmt.Errorf("failed to parse response: %w", err)
// 	}

// 	return &threatModel, nil
// }

// func (c *CloudThreatmodelVersionsCommand) displayThreatModel(tm *threatModel) {
// 	fmt.Println(strings.Repeat("=", 100))
// 	fmt.Println("  Threat Model")
// 	fmt.Println(strings.Repeat("=", 100))
// 	fmt.Println()

// 	fmt.Printf("ID:              %s\n", tm.ID)
// 	fmt.Printf("Name:            %s\n", tm.Name)
// 	fmt.Printf("Slug:            %s\n", tm.Slug)
// 	if tm.Description != "" {
// 		fmt.Printf("Description:     %s\n", tm.Description)
// 	}
// 	fmt.Printf("Status:          %s\n", tm.Status)
// 	fmt.Printf("Version:         %s\n", tm.Version)
// 	if tm.SpecFilePath != "" {
// 		fmt.Printf("Spec File Path:  %s\n", tm.SpecFilePath)
// 	}
// 	fmt.Printf("Organization ID: %s\n", tm.OrganizationID)
// 	fmt.Printf("Asset Count:     %d\n", tm.AssetCount)
// 	fmt.Printf("Threat Count:    %d\n", tm.ThreatCount)
// 	fmt.Printf("Control Count:   %d\n", tm.ControlCount)
// 	fmt.Printf("Data Flow Count: %d\n", tm.DataFlowCount)
// 	fmt.Printf("Use Case Count:  %d\n", tm.UseCaseCount)
// 	fmt.Printf("Exclusion Count: %d\n", tm.ExclusionCount)
// 	fmt.Printf("Third Party Dependency Count: %d\n", tm.ThirdPartyDependencyCount)
// 	if len(tm.Tags) > 0 {
// 		fmt.Printf("Tags:            %s\n", strings.Join(tm.Tags, ", "))
// 	}
// 	if tm.CreatedBy != "" {
// 		fmt.Printf("Created By:      %s\n", tm.CreatedBy)
// 	}
// 	if tm.CreatedAt != "" {
// 		fmt.Printf("Created At:      %s\n", tm.CreatedAt)
// 	}
// 	if tm.UpdatedAt != "" {
// 		fmt.Printf("Updated At:      %s\n", tm.UpdatedAt)
// 	}
// 	fmt.Println()
// }
