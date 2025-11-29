package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type CloudThreatmodelsCommand struct {
	*GlobalCmdOptions
	flagOrgId  string
	httpClient HTTPClient
	keyringSvc KeyringService
	fsSvc      FileSystemService
}

func (c *CloudThreatmodelsCommand) Help() string {
	helpText := `
Usage: threatcl cloud threatmodels [-orgId=<orgId>]

	List threat models for an organization.

	If -orgId is not provided, the command will automatically use the
	first organization from your user profile.

Options:

 -orgId=<orgId>
   Optional organization ID. If not provided, uses the first organization
   from your user profile.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud threatmodels

`
	return strings.TrimSpace(helpText)
}

func (c *CloudThreatmodelsCommand) Synopsis() string {
	return "List threat models for an organization"
}

func (c *CloudThreatmodelsCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud threatmodels")
	flagSet.StringVar(&c.flagOrgId, "orgId", "", "Organization ID (optional)")
	flagSet.Parse(args)

	// Use injected dependencies or defaults
	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = &defaultHTTPClient{
			client: &http.Client{
				Timeout: 10 * time.Second,
			},
		}
	}
	keyringSvc := c.keyringSvc
	if keyringSvc == nil {
		keyringSvc = &defaultKeyringService{}
	}
	fsSvc := c.fsSvc
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}

	// Step 1: Retrieve token
	token, err := getToken(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving token: %s\n", err)
		fmt.Fprintf(os.Stderr, "Please run 'threatcl cloud login' to authenticate.\n")
		return 1
	}

	// Step 2: Get organization ID
	orgId := c.flagOrgId
	if orgId == "" {
		// Fetch user info to get first organization
		whoamiResp, err := c.fetchUserInfo(token, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching user information: %s\n", err)
			return 1
		}

		if len(whoamiResp.Organizations) == 0 {
			fmt.Fprintf(os.Stderr, "Error: No organizations found. Please specify an organization ID with -orgId\n")
			return 1
		}

		orgId = whoamiResp.Organizations[0].Organization.ID
	}

	// Step 3: Fetch threat models
	threatModels, err := c.fetchThreatModels(token, orgId, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching threat models: %s\n", err)
		return 1
	}

	// Step 4: Display results
	c.displayThreatModels(threatModels)

	return 0
}

func (c *CloudThreatmodelsCommand) fetchUserInfo(token string, httpClient HTTPClient, fsSvc FileSystemService) (*whoamiResponse, error) {
	url := fmt.Sprintf("%s/api/v1/users/me", getAPIBaseURL(fsSvc))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("authentication failed - token may be invalid or expired. Please run 'threatcl cloud login' again")
		}
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var whoamiResp whoamiResponse
	if err := json.NewDecoder(resp.Body).Decode(&whoamiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &whoamiResp, nil
}

func (c *CloudThreatmodelsCommand) fetchThreatModels(token string, orgId string, httpClient HTTPClient, fsSvc FileSystemService) ([]threatModel, error) {
	url := fmt.Sprintf("%s/api/v1/org/%s/models", getAPIBaseURL(fsSvc), orgId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("authentication failed - token may be invalid or expired. Please run 'threatcl cloud login' again")
		}
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var threatModels []threatModel
	if err := json.NewDecoder(resp.Body).Decode(&threatModels); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return threatModels, nil
}

func (c *CloudThreatmodelsCommand) displayThreatModels(threatModels []threatModel) {
	if len(threatModels) == 0 {
		fmt.Println("No threat models found.")
		return
	}

	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("  Threat Models")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()
	fmt.Printf("%-36s %-30s %-20s %-10s %-10s\n", "ID", "Name", "Slug", "Status", "Version")
	fmt.Println(strings.Repeat("-", 100))

	for _, tm := range threatModels {
		fmt.Printf("%-36s %-30s %-20s %-10s %-10s\n", tm.ID, tm.Name, tm.Slug, tm.Status, tm.Version)
	}
	fmt.Println()
}
