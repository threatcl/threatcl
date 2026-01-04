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

type CloudSearchCommand struct {
	CloudCommandBase
	flagImpacts string
	flagOrgId   string
}

func (c *CloudSearchCommand) Help() string {
	helpText := `
Usage: threatcl cloud search [options]

	Search for threats across your threat models using various filters.

	This command queries the ThreatCL Cloud GraphQL API to find threats
	matching the specified criteria across one or all of your organizations.

Options:

 -impacts=<value>
   Filter threats by impact type. Valid values: Integrity, Confidentiality, Availability

 -org-id=<uuid>
   Optional organization ID. If not specified, searches across all organizations.

 -config=<file>
   Optional config file

Examples:

 # Search for all threats with Integrity impact
 threatcl cloud search -impacts "Integrity"

 # Search within a specific organization
 threatcl cloud search -impacts "Confidentiality" -org-id "01a8b411-decf-47ae-b804-0f959cc16f21"

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)

`
	return strings.TrimSpace(helpText)
}

func (c *CloudSearchCommand) Synopsis() string {
	return "Search for threats across threat models"
}

func (c *CloudSearchCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud search")
	flagSet.StringVar(&c.flagImpacts, "impacts", "", "Filter by impact (Integrity, Confidentiality, Availability)")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.Parse(args)

	// Validate impacts flag
	if c.flagImpacts == "" {
		fmt.Fprintf(os.Stderr, "Error: -impacts flag is required\n")
		return 1
	}

	validImpacts := map[string]bool{
		"Integrity":       true,
		"Confidentiality": true,
		"Availability":    true,
	}

	if !validImpacts[c.flagImpacts] {
		fmt.Fprintf(os.Stderr, "Error: invalid impact value %q. Must be one of: Integrity, Confidentiality, Availability\n", c.flagImpacts)
		return 1
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Step 1: Retrieve token
	token, err := c.getTokenWithDeps(keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Step 2: Get organizations to search
	var orgIds []string
	if c.flagOrgId != "" {
		orgIds = []string{c.flagOrgId}
	} else {
		// Fetch organizations via GraphQL
		orgs, err := c.fetchOrganizationsGraphQL(token, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching organizations: %s\n", err)
			return 1
		}
		if len(orgs) == 0 {
			fmt.Fprintf(os.Stderr, "%s\n", ErrNoOrganizations)
			return 1
		}
		for _, org := range orgs {
			orgIds = append(orgIds, org.Organization.ID)
		}
	}

	// Step 3: Search threats for each organization
	var allThreats []graphQLThreat
	for _, orgId := range orgIds {
		threats, err := c.searchThreatsGraphQL(token, orgId, c.flagImpacts, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error searching threats in org %s: %s\n", orgId, err)
			continue
		}
		allThreats = append(allThreats, threats...)
	}

	// Step 4: Display results
	c.displaySearchResults(allThreats, c.flagImpacts, len(orgIds))

	return 0
}

// graphQLRequest represents a GraphQL request payload
type graphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// graphQLResponse represents a generic GraphQL response
type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []graphQLError  `json:"errors,omitempty"`
}

// graphQLError represents a GraphQL error
type graphQLError struct {
	Message string `json:"message"`
}

// graphQLOrganization represents an organization from GraphQL response
type graphQLOrganization struct {
	Organization struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"organization"`
	Role     string `json:"role"`
	JoinedAt string `json:"joinedAt"`
}

// graphQLThreat represents a threat from GraphQL response
type graphQLThreat struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Impacts           []string `json:"impacts"`
	Stride            []string `json:"stride"`
	InformationAssets []struct {
		ID                        string `json:"id"`
		Name                      string `json:"name"`
		Description               string `json:"description"`
		InformationClassification string `json:"informationClassification"`
	} `json:"informationAssets"`
	ThreatModel struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Status      string `json:"status"`
		Version     string `json:"version"`
	} `json:"threatModel"`
}

// fetchOrganizationsGraphQL fetches organizations using GraphQL
func (c *CloudSearchCommand) fetchOrganizationsGraphQL(token string, httpClient HTTPClient, fsSvc FileSystemService) ([]graphQLOrganization, error) {
	query := `query orgs {
  myOrganizations {
    organization {
      id
      name
    }
    role
    joinedAt
  }
}`

	reqBody := graphQLRequest{
		Query: query,
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
		MyOrganizations []graphQLOrganization `json:"myOrganizations"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse organizations data: %w", err)
	}

	return data.MyOrganizations, nil
}

// searchThreatsGraphQL searches for threats using GraphQL
func (c *CloudSearchCommand) searchThreatsGraphQL(token, orgId, impacts string, httpClient HTTPClient, fsSvc FileSystemService) ([]graphQLThreat, error) {
	query := `query threats($orgId: ID!, $filter: ThreatFilter) {
  threats(orgId: $orgId, filter: $filter) {
    id
    name
    description
    impacts
    stride
    informationAssets {
      id
      name
      description
      informationClassification
    }
    threatModel {
      id
      name
      description
      status
      version
    }
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]interface{}{
			"orgId": orgId,
			"filter": map[string]interface{}{
				"impacts": impacts,
			},
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
		Threats []graphQLThreat `json:"threats"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse threats data: %w", err)
	}

	return data.Threats, nil
}

// displaySearchResults displays the search results
func (c *CloudSearchCommand) displaySearchResults(threats []graphQLThreat, impacts string, orgCount int) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  ThreatCL Cloud - Search Results (impacts: %s)\n", impacts)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	if len(threats) == 0 {
		fmt.Println("No threats found matching the specified criteria.")
		return
	}

	// Count unique threat models
	threatModelIds := make(map[string]bool)
	for _, threat := range threats {
		threatModelIds[threat.ThreatModel.ID] = true
	}

	fmt.Printf("Found %d threat(s) over %d threatmodel(s) in %d org(s):\n\n", len(threats), len(threatModelIds), orgCount)

	for i, threat := range threats {
		if i > 0 {
			fmt.Println(strings.Repeat("-", 40))
			fmt.Println()
		}

		fmt.Printf("Threat: %s\n", threat.Name)
		fmt.Printf("  ID:          %s\n", threat.ID)
		if threat.Description != "" {
			fmt.Printf("  Description: %s\n", threat.Description)
		}
		fmt.Printf("  Impacts:     %s\n", strings.Join(threat.Impacts, ", "))
		if len(threat.Stride) > 0 {
			fmt.Printf("  STRIDE:      %s\n", strings.Join(threat.Stride, ", "))
		}

		fmt.Println()
		fmt.Printf("  Threat Model:\n")
		fmt.Printf("    Name:    %s\n", threat.ThreatModel.Name)
		fmt.Printf("    ID:      %s\n", threat.ThreatModel.ID)
		fmt.Printf("    Status:  %s\n", threat.ThreatModel.Status)
		fmt.Printf("    Version: %s\n", threat.ThreatModel.Version)

		if len(threat.InformationAssets) > 0 {
			fmt.Println()
			fmt.Printf("  Information Assets (%d):\n", len(threat.InformationAssets))
			for _, asset := range threat.InformationAssets {
				fmt.Printf("    - %s", asset.Name)
				if asset.InformationClassification != "" {
					fmt.Printf(" (%s)", asset.InformationClassification)
				}
				fmt.Println()
			}
		}

		fmt.Println()
	}
}
