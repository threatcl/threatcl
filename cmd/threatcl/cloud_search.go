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
	flagImpacts       string
	flagOrgId         string
	flagType          string
	flagStride        string
	flagHasControls   string
	flagImplemented   string
	flagThreatModelId string
}

func (c *CloudSearchCommand) Help() string {
	helpText := `
Usage: threatcl cloud search [options]

	Search for threats or controls across your threat models using various filters.

	This command queries the ThreatCL Cloud GraphQL API to find threats or controls
	matching the specified criteria across one or all of your organizations.

Options:

 -type=<value>
   Type of entity to search. Valid values: threats (default), controls

 -impacts=<value>
   Filter threats by impact type. Valid values: Integrity, Confidentiality, Availability
   (Only valid when -type=threats)

 -stride=<value>
   Filter threats by STRIDE categories (comma-separated). Valid values:
   Spoofing, Tampering, Repudiation, "Info Disclosure", "Denial Of Service", "Elevation Of Privilege"
   (Only valid when -type=threats)

 -has-controls=<true|false>
   Filter threats by whether they have associated controls.
   (Only valid when -type=threats)

 -implemented=<true|false>
   Filter controls by implementation status.
   (Only valid when -type=controls)

 -threatmodel-id=<uuid>
   Scope search to a specific threat model.

 -org-id=<uuid>
   Optional organization ID. If not specified, uses THREATCL_CLOUD_ORG env var
   or searches across all organizations.

 -config=<file>
   Optional config file

Examples:

 # Search for all threats with Integrity impact
 threatcl cloud search -impacts "Integrity"

 # Filter by STRIDE categories
 threatcl cloud search -stride "Tampering,Info Disclosure"

 # Find threats without controls
 threatcl cloud search -has-controls=false

 # Combine filters
 threatcl cloud search -impacts "Confidentiality" -stride "Info Disclosure" -has-controls=true

 # Search controls
 threatcl cloud search -type controls

 # Search implemented controls only
 threatcl cloud search -type controls -implemented=true

 # Search within a specific threat model
 threatcl cloud search -threatmodel-id "550e8400-e29b-41d4-a716-446655440000"

 # Search within a specific organization
 threatcl cloud search -impacts "Confidentiality" -org-id "01a8b411-decf-47ae-b804-0f959cc16f21"

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)

 THREATCL_CLOUD_ORG
   Default organization ID to use when -org-id is not specified.

`
	return strings.TrimSpace(helpText)
}

func (c *CloudSearchCommand) Synopsis() string {
	return "Search for threats and controls across threat models"
}

func (c *CloudSearchCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud search")
	flagSet.StringVar(&c.flagType, "type", "threats", "Type of entity to search (threats, controls)")
	flagSet.StringVar(&c.flagImpacts, "impacts", "", "Filter by impact (Integrity, Confidentiality, Availability)")
	flagSet.StringVar(&c.flagStride, "stride", "", "Filter by STRIDE categories (comma-separated)")
	flagSet.StringVar(&c.flagHasControls, "has-controls", "", "Filter threats by whether they have controls (true/false)")
	flagSet.StringVar(&c.flagImplemented, "implemented", "", "Filter controls by implementation status (true/false)")
	flagSet.StringVar(&c.flagThreatModelId, "threatmodel-id", "", "Scope search to a specific threat model")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.Parse(args)

	// Validate type flag
	if c.flagType != "threats" && c.flagType != "controls" {
		fmt.Fprintf(os.Stderr, "Error: invalid -type value %q. Must be one of: threats, controls\n", c.flagType)
		return 1
	}

	// Validate flag combinations based on type
	if c.flagType == "controls" {
		if c.flagImpacts != "" {
			fmt.Fprintf(os.Stderr, "Error: -impacts flag is not valid when -type=controls\n")
			return 1
		}
		if c.flagStride != "" {
			fmt.Fprintf(os.Stderr, "Error: -stride flag is not valid when -type=controls\n")
			return 1
		}
		if c.flagHasControls != "" {
			fmt.Fprintf(os.Stderr, "Error: -has-controls flag is not valid when -type=controls\n")
			return 1
		}
	}

	if c.flagType == "threats" {
		if c.flagImplemented != "" {
			fmt.Fprintf(os.Stderr, "Error: -implemented flag is not valid when -type=threats\n")
			return 1
		}
	}

	// Validate impacts flag if provided
	if c.flagImpacts != "" {
		validImpacts := map[string]bool{
			"Integrity":       true,
			"Confidentiality": true,
			"Availability":    true,
		}
		if !validImpacts[c.flagImpacts] {
			fmt.Fprintf(os.Stderr, "Error: invalid impact value %q. Must be one of: Integrity, Confidentiality, Availability\n", c.flagImpacts)
			return 1
		}
	}

	// Validate stride flag if provided
	var strideCategories []string
	if c.flagStride != "" {
		validStride := map[string]bool{
			"Spoofing":               true,
			"Tampering":              true,
			"Repudiation":            true,
			"Info Disclosure":        true,
			"Denial Of Service":      true,
			"Elevation Of Privilege": true,
		}
		strideCategories = strings.Split(c.flagStride, ",")
		for i, s := range strideCategories {
			strideCategories[i] = strings.TrimSpace(s)
			if !validStride[strideCategories[i]] {
				fmt.Fprintf(os.Stderr, "Error: invalid STRIDE value %q. Must be one of: Spoofing, Tampering, Repudiation, Info Disclosure, Denial Of Service, Elevation Of Privilege\n", strideCategories[i])
				return 1
			}
		}
	}

	// Validate has-controls flag if provided
	var hasControls *bool
	if c.flagHasControls != "" {
		switch c.flagHasControls {
		case "true":
			val := true
			hasControls = &val
		case "false":
			val := false
			hasControls = &val
		default:
			fmt.Fprintf(os.Stderr, "Error: invalid -has-controls value %q. Must be true or false\n", c.flagHasControls)
			return 1
		}
	}

	// Validate implemented flag if provided
	var implemented *bool
	if c.flagImplemented != "" {
		switch c.flagImplemented {
		case "true":
			val := true
			implemented = &val
		case "false":
			val := false
			implemented = &val
		default:
			fmt.Fprintf(os.Stderr, "Error: invalid -implemented value %q. Must be true or false\n", c.flagImplemented)
			return 1
		}
	}

	// Initialize dependencies
	httpClient, keyringSvc, fsSvc := c.initDependencies(30 * time.Second)

	// Step 1: Retrieve token (use default org token for searches)
	token, _, err := c.getTokenAndOrgId(c.flagOrgId, keyringSvc, fsSvc)
	if err != nil {
		return c.handleTokenError(err)
	}

	// Step 2: Get organizations to search
	// Build a map of org ID -> org Name for display
	orgInfo := make(map[string]string) // orgId -> orgName
	var orgIds []string
	if c.flagOrgId != "" {
		orgIds = []string{c.flagOrgId}
		// When a specific org-id is provided, we still need to fetch org info to get the name
		orgs, err := c.fetchOrganizationsGraphQL(token, httpClient, fsSvc)
		if err == nil {
			for _, org := range orgs {
				if org.Organization.ID == c.flagOrgId {
					orgInfo[org.Organization.ID] = org.Organization.Name
					break
				}
			}
		}
		// If we couldn't find the org name, use a placeholder
		if _, exists := orgInfo[c.flagOrgId]; !exists {
			orgInfo[c.flagOrgId] = ""
		}
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
			orgInfo[org.Organization.ID] = org.Organization.Name
		}
	}

	// Step 3: Search based on type
	if c.flagType == "controls" {
		return c.searchAndDisplayControls(token, orgIds, orgInfo, implemented, httpClient, fsSvc)
	}

	return c.searchAndDisplayThreats(token, orgIds, orgInfo, strideCategories, hasControls, httpClient, fsSvc)
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
	// OrgID and OrgName are populated after the GraphQL query
	// to track which organization this threat belongs to
	OrgID   string `json:"-"`
	OrgName string `json:"-"`
}

// graphQLControl represents a control from GraphQL response
type graphQLControl struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Implemented bool   `json:"implemented"`
	ThreatModel struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Status      string `json:"status"`
		Version     string `json:"version"`
	} `json:"threatModel"`
	// OrgID and OrgName are populated after the GraphQL query
	// to track which organization this control belongs to
	OrgID   string `json:"-"`
	OrgName string `json:"-"`
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

// threatSearchFilter contains the filter options for threat search
type threatSearchFilter struct {
	Impacts       string
	Stride        []string
	HasControls   *bool
	ThreatModelId string
}

// searchThreatsGraphQL searches for threats using GraphQL
func (c *CloudSearchCommand) searchThreatsGraphQL(token, orgId string, filter threatSearchFilter, httpClient HTTPClient, fsSvc FileSystemService) ([]graphQLThreat, error) {
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

	// Build filter map dynamically based on provided values
	filterMap := make(map[string]any)
	if filter.Impacts != "" {
		filterMap["impacts"] = filter.Impacts
	}
	if len(filter.Stride) > 0 {
		filterMap["stride"] = filter.Stride
	}
	if filter.HasControls != nil {
		filterMap["hasControls"] = *filter.HasControls
	}
	if filter.ThreatModelId != "" {
		filterMap["threatModelId"] = filter.ThreatModelId
	}

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]any{
			"orgId":  orgId,
			"filter": filterMap,
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

// controlSearchFilter contains the filter options for control search
type controlSearchFilter struct {
	Implemented   *bool
	ThreatModelId string
}

// searchControlsGraphQL searches for controls using GraphQL
func (c *CloudSearchCommand) searchControlsGraphQL(token, orgId string, filter controlSearchFilter, httpClient HTTPClient, fsSvc FileSystemService) ([]graphQLControl, error) {
	query := `query controls($orgId: ID!, $filter: ControlFilter) {
  controls(orgId: $orgId, filter: $filter) {
    id
    name
    description
    implemented
    threatModel {
      id
      name
      description
      status
      version
    }
  }
}`

	// Build filter map dynamically based on provided values
	filterMap := make(map[string]any)
	if filter.Implemented != nil {
		filterMap["implemented"] = *filter.Implemented
	}
	if filter.ThreatModelId != "" {
		filterMap["threatModelId"] = filter.ThreatModelId
	}

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]any{
			"orgId":  orgId,
			"filter": filterMap,
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
		Controls []graphQLControl `json:"controls"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse controls data: %w", err)
	}

	return data.Controls, nil
}

// searchAndDisplayThreats searches for threats and displays results
func (c *CloudSearchCommand) searchAndDisplayThreats(token string, orgIds []string, orgInfo map[string]string, strideCategories []string, hasControls *bool, httpClient HTTPClient, fsSvc FileSystemService) int {
	filter := threatSearchFilter{
		Impacts:       c.flagImpacts,
		Stride:        strideCategories,
		HasControls:   hasControls,
		ThreatModelId: c.flagThreatModelId,
	}

	var allThreats []graphQLThreat
	for _, orgId := range orgIds {
		threats, err := c.searchThreatsGraphQL(token, orgId, filter, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error searching threats in org %s: %s\n", orgId, err)
			continue
		}
		// Populate org info on each threat
		for i := range threats {
			threats[i].OrgID = orgId
			threats[i].OrgName = orgInfo[orgId]
		}
		allThreats = append(allThreats, threats...)
	}

	c.displayThreatResults(allThreats, c.buildFilterDescription(), len(orgIds))
	return 0
}

// searchAndDisplayControls searches for controls and displays results
func (c *CloudSearchCommand) searchAndDisplayControls(token string, orgIds []string, orgInfo map[string]string, implemented *bool, httpClient HTTPClient, fsSvc FileSystemService) int {
	filter := controlSearchFilter{
		Implemented:   implemented,
		ThreatModelId: c.flagThreatModelId,
	}

	var allControls []graphQLControl
	for _, orgId := range orgIds {
		controls, err := c.searchControlsGraphQL(token, orgId, filter, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error searching controls in org %s: %s\n", orgId, err)
			continue
		}
		// Populate org info on each control
		for i := range controls {
			controls[i].OrgID = orgId
			controls[i].OrgName = orgInfo[orgId]
		}
		allControls = append(allControls, controls...)
	}

	c.displayControlResults(allControls, c.buildFilterDescription(), len(orgIds))
	return 0
}

// buildFilterDescription builds a human-readable description of the active filters
func (c *CloudSearchCommand) buildFilterDescription() string {
	var parts []string

	if c.flagImpacts != "" {
		parts = append(parts, fmt.Sprintf("impacts: %s", c.flagImpacts))
	}
	if c.flagStride != "" {
		parts = append(parts, fmt.Sprintf("stride: %s", c.flagStride))
	}
	if c.flagHasControls != "" {
		parts = append(parts, fmt.Sprintf("has-controls: %s", c.flagHasControls))
	}
	if c.flagImplemented != "" {
		parts = append(parts, fmt.Sprintf("implemented: %s", c.flagImplemented))
	}
	if c.flagThreatModelId != "" {
		parts = append(parts, fmt.Sprintf("threatmodel-id: %s", c.flagThreatModelId))
	}

	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, ", ")
}

// displayThreatResults displays the threat search results
func (c *CloudSearchCommand) displayThreatResults(threats []graphQLThreat, filterDesc string, orgCount int) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  ThreatCL Cloud - Threat Search Results\n")
	fmt.Printf("  Filters: %s\n", filterDesc)
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
		fmt.Printf("    Name:     %s\n", threat.ThreatModel.Name)
		fmt.Printf("    ID:       %s\n", threat.ThreatModel.ID)
		fmt.Printf("    Status:   %s\n", threat.ThreatModel.Status)
		fmt.Printf("    Version:  %s\n", threat.ThreatModel.Version)
		if threat.OrgName != "" {
			fmt.Printf("    Org Name: %s\n", threat.OrgName)
		}
		fmt.Printf("    Org ID:   %s\n", threat.OrgID)

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

// displayControlResults displays the control search results
func (c *CloudSearchCommand) displayControlResults(controls []graphQLControl, filterDesc string, orgCount int) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  ThreatCL Cloud - Control Search Results\n")
	fmt.Printf("  Filters: %s\n", filterDesc)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	if len(controls) == 0 {
		fmt.Println("No controls found matching the specified criteria.")
		return
	}

	// Count unique threat models
	threatModelIds := make(map[string]bool)
	for _, control := range controls {
		threatModelIds[control.ThreatModel.ID] = true
	}

	fmt.Printf("Found %d control(s) over %d threatmodel(s) in %d org(s):\n\n", len(controls), len(threatModelIds), orgCount)

	for i, control := range controls {
		if i > 0 {
			fmt.Println(strings.Repeat("-", 40))
			fmt.Println()
		}

		fmt.Printf("Control: %s\n", control.Name)
		fmt.Printf("  ID:          %s\n", control.ID)
		if control.Description != "" {
			fmt.Printf("  Description: %s\n", control.Description)
		}
		fmt.Printf("  Implemented: %t\n", control.Implemented)

		fmt.Println()
		fmt.Printf("  Threat Model:\n")
		fmt.Printf("    Name:     %s\n", control.ThreatModel.Name)
		fmt.Printf("    ID:       %s\n", control.ThreatModel.ID)
		fmt.Printf("    Status:   %s\n", control.ThreatModel.Status)
		fmt.Printf("    Version:  %s\n", control.ThreatModel.Version)
		if control.OrgName != "" {
			fmt.Printf("    Org Name: %s\n", control.OrgName)
		}
		fmt.Printf("    Org ID:   %s\n", control.OrgID)

		fmt.Println()
	}
}
