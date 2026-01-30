package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mitchellh/cli"
)

// CloudLibraryCommand is the parent command for library operations
type CloudLibraryCommand struct{}

func (c *CloudLibraryCommand) Help() string {
	helpText := `
Usage: threatcl cloud library <subcommand> [options]

  Query threat and control libraries from ThreatCL Cloud.

Subcommands:

  folders      List library folders
  folder       Get a specific library folder by ID
  threats      List threat library items
  threat       Get a specific threat library item by ID
  threat-ref   Get a threat library item by reference ID
  controls     List control library items
  control      Get a specific control library item by ID
  control-ref  Get a control library item by reference ID
  stats        Get library usage statistics

Run 'threatcl cloud library <subcommand> -help' for more information on a specific subcommand.
`
	return strings.TrimSpace(helpText)
}

func (c *CloudLibraryCommand) Synopsis() string {
	return "Query threat and control libraries"
}

func (c *CloudLibraryCommand) Run(args []string) int {
	return cli.RunResultHelp
}

// outputJSON marshals data to JSON and prints to stdout
func outputLibraryJSON(data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

// Library Folder types
type libraryFolder struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

// Threat Library types
type threatLibraryItem struct {
	ID             string                  `json:"id"`
	ReferenceID    string                  `json:"referenceId"`
	Name           string                  `json:"name"`
	Status         string                  `json:"status"`
	CurrentVersion *threatLibraryVersion   `json:"currentVersion"`
	Versions       []threatLibraryVersion  `json:"versions"`
	UsageCount     int                     `json:"usageCount"`
	UsedByModels   []libraryUsedByModel    `json:"usedByModels"`
}

type threatLibraryVersion struct {
	Version             string                `json:"version"`
	Name                string                `json:"name"`
	Description         string                `json:"description"`
	Impacts             []string              `json:"impacts"`
	Stride              []string              `json:"stride"`
	Severity            string                `json:"severity"`
	Likelihood          string                `json:"likelihood"`
	CWEIds              []string              `json:"cweIds"`
	MitreAttackIds      []string              `json:"mitreAttackIds"`
	Tags                []string              `json:"tags"`
	RecommendedControls []*controlLibraryItem `json:"recommendedControls"`
}

// Control Library types
type controlLibraryItem struct {
	ID             string                  `json:"id"`
	ReferenceID    string                  `json:"referenceId"`
	Name           string                  `json:"name"`
	Status         string                  `json:"status"`
	CurrentVersion *controlLibraryVersion  `json:"currentVersion"`
	Versions       []controlLibraryVersion `json:"versions"`
	UsageCount     int                     `json:"usageCount"`
	UsedByModels   []libraryUsedByModel    `json:"usedByModels"`
}

type controlLibraryVersion struct {
	Version                string           `json:"version"`
	Name                   string           `json:"name"`
	Description            string           `json:"description"`
	ControlType            string           `json:"controlType"`
	ControlCategory        string           `json:"controlCategory"`
	ImplementationGuidance string           `json:"implementationGuidance"`
	NISTControls           []string         `json:"nistControls"`
	CISControls            []string         `json:"cisControls"`
	ISOControls            []string         `json:"isoControls"`
	Tags                   []string         `json:"tags"`
	RelatedThreats         []libraryItemRef `json:"relatedThreats"`
	DefaultRiskReduction   int              `json:"defaultRiskReduction"`
}

// libraryItemRef represents a reference to a library item (threat or control)
type libraryItemRef struct {
	ReferenceID string `json:"referenceId"`
	Name        string `json:"name"`
}

type libraryUsedByModel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Library stats types
type libraryUsageStats struct {
	TotalThreatItems      int               `json:"totalThreatItems"`
	TotalControlItems     int               `json:"totalControlItems"`
	PublishedThreatItems  int               `json:"publishedThreatItems"`
	PublishedControlItems int               `json:"publishedControlItems"`
	MostUsedThreats       []libraryStatItem `json:"mostUsedThreats"`
	MostUsedControls      []libraryStatItem `json:"mostUsedControls"`
}

type libraryStatItem struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	UsageCount int    `json:"usageCount"`
}

// Valid status values for library items
var validLibraryStatuses = map[string]bool{
	"DRAFT":      true,
	"PUBLISHED":  true,
	"ARCHIVED":   true,
	"DEPRECATED": true,
}

// Valid folder types
var validFolderTypes = map[string]bool{
	"THREAT":  true,
	"CONTROL": true,
}

// validateLibraryStatus checks if a status value is valid
func validateLibraryStatus(status string) bool {
	if status == "" {
		return true // Empty is valid (no filter)
	}
	return validLibraryStatuses[status]
}

// validateFolderType checks if a folder type value is valid
func validateFolderType(folderType string) bool {
	if folderType == "" {
		return true // Empty is valid (no filter)
	}
	return validFolderTypes[folderType]
}

// splitCommaSeparated splits a comma-separated string into a slice
// Returns nil if the input is empty
func splitCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
