package graphql

import (
	"testing"

	"github.com/threatcl/spec"
)

func TestMapThreatModelToGraphQL(t *testing.T) {
	tm := &spec.Threatmodel{
		Name:        "Test Threat Model",
		Author:      "test@example.com",
		Description: "A test threat model",
		Link:        "https://example.com",
		CreatedAt:   1234567890,
		UpdatedAt:   1234567900,
		Attributes: &spec.Attribute{
			NewInitiative:  true,
			InternetFacing: false,
			InitiativeSize: "Medium",
		},
	}

	sourceFile := "/path/to/file.hcl"
	result := MapThreatModelToGraphQL(tm, sourceFile)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Name != tm.Name {
		t.Errorf("Expected name '%s', got '%s'", tm.Name, result.Name)
	}

	if result.Author != tm.Author {
		t.Errorf("Expected author '%s', got '%s'", tm.Author, result.Author)
	}

	if result.Description == nil || *result.Description != tm.Description {
		t.Errorf("Expected description '%s', got '%v'", tm.Description, result.Description)
	}

	if result.SourceFile != sourceFile {
		t.Errorf("Expected sourceFile '%s', got '%s'", sourceFile, result.SourceFile)
	}

	if result.Attributes == nil {
		t.Fatal("Expected non-nil Attributes")
	}

	if result.Attributes.NewInitiative == nil || *result.Attributes.NewInitiative != true {
		t.Error("Expected NewInitiative to be true")
	}

	if result.Attributes.InternetFacing == nil || *result.Attributes.InternetFacing != false {
		t.Error("Expected InternetFacing to be false")
	}

	if result.Attributes.InitiativeSize == nil || *result.Attributes.InitiativeSize != "Medium" {
		t.Error("Expected InitiativeSize to be 'Medium'")
	}
}

func TestMapThreatModelToGraphQL_MermaidDiagrams(t *testing.T) {
	tm := &spec.Threatmodel{
		Name:   "Test Threat Model",
		Author: "test@example.com",
		MermaidDiagrams: []*spec.MermaidDiagram{
			{
				Name:        "Login sequence",
				Description: "How a user authenticates",
				Content:     "sequenceDiagram\n  User->>App: credentials",
			},
		},
	}

	result := MapThreatModelToGraphQL(tm, "test.hcl")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if len(result.MermaidDiagrams) != 1 {
		t.Fatalf("Expected 1 mermaid diagram, got %d", len(result.MermaidDiagrams))
	}

	m := result.MermaidDiagrams[0]
	if m.Name != "Login sequence" {
		t.Errorf("Expected mermaid name 'Login sequence', got '%s'", m.Name)
	}
	if m.Content != "sequenceDiagram\n  User->>App: credentials" {
		t.Errorf("Unexpected mermaid content: %q", m.Content)
	}
}

func TestMapThreatModelToGraphQL_NilInput(t *testing.T) {
	result := MapThreatModelToGraphQL(nil, "test.hcl")
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestMapThreatModelToGraphQL_NoAttributes(t *testing.T) {
	tm := &spec.Threatmodel{
		Name:   "Test",
		Author: "test@example.com",
	}

	result := MapThreatModelToGraphQL(tm, "test.hcl")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Attributes != nil {
		t.Error("Expected nil Attributes when input has no attributes")
	}
}

func TestMapProcessToGraphQL(t *testing.T) {
	process := &spec.DfdProcess{
		Name:      "User Authentication",
		TrustZone: "Public Zone",
	}

	result := MapProcessToGraphQL(process)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Name != process.Name {
		t.Errorf("Expected name '%s', got '%s'", process.Name, result.Name)
	}

	if result.TrustZone == nil || *result.TrustZone != process.TrustZone {
		t.Errorf("Expected trust zone '%s', got '%v'", process.TrustZone, result.TrustZone)
	}
}

func TestMapProcessesToGraphQL(t *testing.T) {
	processes := []*spec.DfdProcess{
		{Name: "Process 1", TrustZone: "Zone A"},
		{Name: "Process 2", TrustZone: "Zone B"},
	}

	result := MapProcessesToGraphQL(processes)
	if len(result) != 2 {
		t.Fatalf("Expected 2 processes, got %d", len(result))
	}

	if result[0].Name != "Process 1" {
		t.Errorf("Expected first process name 'Process 1', got '%s'", result[0].Name)
	}
}

func TestMapDataStoreToGraphQL(t *testing.T) {
	dataStore := &spec.DfdData{
		Name:      "User Database",
		TrustZone: "Secure Zone",
		IaLink:    "user_credentials",
	}

	result := MapDataStoreToGraphQL(dataStore)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Name != dataStore.Name {
		t.Errorf("Expected name '%s', got '%s'", dataStore.Name, result.Name)
	}

	if result.InformationAsset == nil || *result.InformationAsset != dataStore.IaLink {
		t.Errorf("Expected information asset '%s', got '%v'", dataStore.IaLink, result.InformationAsset)
	}
}

func TestMapExternalElementToGraphQL(t *testing.T) {
	element := &spec.DfdExternal{
		Name:      "External API",
		TrustZone: "Internet",
	}

	result := MapExternalElementToGraphQL(element)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Name != element.Name {
		t.Errorf("Expected name '%s', got '%s'", element.Name, result.Name)
	}
}

func TestMapFlowToGraphQL(t *testing.T) {
	flow := &spec.DfdFlow{
		Name: "HTTPS Request",
		From: "User",
		To:   "Web Server",
	}

	result := MapFlowToGraphQL(flow)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Name != flow.Name {
		t.Errorf("Expected name '%s', got '%s'", flow.Name, result.Name)
	}

	if result.From != flow.From {
		t.Errorf("Expected from '%s', got '%s'", flow.From, result.From)
	}

	if result.To != flow.To {
		t.Errorf("Expected to '%s', got '%s'", flow.To, result.To)
	}
}

func TestMapTrustZoneToGraphQL(t *testing.T) {
	trustZone := &spec.DfdTrustZone{
		Name: "DMZ",
	}

	result := MapTrustZoneToGraphQL(trustZone)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Name != trustZone.Name {
		t.Errorf("Expected name '%s', got '%s'", trustZone.Name, result.Name)
	}
}

func TestStrPtrOrNil(t *testing.T) {
	// Test with non-empty string
	str := "test"
	result := strPtrOrNil(str)
	if result == nil {
		t.Error("Expected non-nil pointer for non-empty string")
	}
	if *result != str {
		t.Errorf("Expected '%s', got '%s'", str, *result)
	}

	// Test with empty string
	result = strPtrOrNil("")
	if result != nil {
		t.Error("Expected nil pointer for empty string")
	}
}

func TestInt64PtrToIntPtr(t *testing.T) {
	// Test with non-zero value
	var val int64 = 123456
	result := int64PtrToIntPtr(val)
	if result == nil {
		t.Error("Expected non-nil pointer for non-zero value")
	}
	if *result != int(val) {
		t.Errorf("Expected %d, got %d", val, *result)
	}

	// Test with zero value
	result = int64PtrToIntPtr(0)
	if result != nil {
		t.Error("Expected nil pointer for zero value")
	}
}

func TestMapNilSlices(t *testing.T) {
	// Test that nil slices return empty slices, not nil
	processes := MapProcessesToGraphQL(nil)
	if processes == nil {
		t.Error("Expected empty slice, got nil")
	}
	if len(processes) != 0 {
		t.Errorf("Expected empty slice, got length %d", len(processes))
	}

	dataStores := MapDataStoresToGraphQL(nil)
	if dataStores == nil {
		t.Error("Expected empty slice, got nil")
	}

	elements := MapExternalElementsToGraphQL(nil)
	if elements == nil {
		t.Error("Expected empty slice, got nil")
	}

	flows := MapFlowsToGraphQL(nil)
	if flows == nil {
		t.Error("Expected empty slice, got nil")
	}

	trustZones := MapTrustZonesToGraphQL(nil)
	if trustZones == nil {
		t.Error("Expected empty slice, got nil")
	}
}

func TestMapThreatModelToGraphQL_Repository(t *testing.T) {
	tm := &spec.Threatmodel{
		Name:       "Repo TM",
		Author:     "test@example.com",
		Repository: []string{"https://github.com/x/y", "https://github.com/x/z"},
	}

	result := MapThreatModelToGraphQL(tm, "f.hcl")
	if len(result.Repository) != 2 {
		t.Fatalf("Expected 2 repositories, got %d", len(result.Repository))
	}
	if result.Repository[0] != "https://github.com/x/y" {
		t.Errorf("Expected first repo 'https://github.com/x/y', got '%s'", result.Repository[0])
	}
}

func TestMapRiskRatingToGraphQL(t *testing.T) {
	// high x very_high resolves to a critical inherent band; a single 75%
	// implemented control reduces the residual score.
	threat := &spec.Threat{
		Name:        "Token theft",
		Description: "d",
		Risk: &spec.Risk{
			Likelihood: "high",
			Impact:     "very_high",
			Rationale:  "unencrypted tokens",
		},
		Controls: []*spec.Control{
			{Name: "TLS", Description: "tls", Implemented: true, RiskReduction: 75},
		},
	}

	rr := MapRiskRatingToGraphQL(threat)
	if rr == nil {
		t.Fatal("Expected non-nil RiskRating")
	}
	if rr.Likelihood != "high" || rr.Impact != "very_high" {
		t.Errorf("Expected high/very_high, got %s/%s", rr.Likelihood, rr.Impact)
	}
	if rr.Severity != "critical" {
		t.Errorf("Expected severity 'critical', got '%s'", rr.Severity)
	}
	if rr.Rationale == nil || *rr.Rationale != "unencrypted tokens" {
		t.Errorf("Expected rationale, got %v", rr.Rationale)
	}
	// Computed values should pass through verbatim from the spec methods.
	if rr.InherentScore != threat.Risk.InherentScore() {
		t.Errorf("InherentScore = %v, want %v", rr.InherentScore, threat.Risk.InherentScore())
	}
	if rr.ResidualScore != threat.ResidualScore() {
		t.Errorf("ResidualScore = %v, want %v", rr.ResidualScore, threat.ResidualScore())
	}
	if rr.ResidualSeverity != threat.ResidualSeverity() {
		t.Errorf("ResidualSeverity = %v, want %v", rr.ResidualSeverity, threat.ResidualSeverity())
	}
	if rr.ResidualRiskReduction != 75 {
		t.Errorf("ResidualRiskReduction = %v, want 75", rr.ResidualRiskReduction)
	}
}

func TestMapRiskRatingToGraphQL_NoRisk(t *testing.T) {
	if rr := MapRiskRatingToGraphQL(&spec.Threat{Name: "no risk"}); rr != nil {
		t.Errorf("Expected nil for threat without a risk block, got %+v", rr)
	}
	if rr := MapRiskRatingToGraphQL(nil); rr != nil {
		t.Errorf("Expected nil for nil threat, got %+v", rr)
	}
}

func TestMatchesThreatFilter_Severity(t *testing.T) {
	// high x very_high => critical inherent severity
	withRisk := &spec.Threat{Name: "a", Risk: &spec.Risk{Likelihood: "high", Impact: "very_high"}}
	noRisk := &spec.Threat{Name: "b"}

	tests := []struct {
		name   string
		threat *spec.Threat
		filter *ThreatFilter
		want   bool
	}{
		{"match critical", withRisk, &ThreatFilter{Severity: []string{"critical"}}, true},
		{"case-insensitive", withRisk, &ThreatFilter{Severity: []string{"Critical"}}, true},
		{"no match for low", withRisk, &ThreatFilter{Severity: []string{"low"}}, false},
		{"no-risk threat excluded", noRisk, &ThreatFilter{Severity: []string{"critical"}}, false},
		{"empty severity filter matches", withRisk, &ThreatFilter{}, true},
	}

	for _, tc := range tests {
		if got := matchesThreatFilter(tc.threat, tc.filter); got != tc.want {
			t.Errorf("%s: matchesThreatFilter = %v, want %v", tc.name, got, tc.want)
		}
	}
}
