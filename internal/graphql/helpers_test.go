package graphql

import (
	"testing"

	"github.com/threatcl/spec"
)

func TestMatchesFilter(t *testing.T) {
	withAttrs := &spec.Threatmodel{
		Name:   "With Attrs",
		Author: "@alice",
		Attributes: &spec.Attribute{
			NewInitiative:  true,
			InternetFacing: false,
			InitiativeSize: "Small",
		},
	}
	noAttrs := &spec.Threatmodel{
		Name:   "No Attrs",
		Author: "@bob",
	}

	tests := []struct {
		name   string
		tm     *spec.Threatmodel
		filter *ThreatModelFilter
		want   bool
	}{
		{"nil filter matches", withAttrs, nil, true},
		{"empty filter matches", withAttrs, &ThreatModelFilter{}, true},
		{"author match", withAttrs, &ThreatModelFilter{Author: strPtr("@alice")}, true},
		{"author mismatch", withAttrs, &ThreatModelFilter{Author: strPtr("@mallory")}, false},
		{"internet facing match", withAttrs, &ThreatModelFilter{InternetFacing: boolPtr(false)}, true},
		{"internet facing mismatch", withAttrs, &ThreatModelFilter{InternetFacing: boolPtr(true)}, false},
		{"new initiative match", withAttrs, &ThreatModelFilter{NewInitiative: boolPtr(true)}, true},
		{"new initiative mismatch", withAttrs, &ThreatModelFilter{NewInitiative: boolPtr(false)}, false},
		{"initiative size match", withAttrs, &ThreatModelFilter{InitiativeSize: strPtr("Small")}, true},
		{"initiative size mismatch", withAttrs, &ThreatModelFilter{InitiativeSize: strPtr("Large")}, false},
		{"author and attribute filters combined", withAttrs, &ThreatModelFilter{
			Author:         strPtr("@alice"),
			NewInitiative:  boolPtr(true),
			InitiativeSize: strPtr("Small"),
		}, true},
		{"no attributes with internet facing filter", noAttrs, &ThreatModelFilter{InternetFacing: boolPtr(false)}, false},
		{"no attributes with new initiative filter", noAttrs, &ThreatModelFilter{NewInitiative: boolPtr(false)}, false},
		{"no attributes with initiative size filter", noAttrs, &ThreatModelFilter{InitiativeSize: strPtr("Small")}, false},
		{"no attributes with author-only filter", noAttrs, &ThreatModelFilter{Author: strPtr("@bob")}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesFilter(tc.tm, tc.filter); got != tc.want {
				t.Errorf("matchesFilter() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatchesThreatFilter(t *testing.T) {
	threat := &spec.Threat{
		Name:       "Crown Theft",
		ImpactType: []string{"Confidentiality", "Integrity"},
		Stride:     []string{"Spoofing", "Tampering"},
		Controls: []*spec.Control{
			{Name: "Guards", Implemented: true, RiskReduction: 50},
			{Name: "Moat", Implemented: false},
		},
	}
	noControls := &spec.Threat{
		Name: "Gold Theft",
	}

	tests := []struct {
		name   string
		threat *spec.Threat
		filter *ThreatFilter
		want   bool
	}{
		{"nil filter matches", threat, nil, true},
		{"empty filter matches", threat, &ThreatFilter{}, true},
		{"name substring match", threat, &ThreatFilter{Name: strPtr("crown")}, true},
		{"name case-insensitive match", threat, &ThreatFilter{Name: strPtr("THEFT")}, true},
		{"name no match", threat, &ThreatFilter{Name: strPtr("bribery")}, false},
		{"empty name filter matches", threat, &ThreatFilter{Name: strPtr("")}, true},
		{"impacts match", threat, &ThreatFilter{Impacts: []string{"Integrity"}}, true},
		{"impacts no match", threat, &ThreatFilter{Impacts: []string{"Availability"}}, false},
		{"impacts filter on threat without impacts", noControls, &ThreatFilter{Impacts: []string{"Confidentiality"}}, false},
		{"stride match", threat, &ThreatFilter{Stride: []string{"Tampering"}}, true},
		{"stride no match", threat, &ThreatFilter{Stride: []string{"Repudiation"}}, false},
		{"has implemented controls true match", threat, &ThreatFilter{HasImplementedControls: boolPtr(true)}, true},
		{"has implemented controls false mismatch", threat, &ThreatFilter{HasImplementedControls: boolPtr(false)}, false},
		{"no controls matches false", noControls, &ThreatFilter{HasImplementedControls: boolPtr(false)}, true},
		{"no controls does not match true", noControls, &ThreatFilter{HasImplementedControls: boolPtr(true)}, false},
		{"combined filters match", threat, &ThreatFilter{
			Name:                   strPtr("crown"),
			Impacts:                []string{"Confidentiality"},
			Stride:                 []string{"Spoofing"},
			HasImplementedControls: boolPtr(true),
		}, true},
		{"combined filters one mismatch", threat, &ThreatFilter{
			Name:    strPtr("crown"),
			Impacts: []string{"Availability"},
		}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesThreatFilter(tc.threat, tc.filter); got != tc.want {
				t.Errorf("matchesThreatFilter() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"match", []string{"x", "y"}, []string{"y"}, true},
		{"no match", []string{"x", "y"}, []string{"z"}, false},
		{"empty a", []string{}, []string{"x"}, false},
		{"nil a", nil, []string{"x"}, false},
		{"empty b", []string{"x"}, []string{}, false},
		{"multiple candidates one matches", []string{"a", "b", "c"}, []string{"z", "c"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsAny(tc.a, tc.b); got != tc.want {
				t.Errorf("containsAny(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestContainsSubstring(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{"exact match", "crown", "crown", true},
		{"substring match", "Crown theft", "theft", true},
		{"case-insensitive", "Crown Theft", "cRoWn", true},
		{"no match", "Crown theft", "gold", false},
		{"empty substring matches", "anything", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsSubstring(tc.s, tc.substr); got != tc.want {
				t.Errorf("containsSubstring(%q, %q) = %v, want %v", tc.s, tc.substr, got, tc.want)
			}
		})
	}
}
