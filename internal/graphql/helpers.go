package graphql

import (
	"strings"

	"github.com/threatcl/spec"
)

// Helper functions for filtering

// matchesFilter checks if a threat model matches the given filter
func matchesFilter(tm *spec.Threatmodel, filter *ThreatModelFilter) bool {
	if filter == nil {
		return true
	}

	// Check author filter
	if filter.Author != nil && tm.Author != *filter.Author {
		return false
	}

	// Check attributes-based filters
	if tm.Attributes != nil {
		if filter.InternetFacing != nil && tm.Attributes.InternetFacing != *filter.InternetFacing {
			return false
		}

		if filter.NewInitiative != nil && tm.Attributes.NewInitiative != *filter.NewInitiative {
			return false
		}

		if filter.InitiativeSize != nil && tm.Attributes.InitiativeSize != *filter.InitiativeSize {
			return false
		}
	} else {
		// If model has no attributes but filter requires them, it doesn't match
		if filter.InternetFacing != nil || filter.NewInitiative != nil || filter.InitiativeSize != nil {
			return false
		}
	}

	return true
}

// matchesThreatFilter checks if a threat matches the given filter
func matchesThreatFilter(threat *spec.Threat, filter *ThreatFilter) bool {
	if filter == nil {
		return true
	}

	// Check name filter (case-insensitive substring match)
	if filter.Name != nil && *filter.Name != "" {
		// Support partial matching for more flexible queries
		if !containsSubstring(threat.Name, *filter.Name) {
			return false
		}
	}

	// Check impacts filter
	if len(filter.Impacts) > 0 {
		if !containsAny(threat.ImpactType, filter.Impacts) {
			return false
		}
	}

	// Check STRIDE filter
	if len(filter.Stride) > 0 {
		if !containsAny(threat.Stride, filter.Stride) {
			return false
		}
	}

	// Check hasImplementedControls filter
	if filter.HasImplementedControls != nil {
		hasImplemented := false
		for _, control := range threat.Controls {
			if control.Implemented {
				hasImplemented = true
				break
			}
		}
		if hasImplemented != *filter.HasImplementedControls {
			return false
		}
	}

	return true
}

// containsAny checks if slice a contains any element from slice b
func containsAny(a, b []string) bool {
	if len(a) == 0 {
		return false
	}
	for _, itemB := range b {
		for _, itemA := range a {
			if itemA == itemB {
				return true
			}
		}
	}
	return false
}

// containsSubstring checks if string s contains substring substr (case-insensitive)
func containsSubstring(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
