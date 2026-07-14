package graphql

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/internal/cache"
)

// resolverFixtureHCL contains two threat models: one fully populated (with
// attributes, assets, threats, risk, and controls) and one minimal (no
// attributes block, no controls), so filters can distinguish between them.
const resolverFixtureHCL = `spec_version = "0.6.0"

threatmodel "Tower of London" {
  description = "A historic castle"
  author = "@alice"

  attributes {
    new_initiative = true
    internet_facing = true
    initiative_size = "Small"
  }

  additional_attribute "network_segment" {
    value = "dmz"
  }

  information_asset "crown jewels" {
    description = "including the imperial state crown"
    information_classification = "Confidential"
  }

  third_party_dependency "community watch" {
    description = "The community watch helps guard the premise"
    uptime_dependency = "degraded"
  }

  threat "Crown theft" {
    description = "Someone steals the crown"
    impacts = ["Confidentiality"]
    stride = ["Spoofing", "Tampering"]

    risk {
      likelihood = "high"
      impact     = "very_high"
      rationale  = "priceless and portable"
    }

    control "Lots of Guards" {
      implemented = true
      description = "Lots of guards patrol the area"
      risk_reduction = 80
    }
  }

  threat "Guard bribery" {
    description = "A guard is bribed"
    impacts = ["Integrity"]

    control "Vetting" {
      implemented = false
      description = "Background checks"
      risk_reduction = 40
    }
  }
}

threatmodel "Fort Knox" {
  description = "A fort"
  author = "@bob"

  information_asset "Gold" {
    description = "Lots of gold"
    information_classification = "Public"
  }

  threat "Gold theft" {
    description = "Someone steals the gold"
    impacts = ["Availability"]
  }
}
`

// newTestResolver writes the given HCL into a temp dir, loads it into a fresh
// cache, and returns a Resolver backed by that cache. An empty hcl string
// yields a resolver over an empty cache.
func newTestResolver(t *testing.T, hcl string) *Resolver {
	t.Helper()

	dir := t.TempDir()
	if hcl != "" {
		if err := os.WriteFile(filepath.Join(dir, "models.hcl"), []byte(hcl), 0o644); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}
	}

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("failed to load spec config: %v", err)
	}

	c := cache.NewThreatModelCache(cfg, dir)
	if err := c.LoadAll(); err != nil {
		t.Fatalf("failed to load fixture into cache: %v", err)
	}

	return &Resolver{Cache: c}
}

func modelNames(models []*ThreatModel) map[string]bool {
	names := map[string]bool{}
	for _, m := range models {
		names[m.Name] = true
	}
	return names
}

func threatNames(threats []*spec.Threat) map[string]bool {
	names := map[string]bool{}
	for _, th := range threats {
		names[th.Name] = true
	}
	return names
}

func TestQueryResolver_ThreatModels(t *testing.T) {
	r := newTestResolver(t, resolverFixtureHCL)
	q := r.Query()
	ctx := context.Background()

	tests := []struct {
		name   string
		filter *ThreatModelFilter
		want   []string
	}{
		{"no filter returns all", nil, []string{"Tower of London", "Fort Knox"}},
		{"author filter", &ThreatModelFilter{Author: strPtr("@bob")}, []string{"Fort Knox"}},
		{"internet facing filter excludes model without attributes", &ThreatModelFilter{InternetFacing: boolPtr(true)}, []string{"Tower of London"}},
		{"new initiative filter", &ThreatModelFilter{NewInitiative: boolPtr(true)}, []string{"Tower of London"}},
		{"initiative size filter", &ThreatModelFilter{InitiativeSize: strPtr("Small")}, []string{"Tower of London"}},
		{"non-matching author returns empty", &ThreatModelFilter{Author: strPtr("@mallory")}, []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := q.ThreatModels(ctx, tc.filter)
			if err != nil {
				t.Fatalf("ThreatModels() error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ThreatModels() returned %d models, want %d", len(got), len(tc.want))
			}
			names := modelNames(got)
			for _, want := range tc.want {
				if !names[want] {
					t.Errorf("ThreatModels() missing model %q, got %v", want, names)
				}
			}
		})
	}

	t.Run("source file is populated", func(t *testing.T) {
		got, err := q.ThreatModels(ctx, nil)
		if err != nil {
			t.Fatalf("ThreatModels() error: %v", err)
		}
		for _, m := range got {
			if filepath.Base(m.SourceFile) != "models.hcl" {
				t.Errorf("model %q SourceFile = %q, want basename models.hcl", m.Name, m.SourceFile)
			}
		}
	})
}

func TestQueryResolver_ThreatModel(t *testing.T) {
	r := newTestResolver(t, resolverFixtureHCL)
	q := r.Query()
	ctx := context.Background()

	t.Run("found", func(t *testing.T) {
		got, err := q.ThreatModel(ctx, "Tower of London")
		if err != nil {
			t.Fatalf("ThreatModel() error: %v", err)
		}
		if got == nil {
			t.Fatal("ThreatModel() returned nil for existing model")
		}
		if got.Name != "Tower of London" {
			t.Errorf("Name = %q, want 'Tower of London'", got.Name)
		}
		if got.Author != "@alice" {
			t.Errorf("Author = %q, want '@alice'", got.Author)
		}
		if got.Description == nil || *got.Description != "A historic castle" {
			t.Errorf("Description = %v, want 'A historic castle'", got.Description)
		}
		if filepath.Base(got.SourceFile) != "models.hcl" {
			t.Errorf("SourceFile = %q, want basename models.hcl", got.SourceFile)
		}
		if len(got.Threats) != 2 {
			t.Errorf("expected 2 threats, got %d", len(got.Threats))
		}
		if len(got.InformationAssets) != 1 {
			t.Errorf("expected 1 information asset, got %d", len(got.InformationAssets))
		}
		if len(got.AdditionalAttributes) != 1 {
			t.Errorf("expected 1 additional attribute, got %d", len(got.AdditionalAttributes))
		}
		if len(got.ThirdPartyDependencies) != 1 {
			t.Errorf("expected 1 third party dependency, got %d", len(got.ThirdPartyDependencies))
		}
	})

	t.Run("not found returns nil without error", func(t *testing.T) {
		got, err := q.ThreatModel(ctx, "No Such Model")
		if err != nil {
			t.Fatalf("ThreatModel() error: %v", err)
		}
		if got != nil {
			t.Errorf("ThreatModel() = %+v, want nil for unknown name", got)
		}
	})
}

func TestQueryResolver_Threats(t *testing.T) {
	r := newTestResolver(t, resolverFixtureHCL)
	q := r.Query()
	ctx := context.Background()

	tests := []struct {
		name   string
		filter *ThreatFilter
		want   []string
	}{
		{"no filter returns all", nil, []string{"Crown theft", "Guard bribery", "Gold theft"}},
		{"name substring filter", &ThreatFilter{Name: strPtr("theft")}, []string{"Crown theft", "Gold theft"}},
		{"impacts filter", &ThreatFilter{Impacts: []string{"Integrity"}}, []string{"Guard bribery"}},
		{"stride filter", &ThreatFilter{Stride: []string{"Spoofing"}}, []string{"Crown theft"}},
		{"has implemented controls", &ThreatFilter{HasImplementedControls: boolPtr(true)}, []string{"Crown theft"}},
		{"no implemented controls", &ThreatFilter{HasImplementedControls: boolPtr(false)}, []string{"Guard bribery", "Gold theft"}},
		{"severity filter", &ThreatFilter{Severity: []string{"critical"}}, []string{"Crown theft"}},
		{"no matches", &ThreatFilter{Name: strPtr("dragon attack")}, []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := q.Threats(ctx, tc.filter)
			if err != nil {
				t.Fatalf("Threats() error: %v", err)
			}
			if got == nil {
				t.Fatal("Threats() returned nil slice, want empty slice")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("Threats() returned %d threats, want %d", len(got), len(tc.want))
			}
			names := threatNames(got)
			for _, want := range tc.want {
				if !names[want] {
					t.Errorf("Threats() missing threat %q, got %v", want, names)
				}
			}
		})
	}
}

func TestQueryResolver_InformationAssets(t *testing.T) {
	r := newTestResolver(t, resolverFixtureHCL)
	q := r.Query()
	ctx := context.Background()

	tests := []struct {
		name           string
		classification *string
		want           []string
	}{
		{"no classification returns all", nil, []string{"crown jewels", "Gold"}},
		{"confidential only", strPtr("Confidential"), []string{"crown jewels"}},
		{"public only", strPtr("Public"), []string{"Gold"}},
		{"no matches", strPtr("Restricted"), []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := q.InformationAssets(ctx, tc.classification)
			if err != nil {
				t.Fatalf("InformationAssets() error: %v", err)
			}
			if got == nil {
				t.Fatal("InformationAssets() returned nil slice, want empty slice")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("InformationAssets() returned %d assets, want %d", len(got), len(tc.want))
			}
			names := map[string]bool{}
			for _, a := range got {
				names[a.Name] = true
			}
			for _, want := range tc.want {
				if !names[want] {
					t.Errorf("InformationAssets() missing asset %q, got %v", want, names)
				}
			}
		})
	}
}

func TestQueryResolver_Stats(t *testing.T) {
	r := newTestResolver(t, resolverFixtureHCL)
	q := r.Query()

	stats, err := q.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats() error: %v", err)
	}
	if stats == nil {
		t.Fatal("Stats() returned nil")
	}

	if stats.TotalThreatModels != 2 {
		t.Errorf("TotalThreatModels = %d, want 2", stats.TotalThreatModels)
	}
	if stats.TotalThreats != 3 {
		t.Errorf("TotalThreats = %d, want 3", stats.TotalThreats)
	}
	if stats.TotalInformationAssets != 2 {
		t.Errorf("TotalInformationAssets = %d, want 2", stats.TotalInformationAssets)
	}
	if stats.TotalControls != 2 {
		t.Errorf("TotalControls = %d, want 2", stats.TotalControls)
	}
	if stats.ImplementedControls != 1 {
		t.Errorf("ImplementedControls = %d, want 1", stats.ImplementedControls)
	}
	if stats.ThreatsWithRisk != 1 {
		t.Errorf("ThreatsWithRisk = %d, want 1", stats.ThreatsWithRisk)
	}

	// Two controls with risk_reduction 80 and 40 average to 60.
	if stats.AverageRiskReduction == nil {
		t.Fatal("AverageRiskReduction is nil, want 60")
	}
	if *stats.AverageRiskReduction != 60 {
		t.Errorf("AverageRiskReduction = %v, want 60", *stats.AverageRiskReduction)
	}

	// One entry per severity band, in canonical order, with only the
	// critical band populated (high x very_high resolves to critical).
	if len(stats.SeverityCounts) != len(spec.SeverityLevels) {
		t.Fatalf("SeverityCounts has %d entries, want %d", len(stats.SeverityCounts), len(spec.SeverityLevels))
	}
	for i, band := range spec.SeverityLevels {
		sc := stats.SeverityCounts[i]
		if sc.Severity != band {
			t.Errorf("SeverityCounts[%d].Severity = %q, want %q", i, sc.Severity, band)
		}
		wantCount := 0
		if band == spec.SeverityCritical {
			wantCount = 1
		}
		if sc.Count != wantCount {
			t.Errorf("SeverityCounts[%d] (%s) = %d, want %d", i, band, sc.Count, wantCount)
		}
	}
}

func TestQueryResolver_Stats_EmptyCache(t *testing.T) {
	r := newTestResolver(t, "")
	q := r.Query()

	stats, err := q.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats() error: %v", err)
	}

	if stats.TotalThreatModels != 0 || stats.TotalThreats != 0 || stats.TotalControls != 0 {
		t.Errorf("expected zeroed totals, got %+v", stats)
	}
	if stats.AverageRiskReduction != nil {
		t.Errorf("AverageRiskReduction = %v, want nil when there are no controls", *stats.AverageRiskReduction)
	}
	if len(stats.SeverityCounts) != len(spec.SeverityLevels) {
		t.Fatalf("SeverityCounts has %d entries, want %d even for an empty cache", len(stats.SeverityCounts), len(spec.SeverityLevels))
	}
	for _, sc := range stats.SeverityCounts {
		if sc.Count != 0 {
			t.Errorf("SeverityCounts[%s] = %d, want 0", sc.Severity, sc.Count)
		}
	}
}

func TestQueryResolver_EmptyCache(t *testing.T) {
	r := newTestResolver(t, "")
	q := r.Query()
	ctx := context.Background()

	models, err := q.ThreatModels(ctx, nil)
	if err != nil {
		t.Fatalf("ThreatModels() error: %v", err)
	}
	if len(models) != 0 {
		t.Errorf("ThreatModels() = %d models, want 0", len(models))
	}

	threats, err := q.Threats(ctx, nil)
	if err != nil {
		t.Fatalf("Threats() error: %v", err)
	}
	if len(threats) != 0 {
		t.Errorf("Threats() = %d threats, want 0", len(threats))
	}

	assets, err := q.InformationAssets(ctx, nil)
	if err != nil {
		t.Fatalf("InformationAssets() error: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("InformationAssets() = %d assets, want 0", len(assets))
	}
}

func TestThreatResolver_ThreatModel(t *testing.T) {
	r := newTestResolver(t, resolverFixtureHCL)
	tr := r.Threat()
	ctx := context.Background()

	tower, err := r.Cache.Get("Tower of London")
	if err != nil {
		t.Fatalf("failed to get fixture model: %v", err)
	}

	t.Run("threat resolves to its parent model", func(t *testing.T) {
		got, err := tr.ThreatModel(ctx, tower.Threats[0])
		if err != nil {
			t.Fatalf("ThreatModel() error: %v", err)
		}
		if got == nil {
			t.Fatal("ThreatModel() returned nil for a cached threat")
		}
		if got.Name != "Tower of London" {
			t.Errorf("Name = %q, want 'Tower of London'", got.Name)
		}
		if filepath.Base(got.SourceFile) != "models.hcl" {
			t.Errorf("SourceFile = %q, want basename models.hcl", got.SourceFile)
		}
	})

	t.Run("unknown threat returns nil", func(t *testing.T) {
		got, err := tr.ThreatModel(ctx, &spec.Threat{Name: "not in any model"})
		if err != nil {
			t.Fatalf("ThreatModel() error: %v", err)
		}
		if got != nil {
			t.Errorf("ThreatModel() = %+v, want nil for unknown threat", got)
		}
	})
}

func TestThreatResolver_Impacts(t *testing.T) {
	tr := (&Resolver{}).Threat()
	ctx := context.Background()

	t.Run("passes through impacts", func(t *testing.T) {
		got, err := tr.Impacts(ctx, &spec.Threat{ImpactType: []string{"Confidentiality", "Integrity"}})
		if err != nil {
			t.Fatalf("Impacts() error: %v", err)
		}
		if len(got) != 2 || got[0] != "Confidentiality" || got[1] != "Integrity" {
			t.Errorf("Impacts() = %v, want [Confidentiality Integrity]", got)
		}
	})

	t.Run("nil impacts yields empty slice", func(t *testing.T) {
		got, err := tr.Impacts(ctx, &spec.Threat{})
		if err != nil {
			t.Fatalf("Impacts() error: %v", err)
		}
		if got == nil {
			t.Fatal("Impacts() returned nil, want empty slice")
		}
		if len(got) != 0 {
			t.Errorf("Impacts() = %v, want empty", got)
		}
	})
}

func TestThreatResolver_Risk(t *testing.T) {
	tr := (&Resolver{}).Threat()
	ctx := context.Background()

	t.Run("threat with risk", func(t *testing.T) {
		threat := &spec.Threat{
			Name: "Crown theft",
			Risk: &spec.Risk{
				Likelihood: "high",
				Impact:     "very_high",
				Rationale:  "priceless and portable",
			},
		}
		got, err := tr.Risk(ctx, threat)
		if err != nil {
			t.Fatalf("Risk() error: %v", err)
		}
		if got == nil {
			t.Fatal("Risk() returned nil for threat with a risk block")
		}
		if got.Likelihood != "high" || got.Impact != "very_high" {
			t.Errorf("Risk() = %s/%s, want high/very_high", got.Likelihood, got.Impact)
		}
		if got.Severity != spec.SeverityCritical {
			t.Errorf("Severity = %q, want %q", got.Severity, spec.SeverityCritical)
		}
	})

	t.Run("threat without risk", func(t *testing.T) {
		got, err := tr.Risk(ctx, &spec.Threat{Name: "no risk"})
		if err != nil {
			t.Fatalf("Risk() error: %v", err)
		}
		if got != nil {
			t.Errorf("Risk() = %+v, want nil for threat without a risk block", got)
		}
	})
}

func TestInformationAssetResolver_ThreatModel(t *testing.T) {
	r := newTestResolver(t, resolverFixtureHCL)
	ia := r.InformationAsset()
	ctx := context.Background()

	tower, err := r.Cache.Get("Tower of London")
	if err != nil {
		t.Fatalf("failed to get fixture model: %v", err)
	}

	t.Run("asset resolves to its parent model", func(t *testing.T) {
		got, err := ia.ThreatModel(ctx, tower.InformationAssets[0])
		if err != nil {
			t.Fatalf("ThreatModel() error: %v", err)
		}
		if got == nil {
			t.Fatal("ThreatModel() returned nil for a cached asset")
		}
		if got.Name != "Tower of London" {
			t.Errorf("Name = %q, want 'Tower of London'", got.Name)
		}
	})

	t.Run("unknown asset pointer returns nil", func(t *testing.T) {
		// Asset lookup is by pointer identity, so an identical copy that
		// is not the cached instance does not resolve.
		copyOfAsset := *tower.InformationAssets[0]
		got, err := ia.ThreatModel(ctx, &copyOfAsset)
		if err != nil {
			t.Fatalf("ThreatModel() error: %v", err)
		}
		if got != nil {
			t.Errorf("ThreatModel() = %+v, want nil for non-cached asset pointer", got)
		}
	})
}

func TestAdditionalAttributeResolver_Key(t *testing.T) {
	aa := (&Resolver{}).AdditionalAttribute()

	got, err := aa.Key(context.Background(), &spec.AdditionalAttribute{Name: "network_segment", Value: "dmz"})
	if err != nil {
		t.Fatalf("Key() error: %v", err)
	}
	if got != "network_segment" {
		t.Errorf("Key() = %q, want 'network_segment'", got)
	}
}

func TestThirdPartyDependencyResolver_UptimeDependency(t *testing.T) {
	tpd := (&Resolver{}).ThirdPartyDependency()

	got, err := tpd.UptimeDependency(context.Background(), &spec.ThirdPartyDependency{
		Name:             "community watch",
		UptimeDependency: spec.DegradedUptime,
	})
	if err != nil {
		t.Fatalf("UptimeDependency() error: %v", err)
	}
	if got != "degraded" {
		t.Errorf("UptimeDependency() = %q, want 'degraded'", got)
	}
}

func TestDataFlowDiagramResolver(t *testing.T) {
	dfdr := (&Resolver{}).DataFlowDiagram()
	ctx := context.Background()

	dfd := &spec.DataFlowDiagram{
		Name: "dfd1",
		Processes: []*spec.DfdProcess{
			{Name: "update crown", TrustZone: "vault"},
		},
		DataStores: []*spec.DfdData{
			{Name: "crown db", TrustZone: "vault", IaLink: "crown jewels"},
		},
		ExternalElements: []*spec.DfdExternal{
			{Name: "tourist"},
		},
		Flows: []*spec.DfdFlow{
			{Name: "https", From: "tourist", To: "update crown"},
		},
		TrustZones: []*spec.DfdTrustZone{
			{Name: "vault"},
		},
	}

	t.Run("processes", func(t *testing.T) {
		got, err := dfdr.Processes(ctx, dfd)
		if err != nil {
			t.Fatalf("Processes() error: %v", err)
		}
		if len(got) != 1 || got[0].Name != "update crown" {
			t.Fatalf("Processes() = %+v, want one process 'update crown'", got)
		}
		if got[0].TrustZone == nil || *got[0].TrustZone != "vault" {
			t.Errorf("TrustZone = %v, want 'vault'", got[0].TrustZone)
		}
	})

	t.Run("data stores", func(t *testing.T) {
		got, err := dfdr.DataStores(ctx, dfd)
		if err != nil {
			t.Fatalf("DataStores() error: %v", err)
		}
		if len(got) != 1 || got[0].Name != "crown db" {
			t.Fatalf("DataStores() = %+v, want one data store 'crown db'", got)
		}
		if got[0].InformationAsset == nil || *got[0].InformationAsset != "crown jewels" {
			t.Errorf("InformationAsset = %v, want 'crown jewels'", got[0].InformationAsset)
		}
	})

	t.Run("external elements", func(t *testing.T) {
		got, err := dfdr.ExternalElements(ctx, dfd)
		if err != nil {
			t.Fatalf("ExternalElements() error: %v", err)
		}
		if len(got) != 1 || got[0].Name != "tourist" {
			t.Fatalf("ExternalElements() = %+v, want one element 'tourist'", got)
		}
		if got[0].TrustZone != nil {
			t.Errorf("TrustZone = %v, want nil for empty trust zone", got[0].TrustZone)
		}
	})

	t.Run("flows", func(t *testing.T) {
		got, err := dfdr.Flows(ctx, dfd)
		if err != nil {
			t.Fatalf("Flows() error: %v", err)
		}
		if len(got) != 1 || got[0].Name != "https" {
			t.Fatalf("Flows() = %+v, want one flow 'https'", got)
		}
		if got[0].From != "tourist" || got[0].To != "update crown" {
			t.Errorf("Flow = %s -> %s, want tourist -> update crown", got[0].From, got[0].To)
		}
	})

	t.Run("trust zones", func(t *testing.T) {
		got, err := dfdr.TrustZones(ctx, dfd)
		if err != nil {
			t.Fatalf("TrustZones() error: %v", err)
		}
		if len(got) != 1 || got[0].Name != "vault" {
			t.Fatalf("TrustZones() = %+v, want one trust zone 'vault'", got)
		}
	})

	t.Run("empty diagram yields empty non-nil slices", func(t *testing.T) {
		empty := &spec.DataFlowDiagram{Name: "empty"}
		processes, _ := dfdr.Processes(ctx, empty)
		dataStores, _ := dfdr.DataStores(ctx, empty)
		elements, _ := dfdr.ExternalElements(ctx, empty)
		flows, _ := dfdr.Flows(ctx, empty)
		trustZones, _ := dfdr.TrustZones(ctx, empty)

		if processes == nil || dataStores == nil || elements == nil || flows == nil || trustZones == nil {
			t.Error("expected empty non-nil slices for an empty diagram")
		}
		if len(processes)+len(dataStores)+len(elements)+len(flows)+len(trustZones) != 0 {
			t.Error("expected all slices to be empty for an empty diagram")
		}
	})
}
