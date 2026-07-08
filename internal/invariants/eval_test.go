package invariants

import (
	"strings"
	"testing"

	"github.com/threatcl/spec"
)

// testModel builds a threat model exercising every collection invariants can
// target: threats with inline controls, DFDs with trust-zone-nested elements,
// additional attributes, and so on.
func testModel() *spec.Threatmodel {
	return &spec.Threatmodel{
		Name:   "Test Model",
		Author: "@tester",
		Attributes: &spec.Attribute{
			InternetFacing: true,
			InitiativeSize: "Small",
		},
		AdditionalAttributes: []*spec.AdditionalAttribute{
			{Name: "network_segment", Value: "dmz"},
		},
		InformationAssets: []*spec.InformationAsset{
			{Name: "creds", InformationClassification: "Confidential"},
			{Name: "logs"},
		},
		UseCases:   []*spec.UseCase{{Description: "A user logs in"}},
		Exclusions: []*spec.Exclusion{{Description: "Physical attacks"}},
		ThirdPartyDependencies: []*spec.ThirdPartyDependency{
			{Name: "identity provider", Saas: true, UptimeDependency: spec.HardUptime},
		},
		Threats: []*spec.Threat{
			{
				Name:        "Credential theft",
				Description: "Creds get stolen",
				Controls: []*spec.Control{
					{Name: "MFA", Implemented: true, Description: "Multi-factor auth"},
				},
				ExpandedControls: []*spec.Control{
					{Name: "Audit Logging", Implemented: false, Description: "Imported control"},
				},
			},
			{
				Name:        "Uncontrolled threat",
				Description: "Nothing mitigates this",
			},
		},
		DataFlowDiagrams: []*spec.DataFlowDiagram{
			{
				Name: "main",
				ExternalElements: []*spec.DfdExternal{
					{Name: "Browser"},
				},
				TrustZones: []*spec.DfdTrustZone{
					{
						Name:       "AWS",
						Processes:  []*spec.DfdProcess{{Name: "Web Server"}},
						DataStores: []*spec.DfdData{{Name: "DB", IaLink: "creds"}},
					},
				},
				Flows: []*spec.DfdFlow{
					{Name: "login", From: "Browser", To: "Web Server", Protocol: "https"},
					{Name: "query", From: "Web Server", To: "DB"},
				},
			},
		},
	}
}

func testModels() []*Model {
	return []*Model{{TM: testModel(), File: "test.hcl"}}
}

func evalRaw(tb testing.TB, src string, models []*Model) (*Report, error) {
	tb.Helper()
	invs := mustParseRaw(tb, src)
	return Evaluate(invs, models)
}

func mustEvalRaw(tb testing.TB, src string, models []*Model) *Report {
	tb.Helper()
	report, err := evalRaw(tb, src, models)
	if err != nil {
		tb.Fatalf("unexpected evaluate error: %s", err)
	}
	return report
}

func TestEvaluateViolations(t *testing.T) {
	cases := []struct {
		name       string
		src        string
		violations []string // expected ItemNames, in order
	}{
		{
			"threat_target",
			`invariant "threats_have_implemented_controls" {
  target    = "threat"
  condition = anytrue([for c in item.controls : c.implemented])
}`,
			[]string{"Uncontrolled threat"},
		},
		{
			"threatmodel_target_passes",
			`invariant "has_author" {
  target    = "threatmodel"
  condition = item.author != ""
}`,
			nil,
		},
		{
			"when_filter",
			`invariant "internet_facing_needs_dfd" {
  target    = "threatmodel"
  when      = item.attributes.internet_facing
  condition = length(item.data_flow_diagrams) > 0
}`,
			nil,
		},
		{
			"when_filter_skips",
			`invariant "never_evaluated" {
  target    = "threatmodel"
  when      = item.attributes.new_initiative
  condition = false
}`,
			nil,
		},
		{
			"control_target_includes_expanded",
			`invariant "controls_implemented" {
  target    = "control"
  condition = item.implemented
}`,
			[]string{"Audit Logging"},
		},
		{
			"information_asset_target",
			`invariant "assets_classified" {
  target    = "information_asset"
  condition = item.information_classification != ""
}`,
			[]string{"logs"},
		},
		{
			"usecase_indexed_name",
			`invariant "usecases_are_long" {
  target    = "usecase"
  condition = length(item.description) > 100
}`,
			[]string{"usecase #1"},
		},
		{
			"third_party_dependency_target",
			`invariant "no_hard_uptime_deps" {
  target    = "third_party_dependency"
  condition = item.uptime_dependency != "hard"
}`,
			[]string{"identity provider"},
		},
		{
			"process_trust_zone_backfilled",
			`invariant "processes_zoned" {
  target    = "process"
  condition = item.trust_zone == "AWS"
}`,
			nil,
		},
		{
			"external_element_missing_zone",
			`invariant "externals_zoned" {
  target    = "external_element"
  condition = item.trust_zone != ""
}`,
			[]string{"Browser"},
		},
		{
			"flow_target_with_dfd_var",
			`invariant "flows_encrypted" {
  target    = "flow"
  when      = dfd.name == "main"
  condition = lower(item.protocol) == "https"
}`,
			[]string{"query"},
		},
		{
			"data_store_information_asset",
			`invariant "stores_link_assets" {
  target    = "data_store"
  condition = item.information_asset != ""
}`,
			nil,
		},
		{
			"additional_attribute_lookup",
			`invariant "dmz_only" {
  target    = "threatmodel"
  condition = lookup(item.additional_attributes, "network_segment", "") == "dmz"
}`,
			nil,
		},
		{
			"risk_is_null_when_absent",
			`invariant "risk_null" {
  target    = "threat"
  condition = item.risk == null
}`,
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := mustEvalRaw(t, tc.src, testModels())

			if len(report.Violations) != len(tc.violations) {
				t.Fatalf("expected %d violations, got %d: %+v", len(tc.violations), len(report.Violations), report.Violations)
			}
			for i, exp := range tc.violations {
				if report.Violations[i].ItemName != exp {
					t.Errorf("violation %d: expected item %q, got %q", i, exp, report.Violations[i].ItemName)
				}
			}
		})
	}
}

func TestEvaluateSeverityCounts(t *testing.T) {
	report := mustEvalRaw(t, `
invariant "error_rule" {
  target    = "threat"
  condition = anytrue([for c in item.controls : c.implemented])
}

invariant "warning_rule" {
  severity  = "warning"
  target    = "threat"
  condition = length(item.controls) > 1
}
`, testModels())

	if report.ErrorCount() != 1 {
		t.Errorf("expected 1 error, got %d", report.ErrorCount())
	}
	if report.WarningCount() != 1 {
		t.Errorf("expected 1 warning, got %d", report.WarningCount())
	}
}

func TestEvaluateExemption(t *testing.T) {
	report := mustEvalRaw(t, `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel["Test Model"]
    justification = "Known exception; tracked in SEC-1"
  }
}
`, testModels())

	if len(report.Violations) != 0 {
		t.Errorf("expected no violations for an exempted model, got %d", len(report.Violations))
	}
	if len(report.Exemptions) != 1 {
		t.Fatalf("expected 1 exemption use, got %d", len(report.Exemptions))
	}
	if report.Exemptions[0].Justification != "Known exception; tracked in SEC-1" {
		t.Errorf("unexpected justification: %s", report.Exemptions[0].Justification)
	}
}

func TestEvaluateExemptionDanglingReference(t *testing.T) {
	// A reference to a model that isn't in the evaluated set is a hard error,
	// not a silently-dead waiver.
	_, err := evalRaw(t, `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel["Another Model"]
    justification = "Not in this run"
  }
}
`, testModels())

	if err == nil {
		t.Fatalf("expected an error for a dangling exemption reference, got none")
	}
	if !strings.Contains(err.Error(), "resolving exemption #1 model reference") {
		t.Errorf("expected a dangling-reference error, got: %s", err)
	}
	if !strings.Contains(err.Error(), `threat models in this run: "Test Model"`) {
		t.Errorf("expected the error to list the models in the run, got: %s", err)
	}
}

func TestEvaluateExemptionTryEscapeHatch(t *testing.T) {
	// try(..., null) makes an exemption inactive when its model isn't in the
	// evaluated set — for invariants files shared across separately-validated
	// fleets.
	report := mustEvalRaw(t, `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = try(threatmodel["Another Model"], null)
    justification = "Only applies in the fleet that has this model"
  }
}
`, testModels())

	if len(report.Violations) != 1 {
		t.Errorf("expected 1 violation when the exemption is inactive, got %d", len(report.Violations))
	}
	if len(report.Exemptions) != 0 {
		t.Errorf("expected no exemption uses, got %d", len(report.Exemptions))
	}
}

func TestEvaluateExemptionDotAddressing(t *testing.T) {
	// Derived identifier: "Test Model" is addressable as threatmodel.test_model.
	report := mustEvalRaw(t, `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel.test_model
    justification = "Addressed by derived identifier"
  }
}
`, testModels())

	if len(report.Exemptions) != 1 || len(report.Violations) != 0 {
		t.Errorf("expected derived-identifier dot address to exempt, got %d exemptions / %d violations",
			len(report.Exemptions), len(report.Violations))
	}
}

func nestedModels() []*Model {
	return []*Model{
		{TM: &spec.Threatmodel{Name: "Buildings", Id: "buildings", Author: "@x",
			Attributes: &spec.Attribute{InternetFacing: true}}, File: "a.hcl"},
		{TM: &spec.Threatmodel{Name: "Tower of London", Id: "buildings.tower", Author: "@x"}, File: "b.hcl"},
		{TM: &spec.Threatmodel{Name: "London Bridge", Id: "buildings.bridge", Author: "@x"}, File: "c.hcl"},
	}
}

func TestEvaluateExemptionNestedDotAddressing(t *testing.T) {
	// A child at a nested address, and the parent model addressable at the
	// namespace itself.
	report := mustEvalRaw(t, `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel.buildings.tower
    justification = "Nested child address"
  }

  exemption {
    model         = threatmodel.buildings
    justification = "The parent is a model too"
  }
}
`, nestedModels())

	if len(report.Exemptions) != 2 {
		t.Fatalf("expected 2 exemptions (parent and nested child), got %d", len(report.Exemptions))
	}
	if len(report.Violations) != 1 {
		t.Errorf("expected only the non-exempted sibling to violate, got %d violations", len(report.Violations))
	}
	if len(report.Violations) == 1 && report.Violations[0].Model.TM.Name != "London Bridge" {
		t.Errorf("expected 'London Bridge' to violate, got %q", report.Violations[0].Model.TM.Name)
	}
}

func TestEvaluateRegistryErrors(t *testing.T) {
	cases := []struct {
		name   string
		models []*Model
		exp    string
	}{
		{
			"identifier_collision",
			[]*Model{
				{TM: &spec.Threatmodel{Name: "My App", Author: "@x"}, File: "a.hcl"},
				{TM: &spec.Threatmodel{Name: "my app", Author: "@x"}, File: "b.hcl"},
			},
			"collides",
		},
		{
			"reserved_segment_across_files",
			[]*Model{
				{TM: &spec.Threatmodel{Name: "Buildings", Id: "buildings", Author: "@x"}, File: "a.hcl"},
				{TM: &spec.Threatmodel{Name: "Threats Building", Id: "buildings.threats", Author: "@x"}, File: "b.hcl"},
			},
			`segment "threats" shadows a field of the parent model`,
		},
		{
			"name_collides_with_namespace",
			[]*Model{
				{TM: &spec.Threatmodel{Name: "buildings", Id: "other", Author: "@x"}, File: "a.hcl"},
				{TM: &spec.Threatmodel{Name: "Tower of London", Id: "buildings.tower", Author: "@x"}, File: "b.hcl"},
			},
			`name "buildings" collides with another model's id or namespace`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evalRaw(t, `
invariant "anything" {
  target    = "threatmodel"
  condition = true
}
`, tc.models)
			if err == nil {
				t.Fatalf("expected a registry error containing %q, got none", tc.exp)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
		})
	}
}

func TestEvaluateExemptionNonModelReference(t *testing.T) {
	_, err := evalRaw(t, `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel["Test Model"].author
    justification = "A field, not a model"
  }
}
`, testModels())

	if err == nil {
		t.Fatalf("expected an error for a non-model reference, got none")
	}
	if !strings.Contains(err.Error(), "must reference a threat model") {
		t.Errorf("expected a non-model-reference error, got: %s", err)
	}
}

func TestEvaluateMessages(t *testing.T) {
	report := mustEvalRaw(t, `
invariant "with_message_expr" {
  target        = "threat"
  condition     = length(item.controls) > 0
  error_message = "threat '${item.name}' in '${tm.name}' has no controls"
}

invariant "with_description" {
  description = "threats need controls"
  target      = "threat"
  condition   = length(item.controls) > 0
}

invariant "bare" {
  target    = "threat"
  condition = length(item.controls) > 0
}
`, testModels())

	if len(report.Violations) != 3 {
		t.Fatalf("expected 3 violations, got %d", len(report.Violations))
	}
	if exp := "threat 'Uncontrolled threat' in 'Test Model' has no controls"; report.Violations[0].Message != exp {
		t.Errorf("expected interpolated message %q, got %q", exp, report.Violations[0].Message)
	}
	if exp := "threats need controls"; report.Violations[1].Message != exp {
		t.Errorf("expected description message %q, got %q", exp, report.Violations[1].Message)
	}
	if exp := "condition failed"; report.Violations[2].Message != exp {
		t.Errorf("expected fallback message %q, got %q", exp, report.Violations[2].Message)
	}
}

func TestEvaluateExpressionErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		exp  string
	}{
		{
			"unknown_attribute",
			`invariant "x" {
  target    = "threat"
  condition = item.nonexistent == ""
}`,
			"evaluating condition",
		},
		{
			"non_bool_condition",
			`invariant "x" {
  target    = "threat"
  condition = item.name
}`,
			"expression must produce a bool",
		},
		{
			"null_condition",
			`invariant "x" {
  target    = "threat"
  condition = tm.description == "" ? null : true
}`,
			"produced null",
		},
		{
			"bad_when",
			`invariant "x" {
  target    = "threat"
  when      = item.missing_field
  condition = true
}`,
			"evaluating when",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evalRaw(t, tc.src, testModels())
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.exp)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
		})
	}
}

func TestEvaluateEmptyModel(t *testing.T) {
	models := []*Model{{TM: &spec.Threatmodel{Name: "Empty", Author: "@x"}, File: "empty.hcl"}}

	report := mustEvalRaw(t, `
invariant "threats_have_controls" {
  target    = "threat"
  condition = length(item.controls) > 0
}

invariant "processes_zoned" {
  target    = "process"
  condition = item.trust_zone != ""
}
`, models)

	if len(report.Violations) != 0 {
		t.Errorf("expected no violations for empty collections, got %d", len(report.Violations))
	}
}
