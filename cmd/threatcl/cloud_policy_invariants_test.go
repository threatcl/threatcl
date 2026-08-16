package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testInvariantSource = `invariant "threats_have_controls" {
  description = "Every threat must have at least one control"
  severity    = "warning"
  target      = "threat"
  condition   = length(item.controls) > 0
}
`

const testTwoInvariantSource = testInvariantSource + `
invariant "no_public_unauth" {
  target    = "process"
  condition = item.name != ""
}
`

func TestParseSingleInvariant(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		expectErr   string
		expectName  string
		expectSever string
	}{
		{
			name:        "single block",
			source:      testInvariantSource,
			expectName:  "threats_have_controls",
			expectSever: "warning",
		},
		{
			name:      "two blocks",
			source:    testTwoInvariantSource,
			expectErr: "sync-invariants",
		},
		{
			name:      "no blocks",
			source:    "# nothing here\n",
			expectErr: "no invariant blocks found",
		},
		{
			name:      "invalid hcl",
			source:    "invariant {\n",
			expectErr: "invariants.hcl",
		},
		{
			name: "missing condition",
			source: `invariant "broken" {
  target = "threat"
}
`,
			expectErr: "condition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv, err := parseSingleInvariant([]byte(tt.source), "invariants.hcl")

			if tt.expectErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got none", tt.expectErr)
				}
				if !strings.Contains(err.Error(), tt.expectErr) {
					t.Errorf("expected error containing %q, got %q", tt.expectErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if inv.Name != tt.expectName {
				t.Errorf("expected name %q, got %q", tt.expectName, inv.Name)
			}
			if string(inv.Severity) != tt.expectSever {
				t.Errorf("expected severity %q, got %q", tt.expectSever, inv.Severity)
			}
		})
	}
}

func TestInvariantPolicyIdentity(t *testing.T) {
	inv, err := parseSingleInvariant([]byte(testInvariantSource), "invariants.hcl")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	t.Run("defaults to the block", func(t *testing.T) {
		name, severity, err := invariantPolicyIdentity(inv, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "threats_have_controls" {
			t.Errorf("expected name from the block, got %q", name)
		}
		if severity != "warning" {
			t.Errorf("expected severity from the block, got %q", severity)
		}
	})

	t.Run("flags override the name only", func(t *testing.T) {
		name, severity, err := invariantPolicyIdentity(inv, "Threats Have Controls", "warning")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "Threats Have Controls" {
			t.Errorf("expected the supplied name, got %q", name)
		}
		if severity != "warning" {
			t.Errorf("expected severity warning, got %q", severity)
		}
	})

	t.Run("contradicting severity is an error", func(t *testing.T) {
		_, _, err := invariantPolicyIdentity(inv, "", "error")
		if err == nil {
			t.Fatal("expected an error for a severity that contradicts the block")
		}
		if !strings.Contains(err.Error(), "contradicts invariant") {
			t.Errorf("expected a contradiction error, got %q", err)
		}
	})
}

func TestPolicySeverities(t *testing.T) {
	if validPolicySeverity(policyEngineInvariant, "info") {
		t.Error("info should not be a valid invariant severity")
	}
	if !validPolicySeverity(policyEngineRego, "info") {
		t.Error("info should be a valid rego severity")
	}
	if !validPolicySeverity(policyEngineInvariant, "warning") {
		t.Error("warning should be a valid invariant severity")
	}
	// An unspecified engine (update, where the row already has one) keeps the
	// full set rather than guessing.
	if !validPolicySeverity("", "info") {
		t.Error("info should be accepted when no engine is specified")
	}
}

func TestValidPolicyEngine(t *testing.T) {
	for _, engine := range []string{policyEngineRego, policyEngineInvariant} {
		if !validPolicyEngine(engine) {
			t.Errorf("expected %q to be a valid engine", engine)
		}
	}
	for _, engine := range []string{"", "opa", "Invariant"} {
		if validPolicyEngine(engine) {
			t.Errorf("expected %q to be an invalid engine", engine)
		}
	}
}

func TestPolicyEngineAndSourceFallbacks(t *testing.T) {
	// A deployment that predates the engine/source fields answers with
	// rego_source only, and the CLI should still read it as a rego policy.
	legacy := policy{RegoSource: "package threatcl.legacy\n"}
	if legacy.engineName() != policyEngineRego {
		t.Errorf("expected an absent engine to read as rego, got %q", legacy.engineName())
	}
	if legacy.sourceText() != "package threatcl.legacy\n" {
		t.Errorf("expected the rego_source fallback, got %q", legacy.sourceText())
	}

	inv := policy{Engine: policyEngineInvariant, Source: testInvariantSource}
	if inv.engineName() != policyEngineInvariant {
		t.Errorf("expected engine invariant, got %q", inv.engineName())
	}
	if inv.sourceText() != testInvariantSource {
		t.Error("expected source to be used when present")
	}
}

func TestInvariantDetails(t *testing.T) {
	t.Run("decodes invariant details", func(t *testing.T) {
		result := policyEvaluationResult{Details: map[string]any{
			"engine":        "invariant",
			"target":        "process",
			"items_checked": float64(14),
			"violations": []any{map[string]any{
				"item_kind": "process",
				"item_name": "Public API",
				"segment":   "models/api.hcl",
				"message":   "public processes must require auth",
			}},
		}}

		details := result.invariantDetails()
		if details == nil {
			t.Fatal("expected invariant details, got nil")
		}
		if details.Target != "process" {
			t.Errorf("expected target process, got %q", details.Target)
		}
		if details.ItemsChecked != 14 {
			t.Errorf("expected 14 items checked, got %d", details.ItemsChecked)
		}
		if len(details.Violations) != 1 || details.Violations[0].ItemName != "Public API" {
			t.Errorf("unexpected violations: %+v", details.Violations)
		}
	})

	t.Run("ignores other engines", func(t *testing.T) {
		rego := policyEvaluationResult{Details: map[string]any{"threats_without_controls": []any{}}}
		if rego.invariantDetails() != nil {
			t.Error("expected nil details for a rego result")
		}

		none := policyEvaluationResult{}
		if none.invariantDetails() != nil {
			t.Error("expected nil details when there are none")
		}
	})
}

func TestRenderInvariantDetails(t *testing.T) {
	t.Run("violations and active exemptions", func(t *testing.T) {
		var buf bytes.Buffer
		renderInvariantDetails(&buf, &invariantResultDetails{
			Engine: policyEngineInvariant,
			Target: "process",
			Violations: []invariantViolation{{
				ItemKind: "process",
				ItemName: "Public API",
				Segment:  "models/api.hcl",
				Message:  "public processes must require auth",
			}},
			Exemptions: []invariantExemption{
				{
					Model:         "Legacy",
					Segment:       "models/legacy.hcl",
					Justification: "grandfathered until Q3",
				},
				{
					Model:         "threatmodel[\"Other\"]",
					Justification: "not in this run",
					Inactive:      true,
					Reason:        "resolved to null",
				},
			},
		})

		out := buf.String()
		if !strings.Contains(out, "process 'Public API' (models/api.hcl): public processes must require auth") {
			t.Errorf("expected the violation to be rendered, got %q", out)
		}
		if !strings.Contains(out, "~ exempt: Legacy (models/legacy.hcl): grandfathered until Q3") {
			t.Errorf("expected the active exemption to be rendered, got %q", out)
		}
		if strings.Contains(out, "not in this run") {
			t.Errorf("inactive exemptions should be left to -json, got %q", out)
		}
	})

	t.Run("eval error", func(t *testing.T) {
		var buf bytes.Buffer
		renderInvariantDetails(&buf, &invariantResultDetails{
			Engine:    policyEngineInvariant,
			EvalError: "condition: unknown variable \"itm\"",
		})

		if !strings.Contains(buf.String(), "! rule error: condition: unknown variable") {
			t.Errorf("expected the rule error to be rendered, got %q", buf.String())
		}
	})

	t.Run("caps a long violation list", func(t *testing.T) {
		violations := make([]invariantViolation, 0, maxRenderedViolations+3)
		for i := 0; i < maxRenderedViolations+3; i++ {
			violations = append(violations, invariantViolation{ItemKind: "threat", ItemName: "t", Message: "nope"})
		}

		var buf bytes.Buffer
		renderInvariantDetails(&buf, &invariantResultDetails{Engine: policyEngineInvariant, Violations: violations})

		out := buf.String()
		if strings.Count(out, "- threat") != maxRenderedViolations {
			t.Errorf("expected %d rendered violations, got %q", maxRenderedViolations, out)
		}
		if !strings.Contains(out, "... and 3 more") {
			t.Errorf("expected the remainder to be counted rather than dropped silently, got %q", out)
		}
	})

	t.Run("nil is a no-op", func(t *testing.T) {
		var buf bytes.Buffer
		renderInvariantDetails(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected no output, got %q", buf.String())
		}
	})
}

func TestPolicyRequestSetSource(t *testing.T) {
	t.Run("rego sends both source fields", func(t *testing.T) {
		create := policyCreateRequest{Name: "Controls Required", Severity: "error"}
		create.setSource(policyEngineRego, "package threatcl.test\n")

		body := marshalToMap(t, create)
		if body["engine"] != nil {
			t.Errorf("expected no engine field for rego, got %v", body["engine"])
		}
		if body["source"] != "package threatcl.test\n" {
			t.Errorf("expected source to be set, got %v", body["source"])
		}
		if body["rego_source"] != "package threatcl.test\n" {
			t.Errorf("expected the deprecated alias alongside source, got %v", body["rego_source"])
		}
	})

	t.Run("invariant sends engine and source only", func(t *testing.T) {
		create := policyCreateRequest{Name: "threats_have_controls", Severity: "warning"}
		create.setSource(policyEngineInvariant, testInvariantSource)

		body := marshalToMap(t, create)
		if body["engine"] != policyEngineInvariant {
			t.Errorf("expected engine invariant, got %v", body["engine"])
		}
		if body["source"] != testInvariantSource {
			t.Errorf("expected source to hold the invariant block, got %v", body["source"])
		}
		if _, ok := body["rego_source"]; ok {
			t.Error("expected no rego_source on an invariant policy - an older client would compile it as Rego")
		}
	})

	t.Run("update mirrors create", func(t *testing.T) {
		update := policyUpdateRequest{}
		update.setSource(policyEngineInvariant, testInvariantSource)

		body := marshalToMap(t, update)
		if body["engine"] != policyEngineInvariant {
			t.Errorf("expected engine invariant, got %v", body["engine"])
		}
		if _, ok := body["rego_source"]; ok {
			t.Error("expected no rego_source on an invariant update")
		}

		unspecified := policyUpdateRequest{}
		unspecified.setSource("", "package threatcl.test\n")

		body = marshalToMap(t, unspecified)
		if _, ok := body["engine"]; ok {
			t.Error("expected no engine field when the flag was not given - the server resolves it from the row")
		}
		if body["rego_source"] != "package threatcl.test\n" {
			t.Errorf("expected the deprecated alias for compatibility, got %v", body["rego_source"])
		}
	})
}

func marshalToMap(t testing.TB, v any) map[string]any {
	t.Helper()

	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	return out
}
