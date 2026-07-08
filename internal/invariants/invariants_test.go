package invariants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseRaw(tb testing.TB, src string) ([]*Invariant, error) {
	tb.Helper()
	return ParseHCLRaw([]byte(src), "test.hcl")
}

func mustParseRaw(tb testing.TB, src string) []*Invariant {
	tb.Helper()
	invs, err := parseRaw(tb, src)
	if err != nil {
		tb.Fatalf("unexpected parse error: %s", err)
	}
	return invs
}

func TestParseValidFile(t *testing.T) {
	invs := mustParseRaw(t, `
invariant "threats_have_controls" {
  description = "Every threat must have at least one implemented control"
  target      = "threat"
  condition   = anytrue([for c in item.controls : c.implemented])
}

invariant "audit_logging" {
  description = "All features must emit audit logs"
  severity    = "warning"
  target      = "threatmodel"
  when        = item.attributes.internet_facing
  condition   = anytrue([for c in tm.controls : can(regex("(?i)audit", c.name))])
  error_message = "threatmodel '${item.name}' has no audit logging control"

  exemption {
    model         = threatmodel["Legacy API"]
    justification = "Grandfathered until Q3; tracked in SEC-123"
  }
}
`)

	if len(invs) != 2 {
		t.Fatalf("expected 2 invariants, got %d", len(invs))
	}

	first := invs[0]
	if first.Name != "threats_have_controls" {
		t.Errorf("unexpected name: %s", first.Name)
	}
	if first.Severity != SeverityError {
		t.Errorf("expected default severity error, got %s", first.Severity)
	}
	if first.Target != "threat" {
		t.Errorf("unexpected target: %s", first.Target)
	}
	if first.when != nil {
		t.Errorf("expected absent when to be nil")
	}
	if first.errorMessage != nil {
		t.Errorf("expected absent error_message to be nil")
	}

	second := invs[1]
	if second.Severity != SeverityWarning {
		t.Errorf("expected severity warning, got %s", second.Severity)
	}
	if second.when == nil {
		t.Errorf("expected when to be set")
	}
	if second.errorMessage == nil {
		t.Errorf("expected error_message to be set")
	}
	if len(second.Exemptions) != 1 {
		t.Fatalf("expected 1 exemption, got %d", len(second.Exemptions))
	}
	if second.Exemptions[0].model == nil {
		t.Errorf("expected exemption model expression to be set")
	}
	if !strings.Contains(second.Exemptions[0].Justification, "SEC-123") {
		t.Errorf("unexpected justification: %s", second.Exemptions[0].Justification)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		exp  string
	}{
		{
			"invalid_severity",
			`invariant "x" {
  severity  = "fatal"
  target    = "threat"
  condition = true
}`,
			`invalid severity "fatal"`,
		},
		{
			"invalid_target",
			`invariant "x" {
  target    = "endpoint"
  condition = true
}`,
			`invalid target "endpoint"`,
		},
		{
			"unknown_variable",
			`invariant "x" {
  target    = "threat"
  condition = model.name != ""
}`,
			`condition references unknown variable "model"`,
		},
		{
			"dfd_variable_outside_dfd_target",
			`invariant "x" {
  target    = "threat"
  condition = dfd.name != ""
}`,
			`condition references unknown variable "dfd"`,
		},
		{
			"missing_condition",
			`invariant "x" {
  target = "threat"
}`,
			`missing required attribute "condition"`,
		},
		{
			"missing_target",
			`invariant "x" {
  condition = true
}`,
			"Missing required argument",
		},
		{
			"duplicate_names",
			`invariant "x" {
  target    = "threat"
  condition = true
}
invariant "x" {
  target    = "control"
  condition = true
}`,
			"defined more than once",
		},
		{
			"exemption_without_justification",
			`invariant "x" {
  target    = "threat"
  condition = true

  exemption {
    model         = threatmodel["Some Model"]
    justification = "  "
  }
}`,
			"requires a justification",
		},
		{
			"exemption_without_model",
			`invariant "x" {
  target    = "threat"
  condition = true

  exemption {
    justification = "No model reference"
  }
}`,
			`missing required attribute "model"`,
		},
		{
			"exemption_with_unknown_variable",
			`invariant "x" {
  target    = "threat"
  condition = true

  exemption {
    model         = tm["Some Model"]
    justification = "Wrong root"
  }
}`,
			`exemption model references unknown variable "tm"`,
		},
		{
			"no_invariants",
			`# just a comment`,
			"no invariant blocks found",
		},
		{
			"unknown_block",
			`policy "x" {
  target = "threat"
}`,
			"Blocks of type \"policy\" are not expected here",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRaw(t, tc.src)
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.exp)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
		})
	}
}

func TestParseDfdVariableAllowedForDfdTargets(t *testing.T) {
	invs := mustParseRaw(t, `
invariant "x" {
  target    = "process"
  condition = item.trust_zone != "" && dfd.name != "" && tm.name != ""
}
`)
	if len(invs) != 1 {
		t.Fatalf("expected 1 invariant, got %d", len(invs))
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invariants.hcl")
	err := os.WriteFile(path, []byte(`
invariant "x" {
  target    = "threat"
  condition = true
}
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	invs, err := ParseFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(invs) != 1 {
		t.Fatalf("expected 1 invariant, got %d", len(invs))
	}

	if _, err := ParseFile(filepath.Join(dir, "missing.hcl")); err == nil {
		t.Errorf("expected an error for a missing file")
	}
}
