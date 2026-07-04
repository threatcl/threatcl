package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/zenizh/go-capturer"
)

var update = flag.Bool("update", false, "update golden files")

// TestValidateInvariantsGolden snapshots the full stdout of
// `threatcl validate -invariants=...` against golden files in
// testdata/golden/. Regenerate with:
//
//	go test ./cmd/threatcl -run TestValidateInvariantsGolden -update
//
// The invariants themselves are inline (only *.golden files live under
// testdata/, so the directory-walking tests that treat every .hcl under
// testdata/ as a threat model are unaffected).
func TestValidateInvariantsGolden(t *testing.T) {
	cases := []struct {
		name       string
		invariants string
		files      []string
		code       int
	}{
		{
			// Every rule holds: just the exemption-free, violation-free summary.
			name: "clean_pass",
			invariants: `
invariant "models_have_authors" {
  target    = "threatmodel"
  condition = item.author != ""
}

invariant "assets_are_classified" {
  target    = "information_asset"
  condition = item.information_classification != ""
}`,
			files: []string{"./testdata/tm1.hcl"},
			code:  0,
		},
		{
			// Error and warning severities together, with all three message
			// forms: description, interpolated error_message, and the bare
			// fallback.
			name: "mixed_violations",
			invariants: `
invariant "threats_have_controls" {
  description = "Every threat must have at least one control"
  target      = "threat"
  condition   = length(item.controls) > 0
}

invariant "models_have_dfds" {
  severity      = "warning"
  target        = "threatmodel"
  condition     = length(item.data_flow_diagrams) > 0
  error_message = "threatmodel '${item.name}' by ${item.author} has no data flow diagrams"
}

invariant "usecases_mention_actors" {
  severity  = "warning"
  target    = "usecase"
  condition = can(regex("(?i)user|admin", item.description))
}

invariant "exclusions_are_detailed" {
  target    = "exclusion"
  condition = length(item.description) > 15
}`,
			files: []string{"./testdata/tm1.hcl"},
			code:  1,
		},
		{
			// Exemptions print with their justification; the when filter keeps
			// the internet-facing rule off the model without attributes.
			name: "exemptions_and_when",
			invariants: `
invariant "models_have_threats" {
  target    = "threatmodel"
  condition = length(item.threats) > 0

  exemption "tm tm1 two" {
    justification = "Attribute-only model; tracked in SEC-1"
  }
}

invariant "internet_facing_models_classify_assets" {
  target    = "threatmodel"
  when      = item.attributes.internet_facing
  condition = alltrue([for a in item.information_assets : a.information_classification != ""])
}`,
			files: []string{"./testdata/tm1.hcl"},
			code:  0,
		},
		{
			// DFD element targets across a v2 diagram and a legacy diagram
			// (shifted to "Legacy DFD" by the spec parser), with dfd.name
			// interpolation and trust zones resolved on nested elements.
			name: "dfd_targets",
			invariants: `
invariant "externals_have_trust_zones" {
  target        = "external_element"
  condition     = item.trust_zone != ""
  error_message = "external element '${item.name}' in diagram '${dfd.name}' has no trust zone"
}

invariant "flows_declare_protocol" {
  severity      = "warning"
  target        = "flow"
  condition     = item.protocol != ""
  error_message = "flow '${item.name}' (${item.from} -> ${item.to}) in diagram '${dfd.name}' has no protocol"
}

invariant "processes_have_trust_zones" {
  target    = "process"
  condition = item.trust_zone != ""
}`,
			files: []string{"./testdata/tm5.hcl"},
			code:  1,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testValidateCommand(t)
			invFile := writeInvariantsFile(t, tc.invariants)

			var code int

			out := capturer.CaptureStdout(func() {
				code = cmd.Run(append([]string{"-invariants=" + invFile}, tc.files...))
			})

			if code != tc.code {
				t.Errorf("Code did not equal %d: %d", tc.code, code)
			}

			golden := filepath.Join("testdata", "golden", tc.name+".golden")

			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("reading golden file (re-run with -update to generate): %s", err)
			}

			if out != string(want) {
				diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
					A:        difflib.SplitLines(string(want)),
					B:        difflib.SplitLines(out),
					FromFile: golden,
					ToFile:   "got",
					Context:  3,
				})
				t.Errorf("Output doesn't match golden file (re-run with -update to regenerate):\n%s", diff)
			}
		})
	}
}
