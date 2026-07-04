// Package invariants implements org-wide, machine-checked rules ("invariants")
// that are evaluated against parsed threat models. An invariants file is plain
// HCL, separate from the threat model spec: each `invariant` block names a
// target collection within a threat model (threats, controls, DFD processes,
// ...), an optional `when` filter, and a `condition` expression that must hold
// for every targeted item. Conditions are native HCL expressions evaluated
// with the target item (`item`), its owning threat model (`tm`), and — for
// data-flow-diagram elements — the owning diagram (`dfd`) in scope.
//
// The package is deliberately self-contained within threatcl (rather than the
// github.com/threatcl/spec module): invariants describe organisational policy
// over models, not the models themselves. Parsing (ParseFile) and evaluation
// (Evaluate) are the two seams; the cty mapping of spec structs is an internal
// concern.
package invariants

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/threatcl/spec"
	"github.com/zclconf/go-cty/cty"
)

// Severity controls whether a violated invariant fails validation ("error")
// or is only reported ("warning").
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Invariant is one parsed `invariant` block from an invariants file.
type Invariant struct {
	Name        string
	Description string
	Severity    Severity
	Target      string
	Exemptions  []*Exemption

	when         hcl.Expression
	condition    hcl.Expression
	errorMessage hcl.Expression
}

// Exemption waives an invariant for a single named threat model. The
// justification is required so the waiver is auditable in the policy file.
type Exemption struct {
	Model         string
	Justification string
}

func (i *Invariant) exemptionFor(model string) *Exemption {
	for _, e := range i.Exemptions {
		if e.Model == model {
			return e
		}
	}
	return nil
}

// Target names accepted by the `target` attribute. Each maps to a collection
// within a single threat model; "threatmodel" targets the model itself.
var validTargets = map[string]bool{
	"threatmodel":            true,
	"threat":                 true,
	"control":                true,
	"information_asset":      true,
	"usecase":                true,
	"exclusion":              true,
	"third_party_dependency": true,
	"data_flow_diagram":      true,
	"process":                true,
	"external_element":       true,
	"data_store":             true,
	"flow":                   true,
	"trust_zone":             true,
}

// dfdChildTargets are the targets that live inside a data flow diagram and so
// additionally have `dfd` in scope during evaluation.
var dfdChildTargets = map[string]bool{
	"process":          true,
	"external_element": true,
	"data_store":       true,
	"flow":             true,
	"trust_zone":       true,
}

type fileHCL struct {
	Invariants []*invariantHCL `hcl:"invariant,block"`
}

type invariantHCL struct {
	Name         string          `hcl:"name,label"`
	Description  string          `hcl:"description,optional"`
	Severity     string          `hcl:"severity,optional"`
	Target       string          `hcl:"target"`
	When         hcl.Expression  `hcl:"when,optional"`
	Condition    hcl.Expression  `hcl:"condition"`
	ErrorMessage hcl.Expression  `hcl:"error_message,optional"`
	Exemptions   []*exemptionHCL `hcl:"exemption,block"`
}

type exemptionHCL struct {
	Model         string `hcl:"model,label"`
	Justification string `hcl:"justification"`
}

// ParseFile parses and validates an invariants HCL file.
func ParseFile(path string) ([]*Invariant, error) {
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, diags
	}
	return decode(f.Body)
}

// ParseHCLRaw parses and validates invariants from raw HCL bytes. filename is
// only used in error messages.
func ParseHCLRaw(src []byte, filename string) ([]*Invariant, error) {
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, diags
	}
	return decode(f.Body)
}

func decode(body hcl.Body) ([]*Invariant, error) {
	var raw fileHCL
	diags := gohcl.DecodeBody(body, nil, &raw)
	if diags.HasErrors() {
		return nil, diags
	}

	var errs []error
	seen := map[string]bool{}
	out := make([]*Invariant, 0, len(raw.Invariants))
	for _, r := range raw.Invariants {
		inv, err := r.validate()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[inv.Name] {
			errs = append(errs, fmt.Errorf("invariant %q: defined more than once", inv.Name))
			continue
		}
		seen[inv.Name] = true
		out = append(out, inv)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no invariant blocks found")
	}
	return out, nil
}

// absentExpr reports whether an optional expression attribute was omitted.
// gohcl decodes a missing hcl.Expression field as a synthetic static null
// rather than leaving it nil, so "not set" has to be detected by evaluation.
func absentExpr(expr hcl.Expression) bool {
	if expr == nil {
		return true
	}
	if len(expr.Variables()) > 0 {
		return false
	}
	v, diags := expr.Value(nil)
	return !diags.HasErrors() && v.IsNull() && v.Type() == cty.DynamicPseudoType
}

func (r *invariantHCL) validate() (*Invariant, error) {
	var errs []error

	if absentExpr(r.When) {
		r.When = nil
	}
	if absentExpr(r.ErrorMessage) {
		r.ErrorMessage = nil
	}
	// gohcl can't mark expression attributes required — a missing one decodes
	// as a synthetic null — so enforce condition here.
	if absentExpr(r.Condition) {
		errs = append(errs, fmt.Errorf("invariant %q: missing required attribute \"condition\"", r.Name))
	}

	severity := SeverityError
	switch strings.ToLower(r.Severity) {
	case "":
	case string(SeverityError):
	case string(SeverityWarning):
		severity = SeverityWarning
	default:
		errs = append(errs, fmt.Errorf("invariant %q: invalid severity %q (must be %q or %q)", r.Name, r.Severity, SeverityError, SeverityWarning))
	}

	if !validTargets[r.Target] {
		errs = append(errs, fmt.Errorf("invariant %q: invalid target %q (must be one of %s)", r.Name, r.Target, strings.Join(targetNames(), ", ")))
	}

	allowed := map[string]bool{"item": true, "tm": true}
	if dfdChildTargets[r.Target] {
		allowed["dfd"] = true
	}
	for _, pair := range []struct {
		attr string
		expr hcl.Expression
	}{
		{"when", r.When},
		{"condition", r.Condition},
		{"error_message", r.ErrorMessage},
	} {
		if err := checkVariables(pair.expr, allowed, r.Name, pair.attr); err != nil {
			errs = append(errs, err)
		}
	}

	exemptions := make([]*Exemption, 0, len(r.Exemptions))
	for _, e := range r.Exemptions {
		if strings.TrimSpace(e.Justification) == "" {
			errs = append(errs, fmt.Errorf("invariant %q: exemption for %q requires a justification", r.Name, e.Model))
			continue
		}
		exemptions = append(exemptions, &Exemption{Model: e.Model, Justification: e.Justification})
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return &Invariant{
		Name:         r.Name,
		Description:  r.Description,
		Severity:     severity,
		Target:       r.Target,
		Exemptions:   exemptions,
		when:         r.When,
		condition:    r.Condition,
		errorMessage: r.ErrorMessage,
	}, nil
}

func checkVariables(expr hcl.Expression, allowed map[string]bool, invName, attr string) error {
	if expr == nil {
		return nil
	}
	var errs []error
	for _, traversal := range expr.Variables() {
		root := traversal.RootName()
		if !allowed[root] {
			errs = append(errs, fmt.Errorf("invariant %q: %s references unknown variable %q (available: %s)", invName, attr, root, strings.Join(sortedKeys(allowed), ", ")))
		}
	}
	return errors.Join(errs...)
}

func targetNames() []string {
	return sortedKeys(validTargets)
}

// Model pairs a parsed threat model with the file it came from, for reporting.
type Model struct {
	TM   *spec.Threatmodel
	File string
}
