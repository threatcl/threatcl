package invariants

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
)

// Violation records one item that failed an invariant's condition.
type Violation struct {
	Invariant *Invariant
	Model     *Model
	ItemKind  string
	ItemName  string
	Message   string
}

// ExemptionUse records an invariant that was skipped for a model because the
// invariants file exempts it.
type ExemptionUse struct {
	Invariant     *Invariant
	Model         *Model
	Justification string
}

// Report is the outcome of evaluating a set of invariants against a set of
// threat models. Ordering is deterministic: models in input order, then
// invariants in file order, then items in model order.
type Report struct {
	Violations []*Violation
	Exemptions []*ExemptionUse
	Invariants int
	Models     int
}

// ErrorCount returns the number of violations of error-severity invariants.
func (r *Report) ErrorCount() int {
	n := 0
	for _, v := range r.Violations {
		if v.Invariant.Severity == SeverityError {
			n++
		}
	}
	return n
}

// WarningCount returns the number of violations of warning-severity invariants.
func (r *Report) WarningCount() int {
	return len(r.Violations) - r.ErrorCount()
}

// item is one evaluation subject: the value bound to `item`, plus the owning
// diagram for DFD elements (bound to `dfd` when non-nil).
type item struct {
	name string
	val  cty.Value
	dfd  *cty.Value
}

// Evaluate checks every invariant against every model. Exempted models are
// skipped (and recorded), not evaluated. A returned error means an invariant
// itself is broken — its expression failed to evaluate or didn't produce the
// right type — as opposed to a model merely violating it.
func Evaluate(invs []*Invariant, models []*Model) (*Report, error) {
	report := &Report{Invariants: len(invs), Models: len(models)}
	funcs := invariantFunctions()

	tmVals := make([]cty.Value, len(models))
	for i, m := range models {
		tmVals[i] = threatmodelVal(m.TM)
	}

	exempted, err := resolveExemptions(invs, models, tmVals, funcs)
	if err != nil {
		return nil, err
	}

	for i, m := range models {
		tmVal := tmVals[i]
		for _, inv := range invs {
			if justification, ok := exempted[inv][m.TM.Name]; ok {
				report.Exemptions = append(report.Exemptions, &ExemptionUse{
					Invariant:     inv,
					Model:         m,
					Justification: justification,
				})
				continue
			}
			for _, it := range collectItems(inv.Target, tmVal) {
				ctx := &hcl.EvalContext{
					Variables: map[string]cty.Value{"item": it.val, "tm": tmVal},
					Functions: funcs,
				}
				if it.dfd != nil {
					ctx.Variables["dfd"] = *it.dfd
				}

				if inv.when != nil {
					applies, err := evalBool(inv.when, ctx)
					if err != nil {
						return nil, evalError(inv, "when", m, it, err)
					}
					if !applies {
						continue
					}
				}

				holds, err := evalBool(inv.condition, ctx)
				if err != nil {
					return nil, evalError(inv, "condition", m, it, err)
				}
				if holds {
					continue
				}

				msg, err := inv.message(ctx)
				if err != nil {
					return nil, evalError(inv, "error_message", m, it, err)
				}
				report.Violations = append(report.Violations, &Violation{
					Invariant: inv,
					Model:     m,
					ItemKind:  inv.Target,
					ItemName:  it.name,
					Message:   msg,
				})
			}
		}
	}
	return report, nil
}

// resolveExemptions evaluates every exemption's model reference against the
// `threatmodel` registry — the models in this run, keyed by name — and returns
// the exempted model names (with justifications) per invariant. A reference to
// a name not in the registry is a hard error naming the missing model; an
// exemption whose reference evaluates to null (e.g. via
// try(threatmodel["Other Fleet"], null) in an invariants file shared across
// separately-validated fleets) is inactive rather than an error.
func resolveExemptions(invs []*Invariant, models []*Model, tmVals []cty.Value, funcs map[string]function.Function) (map[*Invariant]map[string]string, error) {
	registry := map[string]cty.Value{}
	for i, m := range models {
		registry[m.TM.Name] = tmVals[i]
	}
	registryVal := cty.EmptyObjectVal
	if len(registry) > 0 {
		registryVal = cty.ObjectVal(registry)
	}
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"threatmodel": registryVal},
		Functions: funcs,
	}

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, fmt.Sprintf("%q", name))
	}
	sort.Strings(names)

	exempted := map[*Invariant]map[string]string{}
	for _, inv := range invs {
		exempted[inv] = map[string]string{}
		for i, ex := range inv.Exemptions {
			v, diags := ex.model.Value(ctx)
			if diags.HasErrors() {
				return nil, fmt.Errorf("invariant %q: resolving exemption #%d model reference: %w (threat models in this run: %s)",
					inv.Name, i+1, diags, strings.Join(names, ", "))
			}
			if v.IsNull() {
				continue
			}
			if !v.Type().IsObjectType() || !v.Type().HasAttribute("name") {
				return nil, fmt.Errorf("invariant %q: exemption #%d model must reference a threat model, e.g. threatmodel[\"Some Model\"]", inv.Name, i+1)
			}
			exempted[inv][v.GetAttr("name").AsString()] = ex.Justification
		}
	}
	return exempted, nil
}

func evalError(inv *Invariant, attr string, m *Model, it item, err error) error {
	return fmt.Errorf("invariant %q: evaluating %s for %s %q in threatmodel %q (%s): %w",
		inv.Name, attr, inv.Target, it.name, m.TM.Name, m.File, err)
}

func evalBool(expr hcl.Expression, ctx *hcl.EvalContext) (bool, error) {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return false, diags
	}
	v, err := convert.Convert(v, cty.Bool)
	if err != nil {
		return false, fmt.Errorf("expression must produce a bool: %w", err)
	}
	if v.IsNull() {
		return false, fmt.Errorf("expression produced null instead of a bool")
	}
	return v.True(), nil
}

// message resolves the violation message: the error_message expression if
// present, else the invariant's description, else a generic fallback.
func (i *Invariant) message(ctx *hcl.EvalContext) (string, error) {
	if i.errorMessage == nil {
		if i.Description != "" {
			return i.Description, nil
		}
		return "condition failed", nil
	}
	v, diags := i.errorMessage.Value(ctx)
	if diags.HasErrors() {
		return "", diags
	}
	v, err := convert.Convert(v, cty.String)
	if err != nil {
		return "", fmt.Errorf("error_message must produce a string: %w", err)
	}
	if v.IsNull() {
		return "", fmt.Errorf("error_message produced null instead of a string")
	}
	return v.AsString(), nil
}

// dfdChildAttr maps a DFD-element target to the diagram attribute holding its
// collection.
var dfdChildAttr = map[string]string{
	"process":          "processes",
	"external_element": "external_elements",
	"data_store":       "data_stores",
	"flow":             "flows",
	"trust_zone":       "trust_zones",
}

// collectItems extracts the evaluation subjects for a target from the already
// mapped threat model value, so items are exactly what expressions see.
func collectItems(target string, tmVal cty.Value) []item {
	switch target {
	case "threatmodel":
		return []item{{name: tmVal.GetAttr("name").AsString(), val: tmVal}}
	case "threat":
		return namedItems(tmVal.GetAttr("threats"), "name")
	case "control":
		return namedItems(tmVal.GetAttr("controls"), "name")
	case "information_asset":
		return namedItems(tmVal.GetAttr("information_assets"), "name")
	case "third_party_dependency":
		return namedItems(tmVal.GetAttr("third_party_dependencies"), "name")
	case "usecase":
		return indexedItems(tmVal.GetAttr("usecases"), "usecase")
	case "exclusion":
		return indexedItems(tmVal.GetAttr("exclusions"), "exclusion")
	case "data_flow_diagram":
		return namedItems(tmVal.GetAttr("data_flow_diagrams"), "name")
	default:
		attr := dfdChildAttr[target]
		out := []item{}
		for it := tmVal.GetAttr("data_flow_diagrams").ElementIterator(); it.Next(); {
			_, dfd := it.Element()
			for elIt := dfd.GetAttr(attr).ElementIterator(); elIt.Next(); {
				_, el := elIt.Element()
				out = append(out, item{name: el.GetAttr("name").AsString(), val: el, dfd: &dfd})
			}
		}
		return out
	}
}

func namedItems(list cty.Value, nameAttr string) []item {
	out := []item{}
	for it := list.ElementIterator(); it.Next(); {
		_, v := it.Element()
		out = append(out, item{name: v.GetAttr(nameAttr).AsString(), val: v})
	}
	return out
}

// indexedItems labels items that have no name of their own (usecases,
// exclusions) by their 1-based position.
func indexedItems(list cty.Value, kind string) []item {
	out := []item{}
	i := 0
	for it := list.ElementIterator(); it.Next(); {
		_, v := it.Element()
		i++
		out = append(out, item{name: fmt.Sprintf("%s #%d", kind, i), val: v})
	}
	return out
}
