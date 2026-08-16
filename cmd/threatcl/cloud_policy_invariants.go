package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/threatcl/spec/invariants"
)

// Policy engines. A policy's rule text lives in one source field; the engine
// says how to read it - an OPA Rego module, or a single threatcl `invariant`
// HCL block evaluated by the same engine `threatcl validate -invariants` uses.
const (
	policyEngineRego      = "rego"
	policyEngineInvariant = "invariant"
)

// validPolicyEngine reports whether an -engine flag value is one the CLI knows
// how to send.
func validPolicyEngine(engine string) bool {
	return engine == policyEngineRego || engine == policyEngineInvariant
}

// policyEngineOrDefault names a policy's engine, defaulting to rego for
// responses from a deployment that predates the field.
func policyEngineOrDefault(engine string) string {
	if engine == "" {
		return policyEngineRego
	}
	return engine
}

// parseSingleInvariant parses source that must hold exactly one `invariant`
// block - the shape one policy row takes - and returns it. Parsing locally
// before the API call turns a round-trip into an immediate, precise error and
// lets create derive the policy's name and severity from the block, which is
// authoritative for both.
func parseSingleInvariant(source []byte, filename string) (*invariants.Invariant, error) {
	invs, err := invariants.ParseHCLRaw(source, filename)
	if err != nil {
		return nil, err
	}

	if len(invs) != 1 {
		return nil, fmt.Errorf(
			"an invariant policy is a single invariant block, but %s declares %d; use 'threatcl cloud policy sync-invariants' to import a whole file",
			filename, len(invs),
		)
	}

	return invs[0], nil
}

// invariantViolation is one item that failed an invariant, as reported in an
// evaluation result's details
type invariantViolation struct {
	ItemKind string `json:"item_kind"`
	ItemName string `json:"item_name"`
	Segment  string `json:"segment"`
	Message  string `json:"message"`
}

// invariantExemption is one exemption considered during an evaluation.
// Inactive exemptions named no model in the run - the common case for a shared
// invariants file evaluated one model at a time - and are not violations.
type invariantExemption struct {
	Model         string `json:"model"`
	Segment       string `json:"segment"`
	Justification string `json:"justification"`
	Inactive      bool   `json:"inactive"`
	Reason        string `json:"reason"`
}

// invariantResultDetails is the `details` payload of an invariant-engine
// evaluation result. EvalError means the rule itself failed to evaluate - the
// model was never checked against it - rather than the model being in breach.
type invariantResultDetails struct {
	Engine       string               `json:"engine"`
	Target       string               `json:"target"`
	ItemsChecked int                  `json:"items_checked"`
	Violations   []invariantViolation `json:"violations"`
	Exemptions   []invariantExemption `json:"exemptions"`
	EvalError    string               `json:"eval_error"`
}

// invariantDetails re-decodes a result's details as invariant details, or
// returns nil when the result came from another engine. `engine` is the
// discriminator; a rego result carries whatever its module returned.
func (r policyEvaluationResult) invariantDetails() *invariantResultDetails {
	if r.Details == nil {
		return nil
	}
	if engine, _ := r.Details["engine"].(string); engine != policyEngineInvariant {
		return nil
	}

	raw, err := json.Marshal(r.Details)
	if err != nil {
		return nil
	}

	var details invariantResultDetails
	if err := json.Unmarshal(raw, &details); err != nil {
		return nil
	}

	return &details
}

// maxRenderedViolations caps how many violations a single failed invariant
// prints before the rest are summarised, so one broad rule can't bury the rest
// of the run in CI output.
const maxRenderedViolations = 10

// renderInvariantDetails writes the violations an invariant result reported,
// indented beneath its row in the results table. Active exemptions are printed
// too - a waiver stays visible in every run, as it does in
// `threatcl validate -invariants` - while inactive ones are left to -json,
// since a shared invariants file leaves most of them inactive on any one model.
func renderInvariantDetails(w io.Writer, details *invariantResultDetails) {
	if details == nil {
		return
	}

	if details.EvalError != "" {
		fmt.Fprintf(w, "    ! rule error: %s\n", details.EvalError)
	}

	for i, v := range details.Violations {
		if i == maxRenderedViolations {
			fmt.Fprintf(w, "    ... and %d more\n", len(details.Violations)-maxRenderedViolations)
			break
		}
		fmt.Fprintf(w, "    - %s\n", formatInvariantViolation(v))
	}

	for _, e := range details.Exemptions {
		if e.Inactive {
			continue
		}
		where := e.Model
		if e.Segment != "" {
			where = fmt.Sprintf("%s (%s)", e.Model, e.Segment)
		}
		fmt.Fprintf(w, "    ~ exempt: %s: %s\n", where, e.Justification)
	}
}

// formatInvariantViolation names the offending item, the segment it came from,
// and the invariant's rendered message, the way `threatcl validate` reports a
// local violation.
func formatInvariantViolation(v invariantViolation) string {
	var b strings.Builder

	switch {
	case v.ItemKind != "" && v.ItemName != "":
		fmt.Fprintf(&b, "%s '%s'", v.ItemKind, v.ItemName)
	case v.ItemName != "":
		fmt.Fprintf(&b, "'%s'", v.ItemName)
	case v.ItemKind != "":
		b.WriteString(v.ItemKind)
	}

	if v.Segment != "" {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "(%s)", v.Segment)
	}

	if v.Message != "" {
		if b.Len() > 0 {
			b.WriteString(": ")
		}
		b.WriteString(v.Message)
	}

	return b.String()
}
