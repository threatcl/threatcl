package invariants

import (
	"sort"

	"github.com/threatcl/spec"
	"github.com/zclconf/go-cty/cty"
)

// The cty object types exposed to invariant expressions. Every value builder
// below fills in every field, so lists stay uniformly typed and rule authors
// can rely on a field existing (empty rather than absent). Field names match
// the HCL attribute names in the threat model spec.

var (
	proposedControlCty = cty.Object(map[string]cty.Type{
		"implemented": cty.Bool,
		"description": cty.String,
	})
	controlCty = cty.Object(map[string]cty.Type{
		"name":                 cty.String,
		"implemented":          cty.Bool,
		"description":          cty.String,
		"implementation_notes": cty.String,
		"ref":                  cty.String,
		"risk_reduction":       cty.Number,
		"attributes":           cty.Map(cty.String),
	})
	riskCty = cty.Object(map[string]cty.Type{
		"likelihood": cty.String,
		"impact":     cty.String,
		"severity":   cty.String,
		"rationale":  cty.String,
	})
	threatCty = cty.Object(map[string]cty.Type{
		"name":                   cty.String,
		"description":            cty.String,
		"impacts":                cty.List(cty.String),
		"stride":                 cty.List(cty.String),
		"information_asset_refs": cty.List(cty.String),
		"control":                cty.String,
		"ref":                    cty.String,
		"controls":               cty.List(controlCty),
		"proposed_controls":      cty.List(proposedControlCty),
		"risk":                   riskCty,
	})
	informationAssetCty = cty.Object(map[string]cty.Type{
		"name":                       cty.String,
		"description":                cty.String,
		"information_classification": cty.String,
		"source":                     cty.String,
		"ref":                        cty.String,
	})
	usecaseCty = cty.Object(map[string]cty.Type{
		"description": cty.String,
	})
	exclusionCty = cty.Object(map[string]cty.Type{
		"description": cty.String,
	})
	thirdPartyDependencyCty = cty.Object(map[string]cty.Type{
		"name":              cty.String,
		"description":       cty.String,
		"saas":              cty.Bool,
		"paying_customer":   cty.Bool,
		"open_source":       cty.Bool,
		"uptime_dependency": cty.String,
		"uptime_notes":      cty.String,
		"infrastructure":    cty.Bool,
	})
	processCty = cty.Object(map[string]cty.Type{
		"name":       cty.String,
		"trust_zone": cty.String,
	})
	externalElementCty = cty.Object(map[string]cty.Type{
		"name":       cty.String,
		"trust_zone": cty.String,
	})
	dataStoreCty = cty.Object(map[string]cty.Type{
		"name":              cty.String,
		"trust_zone":        cty.String,
		"information_asset": cty.String,
	})
	flowCty = cty.Object(map[string]cty.Type{
		"name":     cty.String,
		"from":     cty.String,
		"to":       cty.String,
		"protocol": cty.String,
	})
	trustZoneCty = cty.Object(map[string]cty.Type{
		"name":              cty.String,
		"processes":         cty.List(processCty),
		"external_elements": cty.List(externalElementCty),
		"data_stores":       cty.List(dataStoreCty),
	})
	dfdCty = cty.Object(map[string]cty.Type{
		"name":              cty.String,
		"processes":         cty.List(processCty),
		"external_elements": cty.List(externalElementCty),
		"data_stores":       cty.List(dataStoreCty),
		"flows":             cty.List(flowCty),
		"trust_zones":       cty.List(trustZoneCty),
	})
	attributesCty = cty.Object(map[string]cty.Type{
		"new_initiative":  cty.Bool,
		"internet_facing": cty.Bool,
		"initiative_size": cty.String,
	})
)

func listVal(vals []cty.Value, elem cty.Type) cty.Value {
	if len(vals) == 0 {
		return cty.ListValEmpty(elem)
	}
	return cty.ListVal(vals)
}

func stringListVal(in []string) cty.Value {
	vals := make([]cty.Value, 0, len(in))
	for _, s := range in {
		vals = append(vals, cty.StringVal(s))
	}
	return listVal(vals, cty.String)
}

func controlVal(c *spec.Control) cty.Value {
	attrs := map[string]cty.Value{}
	for _, a := range c.Attributes {
		attrs[a.Name] = cty.StringVal(a.Value)
	}
	attrsVal := cty.MapValEmpty(cty.String)
	if len(attrs) > 0 {
		attrsVal = cty.MapVal(attrs)
	}
	return cty.ObjectVal(map[string]cty.Value{
		"name":                 cty.StringVal(c.Name),
		"implemented":          cty.BoolVal(c.Implemented),
		"description":          cty.StringVal(c.Description),
		"implementation_notes": cty.StringVal(c.ImplementationNotes),
		"ref":                  cty.StringVal(c.Ref),
		"risk_reduction":       cty.NumberIntVal(int64(c.RiskReduction)),
		"attributes":           attrsVal,
	})
}

func proposedControlVal(p *spec.ProposedControl) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"implemented": cty.BoolVal(p.Implemented),
		"description": cty.StringVal(p.Description),
	})
}

func riskVal(r *spec.Risk) cty.Value {
	if r == nil {
		return cty.NullVal(riskCty)
	}
	return cty.ObjectVal(map[string]cty.Value{
		"likelihood": cty.StringVal(r.Likelihood),
		"impact":     cty.StringVal(r.Impact),
		"severity":   cty.StringVal(r.Severity()),
		"rationale":  cty.StringVal(r.Rationale),
	})
}

// threatControls flattens a threat's inline controls and any controls
// expanded from control_imports into one slice.
func threatControls(t *spec.Threat) []*spec.Control {
	out := make([]*spec.Control, 0, len(t.Controls)+len(t.ExpandedControls))
	out = append(out, t.Controls...)
	out = append(out, t.ExpandedControls...)
	return out
}

func threatVal(t *spec.Threat) cty.Value {
	controls := make([]cty.Value, 0)
	for _, c := range threatControls(t) {
		controls = append(controls, controlVal(c))
	}
	proposed := make([]cty.Value, 0, len(t.ProposedControls))
	for _, p := range t.ProposedControls {
		proposed = append(proposed, proposedControlVal(p))
	}
	return cty.ObjectVal(map[string]cty.Value{
		"name":                   cty.StringVal(t.Name),
		"description":            cty.StringVal(t.Description),
		"impacts":                stringListVal(t.ImpactType),
		"stride":                 stringListVal(t.Stride),
		"information_asset_refs": stringListVal(t.InformationAssetRefs),
		"control":                cty.StringVal(t.Control),
		"ref":                    cty.StringVal(t.Ref),
		"controls":               listVal(controls, controlCty),
		"proposed_controls":      listVal(proposed, proposedControlCty),
		"risk":                   riskVal(t.Risk),
	})
}

func informationAssetVal(ia *spec.InformationAsset) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"name":                       cty.StringVal(ia.Name),
		"description":                cty.StringVal(ia.Description),
		"information_classification": cty.StringVal(ia.InformationClassification),
		"source":                     cty.StringVal(ia.Source),
		"ref":                        cty.StringVal(ia.Ref),
	})
}

func thirdPartyDependencyVal(t *spec.ThirdPartyDependency) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"name":              cty.StringVal(t.Name),
		"description":       cty.StringVal(t.Description),
		"saas":              cty.BoolVal(t.Saas),
		"paying_customer":   cty.BoolVal(t.PayingCustomer),
		"open_source":       cty.BoolVal(t.OpenSource),
		"uptime_dependency": cty.StringVal(string(t.UptimeDependency)),
		"uptime_notes":      cty.StringVal(t.UptimeNotes),
		"infrastructure":    cty.BoolVal(t.Infrastructure),
	})
}

// zoneOr returns the element's own trust zone, or the name of the enclosing
// trust_zone block for nested elements. The spec parser rejects mismatches but
// doesn't backfill the field, so expressions get the resolved zone either way.
func zoneOr(own, enclosing string) string {
	if own != "" {
		return own
	}
	return enclosing
}

func processVal(p *spec.DfdProcess, enclosingZone string) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"name":       cty.StringVal(p.Name),
		"trust_zone": cty.StringVal(zoneOr(p.TrustZone, enclosingZone)),
	})
}

func externalElementVal(e *spec.DfdExternal, enclosingZone string) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"name":       cty.StringVal(e.Name),
		"trust_zone": cty.StringVal(zoneOr(e.TrustZone, enclosingZone)),
	})
}

func dataStoreVal(d *spec.DfdData, enclosingZone string) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"name":              cty.StringVal(d.Name),
		"trust_zone":        cty.StringVal(zoneOr(d.TrustZone, enclosingZone)),
		"information_asset": cty.StringVal(d.IaLink),
	})
}

func flowVal(f *spec.DfdFlow) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"name":     cty.StringVal(f.Name),
		"from":     cty.StringVal(f.From),
		"to":       cty.StringVal(f.To),
		"protocol": cty.StringVal(f.Protocol),
	})
}

func trustZoneVal(z *spec.DfdTrustZone) cty.Value {
	processes := make([]cty.Value, 0, len(z.Processes))
	for _, p := range z.Processes {
		processes = append(processes, processVal(p, z.Name))
	}
	externals := make([]cty.Value, 0, len(z.ExternalElements))
	for _, e := range z.ExternalElements {
		externals = append(externals, externalElementVal(e, z.Name))
	}
	stores := make([]cty.Value, 0, len(z.DataStores))
	for _, d := range z.DataStores {
		stores = append(stores, dataStoreVal(d, z.Name))
	}
	return cty.ObjectVal(map[string]cty.Value{
		"name":              cty.StringVal(z.Name),
		"processes":         listVal(processes, processCty),
		"external_elements": listVal(externals, externalElementCty),
		"data_stores":       listVal(stores, dataStoreCty),
	})
}

// dfdVal maps a data flow diagram. The processes/external_elements/data_stores
// lists include elements declared directly on the diagram and those nested
// inside trust_zone blocks, so `dfd.processes` is the complete set.
func dfdVal(d *spec.DataFlowDiagram) cty.Value {
	processes := make([]cty.Value, 0, len(d.Processes))
	for _, p := range d.Processes {
		processes = append(processes, processVal(p, ""))
	}
	externals := make([]cty.Value, 0, len(d.ExternalElements))
	for _, e := range d.ExternalElements {
		externals = append(externals, externalElementVal(e, ""))
	}
	stores := make([]cty.Value, 0, len(d.DataStores))
	for _, ds := range d.DataStores {
		stores = append(stores, dataStoreVal(ds, ""))
	}
	zones := make([]cty.Value, 0, len(d.TrustZones))
	for _, z := range d.TrustZones {
		zones = append(zones, trustZoneVal(z))
		for _, p := range z.Processes {
			processes = append(processes, processVal(p, z.Name))
		}
		for _, e := range z.ExternalElements {
			externals = append(externals, externalElementVal(e, z.Name))
		}
		for _, ds := range z.DataStores {
			stores = append(stores, dataStoreVal(ds, z.Name))
		}
	}
	flows := make([]cty.Value, 0, len(d.Flows))
	for _, f := range d.Flows {
		flows = append(flows, flowVal(f))
	}
	return cty.ObjectVal(map[string]cty.Value{
		"name":              cty.StringVal(d.Name),
		"processes":         listVal(processes, processCty),
		"external_elements": listVal(externals, externalElementCty),
		"data_stores":       listVal(stores, dataStoreCty),
		"flows":             listVal(flows, flowCty),
		"trust_zones":       listVal(zones, trustZoneCty),
	})
}

func attributesVal(a *spec.Attribute) cty.Value {
	if a == nil {
		return cty.ObjectVal(map[string]cty.Value{
			"new_initiative":  cty.False,
			"internet_facing": cty.False,
			"initiative_size": cty.StringVal(""),
		})
	}
	return cty.ObjectVal(map[string]cty.Value{
		"new_initiative":  cty.BoolVal(a.NewInitiative),
		"internet_facing": cty.BoolVal(a.InternetFacing),
		"initiative_size": cty.StringVal(a.InitiativeSize),
	})
}

// threatmodelVal maps a whole threat model into the `tm` value. In addition to
// the spec's own fields it exposes `controls`: every control across every
// threat, flattened, since "the model must include control X" is the common
// rule shape.
func threatmodelVal(tm *spec.Threatmodel) cty.Value {
	assets := make([]cty.Value, 0, len(tm.InformationAssets))
	for _, ia := range tm.InformationAssets {
		assets = append(assets, informationAssetVal(ia))
	}
	threats := make([]cty.Value, 0, len(tm.Threats))
	allControls := make([]cty.Value, 0)
	for _, t := range tm.Threats {
		threats = append(threats, threatVal(t))
		for _, c := range threatControls(t) {
			allControls = append(allControls, controlVal(c))
		}
	}
	usecases := make([]cty.Value, 0, len(tm.UseCases))
	for _, u := range tm.UseCases {
		usecases = append(usecases, cty.ObjectVal(map[string]cty.Value{"description": cty.StringVal(u.Description)}))
	}
	exclusions := make([]cty.Value, 0, len(tm.Exclusions))
	for _, e := range tm.Exclusions {
		exclusions = append(exclusions, cty.ObjectVal(map[string]cty.Value{"description": cty.StringVal(e.Description)}))
	}
	tpds := make([]cty.Value, 0, len(tm.ThirdPartyDependencies))
	for _, t := range tm.ThirdPartyDependencies {
		tpds = append(tpds, thirdPartyDependencyVal(t))
	}
	dfds := make([]cty.Value, 0, len(tm.DataFlowDiagrams))
	for _, d := range tm.DataFlowDiagrams {
		dfds = append(dfds, dfdVal(d))
	}
	additional := map[string]cty.Value{}
	for _, a := range tm.AdditionalAttributes {
		additional[a.Name] = cty.StringVal(a.Value)
	}
	additionalVal := cty.MapValEmpty(cty.String)
	if len(additional) > 0 {
		additionalVal = cty.MapVal(additional)
	}

	return cty.ObjectVal(map[string]cty.Value{
		"name":                     cty.StringVal(tm.Name),
		"id":                       cty.StringVal(tm.Id),
		"extends":                  cty.StringVal(tm.Extends),
		"description":              cty.StringVal(tm.Description),
		"author":                   cty.StringVal(tm.Author),
		"link":                     cty.StringVal(tm.Link),
		"diagram_link":             cty.StringVal(tm.DiagramLink),
		"repository":               stringListVal(tm.Repository),
		"created_at":               cty.NumberIntVal(tm.CreatedAt),
		"updated_at":               cty.NumberIntVal(tm.UpdatedAt),
		"attributes":               attributesVal(tm.Attributes),
		"additional_attributes":    additionalVal,
		"information_assets":       listVal(assets, informationAssetCty),
		"threats":                  listVal(threats, threatCty),
		"usecases":                 listVal(usecases, usecaseCty),
		"exclusions":               listVal(exclusions, exclusionCty),
		"third_party_dependencies": listVal(tpds, thirdPartyDependencyCty),
		"data_flow_diagrams":       listVal(dfds, dfdCty),
		"controls":                 listVal(allControls, controlCty),
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
