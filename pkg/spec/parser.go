package spec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type ThreatmodelParser struct {
	initiativeSizeOptions          map[string]bool
	defaultInitiativeSize          string
	infoClassifications            map[string]bool
	impactTypes                    map[string]bool
	strideElements                 map[string]bool
	uptimeDepClassification        map[string]bool
	defaultUptimeDepClassification UptimeDependencyClassification
	defaultInfoClassification      string
	wrapped                        *ThreatmodelWrapped
	specCfg                        *ThreatmodelSpecConfig
}

func NewThreatmodelParser(cfg *ThreatmodelSpecConfig) *ThreatmodelParser {
	tmParser := &ThreatmodelParser{
		initiativeSizeOptions:   map[string]bool{},
		infoClassifications:     map[string]bool{},
		impactTypes:             map[string]bool{},
		strideElements:          map[string]bool{},
		uptimeDepClassification: map[string]bool{},
		wrapped:                 &ThreatmodelWrapped{},
		specCfg:                 cfg,
	}
	tmParser.populateInitiativeSizeOptions()
	tmParser.populateInfoClassifications()
	tmParser.populateImpactTypes()
	tmParser.populateStrideElements()
	tmParser.populateUptimeDepClassifications()
	return tmParser
}

func (p *ThreatmodelParser) populateInitiativeSizeOptions() {

	for _, cfgInitiativeSizeOption := range p.specCfg.InitiativeSizes {
		p.initiativeSizeOptions[cfgInitiativeSizeOption] = true
	}
	p.defaultInitiativeSize = p.specCfg.DefaultInitiativeSize
}

func (p *ThreatmodelParser) populateInfoClassifications() {

	for _, cfgInfoClassification := range p.specCfg.InfoClassifications {
		p.infoClassifications[cfgInfoClassification] = true
	}
	p.defaultInfoClassification = p.specCfg.DefaultInfoClassification
}

func (p *ThreatmodelParser) populateImpactTypes() {
	for _, cfgImpactType := range p.specCfg.ImpactTypes {
		p.impactTypes[cfgImpactType] = true
	}
}

func (p *ThreatmodelParser) populateStrideElements() {
	for _, cfgStride := range p.specCfg.STRIDE {
		p.strideElements[cfgStride] = true
	}
}

func (p *ThreatmodelParser) populateUptimeDepClassifications() {
	for _, cfgUptimeDep := range p.specCfg.UptimeDepClassifications {
		p.uptimeDepClassification[cfgUptimeDep] = true
	}
	p.defaultUptimeDepClassification = UptimeDependencyClassification(p.specCfg.DefaultUptimeDepClassification)
}

func (p *ThreatmodelParser) normalizeInitiativeSize(in string) string {
	if p.initiativeSizeOptions[strings.Title(strings.ToLower(in))] {
		return strings.Title(strings.ToLower(in))
	}

	return p.defaultInitiativeSize
}

func (p *ThreatmodelParser) normalizeInfoClassification(in string) string {
	if p.infoClassifications[strings.Title(strings.ToLower(in))] {
		return strings.Title(strings.ToLower(in))
	}
	return p.defaultInfoClassification
}

func (p *ThreatmodelParser) normalizeImpactType(in string) string {
	if p.impactTypes[strings.Title(strings.ToLower(in))] {
		return strings.Title(strings.ToLower(in))
	}
	return ""
}

func (p *ThreatmodelParser) normalizeStride(in string) string {
	if p.strideElements[strings.Title(strings.ToLower(in))] {
		return strings.Title(strings.ToLower(in))
	}
	return ""
}

func (p *ThreatmodelParser) normalizeUptimeDepClassification(in string) UptimeDependencyClassification {
	if p.uptimeDepClassification[strings.ToLower(in)] {
		return UptimeDependencyClassification(strings.ToLower(in))
	}
	return p.defaultUptimeDepClassification
}

func (p *ThreatmodelParser) GetWrapped() *ThreatmodelWrapped {
	return p.wrapped
}

func (p *ThreatmodelParser) AddTMAndWrite(tm Threatmodel, f io.Writer, debug bool) error {

	if debug {
		spew.Dump(tm)
	}

	if p.wrapped.SpecVersion == "" {
		// We haven't yet set the SpecVersion for this model, which may mean that we're adding a new TM to an existing wrapped object. Let's set it from the loaded CFG
		p.wrapped.SpecVersion = p.specCfg.Version
	}

	p.wrapped.Threatmodels = append(p.wrapped.Threatmodels, tm)

	w := bufio.NewWriter(f)
	defer w.Flush()
	hclOut := hclwrite.NewEmptyFile()
	gohcl.EncodeIntoBody(p.wrapped, hclOut.Body())
	_, err := w.Write(hclOut.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func (p *ThreatmodelParser) ValidateTm(tm *Threatmodel) error {
	var errMap error
	// Normalize threatmodel attributes
	if tm.Attributes != nil {

		// Normalize threatmodel attributes initiative_size
		if tm.Attributes.InitiativeSize != "" {
			tm.Attributes.InitiativeSize = p.normalizeInitiativeSize(tm.Attributes.InitiativeSize)
		}
	}

	// Checking for unique information_assets per threatmodel
	// Also Normalize info classification
	if tm.InformationAssets != nil {
		infoAssets := make(map[string]interface{})
		for _, ia := range tm.InformationAssets {
			if _, ok := infoAssets[ia.Name]; ok {
				errMap = multierror.Append(errMap, fmt.Errorf(
					"TM '%s': duplicate information_asset '%s'",
					tm.Name,
					ia.Name,
				))
			}

			// Normalize InformationClassification
			if ia.InformationClassification != "" {
				ia.InformationClassification = p.normalizeInfoClassification(ia.InformationClassification)
			}

			infoAssets[ia.Name] = nil
		}
	}

	// Validating any DFD data within a threat model
	if tm.DataFlowDiagram != nil {

		// Checking for unique TrustZones
		zones := make(map[string]interface{})
		if tm.DataFlowDiagram.TrustZones != nil {
			for _, zone := range tm.DataFlowDiagram.TrustZones {
				if _, ok := zones[zone.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate trust_zone block found '%s'",
						tm.Name,
						zone.Name,
					))
				}

				zones[zone.Name] = nil
			}
		}

		// Checking for unique processes/data_store/external_element in data_flow_diagram
		elements := make(map[string]interface{})
		if tm.DataFlowDiagram.Processes != nil {
			for _, process := range tm.DataFlowDiagram.Processes {
				if _, ok := elements[process.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate process found in dfd '%s'",
						tm.Name,
						process.Name,
					))
				}

				elements[process.Name] = nil
			}
		}

		// Now check for Processes in trust_zones
		if tm.DataFlowDiagram.TrustZones != nil {
			for _, zone := range tm.DataFlowDiagram.TrustZones {
				if zone.Processes != nil {
					for _, process := range zone.Processes {
						if _, ok := elements[process.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate process found in dfd '%s'",
								tm.Name,
								process.Name,
							))
						}

						elements[process.Name] = nil
					}
				}
			}
		}

		if tm.DataFlowDiagram.ExternalElements != nil {
			for _, external_element := range tm.DataFlowDiagram.ExternalElements {
				if _, ok := elements[external_element.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate external_element found in dfd '%s'",
						tm.Name,
						external_element.Name,
					))
				}

				elements[external_element.Name] = nil
			}
		}

		// Now check for external_elements in trust_zones
		if tm.DataFlowDiagram.TrustZones != nil {
			for _, zone := range tm.DataFlowDiagram.TrustZones {
				if zone.ExternalElements != nil {
					for _, external_element := range zone.ExternalElements {
						if _, ok := elements[external_element.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate external_element found in dfd '%s'",
								tm.Name,
								external_element.Name,
							))
						}

						elements[external_element.Name] = nil
					}
				}
			}
		}

		// Checking for unique data_stores in data_flow_diagram
		if tm.DataFlowDiagram.DataStores != nil {
			for _, data_store := range tm.DataFlowDiagram.DataStores {
				if _, ok := elements[data_store.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate data_store found in dfd '%s'",
						tm.Name,
						data_store.Name,
					))
				}

				elements[data_store.Name] = nil

				// While in DataStores, let's check if they have iaRefs, and that they
				// are valid
				if data_store.IaLink != "" {
					err := validateInformationAssetRef(tm, data_store.IaLink)
					if err != nil {
						errMap = multierror.Append(errMap, fmt.Errorf(
							"TM '%s' DFD Data Store '%s' %s",
							tm.Name,
							data_store.Name,
							err,
						))
					}
				}
			}
		}

		// Now check for data_stores in trust_zones
		if tm.DataFlowDiagram.TrustZones != nil {
			for _, zone := range tm.DataFlowDiagram.TrustZones {
				if zone.DataStores != nil {
					for _, data_store := range zone.DataStores {
						if _, ok := elements[data_store.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate data_store found in dfd '%s'",
								tm.Name,
								data_store.Name,
							))
						}

						elements[data_store.Name] = nil

						// While in DataStores, let's check if they have iaRefs, and that they
						// are valid
						if data_store.IaLink != "" {
							err := validateInformationAssetRef(tm, data_store.IaLink)
							if err != nil {
								errMap = multierror.Append(errMap, fmt.Errorf(
									"TM '%s' DFD Data Store '%s' %s",
									tm.Name,
									data_store.Name,
									err,
								))
							}
						}
					}
				}
			}
		}

		// Now check for mis-matched trust-zones
		if tm.DataFlowDiagram.TrustZones != nil {
			for _, zone := range tm.DataFlowDiagram.TrustZones {
				if zone.Processes != nil {
					for _, process := range zone.Processes {
						if process.TrustZone != "" && process.TrustZone != zone.Name {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': process trust_zone mis-match found in '%s'",
								tm.Name,
								process.Name,
							))
						}
					}
				}

				if zone.ExternalElements != nil {
					for _, external_element := range zone.ExternalElements {
						if external_element.TrustZone != "" && external_element.TrustZone != zone.Name {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': external_element trust_zone mis-match found in '%s'",
								tm.Name,
								external_element.Name,
							))
						}
					}
				}

				if zone.DataStores != nil {
					for _, data_store := range zone.DataStores {
						if data_store.TrustZone != "" && data_store.TrustZone != zone.Name {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': data_store trust_zone mis-match found in '%s'",
								tm.Name,
								data_store.Name,
							))
						}
					}
				}
			}
		}

		// Validate data flows
		flows := make(map[string]interface{})
		if tm.DataFlowDiagram.Flows != nil {
			for _, rawflow := range tm.DataFlowDiagram.Flows {
				flow := fmt.Sprintf("%s:%s", rawflow.From, rawflow.To)

				// check for unique flows
				if _, ok := flows[flow]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate flow found in dfd '%s'",
						tm.Name,
						flow,
					))
				}

				// now check that flows connect to legit processes
				if _, ok := elements[rawflow.From]; !ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': invalid from connection for flow '%s'",
						tm.Name,
						flow,
					))
				}

				if _, ok := elements[rawflow.To]; !ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': invalid to connection for flow '%s'",
						tm.Name,
						flow,
					))
				}

				// now check that the flow doesn't connect to itself
				if rawflow.From == rawflow.To {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': flow can't connect to itself '%s'",
						tm.Name,
						flow,
					))
				}

				flows[flow] = nil

			}
		}
	}

	// Normalize threat impacts and stride
	if tm.Threats != nil {
		for _, tr := range tm.Threats {
			normalized := []string{}
			for _, impact := range tr.ImpactType {
				normalized = append(normalized, p.normalizeImpactType(impact))
			}
			tr.ImpactType = normalized

			normalizedStride := []string{}
			for _, stride := range tr.Stride {
				normalizedStride = append(normalizedStride, p.normalizeStride(stride))
			}
			tr.Stride = normalizedStride

			// Validating that InformationAssetRefs are valid
			for _, iaRef := range tr.InformationAssetRefs {
				err := validateInformationAssetRef(tm, iaRef)
				if err != nil {
					errMap = multierror.Append(errMap,
						fmt.Errorf("TM '%s' / Threat '%s': %s", tm.Name, tr.Description, err),
					)
				}
			}
		}
	}

	// Normalize third party deps - uptime dep classification
	if tm.ThirdPartyDependencies != nil {
		for _, tpd := range tm.ThirdPartyDependencies {
			tpd.UptimeDependency = p.normalizeUptimeDepClassification(string(tpd.UptimeDependency))
		}
	}

	if errMap != nil {
		return errMap
	}

	return nil

}

// Validate that the supplied informatin_asset name is found in the tm
func validateInformationAssetRef(tm *Threatmodel, asset string) error {
	if tm.InformationAssets != nil {
		foundIa := false
		for _, ia := range tm.InformationAssets {
			if asset == ia.Name {
				foundIa = true
				break
			}
		}

		if !foundIa {
			return fmt.Errorf(
				"trying to refer to non-existent information_asset '%s'",
				asset,
			)
		}
	} else {
		return fmt.Errorf(
			"trying to refer to non-existent information_asset '%s'",
			asset,
		)
	}

	return nil
}

func (p *ThreatmodelParser) validateTms() error {
	// Validating all the threatmodels
	var errMap error
	tmMap := make(map[string]interface{})

	for _, t := range p.wrapped.Threatmodels {
		// Validating unique threatmodel name
		if _, ok := tmMap[t.Name]; ok {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"TM '%s': duplicate found.",
				t.Name,
			))
		}
		tmMap[t.Name] = nil

		err := p.ValidateTm(&t)
		if err != nil {
			errMap = multierror.Append(errMap, err)
		}

	}

	if errMap != nil {
		return errMap
	}

	return nil
}

func (p *ThreatmodelParser) validateSpec(filename string) {
	// @TODO: This has been edited to not print to STDOUT - it should be wrapped in a DEBUG flag

	// Check the version in the file against the current config
	if p.wrapped.SpecVersion != "" {
		if p.wrapped.SpecVersion != p.specCfg.Version {
			// fmt.Fprintf(os.Stdout, "%s: Provided version ('%s') doesn't match the hcltm version ('%s')\n", filename, p.wrapped.SpecVersion, p.specCfg.Version)
		}
	} else {
		fmt.Fprintf(os.Stdout, "%s: No provided version. The current hcltm version is '%s'\n", filename, p.specCfg.Version)
	}

}

// extractVars does a shallow parsing of an HCL file looking for
// 'variable' blocks
func extractVars(f *hcl.File) (map[string]string, error) {
	output := make(map[string]string)
	var errMap error

	extract, _, diags := f.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type:       "variable",
				LabelNames: []string{"name"},
			},
		},
	})

	if diags.HasErrors() {
		return output, diags
	}

	for _, b := range extract.Blocks {
		attributeExtract, _, _ := b.Body.PartialContent(&hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{
				{
					Name: "value",
				},
			},
		})

		if attr, exist := attributeExtract.Attributes["value"]; exist {
			value_extract := ""
			attrDiags := gohcl.DecodeExpression(attr.Expr, nil, &value_extract)
			if attrDiags.HasErrors() {
				errMap = multierror.Append(errMap, attrDiags)
			} else {
				if len(value_extract) > 0 && len(b.Labels) > 0 {
					output[b.Labels[0]] = value_extract
				}
			}
		}
	}

	return output, nil

}

func (p *ThreatmodelParser) buildVarCtx(ctx *hcl.EvalContext, varMap map[string]string) error {

	var varMapOut map[string]cty.Value
	varMapOut = make(map[string]cty.Value)

	for k, v := range varMap {
		varMapOut[k] = cty.StringVal(v)
	}

	ctx.Variables["var"] = cty.ObjectVal(varMapOut)

	return nil

}

// extractImports does a shallow parsing of an HCL file looking for
// 'threatmodel' blocks that include 'imports' attributes
func extractImports(f *hcl.File) ([]string, error) {
	output := []string{}
	var errMap error

	extract, _, diags := f.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type:       "threatmodel",
				LabelNames: []string{"name"},
			},
		},
	})

	if diags.HasErrors() {
		return output, diags
	}

	for _, b := range extract.Blocks {
		attributeExtract, _, _ := b.Body.PartialContent(&hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{
				{
					Name: "imports",
				},
			},
		})

		if attr, exist := attributeExtract.Attributes["imports"]; exist {
			imports := []string{}
			attrDiags := gohcl.DecodeExpression(attr.Expr, nil, &imports)
			if attrDiags.HasErrors() {
				errMap = multierror.Append(errMap, attrDiags)
			} else {
				for _, i := range imports {
					foundOutput := false
					for _, existingOutput := range output {
						if existingOutput == i {
							foundOutput = true
						}
					}

					if !foundOutput {
						output = append(output, i)
					}
				}
			}
		}
	}

	return output, errMap
}

func (p *ThreatmodelParser) buildCtx(ctx *hcl.EvalContext, imports []string, parentfilename string) error {
	var controls map[string]cty.Value
	controls = make(map[string]cty.Value)

	for _, i := range imports {
		importPath := fmt.Sprintf("%s/%s", filepath.Dir(parentfilename), i)
		importTmp := NewThreatmodelParser(p.specCfg)
		importDiag := importTmp.ParseHCLFile(importPath, true)

		if importDiag != nil {
			return importDiag
		}

		for _, c := range importTmp.GetWrapped().Components {
			controls[c.ComponentName] = cty.ObjectVal(map[string]cty.Value{
				"description": cty.StringVal(c.Description),
			})
		}
	}

	ctx.Variables["import"] = cty.ObjectVal(map[string]cty.Value{
		"control": cty.ObjectVal(controls),
	})

	return nil
}

// parseHCL actually does the parsing - called by either ParseHCLFile or ParseHCLRaw
func (p *ThreatmodelParser) parseHCL(f *hcl.File, filename string, isChild bool) error {

	ctx := &hcl.EvalContext{}
	ctx.Variables = map[string]cty.Value{}

	// @TODO while imports should only be in the parent, variables can be in sub files?
	if !isChild {
		// extract any imports = [] from this hcl file
		imports, err := extractImports(f)
		if err != nil {
			return err
		}

		// if we have imports we need to build EvalContext for them
		if len(imports) > 0 {
			if filename == "STDIN" {
				fmt.Printf("Warning: STDIN processing of hcltm files doesn't handle imports, and we've detected an import\n")
			}

			err = p.buildCtx(ctx, imports, filename)

			if err != nil {
				return err
			}
		}

		// extract any variables from this hcl file
		varMap, err := extractVars(f)
		if err != nil {
			return err
		}

		if len(varMap) > 0 {

			err = p.buildVarCtx(ctx, varMap)

			if err != nil {
				return err
			}
		}
	}

	var diags hcl.Diagnostics

	diags = gohcl.DecodeBody(f.Body, ctx, p.wrapped)

	if diags.HasErrors() {
		return diags
	}

	p.validateSpec(filename)

	err := p.validateTms()
	if err != nil {
		return err
	}

	return nil
}

// ParseFile parses a single Threatmodel file, and will account for either
// JSON or HCL (this is a wrapper sort of for the two different methods)
func (p *ThreatmodelParser) ParseFile(filename string, isChild bool) error {
	if filepath.Ext(filename) == ".hcl" {
		return p.ParseHCLFile(filename, isChild)
	} else if filepath.Ext(filename) == ".json" {
		return p.ParseJSONFile(filename, isChild)
	} else {
		return fmt.Errorf("File isn't HCL or JSON")
	}
}

// ParseHCLFile parses a single HCL Threatmodel file
func (p *ThreatmodelParser) ParseHCLFile(filename string, isChild bool) error {
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCLFile(filename)

	if diags.HasErrors() {
		return diags
	}

	return p.parseHCL(f, filename, isChild)
}

// ParseHCLRaw parses a byte slice into HCL Threatmodels
// This is used for piping in STDIN
func (p *ThreatmodelParser) ParseHCLRaw(input []byte) error {
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCL(input, "STDIN")

	if diags.HasErrors() {
		return diags
	}

	return p.parseHCL(f, "STDIN", false)
}

// ParseJSONFile parses a single JSON Threatmodel file
func (p *ThreatmodelParser) ParseJSONFile(filename string, isChild bool) error {
	parser := hclparse.NewParser()
	f, diags := parser.ParseJSONFile(filename)

	if diags.HasErrors() {
		return diags
	}

	return p.parseHCL(f, filename, isChild)
}

// ParseJSONRaw parses a byte slice into HCL Threatmodels from JSON
// This is used for piping in STDIN
func (p *ThreatmodelParser) ParseJSONRaw(input []byte) error {
	parser := hclparse.NewParser()
	f, diags := parser.ParseJSON(input, "STDIN")

	if diags.HasErrors() {
		return diags
	}

	return p.parseHCL(f, "STDIN", false)
}
