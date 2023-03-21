package spec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

func (p *ThreatmodelParser) validateTms() error {
	// Validating all the threatmodels
	var errMap error
	tmMap := make(map[string]interface{})

	newWrapped := []Threatmodel{}
	for _, t := range p.wrapped.Threatmodels {
		err, _ := t.shiftLegacyDfd()
		if err != nil {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"TM '%s': error shifting legacy DFD: %s", t.Name, err))
		}
		// fmt.Printf("We did a shift: %d\n", shiftedCount)
		newWrapped = append(newWrapped, t)
	}

	p.wrapped.Threatmodels = newWrapped

	for _, t := range p.wrapped.Threatmodels {
		// Validating unique threatmodel name
		if _, ok := tmMap[t.Name]; ok {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"TM '%s': duplicate found.",
				t.Name,
			))
		}
		tmMap[t.Name] = nil

		// err := p.ValidateTm(&t)
		err := t.ValidateTm(p)
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
		importTmp, err := fetchRemoteTm(p.specCfg, i, parentfilename)
		if err != nil {
			return err
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
	var err error
	if filepath.Ext(filename) == ".hcl" {
		err = p.ParseHCLFile(filename, isChild)
		if err != nil {
			return err
		}
	} else if filepath.Ext(filename) == ".json" {
		err = p.ParseJSONFile(filename, isChild)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("File isn't HCL or JSON")
	}

	for i := 0; i < len(p.wrapped.Threatmodels); i++ {
		w := &p.wrapped.Threatmodels[i]
		if w.Including != "" {
			err = w.Include(p.specCfg, filename)
			if err != nil {
				return err
			}
		}
	}

	return err

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
