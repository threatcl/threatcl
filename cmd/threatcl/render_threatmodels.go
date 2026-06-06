package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/threatcl/go-otm/pkg/otm"
	"github.com/threatcl/spec"
)

// renderThreatmodels renders the supplied threat models into the requested
// output format. parser is required for the "hcl" format because HclString
// encodes from parser state (including spec_version, components, variables,
// and any backend blocks left in wrapped). templatePath, if non-empty, is read
// as a markdown template for the "md" format.
func renderThreatmodels(
	tms []spec.Threatmodel,
	parser *spec.ThreatmodelParser,
	format, templatePath string,
) (string, error) {
	switch format {
	case "json":
		tmJSON, err := json.Marshal(tms)
		if err != nil {
			return "", fmt.Errorf("error parsing into json: %s", err)
		}
		return string(tmJSON), nil

	case "otm":
		allOtms := []otm.OtmSchemaJson{}
		for _, tm := range tms {
			tmOtm, err := tm.RenderOtm()
			if err != nil {
				return "", fmt.Errorf("error parsing into otm: %s", err)
			}
			appendMermaidRepresentations(&tmOtm, tm)
			allOtms = append(allOtms, tmOtm)
		}

		var (
			otmJSON []byte
			err     error
		)
		switch {
		case len(tms) > 1:
			otmJSON, err = json.Marshal(allOtms)
		case len(tms) == 1:
			otmJSON, err = json.Marshal(allOtms[0])
		}
		if err != nil {
			return "", fmt.Errorf("error parsing into otm: %s", err)
		}
		return string(otmJSON), nil

	case "hcl":
		if parser == nil {
			return "", fmt.Errorf("hcl format requires a parser")
		}
		return parser.HclString(), nil

	case "md":
		tmTemplate := ""
		if templatePath != "" {
			var err error
			tmTemplate, err = readTemplateFile(templatePath)
			if err != nil {
				return "", fmt.Errorf("error reading template file: %s", err)
			}
		}
		if tmTemplate == "" {
			tmTemplate = spec.TmMDTemplate
		}

		var out string
		for _, tm := range tms {
			tmReader, err := tm.RenderMarkdown(tmTemplate)
			if err != nil {
				return "", fmt.Errorf("error parsing into md: %s", err)
			}
			tmBytes, err := io.ReadAll(tmReader)
			if err != nil {
				return "", fmt.Errorf("error reading markdown: %s", err)
			}
			out = out + string(tmBytes)
		}
		return out, nil
	}

	return "", fmt.Errorf("Incorrect -format option")
}

// appendMermaidRepresentations adds an OTM representation for each embedded
// mermaid block so they survive otm export (spec.RenderOtm only maps
// diagram_link). OTM has no first-class field for inline diagram source, so the
// raw mermaid is carried in the representation attributes (format=mermaid,
// content=<source>) and the block's optional description maps to the
// representation description. IDs are namespaced "mermaid-<n>" to avoid
// colliding with the "diagram-1" id RenderOtm emits for diagram_link.
func appendMermaidRepresentations(o *otm.OtmSchemaJson, tm spec.Threatmodel) {
	for i, m := range tm.MermaidDiagrams {
		repr := otm.OtmSchemaJsonRepresentationsElem{
			Id:   fmt.Sprintf("mermaid-%d", i+1),
			Name: m.Name,
			Type: "diagram",
			Attributes: otm.OtmSchemaJsonRepresentationsElemAttributes{
				"format":  "mermaid",
				"content": m.Content,
			},
		}
		if m.Description != "" {
			desc := m.Description
			repr.Description = &desc
		}
		o.Representations = append(o.Representations, repr)
	}
}
