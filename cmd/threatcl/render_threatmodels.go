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
