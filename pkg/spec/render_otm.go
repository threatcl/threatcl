package spec

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/xntrik/go-otm/pkg/otm"
)

const (
	OtmVer = "0.2.0"
)

func (tm *Threatmodel) RenderOtm() (otm.OtmSchemaJson, error) {
	o := otm.OtmSchemaJson{}
	o.OtmVersion = OtmVer

	o.Project.Name = tm.Name
	o.Project.Id = toKebabCase(tm.Name)
	o.Project.Description = pToStr(tm.Description)
	o.Project.Owner = pToStr(tm.Author)
	o.Project.Attributes = tm.getAttributes()

	for _, ia := range tm.InformationAssets {
		asset := otm.OtmSchemaJsonAssetsElem{
			Name:        ia.Name,
			Id:          toKebabCase(ia.Name),
			Description: pToStr(ia.Description),
		}

		attr := make(map[string]interface{})
		if ia.InformationClassification != "" {
			attr["information_classification"] = ia.InformationClassification
		}

		if ia.Source != "" {
			attr["source"] = ia.Source
		}

		o.Assets = append(o.Assets, asset)
	}

	for idx, t := range tm.Threats {
		threat := otm.OtmSchemaJsonThreatsElem{
			Name:        fmt.Sprintf("Threat %d", idx+1),
			Id:          toKebabCase(fmt.Sprintf("Threat %d", idx+1)),
			Description: pToStr(t.Description),
		}

		categories := make([]*string, 0)
		for _, stride := range t.Stride {
			categories = append(categories, pToStr(stride))
		}

		for _, impact := range t.ImpactType {
			categories = append(categories, pToStr(impact))
		}

		threat.Categories = categories

		o.Threats = append(o.Threats, threat)

		// We add mitigations while we're in here
		for _, control := range t.Controls {

			mitigation := otm.OtmSchemaJsonMitigationsElem{
				Name:          control.Name,
				Id:            toKebabCase(control.Name),
				Description:   pToStr(control.Description),
				RiskReduction: float64(control.RiskReduction),
			}

			attr := make(map[string]interface{})

			for _, atrVal := range control.Attributes {
				attr[toKebabUnder(atrVal.Name)] = atrVal.Value
			}

			attr["implemented"] = control.Implemented

			if control.ImplementationNotes != "" {
				attr["implementation_notes"] = control.ImplementationNotes
			}

			mitigation.Attributes = attr

			o.Mitigations = append(o.Mitigations, mitigation)

		}
	}

	if tm.DiagramLink != "" {
		repr := otm.OtmSchemaJsonRepresentationsElem{
			Description: pToStr(tm.DiagramLink),
			Type:        "diagram",
			Name:        "Diagram 1",
			Id:          "diagram-1",
		}

		o.Representations = append(o.Representations, repr)
	}

	// jsonOut, err := json.Marshal(o)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// return jsonOut, nil
	return o, nil
}

func (tm *Threatmodel) getAttributes() map[string]interface{} {
	attr := make(map[string]interface{})

	if tm.Attributes != nil {
		attr["new_initiative"] = tm.Attributes.NewInitiative
		attr["internet_facing"] = tm.Attributes.InternetFacing
		attr["initiative_size"] = tm.Attributes.InitiativeSize
	}

	for _, atrVal := range tm.AdditionalAttributes {
		attr[toKebabUnder(atrVal.Name)] = atrVal.Value
	}

	return attr
}

func pToStr(s string) *string {
	return &s
}

func toKebabCase(s string) string {
	return toKebabCaseInner(s, '-')
}

func toKebabUnder(s string) string {
	return toKebabCaseInner(s, '_')
}

func toKebabCaseInner(s string, divider rune) string {
	var kebab strings.Builder
	var prevDash bool // Track whether the previous character was a dash to avoid consecutive dashes

	for i, r := range s {
		// Check if the character is alphanumeric (letter or number)
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			// Convert uppercase to lowercase and add a hyphen if this is not the start and the previous character wasn't a dash
			if unicode.IsUpper(r) && i > 0 && !prevDash {
				kebab.WriteRune(divider)
				prevDash = true
			}
			kebab.WriteRune(unicode.ToLower(r))
			prevDash = false // Reset the dash tracker
		} else if i > 0 && !prevDash && kebab.Len() > 0 { // For non-alphanumeric characters, potentially add a dash if one hasn't been added
			kebab.WriteRune(divider)
			prevDash = true // Mark that a dash was added
			continue
		}
	}

	// Remove trailing dash if present
	kebabStr := kebab.String()
	if strings.HasSuffix(kebabStr, string(divider)) {
		kebabStr = kebabStr[:len(kebabStr)-1]
	}

	return kebabStr
}
