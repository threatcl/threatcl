package spec

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestKebab(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  string
	}{
		{
			"empty",
			"",
			"",
		},
		{
			"message with space",
			"message with space",
			"message-with-space",
		},
		{
			"message start with dash",
			"-message with space",
			"message-with-space",
		},
		{
			"ThisIsATest",
			"ThisIsATest",
			"this-is-a-test",
		},
		{
			"message with space random characters",
			"message with space!#$%",
			"message-with-space",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.exp != toKebabCase(tc.in) {
				t.Errorf("'%s' should have been converted to '%s' but ended up being '%s'", tc.in, tc.exp, toKebabCase(tc.in))
			}
		})
	}
}

func TestKebabUnder(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  string
	}{
		{
			"empty",
			"",
			"",
		},
		{
			"message with space",
			"message with space",
			"message_with_space",
		},
		{
			"message with space random characters",
			"message with space!#$%",
			"message_with_space",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.exp != toKebabUnder(tc.in) {
				t.Errorf("'%s' should have been converted to '%s' but ended up being '%s'", tc.in, tc.exp, toKebabUnder(tc.in))
			}
		})
	}
}

func TestRenderOtm(t *testing.T) {
	tmAttr := &Attribute{}
	additionalAttr := &AdditionalAttribute{
		Name:  "Name",
		Value: "Value",
	}
	tm := &Threatmodel{
		Name:        "test",
		Author:      "x",
		DiagramLink: "http://linkieboop",
		Attributes:  tmAttr,
	}
	tm.AdditionalAttributes = append(tm.AdditionalAttributes, additionalAttr)
	ia := &InformationAsset{
		Name:                      "blep",
		Source:                    "source",
		InformationClassification: "Confidential",
	}

	tm.InformationAssets = append(tm.InformationAssets, ia)
	controlAttribute := &ControlAttribute{
		Name:  "Name",
		Value: "Value",
	}
	control := &Control{
		Name:                "control name",
		ImplementationNotes: "implementation notes",
	}
	control.Attributes = append(control.Attributes, controlAttribute)
	threat := &Threat{
		Description: "threat description",
		Stride: []string{
			"Spoofing",
		},
		ImpactType: []string{
			"Confidentiality",
		},
	}
	threat.Controls = append(threat.Controls, control)
	tm.Threats = append(tm.Threats, threat)

	otmJson, err := tm.RenderOtm()
	if err != nil {
		t.Errorf("Error parsing model: %s", err)
	}

	jsonOut, err := json.Marshal(otmJson)
	if err != nil {
		t.Errorf("Error marshing into json: %s", err)
	}

	fmt.Printf("jsonOut:\n%s\n", string(jsonOut))

	if !strings.Contains(string(jsonOut), "name\":\"test") {
		t.Errorf("Json (%s) didn't equal", string(jsonOut))
	}

}
