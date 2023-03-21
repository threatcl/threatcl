package spec

import (
	"strings"
	"testing"
)

func TestControlStringConstraint(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		exp       []string
		invertexp bool
	}{
		{
			"old_version_and_no_control",
			"./testdata/tm1.hcl",
			[]string{"Deprecation warning: This threat model has defined `control`"},
			true,
		},
		{
			"old_version_and_control",
			"./testdata/tm-withimport.hcl",
			[]string{"Deprecation warning: This threat model has defined `control`"},
			false,
		},
		{
			"old_version_and_control_block",
			"./testdata/tm-constraint-proposed.hcl",
			[]string{"Deprecation warning: This threat model has defined `proposed_control`"},
			false,
		},
		{
			"old_dfd",
			"./testdata/tm-constraint-multidfd.hcl",
			[]string{"Deprecation warning: This threat model has a defined `data_flow_diagram`"},
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			defaultCfg := &ThreatmodelSpecConfig{}
			defaultCfg.setDefaults()
			tmParser := NewThreatmodelParser(defaultCfg)

			err := tmParser.ParseFile(tc.in, false)
			if err != nil {
				t.Errorf("Error parsing hcl file: %s", err)
			}

			constraintMsg, err := VersionConstraints(tmParser.GetWrapped(), false)
			if err != nil {
				t.Errorf("Error parsing constraints: %s", err)
			}

			if !tc.invertexp {
				for _, exp := range tc.exp {
					if !strings.Contains(constraintMsg, exp) {
						t.Errorf("Expected %s to contain %s", constraintMsg, exp)
					}
				}
			} else {
				for _, exp := range tc.exp {
					if strings.Contains(constraintMsg, exp) {
						t.Errorf("Was not expecting %s to contain %s", constraintMsg, exp)
					}
				}
			}

		})
	}
}
