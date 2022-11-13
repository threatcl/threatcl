package spec

import (
	"testing"
)

func TestNormalizers(t *testing.T) {

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	cases := []struct {
		name string
		in   string
		out  string
		fn   func(in string) string
	}{
		{
			"initsize_empty",
			"",
			"Undefined",
			tmParser.normalizeInitiativeSize,
		},
		{
			"initsize_random",
			"Blep",
			"Undefined",
			tmParser.normalizeInitiativeSize,
		},
		{
			"initsize_smal",
			"smal",
			"Undefined",
			tmParser.normalizeInitiativeSize,
		},
		{
			"initsize_smALL",
			"smALL",
			"Small",
			tmParser.normalizeInitiativeSize,
		},
		{
			"initsize_small",
			"small",
			"Small",
			tmParser.normalizeInitiativeSize,
		},
		{
			"initsize_Small",
			"Small",
			"Small",
			tmParser.normalizeInitiativeSize,
		},
		{
			"infoclass_empty",
			"",
			"Confidential",
			tmParser.normalizeInfoClassification,
		},
		{
			"infoclass_random",
			"Blep",
			"Confidential",
			tmParser.normalizeInfoClassification,
		},
		{
			"infoclass_Public",
			"Public",
			"Public",
			tmParser.normalizeInfoClassification,
		},
		{
			"infoclass_public",
			"public",
			"Public",
			tmParser.normalizeInfoClassification,
		},
		{
			"infoclass_publIC",
			"publIC",
			"Public",
			tmParser.normalizeInfoClassification,
		},
		{
			"impact_empty",
			"",
			"",
			tmParser.normalizeImpactType,
		},
		{
			"impact_random",
			"Blep",
			"",
			tmParser.normalizeImpactType,
		},
		{
			"impact_integrity",
			"integrity",
			"Integrity",
			tmParser.normalizeImpactType,
		},
		{
			"impact_Integrity",
			"Integrity",
			"Integrity",
			tmParser.normalizeImpactType,
		},
		{
			"impact_inteGRITy",
			"inteGRITy",
			"Integrity",
			tmParser.normalizeImpactType,
		},
		{
			"stride_random",
			"Blap",
			"",
			tmParser.normalizeStride,
		},
		{
			"stride_spoofing",
			"spoofing",
			"Spoofing",
			tmParser.normalizeStride,
		},
		{
			"stride_ElevationofPrivilege",
			"Elevation of Privilege",
			"Elevation Of Privilege",
			tmParser.normalizeStride,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.fn(tc.in) != tc.out {
				t.Errorf("%s Error: %s != %s", tc.name, tc.fn(tc.in), tc.out)
			}
		})
	}

	uptimeCases := []struct {
		name string
		in   string
		out  UptimeDependencyClassification
		fn   func(in string) UptimeDependencyClassification
	}{
		{
			"uptd_empty",
			"",
			NoneUptime,
			tmParser.normalizeUptimeDepClassification,
		},
		{
			"uptd_degraded",
			"degraded",
			DegradedUptime,
			tmParser.normalizeUptimeDepClassification,
		},
		{
			"uptd_Degraded",
			"Degraded",
			DegradedUptime,
			tmParser.normalizeUptimeDepClassification,
		},
	}

	for _, tc := range uptimeCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.fn(tc.in) != tc.out {
				t.Errorf("%s Error: %s != %s", tc.name, tc.fn(tc.in), tc.out)
			}
		})
	}

}
