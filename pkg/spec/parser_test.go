package spec

import (
	"os"
	"strings"
	"testing"

	"github.com/kami-zh/go-capturer"
)

const (
	tmTestValid = `spec_version = "0.0.3"
		threatmodel "test" {
			author = "@xntrik"
		}
	`
	tmTestValidJson = `{"spec_version": "0.0.3",
    "threatmodel": {
		  "test": {
			  "author": "@xntrik"
			}
		}
	}`
)

func TestNewTMParser(t *testing.T) {

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	tmParser := NewThreatmodelParser(defaultCfg)

	tmParser.validateSpec("blep")

	out := capturer.CaptureStdout(func() {
		tmParser.validateSpec("blop")
	})

	if !strings.Contains(out, "No provided version.") {
		t.Error("Missing stdout from a blank spec version")
		t.Log(out)
	}

	tmw := &ThreatmodelWrapped{
		SpecVersion: "NOPE",
	}

	tmParser.wrapped = tmw

	out = capturer.CaptureStdout(func() {
		tmParser.validateSpec("blop")
	})

	// @TODO: When we tidy up spec versioning, redo these tests
	// if !strings.Contains(out, "Provided version ('NOPE') doesn't match") {
	// 	t.Error("Missing stdout from a blank spec version")
	// 	t.Log(out)
	// }

	if tmParser.GetWrapped() == nil {
		t.Error("GetWrapped shouldn't return nil")
		t.Logf("%+v\n", tmParser.GetWrapped())
	}

}

func TestParseInvalidFileExt(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tm1.csv", false)

	if err == nil {
		t.Errorf("Error parsing illegitimate TM extension: %s", err)
	}
}

func TestParseHCLFile(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm1.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	err = tmParser.ParseFile("./testdata/tm1.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	err = tmParser.ParseHCLFile("./testdata/tm-invalid.hcl", false)

	if err == nil {
		t.Errorf("Error parsing broken TM file: %s", err)
	}
}

func TestParseJsonFile(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseJSONFile("./testdata/tm1.json", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	err = tmParser.ParseFile("./testdata/tm1.json", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	err = tmParser.ParseJSONFile("./testdata/tm-invalid.json", false)

	if err == nil {
		t.Errorf("Error parsing broken TM file: %s", err)
	}
}

func TestParseHCLFileWithVar(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-withvar.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundVarVal := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		for _, threat := range tm.Threats {
			t.Logf("%s - %s", threat.Description, threat.Control)
			if strings.Contains(threat.Description, "test_var_val") {
				foundVarVal = true
			}
		}
	}

	if !foundVarVal {
		t.Errorf("We didn't find the variable")
	}
}

func TestParseHCLFileWithImport(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-withimport.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundImport := false
	foundImportSubfolder := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		for _, threat := range tm.Threats {
			t.Logf("%s - %s", threat.Description, threat.Control)
			if strings.Contains(threat.Description, "ANd it should have spaces") {
				if threat.Control == "Valid controls only" {
					foundImport = true
				}
			}

			if threat.Description == "words" {
				if threat.Control == "Still valid controls only" {
					foundImportSubfolder = true
				}
			}
		}
	}

	if !foundImport {
		t.Errorf("We didn't find the imported control")
	}

	if !foundImportSubfolder {
		t.Errorf("We didn't find the imported control from the subfolder")
	}
}

func TestParseHCLFileWithMissingImport(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-withimport-missingfile.hcl", false)

	if err != nil && !strings.Contains(err.Error(), "The configuration file \"testdata/nope/othercontrols.hcl\" could not be read") {
		t.Errorf("Different error parsing legit TM file: %s", err)
	}

}

func TestParseHCLFileWithBadRefImport(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-withimport-badref.hcl", false)

	if err != nil && !strings.Contains(err.Error(), "This object does not have an attribute named \"aer_control_name\"") {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

}

func TestAddTMAndWrite(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	tm := Threatmodel{
		Name:   "test",
		Author: "x",
	}

	out := capturer.CaptureStdout(func() {
		_ = tmParser.AddTMAndWrite(tm, os.Stdout, false)
	})

	if !strings.Contains(out, "threatmodel \"test\"") {
		t.Error("The tm wasn't added correctly")
	}

	out = capturer.CaptureStdout(func() {
		_ = tmParser.AddTMAndWrite(tm, os.Stdout, true)
	})

	if !strings.Contains(out, "Name: (string) (len=4) \"test\"") {
		t.Error("The tm wasn't added correctly")
	}

}

func TestParseHCLRaw(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		exp         string
		errorthrown bool
	}{
		{
			"valid_hcltm",
			tmTestValid,
			"",
			false,
		},
		{
			"invalid_block",
			"spec_version \"0.0.1\"",
			"Invalid block definition",
			true,
		},
		{
			"invalid_number_literal",
			"spec_version = 0.0.1\"",
			"Invalid number literal",
			true,
		},
		{
			"invalid_spec_version",
			"spec_veon = \"0.0.1\"",
			"Unsupported argument; An argument named \"spec_veon\"",
			true,
		},
		{
			"invalid_dupe_tm",
			tmTestValid + `
	threatmodel "test" {
		author = "j"
	}
			`,
			"TM 'test': duplicate found",
			true,
		},
		{
			"invalid_dupe_infoasset",
			`threatmodel "test" {
		author = "j"
		information_asset "asset" {information_classification = "Public"}
		information_asset "asset" {information_classification = "Public"}
	}
			`,
			"TM 'test': duplicate information_asset 'asset'",
			true,
		},
		{
			"invalid_tminfoassetref",
			`threatmodel "test" {
		author = "j"
		threat {
			description = "threat"
			information_asset_refs = ["nope"]
		}
	}
			`,
			"trying to refer to non-existant information_asset 'nope'",
			true,
		},
		{
			"invalid_tminfoassetref2",
			`threatmodel "test" {
		author = "j"
		information_asset "asset" {information_classification = "Public"}
		threat {
			description = "threat"
			information_asset_refs = ["nope"]
		}
	}
			`,
			"trying to refer to non-existant information_asset 'nope'",
			true,
		},
		{
			"tminfoassetref",
			`threatmodel "test" {
		author = "j"
		information_asset "asset" {information_classification = "Public"}
		threat {
			description = "threat"
			information_asset_refs = ["asset"]
		}
	}
			`,
			"",
			false,
		},
		{
			"tmimportfailurestdin",
			`threatmodel "test" {
		imports = ["errorhere.hcl"]
		author = "j"
		threat {
			description = "threat"
			information_asset_refs = ["asset"]
		}
	}
			`,
			"The configuration file \"./errorhere.hcl\" could not be read.",
			true,
		},
		{
			"tmvar_working",
			`variable "test_var" {
			 value = "test_var_val"
			}
			threatmodel "test" {
			author = "j"
			threat {
			  description = var.test_var
			}
			}`,
			"",
			false,
		},
		{
			"tmvar_arg_block_req_err",
			`variable 1 {
			 value = "test_var_val"
			}
			threatmodel "test" {
			author = "j"
			threat {
			  description = var.test_var
			}
			}`,
			"Argument or block definition required",
			true,
		},
		{
			"tmvar_wrong_arg_err",
			`variable "1" {
			 value = "test_var_val"
			 nope = 2
			}
			threatmodel "test" {
			author = "j"
			threat {
			  description = "var.test_var"
			}
			}`,
			"An argument named \"nope\" is not expected here",
			true,
		},
		// {
		// 	"tmvar_wrong_arg_err2",
		// 	`variable "test_var" {
		// 	 value = 1
		// 	}
		// 	threatmodel "test" {
		// 	author = "j"
		// 	threat {
		// 	  description = var.test_var
		// 	}
		// 	}`,
		// 	"An argument named \"nope\" is not expected here",
		// 	true,
		// },
		{
			"var_in_tm_err",
			`threatmodel "test" {
			variable "test_var" {
			 value = "test_var_val"
			}
			author = "j"
			threat {
			  description = var.test_var
			}
			}`,
			"Blocks of type \"variable\" are not expected here",
			true,
		},
		{
			"dfd_dupe_process",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "1" {}
				}
			}`,
			"duplicate process found in dfd '1'",
			true,
		},
		{
			"dfd_dupe_flow",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "2" {}
					flow "http" {
					  from = "1"
						to = "2"
					}
					flow "http" {
					  from = "1"
						to = "2"
					}
				}
			}`,
			"duplicate flow found in dfd '1:2'",
			true,
		},
		{
			"dfd_invalid_flow_from",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "2" {}
					flow "http" {
					  from = "1"
						to = "2"
					}
					flow "http" {
					  from = "x"
						to = "2"
					}
				}
			}`,
			"invalid from connection for flow 'x:2'",
			true,
		},
		{
			"dfd_invalid_flow_to",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "2" {}
					flow "http" {
					  from = "1"
						to = "2"
					}
					flow "http" {
					  from = "2"
						to = "x"
					}
				}
			}`,
			"invalid to connection for flow '2:x'",
			true,
		},
		{
			"dfd_invalid_self_flow",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "2" {}
					flow "http" {
					  from = "1"
						to = "1"
					}
				}
			}`,
			"flow can't connect to itself '1:1'",
			true,
		},
		{
			"dfd_dupe_external",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					external_element "1" {}
				}
			}`,
			"duplicate external_element found in dfd '1'",
			true,
		},
		{
			"dfd_dupe_data",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
					external_element "a" {}
					data_store "a" {}
				}
			}`,
			"duplicate data_store found in dfd 'a'",
			true,
		},
		{
			"dfd_dupe_zone",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {}
					trust_zone "tza" {}
					external_element "a" {}
					data_store "b" {}
				}
			}`,
			"duplicate trust_zone block found 'tza'",
			true,
		},
		{
			"dfd_dupe_proc_in_zone",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  process "a" {}
					}
					trust_zone "tzb" {}
					process "a" {}
					data_store "b" {}
				}
			}`,
			"duplicate process found in dfd 'a'",
			true,
		},
		{
			"dfd_dupe_element_in_zone",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  external_element "a" {}
					}
					trust_zone "tzb" {}
					process "a" {}
					data_store "b" {}
				}
			}`,
			"duplicate external_element found in dfd 'a'",
			true,
		},
		{
			"dfd_dupe_data_in_zone",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  data_store "a" {}
					}
					trust_zone "tzb" {}
					process "a" {}
					data_store "b" {}
				}
			}`,
			"duplicate data_store found in dfd 'a'",
			true,
		},
		{
			"dfd_mismatch_zone_process",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  process "a" {
						  trust_zone = "nottza"
						}
					}
					trust_zone "tzb" {}
					process "c" {}
					data_store "b" {}
				}
			}`,
			"process trust_zone mis-match found in 'a'",
			true,
		},
		{
			"dfd_mismatch_zone_element",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  external_element "a" {
						  trust_zone = "nottza"
						}
					}
					trust_zone "tzb" {}
					process "c" {}
					data_store "b" {}
				}
			}`,
			"external_element trust_zone mis-match found in 'a'",
			true,
		},
		{
			"dfd_mismatch_zone_data",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  data_store "a" {
						  trust_zone = "nottza"
						}
					}
					trust_zone "tzb" {}
					process "c" {}
					data_store "b" {}
				}
			}`,
			"data_store trust_zone mis-match found in 'a'",
			true,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defaultCfg := &ThreatmodelSpecConfig{}
			defaultCfg.setDefaults()
			tmParser := NewThreatmodelParser(defaultCfg)

			err := tmParser.ParseHCLRaw([]byte(tc.in))

			if err != nil {
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error parsing hcl tm: %s", tc.name, err)
				}
			} else {
				if tc.errorthrown {
					t.Errorf("%s: An error was thrown when it shouldn't have", tc.name)
				}
			}
		})
	}
}

func TestParseJsonRaw(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		exp         string
		errorthrown bool
	}{
		{
			"valid_hcltm",
			tmTestValidJson,
			"",
			false,
		},
		{
			"invalid_block",
			"{spec_version: \"0.0.1\"}",
			"Invalid JSON keyword",
			true,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defaultCfg := &ThreatmodelSpecConfig{}
			defaultCfg.setDefaults()
			tmParser := NewThreatmodelParser(defaultCfg)

			err := tmParser.ParseJSONRaw([]byte(tc.in))

			if err != nil {
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error parsing hcl tm: %s", tc.name, err)
				}
			} else {
				if tc.errorthrown {
					t.Errorf("%s: An error was thrown when it shouldn't have", tc.name)
				}
			}
		})
	}
}

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
