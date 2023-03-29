package spec

import (
	"strings"
	"testing"
)

func TestParseHCLFileWithIncluding(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app.hcl", false)

	// t.Logf("out1: '%s', out2: '%s'", out1, out2)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundIncludeduc := false
	foundSelfuc := false

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		t.Logf("tm: '%s'", tm.Name)
		if tm.Name == "Tower of London" {
			for _, uc := range tm.UseCases {
				if strings.Contains(uc.Description, "fetch the crown") {
					foundIncludeduc = true
				}

				if strings.Contains(uc.Description, "another uc perhaps") {
					foundSelfuc = true
				}
			}

			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Description, "I should be overriden") {
					foundOverwrittenIa = true
				}

			}
		}
	}

	if !foundSelfuc {
		t.Errorf("We didn't find our own use case")
	}

	if !foundIncludeduc {
		t.Errorf("We didn't find our included use case")
	}

	if foundOverwrittenIa {
		t.Errorf("We found an IA that should have been overwritten")
	}

}

func TestParseHCLFileWithIncludingRemote(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app-remote.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		if tm.Name == "Tower of London" {
			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Name, "crown jewels") {
					foundOverwrittenIa = true
				}
			}
		}
	}

	if !foundOverwrittenIa {
		t.Errorf("We didn't find an IA that should have been overwritten")
	}

}

func TestParseHCLFileWithIncludingRemoteGit(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app-remote2.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		if tm.Name == "Tower of London" {
			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Name, "crown jewels") {
					foundOverwrittenIa = true
				}
			}
		}
	}

	if !foundOverwrittenIa {
		t.Errorf("We didn't find an IA that should have been overwritten")
	}

}

func TestParseHCLFileWithIncludingTooMany(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app2.hcl", false)

	if err == nil {
		t.Errorf("We should have gotten an error")
	}

	if !strings.Contains(err.Error(), "incorrect number of threat models. Expected 1 but got 2") {
		t.Errorf("We should have an error about too many models")
	}
}
