package spec

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	gg "github.com/hashicorp/go-getter"
)

func (tm *Threatmodel) Include(cfg *ThreatmodelSpecConfig, myfilename string) error {
	if tm.Including == "" {
		return fmt.Errorf("Empty Including")
	}

	subParser, err := fetchRemoteTm(cfg, tm.Including, myfilename)
	if err != nil {
		return err
	}

	if len(subParser.wrapped.Threatmodels) != 1 {
		return fmt.Errorf("The included threat model file includes an incorrect number of threat models. Expected 1 but got %d", len(subParser.wrapped.Threatmodels))
	}

	subTm := &subParser.wrapped.Threatmodels[0]

	if tm.Description == "" {
		tm.Description = subTm.Description
	}

	if tm.Link == "" {
		tm.Link = subTm.Link
	}

	if tm.DiagramLink == "" {
		tm.DiagramLink = subTm.DiagramLink
	}

	if tm.Attributes == nil {
		tm.Attributes = subTm.Attributes
	}

	for _, ia := range subTm.InformationAssets {
		tm.addInfoIfNotExist(*ia)
	}

	for _, uc := range subTm.UseCases {
		tm.addUcIfNotExist(*uc)
	}

	for _, ex := range subTm.Exclusions {
		tm.addExclIfNotExist(*ex)
	}

	for _, tpd := range subTm.ThirdPartyDependencies {
		tm.addTpdIfNotExist(*tpd)
	}

	if tm.DataFlowDiagram == nil {
		tm.DataFlowDiagram = subTm.DataFlowDiagram
	}

	for _, t := range subTm.Threats {
		tm.addTIfNotExist(*t)
	}

	return nil
}

func (tm *Threatmodel) addInfoIfNotExist(newIa InformationAsset) {

	assetFound := false
	for _, ia := range tm.InformationAssets {
		if ia.Name == newIa.Name {
			assetFound = true
		}
	}

	if assetFound == false {
		tm.InformationAssets = append(tm.InformationAssets, &newIa)
	}

}

func (tm *Threatmodel) addTpdIfNotExist(newTpd ThirdPartyDependency) {

	tpdFound := false
	for _, tpd := range tm.ThirdPartyDependencies {
		if tpd.Name == newTpd.Name {
			tpdFound = true
		}
	}

	if tpdFound == false {
		tm.ThirdPartyDependencies = append(tm.ThirdPartyDependencies, &newTpd)
	}

}

func (tm *Threatmodel) addUcIfNotExist(newUc UseCase) {

	ucFound := false
	for _, uc := range tm.UseCases {
		if newUc.Description == uc.Description {
			ucFound = true
		}
	}

	if ucFound == false {
		tm.UseCases = append(tm.UseCases, &newUc)
	}
}

func (tm *Threatmodel) addExclIfNotExist(newExcl Exclusion) {

	exFound := false
	for _, ex := range tm.Exclusions {
		if newExcl.Description == ex.Description {
			exFound = true
		}
	}

	if exFound == false {
		tm.Exclusions = append(tm.Exclusions, &newExcl)
	}
}

func (tm *Threatmodel) addTIfNotExist(newT Threat) {

	tFound := false
	for _, t := range tm.Threats {
		if newT.Description == t.Description {
			tFound = true
		}
	}

	if tFound == false {
		tm.Threats = append(tm.Threats, &newT)
	}
}

func fetchRemoteTm(cfg *ThreatmodelSpecConfig, source, currentFilename string) (*ThreatmodelParser, error) {
	returnParser := NewThreatmodelParser(cfg)

	tmpDir, err := ioutil.TempDir("", "hcltm")
	if err != nil {
		return nil, err
	}

	absPath, err := filepath.Abs(currentFilename)
	if err != nil {
		return nil, err
	}

	absPath = filepath.Dir(absPath)

	client := gg.Client{
		Src:  source,
		Dst:  tmpDir,
		Pwd:  absPath,
		Mode: gg.ClientModeAny,
	}

	err = client.Get()
	if err != nil {
		return nil, err
	}

	includePath := fmt.Sprintf("%s/%s", tmpDir, filepath.Base(source))
	importDiag := returnParser.ParseHCLFile(includePath, true)

	if importDiag != nil {
		return nil, importDiag
	}

	return returnParser, nil
}

// Validate that the supplied informatin_asset name is found in the tm
func (tm *Threatmodel) validateInformationAssetRef(asset string) error {
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
