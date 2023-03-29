package spec

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	gg "github.com/hashicorp/go-getter"
	"github.com/hashicorp/go-multierror"
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

	for _, dfd := range subTm.DataFlowDiagrams {
		tm.addDfdIfNotExist(*dfd)
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

func (tm *Threatmodel) addDfdIfNotExist(newDfd DataFlowDiagram) {

	dfdFound := false
	for _, dfd := range tm.DataFlowDiagrams {
		if newDfd.Name == dfd.Name {
			dfdFound = true
		}
	}

	if dfdFound == false {
		tm.DataFlowDiagrams = append(tm.DataFlowDiagrams, &newDfd)
	}
}

func fetchRemoteTm(cfg *ThreatmodelSpecConfig, source, currentFilename string) (*ThreatmodelParser, error) {
	returnParser := NewThreatmodelParser(cfg)

	tmpDir, err := ioutil.TempDir("", "hcltm")
	if err != nil {
		return nil, err
	}

	// @TODO The below refers to a non-existent folder
	// to cater for https://github.com/hashicorp/go-getter/issues/114
	tmpDir = fmt.Sprintf("%s/nest", tmpDir)

	absPath, err := filepath.Abs(currentFilename)
	if err != nil {
		return nil, err
	}

	absPath = filepath.Dir(absPath)

	// @TODO The below is a hack to remote URLs
	// We allow an explicit "file" to be referenced after
	// a whole directory (i.e. git repo) is cloned
	// see: https://github.com/hashicorp/go-getter/issues/98

	// for example, the below allows a remote URL to look like
	// github.com/xntrik/hcltm|examples/aws-security-checklist.hcl
	// OR, something more complex, like a private repo
	// git::ssh://git@github.com/xntrik/test|aws-security-checklist.hcl
	splitSource := strings.SplitN(source, "|", 2)

	client := gg.Client{
		Src:  splitSource[0],
		Dst:  tmpDir,
		Pwd:  absPath,
		Mode: gg.ClientModeAny,
	}

	err = client.Get()
	if err != nil {
		return nil, err
	}

	// err = filepath.Walk(tmpDir,
	// 	func(path string, info os.FileInfo, err error) error {
	// 		if err != nil {
	// 			return err
	// 		}
	// 		fmt.Println(path, info.Size())
	// 		return nil
	// 	})
	// if err != nil {
	// 	fmt.Println("Error: ", err)
	// }

	includePath := ""

	switch len(splitSource) {
	case 1:
		includePath = fmt.Sprintf("%s/%s", tmpDir, filepath.Base(source))
	case 2:
		includePath = fmt.Sprintf("%s/%s", tmpDir, splitSource[1])
	}
	importDiag := returnParser.ParseHCLFile(includePath, false)

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

func (tm *Threatmodel) shiftLegacyDfd() (error, int) {
	if tm.LegacyDfd != nil {
		newDfd := &DataFlowDiagram{
			Name:              "Legacy DFD",
			ShiftedFromLegacy: true,
			Processes:         tm.LegacyDfd.Processes,
			ExternalElements:  tm.LegacyDfd.ExternalElements,
			DataStores:        tm.LegacyDfd.DataStores,
			Flows:             tm.LegacyDfd.Flows,
			TrustZones:        tm.LegacyDfd.TrustZones,
			ImportFile:        tm.LegacyDfd.ImportFile,
		}
		tm.LegacyDfd = nil
		tm.DataFlowDiagrams = append(tm.DataFlowDiagrams, newDfd)

		return nil, 1
	}
	return nil, 0
}

func (tm *Threatmodel) ValidateTm(p *ThreatmodelParser) error {
	var errMap error

	// Normalize threatmodel attributes
	if tm.Attributes != nil {

		// Normalize threatmodel attributes initiative_size
		if tm.Attributes.InitiativeSize != "" {
			tm.Attributes.InitiativeSize = p.normalizeInitiativeSize(tm.Attributes.InitiativeSize)
		}
	}

	// Checking for unique information_assets per threatmodel
	// Also Normalize info classification
	if tm.InformationAssets != nil {
		infoAssets := make(map[string]interface{})
		for _, ia := range tm.InformationAssets {
			if _, ok := infoAssets[ia.Name]; ok {
				errMap = multierror.Append(errMap, fmt.Errorf(
					"TM '%s': duplicate information_asset '%s'",
					tm.Name,
					ia.Name,
				))
			}

			// Normalize InformationClassification
			if ia.InformationClassification != "" {
				ia.InformationClassification = p.normalizeInfoClassification(ia.InformationClassification)
			}

			infoAssets[ia.Name] = nil
		}
	}

	// Validating any DFD data within a threat model
	// if tm.DataFlowDiagram != nil {
	for _, adfd := range tm.DataFlowDiagrams {

		// Checking for unique TrustZones
		zones := make(map[string]interface{})
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if _, ok := zones[zone.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate trust_zone block found '%s'",
						tm.Name,
						zone.Name,
					))
				}

				zones[zone.Name] = nil
			}
		}

		// Checking for unique processes/data_store/external_element in data_flow_diagram
		elements := make(map[string]interface{})
		if adfd.Processes != nil {
			for _, process := range adfd.Processes {
				if _, ok := elements[process.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate process found in dfd '%s'",
						tm.Name,
						process.Name,
					))
				}

				elements[process.Name] = nil
			}
		}

		// Now check for Processes in trust_zones
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if zone.Processes != nil {
					for _, process := range zone.Processes {
						if _, ok := elements[process.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate process found in dfd '%s'",
								tm.Name,
								process.Name,
							))
						}

						elements[process.Name] = nil
					}
				}
			}
		}

		if adfd.ExternalElements != nil {
			for _, external_element := range adfd.ExternalElements {
				if _, ok := elements[external_element.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate external_element found in dfd '%s'",
						tm.Name,
						external_element.Name,
					))
				}

				elements[external_element.Name] = nil
			}
		}

		// Now check for external_elements in trust_zones
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if zone.ExternalElements != nil {
					for _, external_element := range zone.ExternalElements {
						if _, ok := elements[external_element.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate external_element found in dfd '%s'",
								tm.Name,
								external_element.Name,
							))
						}

						elements[external_element.Name] = nil
					}
				}
			}
		}

		// Checking for unique data_stores in data_flow_diagram
		if adfd.DataStores != nil {
			for _, data_store := range adfd.DataStores {
				if _, ok := elements[data_store.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate data_store found in dfd '%s'",
						tm.Name,
						data_store.Name,
					))
				}

				elements[data_store.Name] = nil

				// While in DataStores, let's check if they have iaRefs, and that they
				// are valid
				if data_store.IaLink != "" {
					err := tm.validateInformationAssetRef(data_store.IaLink)
					if err != nil {
						errMap = multierror.Append(errMap, fmt.Errorf(
							"TM '%s' DFD Data Store '%s' %s",
							tm.Name,
							data_store.Name,
							err,
						))
					}
				}
			}
		}

		// Now check for data_stores in trust_zones
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if zone.DataStores != nil {
					for _, data_store := range zone.DataStores {
						if _, ok := elements[data_store.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate data_store found in dfd '%s'",
								tm.Name,
								data_store.Name,
							))
						}

						elements[data_store.Name] = nil

						// While in DataStores, let's check if they have iaRefs, and that they
						// are valid
						if data_store.IaLink != "" {
							err := tm.validateInformationAssetRef(data_store.IaLink)
							if err != nil {
								errMap = multierror.Append(errMap, fmt.Errorf(
									"TM '%s' DFD Data Store '%s' %s",
									tm.Name,
									data_store.Name,
									err,
								))
							}
						}
					}
				}
			}
		}

		// Now check for mis-matched trust-zones
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if zone.Processes != nil {
					for _, process := range zone.Processes {
						if process.TrustZone != "" && process.TrustZone != zone.Name {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': process trust_zone mis-match found in '%s'",
								tm.Name,
								process.Name,
							))
						}
					}
				}

				if zone.ExternalElements != nil {
					for _, external_element := range zone.ExternalElements {
						if external_element.TrustZone != "" && external_element.TrustZone != zone.Name {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': external_element trust_zone mis-match found in '%s'",
								tm.Name,
								external_element.Name,
							))
						}
					}
				}

				if zone.DataStores != nil {
					for _, data_store := range zone.DataStores {
						if data_store.TrustZone != "" && data_store.TrustZone != zone.Name {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': data_store trust_zone mis-match found in '%s'",
								tm.Name,
								data_store.Name,
							))
						}
					}
				}
			}
		}

		// Validate data flows
		flows := make(map[string]interface{})
		if adfd.Flows != nil {
			for _, rawflow := range adfd.Flows {
				flow := fmt.Sprintf("%s:%s", rawflow.From, rawflow.To)

				// check for unique flows
				if _, ok := flows[flow]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate flow found in dfd '%s'",
						tm.Name,
						flow,
					))
				}

				// now check that flows connect to legit processes
				if _, ok := elements[rawflow.From]; !ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': invalid from connection for flow '%s'",
						tm.Name,
						flow,
					))
				}

				if _, ok := elements[rawflow.To]; !ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': invalid to connection for flow '%s'",
						tm.Name,
						flow,
					))
				}

				// now check that the flow doesn't connect to itself
				if rawflow.From == rawflow.To {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': flow can't connect to itself '%s'",
						tm.Name,
						flow,
					))
				}

				flows[flow] = nil

			}
		}
	} // end of ranging over dataflowdiagrams

	// Normalize threat impacts and stride
	if tm.Threats != nil {
		for _, tr := range tm.Threats {
			normalized := []string{}
			for _, impact := range tr.ImpactType {
				normalized = append(normalized, p.normalizeImpactType(impact))
			}
			tr.ImpactType = normalized

			normalizedStride := []string{}
			for _, stride := range tr.Stride {
				normalizedStride = append(normalizedStride, p.normalizeStride(stride))
			}
			tr.Stride = normalizedStride

			// Validating that InformationAssetRefs are valid
			for _, iaRef := range tr.InformationAssetRefs {
				err := tm.validateInformationAssetRef(iaRef)
				if err != nil {
					errMap = multierror.Append(errMap,
						fmt.Errorf("TM '%s' / Threat '%s': %s", tm.Name, tr.Description, err),
					)
				}
			}
		}
	}

	// Normalize third party deps - uptime dep classification
	if tm.ThirdPartyDependencies != nil {
		for _, tpd := range tm.ThirdPartyDependencies {
			tpd.UptimeDependency = p.normalizeUptimeDepClassification(string(tpd.UptimeDependency))
		}
	}

	if errMap != nil {
		return errMap
	}

	return nil

}
