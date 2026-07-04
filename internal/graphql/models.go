package graphql

import (
	"github.com/threatcl/spec"
)

// mapThreatModelToGraphQL converts a spec.Threatmodel to a GraphQL ThreatModel
// including the sourceFile field which is not part of the spec
func mapThreatModelToGraphQL(tm *spec.Threatmodel, sourceFile string) *ThreatModel {
	if tm == nil {
		return nil
	}

	return &ThreatModel{
		Name:                   tm.Name,
		Author:                 tm.Author,
		Description:            strPtrOrNil(tm.Description),
		Link:                   strPtrOrNil(tm.Link),
		DiagramLink:            strPtrOrNil(tm.DiagramLink),
		Repository:             tm.Repository,
		CreatedAt:              int64PtrToIntPtr(tm.CreatedAt),
		UpdatedAt:              int64PtrToIntPtr(tm.UpdatedAt),
		Attributes:             mapAttributesToGraphQL(tm.Attributes),
		AdditionalAttributes:   tm.AdditionalAttributes,
		InformationAssets:      tm.InformationAssets,
		Threats:                tm.Threats,
		UseCases:               tm.UseCases,
		Exclusions:             tm.Exclusions,
		ThirdPartyDependencies: tm.ThirdPartyDependencies,
		DataFlowDiagrams:       tm.DataFlowDiagrams,
		MermaidDiagrams:        tm.MermaidDiagrams,
		SourceFile:             sourceFile,
	}
}

// mapRiskRatingToGraphQL converts a threat's optional risk block into a GraphQL
// RiskRating. The severity and score values are computed (they are methods on
// the spec types), and the residual view needs the parent threat in scope to
// account for implemented controls, so the whole threat is passed in. Returns
// nil when the threat has no risk block.
func mapRiskRatingToGraphQL(t *spec.Threat) *RiskRating {
	if t == nil || t.Risk == nil {
		return nil
	}

	return &RiskRating{
		Likelihood:            t.Risk.Likelihood,
		Impact:                t.Risk.Impact,
		Severity:              t.Risk.Severity(),
		Rationale:             strPtrOrNil(t.Risk.Rationale),
		InherentScore:         t.Risk.InherentScore(),
		ResidualScore:         t.ResidualScore(),
		ResidualSeverity:      t.ResidualSeverity(),
		ResidualRiskReduction: t.ResidualRiskReduction(),
	}
}

// mapAttributesToGraphQL converts spec.Attribute to GraphQL Attributes
func mapAttributesToGraphQL(attr *spec.Attribute) *Attributes {
	if attr == nil {
		return nil
	}

	return &Attributes{
		NewInitiative:  &attr.NewInitiative,
		InternetFacing: &attr.InternetFacing,
		InitiativeSize: strPtrOrNil(attr.InitiativeSize),
	}
}

// mapProcessToGraphQL converts spec.DfdProcess to GraphQL Process
func mapProcessToGraphQL(p *spec.DfdProcess) *Process {
	if p == nil {
		return nil
	}

	return &Process{
		Name:      p.Name,
		TrustZone: strPtrOrNil(p.TrustZone),
	}
}

// mapProcessesToGraphQL converts a slice of spec.DfdProcess to GraphQL Process
func mapProcessesToGraphQL(processes []*spec.DfdProcess) []*Process {
	if processes == nil {
		return []*Process{}
	}

	result := make([]*Process, len(processes))
	for i, p := range processes {
		result[i] = mapProcessToGraphQL(p)
	}
	return result
}

// mapDataStoreToGraphQL converts spec.DfdData to GraphQL DataStore
func mapDataStoreToGraphQL(ds *spec.DfdData) *DataStore {
	if ds == nil {
		return nil
	}

	return &DataStore{
		Name:             ds.Name,
		TrustZone:        strPtrOrNil(ds.TrustZone),
		InformationAsset: strPtrOrNil(ds.IaLink),
	}
}

// mapDataStoresToGraphQL converts a slice of spec.DfdData to GraphQL DataStore
func mapDataStoresToGraphQL(dataStores []*spec.DfdData) []*DataStore {
	if dataStores == nil {
		return []*DataStore{}
	}

	result := make([]*DataStore, len(dataStores))
	for i, ds := range dataStores {
		result[i] = mapDataStoreToGraphQL(ds)
	}
	return result
}

// mapExternalElementToGraphQL converts spec.DfdExternal to GraphQL ExternalElement
func mapExternalElementToGraphQL(ext *spec.DfdExternal) *ExternalElement {
	if ext == nil {
		return nil
	}

	return &ExternalElement{
		Name:      ext.Name,
		TrustZone: strPtrOrNil(ext.TrustZone),
	}
}

// mapExternalElementsToGraphQL converts a slice of spec.DfdExternal to GraphQL ExternalElement
func mapExternalElementsToGraphQL(elements []*spec.DfdExternal) []*ExternalElement {
	if elements == nil {
		return []*ExternalElement{}
	}

	result := make([]*ExternalElement, len(elements))
	for i, ext := range elements {
		result[i] = mapExternalElementToGraphQL(ext)
	}
	return result
}

// mapFlowToGraphQL converts spec.DfdFlow to GraphQL Flow
func mapFlowToGraphQL(f *spec.DfdFlow) *Flow {
	if f == nil {
		return nil
	}

	return &Flow{
		Name: f.Name,
		From: f.From,
		To:   f.To,
	}
}

// mapFlowsToGraphQL converts a slice of spec.DfdFlow to GraphQL Flow
func mapFlowsToGraphQL(flows []*spec.DfdFlow) []*Flow {
	if flows == nil {
		return []*Flow{}
	}

	result := make([]*Flow, len(flows))
	for i, f := range flows {
		result[i] = mapFlowToGraphQL(f)
	}
	return result
}

// mapTrustZoneToGraphQL converts spec.DfdTrustZone to GraphQL TrustZone
func mapTrustZoneToGraphQL(tz *spec.DfdTrustZone) *TrustZone {
	if tz == nil {
		return nil
	}

	return &TrustZone{
		Name: tz.Name,
	}
}

// mapTrustZonesToGraphQL converts a slice of spec.DfdTrustZone to GraphQL TrustZone
func mapTrustZonesToGraphQL(trustZones []*spec.DfdTrustZone) []*TrustZone {
	if trustZones == nil {
		return []*TrustZone{}
	}

	result := make([]*TrustZone, len(trustZones))
	for i, tz := range trustZones {
		result[i] = mapTrustZoneToGraphQL(tz)
	}
	return result
}

// Helper functions for optional field conversions

// strPtrOrNil returns a pointer to the string if it's not empty, otherwise nil
func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// int64PtrToIntPtr converts int64 to *int, returning nil for zero values
func int64PtrToIntPtr(i int64) *int {
	if i == 0 {
		return nil
	}
	val := int(i)
	return &val
}

// boolPtr returns a pointer to the boolean value
func boolPtr(b bool) *bool {
	return &b
}

// intPtr returns a pointer to the int value
func intPtr(i int) *int {
	return &i
}

// strPtr returns a pointer to the string value
func strPtr(s string) *string {
	return &s
}
