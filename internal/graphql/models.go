package graphql

import (
	"github.com/threatcl/spec"
)

// MapThreatModelToGraphQL converts a spec.Threatmodel to a GraphQL ThreatModel
// including the sourceFile field which is not part of the spec
func MapThreatModelToGraphQL(tm *spec.Threatmodel, sourceFile string) *ThreatModel {
	if tm == nil {
		return nil
	}

	return &ThreatModel{
		Name:                   tm.Name,
		Author:                 tm.Author,
		Description:            strPtrOrNil(tm.Description),
		Link:                   strPtrOrNil(tm.Link),
		DiagramLink:            strPtrOrNil(tm.DiagramLink),
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
		SourceFile:             sourceFile,
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

// MapProcessToGraphQL converts spec.DfdProcess to GraphQL Process
func MapProcessToGraphQL(p *spec.DfdProcess) *Process {
	if p == nil {
		return nil
	}

	return &Process{
		Name:      p.Name,
		TrustZone: strPtrOrNil(p.TrustZone),
	}
}

// MapProcessesToGraphQL converts a slice of spec.DfdProcess to GraphQL Process
func MapProcessesToGraphQL(processes []*spec.DfdProcess) []*Process {
	if processes == nil {
		return []*Process{}
	}

	result := make([]*Process, len(processes))
	for i, p := range processes {
		result[i] = MapProcessToGraphQL(p)
	}
	return result
}

// MapDataStoreToGraphQL converts spec.DfdData to GraphQL DataStore
func MapDataStoreToGraphQL(ds *spec.DfdData) *DataStore {
	if ds == nil {
		return nil
	}

	return &DataStore{
		Name:             ds.Name,
		TrustZone:        strPtrOrNil(ds.TrustZone),
		InformationAsset: strPtrOrNil(ds.IaLink),
	}
}

// MapDataStoresToGraphQL converts a slice of spec.DfdData to GraphQL DataStore
func MapDataStoresToGraphQL(dataStores []*spec.DfdData) []*DataStore {
	if dataStores == nil {
		return []*DataStore{}
	}

	result := make([]*DataStore, len(dataStores))
	for i, ds := range dataStores {
		result[i] = MapDataStoreToGraphQL(ds)
	}
	return result
}

// MapExternalElementToGraphQL converts spec.DfdExternal to GraphQL ExternalElement
func MapExternalElementToGraphQL(ext *spec.DfdExternal) *ExternalElement {
	if ext == nil {
		return nil
	}

	return &ExternalElement{
		Name:      ext.Name,
		TrustZone: strPtrOrNil(ext.TrustZone),
	}
}

// MapExternalElementsToGraphQL converts a slice of spec.DfdExternal to GraphQL ExternalElement
func MapExternalElementsToGraphQL(elements []*spec.DfdExternal) []*ExternalElement {
	if elements == nil {
		return []*ExternalElement{}
	}

	result := make([]*ExternalElement, len(elements))
	for i, ext := range elements {
		result[i] = MapExternalElementToGraphQL(ext)
	}
	return result
}

// MapFlowToGraphQL converts spec.DfdFlow to GraphQL Flow
func MapFlowToGraphQL(f *spec.DfdFlow) *Flow {
	if f == nil {
		return nil
	}

	return &Flow{
		Name: f.Name,
		From: f.From,
		To:   f.To,
	}
}

// MapFlowsToGraphQL converts a slice of spec.DfdFlow to GraphQL Flow
func MapFlowsToGraphQL(flows []*spec.DfdFlow) []*Flow {
	if flows == nil {
		return []*Flow{}
	}

	result := make([]*Flow, len(flows))
	for i, f := range flows {
		result[i] = MapFlowToGraphQL(f)
	}
	return result
}

// MapTrustZoneToGraphQL converts spec.DfdTrustZone to GraphQL TrustZone
func MapTrustZoneToGraphQL(tz *spec.DfdTrustZone) *TrustZone {
	if tz == nil {
		return nil
	}

	return &TrustZone{
		Name: tz.Name,
	}
}

// MapTrustZonesToGraphQL converts a slice of spec.DfdTrustZone to GraphQL TrustZone
func MapTrustZonesToGraphQL(trustZones []*spec.DfdTrustZone) []*TrustZone {
	if trustZones == nil {
		return []*TrustZone{}
	}

	result := make([]*TrustZone, len(trustZones))
	for i, tz := range trustZones {
		result[i] = MapTrustZoneToGraphQL(tz)
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
