package spec

type Attribute struct {
	NewInitiative  bool   `json:"newInitiative" hcl:"new_initiative,attr"`
	InternetFacing bool   `json:"internetFacing" hcl:"internet_facing,attr"`
	InitiativeSize string `json:"initiativeSize" hcl:"initiative_size,attr"`
}

type AdditionalAttribute struct {
	Name  string `json:"name" hcl:"name,label"`
	Value string `json:"value" hcl:"value"`
}

type InformationAsset struct {
	Name                      string `json:"name" hcl:"name,label"`
	Description               string `json:"description,omitempty" hcl:"description,optional"`
	InformationClassification string `json:"informationClassification,omitempty" hcl:"information_classification,optional"`
	Source                    string `json:"source,omitempty" hcl:"source,optional"`
}

type Threat struct {
	ImpactType           []string           `json:"impacts,omitempty" hcl:"impacts,optional"`
	Description          string             `json:"description" hcl:"description,attr"`
	Control              string             `json:"control,omitempty" hcl:"control,optional"`
	Stride               []string           `json:"stride,omitempty" hcl:"stride,optional"`
	InformationAssetRefs []string           `json:"informationAssetRefs,omitempty" hcl:"information_asset_refs,optional"`
	ProposedControls     []*ProposedControl `json:"proposedControl,omitempty" hcl:"proposed_control,block"`
	Controls             []*Control         `json:"expandedControl,omitempty" hcl:"expanded_control,block"`
}

type ProposedControl struct {
	Implemented bool   `json:"implemented,omitempty" hcl:"implemented,optional"`
	Description string `json:"description" hcl:"description"`
}

type Control struct {
	Name                string              `json:"name" hcl:"name,label"`
	Implemented         bool                `json:"implemented,omitempty" hcl:"implemented,optional"`
	Description         string              `json:"description" hcl:"description"`
	ImplementationNotes string              `json:"implementationNotes,omitempty" hcl:"implementation_notes,optional"`
	RiskReduction       int                 `json:"riskReduction,omitempty" hcl:"risk_reduction,optional"`
	Attributes          []*ControlAttribute `json:"attribute,omitempty" hcl:"attribute,block"`
}

type ControlAttribute struct {
	Name  string `json:"name" hcl:"name,label"`
	Value string `json:"value" hcl:"value"`
}

type UseCase struct {
	Description string `json:"description" hcl:"description,attr"`
}

type Exclusion struct {
	Description string `json:"description" hcl:"description,attr"`
}

type UptimeDependencyClassification string

const (
	NoneUptime        UptimeDependencyClassification = "none"
	DegradedUptime                                   = "degraded"
	HardUptime                                       = "hard"
	OperationalUptime                                = "operational"
)

type ThirdPartyDependency struct {
	Name             string                         `json:"name" hcl:"name,label"`
	Saas             bool                           `json:"saas,omitempty" hcl:"saas,optional"`
	PayingCustomer   bool                           `json:"payingCustomer,omitempty" hcl:"paying_customer,optional"`
	OpenSource       bool                           `json:"openSource,omitempty" hcl:"open_source,optional"`
	UptimeDependency UptimeDependencyClassification `json:"uptimeDependency" hcl:"uptime_dependency,attr"`
	UptimeNotes      string                         `json:"uptimeNotes,omitempty" hcl:"uptime_notes,optional"`
	Infrastructure   bool                           `json:"infrastructure,omitempty" hcl:"infrastructure,optional"`
	Description      string                         `json:"description" hcl:"description,attr"`
}

type DfdProcess struct {
	Name      string `json:"name" hcl:"name,label"`
	TrustZone string `json:"trustZone,omitempty" hcl:"trust_zone,optional"`
}

type DfdExternal struct {
	Name      string `json:"name" hcl:"name,label"`
	TrustZone string `json:"trustZone,omitempty" hcl:"trust_zone,optional"`
}

type DfdData struct {
	Name      string `json:"name" hcl:"name,label"`
	TrustZone string `json:"trustZone,omitempty" hcl:"trust_zone,optional"`
	IaLink    string `json:"informationAsset,omitempty" hcl:"information_asset,optional"`
}

type DfdFlow struct {
	Name string `json:"name" hcl:"name,label"`
	From string `json:"from" hcl:"from,attr"`
	To   string `json:"to" hcl:"to,attr"`
}

type DfdTrustZone struct {
	Name             string         `json:"name" hcl:"name,label"`
	Processes        []*DfdProcess  `json:"process,omitempty" hcl:"process,block"`
	ExternalElements []*DfdExternal `json:"externalElement,omitempty" hcl:"external_element,block"`
	DataStores       []*DfdData     `json:"dataStore,omitempty" hcl:"data_store,block"`
}

type LegacyDataFlowDiagram struct {
	Processes        []*DfdProcess   `json:"process,omitempty" hcl:"process,block"`
	ExternalElements []*DfdExternal  `json:"externalElement,omitempty" hcl:"external_element,block"`
	DataStores       []*DfdData      `json:"dataStore,omitempty" hcl:"data_store,block"`
	Flows            []*DfdFlow      `json:"flow,omitempty" hcl:"flow,block"`
	TrustZones       []*DfdTrustZone `json:"trustZone,omitempty" hcl:"trust_zone,block"`
	ImportFile       string          `json:"import,omitempty" hcl:"import,optional"`
}

type DataFlowDiagram struct {
	Name              string          `json:"name" hcl:"name,label"`
	ShiftedFromLegacy bool            `json:"-"`
	Processes         []*DfdProcess   `json:"process,omitempty" hcl:"process,block"`
	ExternalElements  []*DfdExternal  `json:"externalElement,omitempty" hcl:"external_element,block"`
	DataStores        []*DfdData      `json:"dataStore,omitempty" hcl:"data_store,block"`
	Flows             []*DfdFlow      `json:"flow,omitempty" hcl:"flow,block"`
	TrustZones        []*DfdTrustZone `json:"trustZone,omitempty" hcl:"trust_zone,block"`
	ImportFile        string          `json:"-" hcl:"import,optional"`
}

type Threatmodel struct {
	Name                   string                  `json:"name" hcl:"name,label"`
	Description            string                  `json:"description,omitempty" hcl:"description,optional"`
	Imports                []string                `json:"-" hcl:"imports,optional"`
	Including              string                  `json:"including,omitempty" hcl:"including,optional"`
	Link                   string                  `json:"link,omitempty" hcl:"link,optional"`
	DiagramLink            string                  `json:"diagramLink,omitempty" hcl:"diagram_link,optional"`
	AllDiagrams            []string                `json:"-"` // Used for templates
	Author                 string                  `json:"author" hcl:"author,attr"`
	CreatedAt              int64                   `json:"createdAt,omitempty" hcl:"created_at,optional"`
	UpdatedAt              int64                   `json:"updatedAt,omitempty" hcl:"updated_at,optional"`
	Attributes             *Attribute              `json:"attributes,omitempty" hcl:"attributes,block"`
	AdditionalAttributes   []*AdditionalAttribute  `json:"additionalAttribute,omitempty" hcl:"additional_attribute,block"`
	InformationAssets      []*InformationAsset     `json:"informationAsset,omitempty" hcl:"information_asset,block"`
	Threats                []*Threat               `json:"threat,omitempty" hcl:"threat,block"`
	UseCases               []*UseCase              `json:"useCase,omitempty" hcl:"usecase,block"`
	Exclusions             []*Exclusion            `json:"exclusion,omitempty" hcl:"exclusion,block"`
	ThirdPartyDependencies []*ThirdPartyDependency `json:"thirdPartyDependency,omitempty" hcl:"third_party_dependency,block"`
	DataFlowDiagrams       []*DataFlowDiagram      `json:"dataFlowDiagram,omitempty" hcl:"data_flow_diagram_v2,block"`
	LegacyDfd              *LegacyDataFlowDiagram  `json:"legacyDataFlowDiagram,omitempty" hcl:"data_flow_diagram,block"`
}

type Component struct {
	ComponentType string `json:"componentType" hcl:"component_type,label"`
	ComponentName string `json:"componentName" hcl:"component_name,label"`
	Description   string `json:"description" hcl:"description,attr"`
}

type Variable struct {
	VariableName  string `json:"variableName" hcl:"variable_name,label"`
	VariableValue string `json:"variableValue" hcl:"value,attr"`
}

type ThreatmodelWrapped struct {
	Threatmodels []Threatmodel `json:"threatmodels" hcl:"threatmodel,block"`
	SpecVersion  string        `json:"specVersion,omitempty" hcl:"spec_version,optional"`
	Components   []*Component  `json:"components,omitempty" hcl:"component,block"`
	Variables    []*Variable   `json:"variables,omitempty" hcl:"variable,block"`
}
