package spec

type Attribute struct {
	NewInitiative  bool   `hcl:"new_initiative,attr"`
	InternetFacing bool   `hcl:"internet_facing,attr"`
	InitiativeSize string `hcl:"initiative_size,attr"`
}

type InformationAsset struct {
	Name                      string `hcl:"name,label"`
	Description               string `hcl:"description,optional"`
	InformationClassification string `hcl:"information_classification,optional"`
	Source                    string `hcl:"source,optional"`
}

type Threat struct {
	ImpactType           []string           `hcl:"impacts,optional"`
	Description          string             `hcl:"description,attr"`
	Control              string             `hcl:"control,optional"`
	Stride               []string           `hcl:"stride,optional"`
	InformationAssetRefs []string           `hcl:"information_asset_refs,optional"`
	ProposedControls     []*ProposedControl `hcl:"proposed_control,block"`
	Controls             []*Control         `hcl:"expanded_control,block"`
}

type ProposedControl struct {
	Implemented bool   `hcl:"implemented,optional"`
	Description string `hcl:"description"`
}

type Control struct {
	Name                string              `hcl:"name,label"`
	Implemented         bool                `hcl:"implemented,optional"`
	Description         string              `hcl:"description"`
	ImplementationNotes string              `hcl:"implementation_notes,optional"`
	RiskReduction       int                 `hcl:"risk_reduction,optional"`
	Attributes          []*ControlAttribute `hcl:"attribute,block"`
}

type ControlAttribute struct {
	Name  string `hcl:"name,label"`
	Value string `hcl:"value"`
}

type UseCase struct {
	Description string `hcl:"description,attr"`
}

type Exclusion struct {
	Description string `hcl:"description,attr"`
}

type UptimeDependencyClassification string

const (
	NoneUptime        UptimeDependencyClassification = "none"
	DegradedUptime                                   = "degraded"
	HardUptime                                       = "hard"
	OperationalUptime                                = "operational"
)

type ThirdPartyDependency struct {
	Name             string                         `hcl:"name,label"`
	Saas             bool                           `hcl:"saas,optional"`
	PayingCustomer   bool                           `hcl:"paying_customer,optional"`
	OpenSource       bool                           `hcl:"open_source,optional"`
	UptimeDependency UptimeDependencyClassification `hcl:"uptime_dependency,attr"`
	UptimeNotes      string                         `hcl:"uptime_notes,optional"`
	Infrastructure   bool                           `hcl:"infrastructure,optional"`
	Description      string                         `hcl:"description,attr"`
}

type DfdProcess struct {
	Name      string `hcl:"name,label"`
	TrustZone string `hcl:"trust_zone,optional"`
}

type DfdExternal struct {
	Name      string `hcl:"name,label"`
	TrustZone string `hcl:"trust_zone,optional"`
}

type DfdData struct {
	Name      string `hcl:"name,label"`
	TrustZone string `hcl:"trust_zone,optional"`
	IaLink    string `hcl:"information_asset,optional"`
}

type DfdFlow struct {
	Name string `hcl:"name,label"`
	From string `hcl:"from,attr"`
	To   string `hcl:"to,attr"`
}

type DfdTrustZone struct {
	Name             string         `hcl:"name,label"`
	Processes        []*DfdProcess  `hcl:"process,block"`
	ExternalElements []*DfdExternal `hcl:"external_element,block"`
	DataStores       []*DfdData     `hcl:"data_store,block"`
}

type DataFlowDiagram struct {
	Processes        []*DfdProcess   `hcl:"process,block"`
	ExternalElements []*DfdExternal  `hcl:"external_element,block"`
	DataStores       []*DfdData      `hcl:"data_store,block"`
	Flows            []*DfdFlow      `hcl:"flow,block"`
	TrustZones       []*DfdTrustZone `hcl:"trust_zone,block"`
	ImportFile       string          `hcl:"import,optional"`
}

type Threatmodel struct {
	Name                   string                  `hcl:"name,label"`
	Description            string                  `hcl:"description,optional"`
	Imports                []string                `hcl:"imports,optional"`
	Including              string                  `hcl:"including,optional"`
	Link                   string                  `hcl:"link,optional"`
	DiagramLink            string                  `hcl:"diagram_link,optional"`
	Author                 string                  `hcl:"author,attr"`
	CreatedAt              int64                   `hcl:"created_at,optional"`
	UpdatedAt              int64                   `hcl:"updated_at,optional"`
	Attributes             *Attribute              `hcl:"attributes,block"`
	InformationAssets      []*InformationAsset     `hcl:"information_asset,block"`
	Threats                []*Threat               `hcl:"threat,block"`
	UseCases               []*UseCase              `hcl:"usecase,block"`
	Exclusions             []*Exclusion            `hcl:"exclusion,block"`
	ThirdPartyDependencies []*ThirdPartyDependency `hcl:"third_party_dependency,block"`
	DataFlowDiagram        *DataFlowDiagram        `hcl:"data_flow_diagram,block"`
}

type Component struct {
	ComponentType string `hcl:"component_type,label"`
	ComponentName string `hcl:"component_name,label"`
	Description   string `hcl:"description,attr"`
}

type Variable struct {
	VariableName  string `hcl:"variable_name,label"`
	VariableValue string `hcl:"value,attr"`
}

type ThreatmodelWrapped struct {
	Threatmodels []Threatmodel `hcl:"threatmodel,block"`
	SpecVersion  string        `hcl:"spec_version,optional"`
	Components   []*Component  `hcl:"component,block"`
	Variables    []*Variable   `hcl:"variable,block"`
}
