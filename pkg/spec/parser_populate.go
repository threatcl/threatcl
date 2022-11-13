package spec

func (p *ThreatmodelParser) populateInitiativeSizeOptions() {

	for _, cfgInitiativeSizeOption := range p.specCfg.InitiativeSizes {
		p.initiativeSizeOptions[cfgInitiativeSizeOption] = true
	}
	p.defaultInitiativeSize = p.specCfg.DefaultInitiativeSize
}

func (p *ThreatmodelParser) populateInfoClassifications() {

	for _, cfgInfoClassification := range p.specCfg.InfoClassifications {
		p.infoClassifications[cfgInfoClassification] = true
	}
	p.defaultInfoClassification = p.specCfg.DefaultInfoClassification
}

func (p *ThreatmodelParser) populateImpactTypes() {
	for _, cfgImpactType := range p.specCfg.ImpactTypes {
		p.impactTypes[cfgImpactType] = true
	}
}

func (p *ThreatmodelParser) populateStrideElements() {
	for _, cfgStride := range p.specCfg.STRIDE {
		p.strideElements[cfgStride] = true
	}
}

func (p *ThreatmodelParser) populateUptimeDepClassifications() {
	for _, cfgUptimeDep := range p.specCfg.UptimeDepClassifications {
		p.uptimeDepClassification[cfgUptimeDep] = true
	}
	p.defaultUptimeDepClassification = UptimeDependencyClassification(p.specCfg.DefaultUptimeDepClassification)
}
