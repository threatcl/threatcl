package spec

import (
	"strings"
)

func (p *ThreatmodelParser) normalizeInitiativeSize(in string) string {
	if p.initiativeSizeOptions[strings.Title(strings.ToLower(in))] {
		return strings.Title(strings.ToLower(in))
	}

	return p.defaultInitiativeSize
}

func (p *ThreatmodelParser) normalizeInfoClassification(in string) string {
	if p.infoClassifications[strings.Title(strings.ToLower(in))] {
		return strings.Title(strings.ToLower(in))
	}
	return p.defaultInfoClassification
}

func (p *ThreatmodelParser) normalizeImpactType(in string) string {
	if p.impactTypes[strings.Title(strings.ToLower(in))] {
		return strings.Title(strings.ToLower(in))
	}
	return ""
}

func (p *ThreatmodelParser) normalizeStride(in string) string {
	if p.strideElements[strings.Title(strings.ToLower(in))] {
		return strings.Title(strings.ToLower(in))
	}
	return ""
}

func (p *ThreatmodelParser) normalizeUptimeDepClassification(in string) UptimeDependencyClassification {
	if p.uptimeDepClassification[strings.ToLower(in)] {
		return UptimeDependencyClassification(strings.ToLower(in))
	}
	return p.defaultUptimeDepClassification
}
