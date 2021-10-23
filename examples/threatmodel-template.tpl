# {{.Name}}

Author: {{.Author}}{{ if .Description }}

## Overview

{{ .Description }}
{{- end }}
{{- if .Link }}

See more: {{ .Link }}
{{- end }}
{{- if .DiagramLink }}
{{- if isImage .DiagramLink }}

![Diagram]({{ .DiagramLink }} "Diagram")
{{- else }}

Diagram: {{ .DiagramLink }}
{{- end }}
{{- end }}
{{- with .Attributes }}

|    |    |
| -- | -- |
| Internet Facing | {{ if (eq .InternetFacing true) }}✅ {{ else }}❌ {{ end }} |
| New Initiative | {{ if (eq .NewInitiative true) }}✅ {{ else }}❌ {{ end }} |
| Initiative Size | {{ .InitiativeSize }} |
{{- end }}
{{- with .UseCases }}

## Use Cases
{{ range . }}
* {{ .Description }}
{{- end }}
{{- end }}
{{- with .Exclusions }}

## Exclusions
{{ range . }}
* {{ .Description }}
{{- end }}
{{- end }}
{{- with .InformationAssets }}

## Information Assets
{{ range . }}
### {{ .Name }} [{{ .InformationClassification }}]

{{ .Description }}
{{ end }}
{{- end }}
{{- with .Threats }}

## Threat Scenarios
{{ range . }}
### Threat

{{ .Description }}

{{- if .ImpactType }}

> Impact Type: {{ $impact := .ImpactType }}{{ range $index, $elem := .ImpactType }}{{ if $index}}, {{end}}{{.}}{{end}}
{{- end }}
{{ if .Stride}}
> STRIDE: {{ $stride := .Stride }}{{ range $index, $elem := .Stride }}{{ if $index}}, {{end}}{{.}}{{end}}
{{- end}}
{{- if .InformationAssetRefs }}
Impacted Information Assets:

{{ range .InformationAssetRefs }}* {{.}}
{{ end}}
{{- end}}
{{- if .Control }}

#### Control

{{ .Control }}
{{- end }}
{{- end }}
{{- end }}

{{- with .ThirdPartyDependencies }}
## Third Party Dependencies
{{ range . }}
### {{ .Name }}

{{ .Description }}
{{- if .Saas }}

{{ .Name }} is a SaaS product that we (the company) {{ if .PayingCustomer }}pays for{{ else }}does NOT pay for{{- end}}.
{{- end }}
{{- if .Infrastructure }}

{{ .Name }} is an infrastructure product.
{{- end }}
{{- if .OpenSource }}

{{ .Name }} is an open source dependency.
{{- end }}
{{- if ne .UptimeDependency ""}}

> Uptime Classification: {{ .UptimeDependency | ToUpper }}

{{ .RenderUptime }}
{{- end }}
{{- end }}
{{- end}}

{{- if .CreatedAt }}
{{- if .UpdatedAt }}

---

Created: {{ (unixToTime .CreatedAt) }} - Updated: {{ (unixToTime .UpdatedAt) }}
{{- end }}
{{- end }}

