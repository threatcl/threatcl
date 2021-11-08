<html><head><title>{{.Name}}</title></head>

<body>
<h1>{{.Name}}</h1>

Author: {{.Author}}{{ if .Description }}

<h2>Overview</h2>

{{ .Description }}<br /><br />
{{- end }}
{{- if .Link }}

See more: <a href="{{ .Link }}">{{ .Link }}</a><br />
{{- end }}
{{- if .DiagramLink }}
{{- if isImage .DiagramLink }}

<img src="{{ .DiagramLink }}" alt="Diagram" /><br />
{{- else }}

Diagram: <a href="{{ .DiagramLink }}">{{ .DiagramLink }}</a><br />
{{- end }}
{{- end }}
{{- with .Attributes }}

<table>
<tr><td>Internet Facing</td><td>{{ if (eq .InternetFacing true) }}✅ {{ else }}❌ {{ end }}</td></tr>
<tr><td>New Initiative</td><td>{{ if (eq .NewInitiative true) }}✅ {{ else }}❌ {{ end }}</td></tr>
<tr><td>Initiative Size</td><td>{{ .InitiativeSize }}</td></tr>
</table><br />
{{- end }}
{{- with .UseCases }}

<h2>Use Cases</h2>
<ul>
{{ range . }}
<li>{{ .Description }}</li>
{{- end }}
</ul>
{{- end }}
{{- with .Exclusions }}

<h2>Exclusions</h2>
<ul>
{{ range . }}
<li>{{ .Description }}</li>
{{- end }}
</ul>
{{- end }}
{{- with .InformationAssets }}

<h2>Information Assets</h2>
{{ range . }}
<h3>{{ .Name }} [{{ .InformationClassification }}]</h3>

{{ .Description }}
{{ if .Source }}
Source: {{ .Source }}{{- end }}
{{ end }}
{{- end }}
{{- with .Threats }}

<h2>Threat Scenarios</h2>
{{ range . }}
<h3>Threat</h3>

{{ .Description }}<br />

{{- if .ImpactType }}
<strong>Impact Type:</strong> {{ $impact := .ImpactType }}{{ range $index, $elem := .ImpactType }}{{ if $index}}, {{end}}{{.}}{{end}}<br />
{{- end }}
{{ if .Stride}}
<strong>STRIDE:</strong> {{ $stride := .Stride }}{{ range $index, $elem := .Stride }}{{ if $index}}, {{end}}{{.}}{{end}}<br />
{{- end}}
{{- if .InformationAssetRefs }}
<em>Impacted Information Assets:</em><br />

<ul>
{{ range .InformationAssetRefs }}<li>{{.}}</li>
{{ end}}
</ul>
{{- end}}
{{- if .Control }}

<h4>Control</h4>

{{ .Control }}<br />
{{- end }}
{{- end }}
{{- end }}

{{- with .ThirdPartyDependencies }}
<h4>Third Party Dependencies</h4>
{{ range . }}
<h5>{{ .Name }}</h5>

{{ .Description }}<br />
{{- if .Saas }}

{{ .Name }} is a SaaS product that we (the company) {{ if .PayingCustomer }}pays for{{ else }}does NOT pay for{{- end}}.<br />
{{- end }}
{{- if .Infrastructure }}

{{ .Name }} is an infrastructure product.<br />
{{- end }}
{{- if .OpenSource }}

{{ .Name }} is an open source dependency.<br />
{{- end }}
{{- if ne .UptimeDependency ""}}

<strong>Uptime Classification:</strong> {{ .UptimeDependency | ToUpper }}<br />

{{ .RenderUptime }}<br />
{{- end }}
{{- end }}
{{- end}}

{{- if .CreatedAt }}
{{- if .UpdatedAt }}

<hr></hr>

<em>Created:</em> {{ (unixToTime .CreatedAt) }} - Updated: {{ (unixToTime .UpdatedAt) }}<br />
{{- end }}
{{- end }}

