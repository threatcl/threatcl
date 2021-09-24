# HCLTM Dashboard

A dashboard of threat models.

## Threat Models

| name | author | new initiative? | internet facing? | size |
| -- | -- | -- | -- | -- |
{{- range . }}
| [{{ .Name }}]({{ .File }} "{{ .Hover }}") | {{ .Author }} | {{ .NewInitiative }} | {{ .InternetFacing }} | {{ .Size }} |
{{- end }}
