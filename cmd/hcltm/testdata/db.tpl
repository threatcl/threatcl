# HCLTM Custom Dashboard

A dashboard of threat models.

## Threat Models

| name | author | new initiative? | internet facing? | size | Has DFD? |
| -- | -- | -- | -- | -- | -- |
{{- range . }}
| [{{ .Name }}]({{ .File }} "{{ .Hover }}") | {{ .Author }} | {{ .NewInitiative }} | {{ .InternetFacing }} | {{ .Size }} | {{ .HasDfd }} |
{{- end }}

