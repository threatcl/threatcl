<html><head><title>HCLTM Dashboard</title></head>

<body>
<h1>HCLTM Dashboard</h1>

A dashboard of threat models.

<h2>Threat Models</h2>

<table>
  <tr><th>name</th><th>author</th><th>new initiative?</th><th>internet facing?</th><th>size</th></tr>
{{- range . }}
  <tr><td><a href="{{ .File }}" title="{{ .Hover }}">{{ .Name }}</a></td><td>{{ .Author }}</td><td>{{ .NewInitiative }}</td><td>{{ .InternetFacing }}</td><td>{{ .Size }}</td></tr>
{{- end }}
</table>
</body>
</html>
