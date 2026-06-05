{{- define "redforge.labels" -}}
app.kubernetes.io/name: redforge
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "redforge.sparqlEndpoint" -}}
http://redforge-virtuoso.{{ .Release.Namespace }}.svc.cluster.local:8890/sparql
{{- end }}
