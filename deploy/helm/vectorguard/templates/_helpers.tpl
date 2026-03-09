{{/*
Expand the name of the chart.
*/}}
{{- define "vectorguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "vectorguard.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "vectorguard.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "vectorguard.name" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "vectorguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vectorguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "vectorguard.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vectorguard.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Qdrant URL: use built-in or external
*/}}
{{- define "vectorguard.qdrantUrl" -}}
{{- if .Values.qdrant.enabled }}
{{- printf "http://qdrant.%s.svc.cluster.local:6333" .Release.Namespace }}
{{- else }}
{{- .Values.qdrant.externalUrl }}
{{- end }}
{{- end }}
