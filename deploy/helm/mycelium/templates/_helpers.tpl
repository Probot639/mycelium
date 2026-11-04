{{/*
Chart name, overridable with nameOverride / fullnameOverride like the common
Helm charts, so two releases in one namespace don't clash.
*/}}
{{- define "mycelium.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mycelium.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "mycelium.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Labels every object carries. */}}
{{- define "mycelium.labels" -}}
helm.sh/chart: {{ include "mycelium.chart" . }}
{{ include "mycelium.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "mycelium.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mycelium.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
The in-cluster host:port the fuzzer pods dial. Service name is the coordinator
fullname; the port comes from values.
*/}}
{{- define "mycelium.coordinatorAddr" -}}
{{- printf "%s-coordinator:%d" (include "mycelium.fullname" .) (int .Values.coordinator.service.port) -}}
{{- end -}}

{{/* Full image ref, repository:tag. */}}
{{- define "mycelium.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | toString) -}}
{{- end -}}
