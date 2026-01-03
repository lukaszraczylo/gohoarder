{{/*
Expand the name of the chart.
*/}}
{{- define "gohoarder.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "gohoarder.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "gohoarder.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "gohoarder.labels" -}}
helm.sh/chart: {{ include "gohoarder.chart" . }}
{{ include "gohoarder.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "gohoarder.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gohoarder.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Server labels
*/}}
{{- define "gohoarder.server.labels" -}}
{{ include "gohoarder.labels" . }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Server selector labels
*/}}
{{- define "gohoarder.server.selectorLabels" -}}
{{ include "gohoarder.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "gohoarder.frontend.labels" -}}
{{ include "gohoarder.labels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "gohoarder.frontend.selectorLabels" -}}
{{ include "gohoarder.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Scanner labels
*/}}
{{- define "gohoarder.scanner.labels" -}}
{{ include "gohoarder.labels" . }}
app.kubernetes.io/component: scanner
{{- end }}

{{/*
Scanner selector labels
*/}}
{{- define "gohoarder.scanner.selectorLabels" -}}
{{ include "gohoarder.selectorLabels" . }}
app.kubernetes.io/component: scanner
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "gohoarder.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "gohoarder.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Generate admin API key
*/}}
{{- define "gohoarder.adminApiKey" -}}
{{- if .Values.auth.adminApiKey }}
{{- .Values.auth.adminApiKey }}
{{- else }}
{{- randAlphaNum 32 }}
{{- end }}
{{- end }}

{{/*
Storage volume configuration
*/}}
{{- define "gohoarder.storageVolume" -}}
{{- if eq .Values.storage.backend "filesystem" }}
{{- if .Values.storage.filesystem.useHostPath }}
- name: storage
  hostPath:
    path: {{ .Values.storage.filesystem.hostPath }}
    type: DirectoryOrCreate
{{- else if .Values.storage.filesystem.existingClaim }}
- name: storage
  persistentVolumeClaim:
    claimName: {{ .Values.storage.filesystem.existingClaim }}
{{- else }}
- name: storage
  persistentVolumeClaim:
    claimName: {{ include "gohoarder.fullname" . }}-storage
{{- end }}
{{- else }}
- name: storage
  emptyDir: {}
{{- end }}
{{- end }}

{{/*
Metadata volume configuration
*/}}
{{- define "gohoarder.metadataVolume" -}}
{{- if and (eq .Values.metadata.backend "sqlite") .Values.metadata.sqlite.persistence.enabled }}
{{- if .Values.metadata.sqlite.persistence.existingClaim }}
- name: metadata
  persistentVolumeClaim:
    claimName: {{ .Values.metadata.sqlite.persistence.existingClaim }}
{{- else }}
- name: metadata
  persistentVolumeClaim:
    claimName: {{ include "gohoarder.fullname" . }}-metadata
{{- end }}
{{- else }}
- name: metadata
  emptyDir: {}
{{- end }}
{{- end }}

{{/*
Trivy cache volume configuration
*/}}
{{- define "gohoarder.trivyCacheVolume" -}}
{{- if .Values.security.scanners.trivy.enabled }}
- name: trivy-cache
  emptyDir: {}
{{- end }}
{{- end }}

{{/*
Validate SQLite configuration - SQLite cannot be used with SMB/NFS network storage
*/}}
{{- define "gohoarder.validateSQLiteConfig" -}}
{{- if eq .Values.metadata.backend "sqlite" }}
  {{- if .Values.metadata.sqlite.persistence.enabled }}
    {{- $storageClass := .Values.metadata.sqlite.persistence.storageClass | default .Values.storage.storageClass }}
    {{- if or (contains "smb" ($storageClass | lower)) (contains "cifs" ($storageClass | lower)) (contains "nfs" ($storageClass | lower)) }}
      {{- fail "\n\n❌ ERROR: SQLite cannot be used with SMB/CIFS/NFS network storage!\n\nSQLite requires POSIX file locking which is not reliably supported over network filesystems.\nThis will cause 'database is locked' errors and data corruption.\n\nPlease choose ONE of the following solutions:\n\n1. Use PostgreSQL for network storage (RECOMMENDED for production):\n   metadata:\n     backend: postgresql\n     postgresql:\n       host: your-postgres-host\n       ...\n\n2. Use local storage for SQLite (OK for development):\n   metadata:\n     sqlite:\n       persistence:\n         enabled: true\n         storageClass: local-path  # or another local storage class\n\n3. Disable persistence (data will be lost on pod restart):\n   metadata:\n     sqlite:\n       persistence:\n         enabled: false\n\nFor more information, see: https://www.sqlite.org/lockingv3.html\n" }}
    {{- end }}
  {{- end }}
{{- end }}
{{- end }}
