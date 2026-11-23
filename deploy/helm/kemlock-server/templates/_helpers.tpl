{{/* The chart's name, and a release-scoped full name, cut to 63 characters. */}}
{{- define "kemlock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kemlock.fullname" -}}
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

{{- define "kemlock.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "kemlock.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "kemlock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kemlock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kemlock.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kemlock.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* The Secret holding DATABASE_URL, and the key in it. */}}
{{- define "kemlock.databaseSecretName" -}}
{{- default (printf "%s-database" (include "kemlock.fullname" .)) .Values.database.existingSecret }}
{{- end }}

{{/* Refuses the combinations that corrupt data or can't work. */}}
{{- define "kemlock.validate" -}}
{{- if not .Values.domain }}
{{- fail "domain is required: set it to the address clients use, such as https://vault.example.com" }}
{{- end }}
{{- if not (has .Values.database.type (list "sqlite" "postgres")) }}
{{- fail "database.type must be sqlite or postgres" }}
{{- end }}
{{- if and (eq .Values.database.type "postgres") (not .Values.database.url) (not .Values.database.existingSecret) }}
{{- fail "database.type=postgres needs database.url or database.existingSecret" }}
{{- end }}
{{- if gt (int .Values.replicaCount) 1 }}
{{- if ne .Values.database.type "postgres" }}
{{- fail "replicaCount > 1 needs database.type=postgres: a SQLite file can't be shared" }}
{{- end }}
{{- if ne .Values.blob.type "s3" }}
{{- fail "replicaCount > 1 needs blob.type=s3: a local folder can't be shared" }}
{{- end }}
{{- if not .Values.serverKey.existingSecret }}
{{- fail "replicaCount > 1 needs serverKey.existingSecret: every replica must use the same server key" }}
{{- end }}
{{- if .Values.persistence.enabled }}
{{- fail "replicaCount > 1 needs persistence.enabled=false: one ReadWriteOnce volume can't be shared; the database is PostgreSQL and attachments are in S3" }}
{{- end }}
{{- end }}
{{- if and (eq .Values.database.type "sqlite") (not .Values.persistence.enabled) }}
{{- fail "database.type=sqlite needs persistence.enabled=true: the database file lives in /data" }}
{{- end }}
{{- end }}
