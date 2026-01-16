{{/*
Expand the name of the chart.
*/}}
{{- define "kubewarden-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kubewarden-controller.fullname" -}}
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
Create default fully qualified audit-scanner name
Truncate to 53 per CronJob docs, as k8s controller appends chars when spawning
the job Pods.
*/}}
{{- define "audit-scanner.fullname" -}}
{{- if .Values.fullnameOverride }}
{{-   .Values.fullnameOverride | trunc 53 | trimSuffix "-" }}
{{- else }}
{{-   $name := default "audit-scanner" .Values.nameOverride }}
{{-   if contains $name .Release.Name }}
{{-     .Release.Name | trunc 53 | trimSuffix "-" }}
{{-   else }}
{{-     $name | trunc 53 | trimSuffix "-" }}
{{-   end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kubewarden-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kubewarden-controller.labels" -}}
helm.sh/chart: {{ include "kubewarden-controller.chart" . }}
{{ include "kubewarden-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: controller
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: kubewarden
{{- if .Values.additionalLabels }}
{{ toYaml .Values.additionalLabels }}
{{- end }}
{{- end }}

{{/*
Print the image pull secrets in the expected format (an array of objects with one possible field, "name").
*/}}
{{- define "imagePullSecrets" }}
    {{- $imagePullSecrets := list }}
    {{- range . }}
        {{- if kindIs "string" . }}
            {{- $imagePullSecrets = append $imagePullSecrets (dict "name" .) }}
        {{- else }}
            {{- $imagePullSecrets = append $imagePullSecrets . }}
        {{- end }}
    {{- end }}
    {{- toYaml $imagePullSecrets }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kubewarden-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubewarden-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Annotations
*/}}
{{- define "kubewarden-controller.annotations" -}}
{{- if .Values.additionalAnnotations }}
{{ toYaml .Values.additionalAnnotations }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for kubewarden-controller
*/}}
{{- define "kubewarden-controller.serviceAccountName" -}}
{{- include "kubewarden-controller.fullname" . }}
{{- end }}

{{- define "system_default_registry" -}}
{{- if .Values.global.cattle.systemDefaultRegistry -}}
{{- printf "%s/" .Values.global.cattle.systemDefaultRegistry -}}
{{- else -}}
{{- "" -}}
{{- end -}}
{{- end -}}

{{- define "audit-scanner.command" -}}
{{- $parallelNamespaces := .Values.auditScanner.parallelNamespaces | int -}}
{{- $parallelResources := .Values.auditScanner.parallelResources | int -}}
{{- $parallelPolicies := .Values.auditScanner.parallelPolicies | int -}}
{{- $pageSize := .Values.auditScanner.pageSize| int -}}
- /audit-scanner
- --kubewarden-namespace
- {{ .Release.Namespace }}
- --loglevel
- {{ .Values.auditScanner.logLevel }}
{{- if gt $parallelNamespaces 0 }}
- --parallel-namespaces
- "{{ $parallelNamespaces }}"
{{- end }}
{{- if gt $parallelResources 0 }}
- --parallel-resources
- "{{ $parallelResources }}"
{{- end }}
{{- if gt $parallelPolicies 0 }}
- --parallel-policies
- "{{ $parallelPolicies }}"
{{- end }}
{{- if gt $pageSize 0 }}
- --page-size
- "{{ $pageSize }}"
{{- end }}
{{- if .Values.auditScanner.disableStore }}
- --disable-store
{{- end }}
- --extra-ca
- "/pki/ca.crt"
- --client-cert
- "/client-cert/tls.crt"
- --client-key
- "/client-cert/tls.key"
{{- if .Values.auditScanner.outputScan }}
- --output-scan
{{- end }}
{{- range .Values.global.skipNamespaces }}
- {{ printf "-i" }}
- {{ printf "%s" . }}
{{- end -}}
{{- range .Values.auditScanner.skipAdditionalNamespaces }}
- {{ printf "-i" }}
- {{ printf "%s" . }}
{{- end -}}
{{- if .Values.auditScanner.reportCRDsKind }}
- --report-kind
- {{ .Values.auditScanner.reportCRDsKind }}
{{- end -}}
{{- end -}}
