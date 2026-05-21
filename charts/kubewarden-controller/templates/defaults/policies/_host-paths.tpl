{{- define "kubewarden.defaults.hostPaths" -}}
apiVersion: {{ $.Values.crdVersion }}
kind: ClusterAdmissionPolicy
metadata:
  name: {{ .Values.recommendedPolicies.hostPathsPolicy.name }}
  labels:
    app.kubernetes.io/part-of: kubewarden
    app.kubernetes.io/component: policy
    app.kubernetes.io/managed-by: kubewarden-controller
  annotations:
    io.kubewarden.policy.severity: medium
    io.kubewarden.policy.category: PSP
    {{- include "kubewarden-defaults.annotations" . | nindent 4 }}
spec:
  mode: {{ .Values.recommendedPolicies.defaultPolicyMode | default "monitor" }}
  failurePolicy: {{ include "policy_failure_policy" . | trim }}
  module: {{ template "policy_default_registry" . }}{{ .Values.recommendedPolicies.hostPathsPolicy.module.repository }}:{{ .Values.recommendedPolicies.hostPathsPolicy.module.tag }}
  mutating: false
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE", "UPDATE"]
  {{- include "policy-namespace-selector" . | nindent 2 }}
  settings: {{ .Values.recommendedPolicies.hostPathsPolicy.settings | toYaml | nindent 4 }}
{{- end -}}
