{{- define "kubewarden.defaults.allowPrivilegeEscalation" -}}
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: {{ .Values.recommendedPolicies.allowPrivilegeEscalationPolicy.name }}
  annotations:
    io.kubewarden.policy.severity: medium
    io.kubewarden.policy.category: PSP
spec:
  mode: {{ .Values.recommendedPolicies.defaultPolicyMode | default "monitor" }}
  failurePolicy: {{ include "policy_failure_policy" . | trim }}
  module: {{ template "policy_default_registry" . }}{{ .Values.recommendedPolicies.allowPrivilegeEscalationPolicy.module.repository }}:{{ .Values.recommendedPolicies.allowPrivilegeEscalationPolicy.module.tag }}
  mutating: true
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE", "UPDATE"]
  {{- include "policy-namespace-selector" . | nindent 2 }}
  settings: {{ .Values.recommendedPolicies.allowPrivilegeEscalationPolicy.settings | toYaml | nindent 4 }}
{{- end -}}
