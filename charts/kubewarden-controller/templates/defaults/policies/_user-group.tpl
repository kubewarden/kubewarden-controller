{{- define "kubewarden.defaults.userGroup" -}}
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: {{ .Values.recommendedPolicies.userGroupPolicy.name }}
  annotations:
    io.kubewarden.policy.severity: medium
    io.kubewarden.policy.category: PSP
spec:
  mode: {{ .Values.recommendedPolicies.defaultPolicyMode | default "monitor" }}
  failurePolicy: {{ include "policy_failure_policy" . | trim }}
  module: {{ template "policy_default_registry" . }}{{ .Values.recommendedPolicies.userGroupPolicy.module.repository }}:{{ .Values.recommendedPolicies.userGroupPolicy.module.tag }}
  mutating: true
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE"]
  {{- include "policy-namespace-selector" . | nindent 2 }}
  settings: {{ .Values.recommendedPolicies.userGroupPolicy.settings | toYaml | nindent 4 }}
{{- end -}}
