{{- define "kubewarden.defaults.allowPrivilegeEscalation" -}}
apiVersion: {{ $.Values.crdVersion }}
kind: ClusterAdmissionPolicy
metadata:
  name: {{ .Values.recommendedPolicies.allowPrivilegeEscalationPolicy.name }}
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
  module: {{ template "policy_default_registry" . }}{{ .Values.recommendedPolicies.allowPrivilegeEscalationPolicy.module.repository }}:{{ .Values.recommendedPolicies.allowPrivilegeEscalationPolicy.module.tag }}
  mutating: true
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE"] # kubernetes doesn't allow to add/remove privileged containers to an already running pod
  {{- include "policy-namespace-selector" . | nindent 2 }}
  settings: {{ .Values.recommendedPolicies.allowPrivilegeEscalationPolicy.settings | toYaml | nindent 4 }}
{{- end -}}
