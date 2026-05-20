{{- define "kubewarden.defaults.podPrivileged" -}}
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: {{ .Values.recommendedPolicies.podPrivilegedPolicy.name }}
  annotations:
    io.kubewarden.policy.severity: medium
    io.kubewarden.policy.category: PSP
spec:
  mode: {{ .Values.recommendedPolicies.defaultPolicyMode | default "monitor" }}
  failurePolicy: {{ include "policy_failure_policy" . | trim }}
  module: {{ template "policy_default_registry" . }}{{ .Values.recommendedPolicies.podPrivilegedPolicy.module.repository }}:{{ .Values.recommendedPolicies.podPrivilegedPolicy.module.tag }}
  mutating: false
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE"]
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["replicationcontrollers"]
      operations: ["CREATE", "UPDATE"]
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
      operations: ["CREATE", "UPDATE"]
    - apiGroups: ["batch"]
      apiVersions: ["v1"]
      resources: ["jobs", "cronjobs"]
      operations: ["CREATE", "UPDATE"]
  {{- include "policy-namespace-selector" . | nindent 2 }}
  settings: {{ .Values.recommendedPolicies.podPrivilegedPolicy.settings | toYaml | nindent 4 }}
{{- end -}}
