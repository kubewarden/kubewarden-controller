{{- define "kubewarden.defaults.podPrivileged" -}}
apiVersion: {{ $.Values.crdVersion }}
kind: ClusterAdmissionPolicy
metadata:
  name: {{ .Values.recommendedPolicies.podPrivilegedPolicy.name }}
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
  module: {{ template "policy_default_registry" . }}{{ .Values.recommendedPolicies.podPrivilegedPolicy.module.repository }}:{{ .Values.recommendedPolicies.podPrivilegedPolicy.module.tag }}
  mutating: false
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE"] # kubernetes doesn't allow to add/remove privileged containers to an already running pod
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
