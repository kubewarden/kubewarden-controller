package kubernetes.admission

# RBAC alone would suffice here, but we create a policy just to show
# how it can be done as well.
deny[msg] {
	input.request.object.metadata.namespace == "default"
	msg := "you cannot use the default namespace"
}
