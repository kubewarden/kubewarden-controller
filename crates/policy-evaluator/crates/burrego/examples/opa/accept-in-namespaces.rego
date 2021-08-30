package kubernetes.admission

deny[msg] {
	object_namespace := input.request.object.metadata.namespace
	satisfied := [allowed_namespace | namespace = data.allowed_namespaces[_]; allowed_namespace = object_namespace == namespace]
	not any(satisfied)
	msg := sprintf("object created under an invalid namespace %s; allowed namespaces are %s", [object_namespace, concat(", ", data.allowed_namespaces)])
}
