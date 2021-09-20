package policy

violation[{"msg": msg}] {
	object_namespace := input.review.object.metadata.namespace
	satisfied := [allowed_namespace | namespace = input.parameters.allowed_namespaces[_]; allowed_namespace = object_namespace == namespace]
	not any(satisfied)
	msg := sprintf("object created under an invalid namespace %s; allowed namespaces are %v", [object_namespace, input.parameters.allowed_namespaces])
}
