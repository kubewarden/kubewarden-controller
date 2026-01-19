package policy

import data.kubernetes.admission

main = {
	"apiVersion": "admission.k8s.io/v1",
	"kind": "AdmissionReview",
	"response": response,
}

response = {
	"uid": input.request.uid,
	"allowed": false,
	"status": {"message": reason},
} {
	reason = concat(", ", admission.deny)
	reason != ""
} else = {
	"uid": input.request.uid,
	"allowed": true,
} {
	true
}
