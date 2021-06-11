package kubernetes.admission                                                # line 1
#package example

deny[msg] {                                                                 # line 2
  input.request.kind.kind == "Pod"                                          # line 3
  image := input.request.object.spec.containers[_].image                    # line 4
  not startswith(image, "hooli.com/")                                       # line 5
  msg := sprintf("image '%v' comes from untrusted registry", [image])       # line 6
}
