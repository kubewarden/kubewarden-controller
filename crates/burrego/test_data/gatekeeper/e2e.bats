#!/usr/bin/env bats

@test "[accept in namespace]: valid namespace" {
  run cargo run --example  cli -- -v eval policy.wasm --input-path request-valid.json
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"result":.*\[\]') -ne 0 ]
}

@test "[accept in namespace]: not valid namespace" {
  run cargo run --example  cli -- -v eval policy.wasm --input-path request-not-valid.json
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"msg": "object created under an invalid namespace kube-system; allowed namespaces are \[default test\]"') -ne 0 ]
}
