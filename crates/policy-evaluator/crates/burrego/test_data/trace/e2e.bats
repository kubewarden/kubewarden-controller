#!/usr/bin/env bats

@test "input message is not valid" {
  run cargo run --example  cli -- -v eval policy.wasm -i '{ "message": "mondo" }'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"result":.*false') -ne 0 ]
  [ $(expr "$output" : ".*input\.message has been set to 'mondo'") -ne 0 ]
}

@test "input message is valid" {
  run cargo run --example  cli -- -v eval policy.wasm -i '{ "message": "world" }'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"result":.*true') -ne 0 ]
  [ $(expr "$output" : ".*input\.message has been set to 'world'") -ne 0 ]
}
