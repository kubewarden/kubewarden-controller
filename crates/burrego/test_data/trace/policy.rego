package policy

default main = false

main {
  trace(sprintf("input.message has been set to '%v'", [input.message]));
  m := input.message;
  m == "world"
}
