package example

default hello = false

hello {
	x := input.message
	x == sprintf("looking for %s", [data.world])
}
