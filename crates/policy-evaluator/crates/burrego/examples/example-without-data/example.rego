package example

default hello = false

hello {
    m := input.message
    m == "world"
}
