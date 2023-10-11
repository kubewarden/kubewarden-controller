## Generating CRD docs for the kubewarden/docs

Make sure that crd-ref-docs is installed from
https://github.com/elastic/crd-ref-docs/releases

Then running `make` should generate `CRD-docs-for-docs-repo.md`. 
This entire file should be inserted in the kubewarden/docs repository in docs/operator-manual/CRDs.md

Bit yucky, but it will do for now.