# Contributing

## Making a new release

1. Bump to `version = "X.Y.Z"` on `cargo.toml`.
2. Format if needed, commit and open PR (as `main` branch is protected).
3. Wait for PR to be merged.
4. Once the PR is in `main`, create an annotated signed tag on the merge commit
   of the PR in `main`:
   `git tag -s -a -m "vX.Y.Z" vX.Y.Z`. This will trigger the GH Action for
   release. Wait for it to complete and check that it is created.
5. If needed, edit the GH release description.

## GitHub Actions

For some workflows, GITHUB_TOKEN needs read and write permissions (e.g: to
perform cosign signatures); if you have forked the repository, you may need to
change "settings -> actions -> general -> workflow permissions"  to "Read and
write permissions".

Also, given how the release and release-drafter workflows work, they need git
tags present; push the tags from origin to your fork.
