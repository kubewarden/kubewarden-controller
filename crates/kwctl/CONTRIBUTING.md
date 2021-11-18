# Contributing

## Making a new release

1. Bump to `version = "vX.Y.Z"` on `cargo.toml`.
2. Run `git-chglog --next-tag vX.Y.Z --output CHANGELOG.md`.
3. Format if needed, commit and open PR (as `main` branch is protected).
4. Wait for PR to be merged.
5. Once the PR is in `main`, create an annotated signed tag on the merge commit
   of the PR in `main`:
   `git tag -s -a -m "vX.Y.Z" vX.Y.Z`. This will trigger the GH Action for
   release. Wait for it to complete and check that it is created.
6. If needed, edit the GH release description.
