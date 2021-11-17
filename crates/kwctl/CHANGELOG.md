<a name="unreleased"></a>
## [Unreleased]


<a name="v0.2.3"></a>
## [v0.2.3] - 2021-11-16
### Bug Fixes
- ensure latest version of wasmtime is used

### Code Refactoring
- Use Option<&T> for kwctl functions
- Bump pod-privileged-policy to v0.1.9 in e2e-tests

### Features
- Verify with keys and annotations for `kwctl {pull, run, verify}`
- Add `verify::verify_local_checksum()`
- Implement the verify sub-command

### Pull Requests
- Merge pull request [#84](https://github.com/kubewarden/kwctl/issues/84) from viccuad/sigstore-verify
- Merge pull request [#83](https://github.com/kubewarden/kwctl/issues/83) from ereslibre/update-policy-fetcher
- Merge pull request [#82](https://github.com/kubewarden/kwctl/issues/82) from kubewarden/update-readme
- Merge pull request [#79](https://github.com/kubewarden/kwctl/issues/79) from kubewarden/policy-digest-refactoring
- Merge pull request [#78](https://github.com/kubewarden/kwctl/issues/78) from kubewarden/verify
- Merge pull request [#77](https://github.com/kubewarden/kwctl/issues/77) from kubewarden/upgrade-to-latest-wasmtime
- Merge pull request [#72](https://github.com/kubewarden/kwctl/issues/72) from kubewarden/cargo-args-refactoring


<a name="v0.2.2"></a>
## [v0.2.2] - 2021-10-04

<a name="v0.2.1"></a>
## [v0.2.1] - 2021-09-24

<a name="v0.2.0"></a>
## [v0.2.0] - 2021-09-20
### Features
- implement logging

### Pull Requests
- Merge pull request [#68](https://github.com/kubewarden/kwctl/issues/68) from kubewarden/opa
- Merge pull request [#65](https://github.com/kubewarden/kwctl/issues/65) from kubewarden/builtin-report
- Merge pull request [#62](https://github.com/kubewarden/kwctl/issues/62) from kubewarden/kwctl-do-not-allow-rego-policies-to-be-pushed-without-metadata
- Merge pull request [#61](https://github.com/kubewarden/kwctl/issues/61) from kubewarden/execution-mode-and-run-command
- Merge pull request [#60](https://github.com/kubewarden/kwctl/issues/60) from kubewarden/handle-execution-mode-inside-of-annote-and-inspect
- Merge pull request [#56](https://github.com/kubewarden/kwctl/issues/56) from kubewarden/burrego


<a name="v0.1.10"></a>
## [v0.1.10] - 2021-06-24
### Pull Requests
- Merge pull request [#53](https://github.com/kubewarden/kwctl/issues/53) from kubewarden/completions
- Merge pull request [#51](https://github.com/kubewarden/kwctl/issues/51) from kubewarden/manifest-generate-settings


<a name="v0.1.9"></a>
## [v0.1.9] - 2021-06-16

<a name="v0.1.8"></a>
## [v0.1.8] - 2021-06-16
### Features
- initialize cluster context only if the policy metadata says so

### Pull Requests
- Merge pull request [#50](https://github.com/kubewarden/kwctl/issues/50) from kubewarden/context-aware


<a name="v0.1.7"></a>
## [v0.1.7] - 2021-06-10
### Features
- allow `--settings-json` to provide empty settings
- provide request on stdin

### Pull Requests
- Merge pull request [#45](https://github.com/kubewarden/kwctl/issues/45) from kubewarden/request-stdin


<a name="v0.1.6"></a>
## [v0.1.6] - 2021-06-09
### Pull Requests
- Merge pull request [#42](https://github.com/kubewarden/kwctl/issues/42) from kubewarden/extend-push


<a name="v0.1.5"></a>
## [v0.1.5] - 2021-06-03
### Pull Requests
- Merge pull request [#39](https://github.com/kubewarden/kwctl/issues/39) from kubewarden/policy-testdrive-missing-features


<a name="v0.1.4"></a>
## [v0.1.4] - 2021-06-01

<a name="v0.1.3"></a>
## [v0.1.3] - 2021-05-31
### Pull Requests
- Merge pull request [#38](https://github.com/kubewarden/kwctl/issues/38) from kubewarden/read-docker-config


<a name="v0.1.2"></a>
## [v0.1.2] - 2021-05-31
### Pull Requests
- Merge pull request [#36](https://github.com/kubewarden/kwctl/issues/36) from kubewarden/annotated-by
- Merge pull request [#37](https://github.com/kubewarden/kwctl/issues/37) from kubewarden/check-metadata-before-push
- Merge pull request [#35](https://github.com/kubewarden/kwctl/issues/35) from kubewarden/improve-release


<a name="v0.1.1"></a>
## [v0.1.1] - 2021-05-28
### Features
- allow to skip scheme on `kwctl run` command
- Implement policy pushing to OCI registries

### Pull Requests
- Merge pull request [#31](https://github.com/kubewarden/kwctl/issues/31) from kubewarden/pretty_inspect
- Merge pull request [#30](https://github.com/kubewarden/kwctl/issues/30) from kubewarden/schemaless-run
- Merge pull request [#27](https://github.com/kubewarden/kwctl/issues/27) from kubewarden/improve-readability
- Merge pull request [#26](https://github.com/kubewarden/kwctl/issues/26) from kubewarden/show-tracing-events
- Merge pull request [#25](https://github.com/kubewarden/kwctl/issues/25) from kubewarden/improve-run-error-messages
- Merge pull request [#22](https://github.com/kubewarden/kwctl/issues/22) from kubewarden/policy-list
- Merge pull request [#21](https://github.com/kubewarden/kwctl/issues/21) from kubewarden/manifest-cmd
- Merge pull request [#20](https://github.com/kubewarden/kwctl/issues/20) from kubewarden/push-policies
- Merge pull request [#18](https://github.com/kubewarden/kwctl/issues/18) from kubewarden/metadata
- Merge pull request [#17](https://github.com/kubewarden/kwctl/issues/17) from kubewarden/admission-review-root
- Merge pull request [#16](https://github.com/kubewarden/kwctl/issues/16) from kubewarden/policy-store-removal
- Merge pull request [#15](https://github.com/kubewarden/kwctl/issues/15) from kubewarden/bump-dependencies


<a name="v0.0.1"></a>
## v0.0.1 - 2021-05-06
### Pull Requests
- Merge pull request [#14](https://github.com/kubewarden/kwctl/issues/14) from kubewarden/add-e2e-tests
- Merge pull request [#13](https://github.com/kubewarden/kwctl/issues/13) from kubewarden/refactor
- Merge pull request [#12](https://github.com/kubewarden/kwctl/issues/12) from ereslibre/drop-uri-named-arg


[Unreleased]: https://github.com/kubewarden/kwctl/compare/v0.2.3...HEAD
[v0.2.3]: https://github.com/kubewarden/kwctl/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/kubewarden/kwctl/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/kubewarden/kwctl/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/kubewarden/kwctl/compare/v0.1.10...v0.2.0
[v0.1.10]: https://github.com/kubewarden/kwctl/compare/v0.1.9...v0.1.10
[v0.1.9]: https://github.com/kubewarden/kwctl/compare/v0.1.8...v0.1.9
[v0.1.8]: https://github.com/kubewarden/kwctl/compare/v0.1.7...v0.1.8
[v0.1.7]: https://github.com/kubewarden/kwctl/compare/v0.1.6...v0.1.7
[v0.1.6]: https://github.com/kubewarden/kwctl/compare/v0.1.5...v0.1.6
[v0.1.5]: https://github.com/kubewarden/kwctl/compare/v0.1.4...v0.1.5
[v0.1.4]: https://github.com/kubewarden/kwctl/compare/v0.1.3...v0.1.4
[v0.1.3]: https://github.com/kubewarden/kwctl/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/kubewarden/kwctl/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/kubewarden/kwctl/compare/v0.0.1...v0.1.1
