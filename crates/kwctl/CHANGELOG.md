<a name="unreleased"></a>
## [Unreleased]


<a name="v0.3.0"></a>
## [v0.3.0] - 2022-04-21
### Bug Fixes
- Pass tracing levels as LevelFilter type

### Pull Requests
- Merge pull request [#202](https://github.com/kubewarden/kwctl/issues/202) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#201](https://github.com/kubewarden/kwctl/issues/201) from kubewarden/renovate/all-patch


<a name="v0.3.0-rc1"></a>
## [v0.3.0-rc1] - 2022-04-20
### Code Refactoring
- Fix clippy warnings on new clippy version

### Features
- show Sigstore signatures on kwctl inspect
- Add `kwctl scaffold manifest` & `kwctl scaffold verification-config`
- sigstore - download keys and certs from TUF repo
- Keyless verification for kwctl {verify,pull,run}
- Consume new policy-fetcher verify()
- Add and consume `build_verification_config_from_flags()`
- Add --verification-config-path flag

### Pull Requests
- Merge pull request [#196](https://github.com/kubewarden/kwctl/issues/196) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#197](https://github.com/kubewarden/kwctl/issues/197) from kubewarden/dependabot/cargo/mdcat-0.27.0
- Merge pull request [#190](https://github.com/kubewarden/kwctl/issues/190) from raulcabello/main
- Merge pull request [#193](https://github.com/kubewarden/kwctl/issues/193) from kubewarden/dependabot/cargo/policy-evaluator-v0.2.17
- Merge pull request [#192](https://github.com/kubewarden/kwctl/issues/192) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#191](https://github.com/kubewarden/kwctl/issues/191) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#189](https://github.com/kubewarden/kwctl/issues/189) from viccuad/doc-digest
- Merge pull request [#188](https://github.com/kubewarden/kwctl/issues/188) from ereslibre/consume-policy-fetcher-through-policy-evaluator
- Merge pull request [#183](https://github.com/kubewarden/kwctl/issues/183) from viccuad/scaffold-config
- Merge pull request [#186](https://github.com/kubewarden/kwctl/issues/186) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#182](https://github.com/kubewarden/kwctl/issues/182) from flavio/update-to-latest-policy-fetcher-release
- Merge pull request [#179](https://github.com/kubewarden/kwctl/issues/179) from flavio/sigstore-tuf
- Merge pull request [#176](https://github.com/kubewarden/kwctl/issues/176) from jvanz/issue175-keyless-flags
- Merge pull request [#169](https://github.com/kubewarden/kwctl/issues/169) from viccuad/verify-keyless
- Merge pull request [#178](https://github.com/kubewarden/kwctl/issues/178) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#165](https://github.com/kubewarden/kwctl/issues/165) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#172](https://github.com/kubewarden/kwctl/issues/172) from kubewarden/dependabot/cargo/clap_complete-3.1.1
- Merge pull request [#158](https://github.com/kubewarden/kwctl/issues/158) from kubewarden/dependabot/cargo/mdcat-0.26.1
- Merge pull request [#174](https://github.com/kubewarden/kwctl/issues/174) from flavio/fix-clippy-warnings
- Merge pull request [#163](https://github.com/kubewarden/kwctl/issues/163) from kubewarden/dependabot/cargo/tokio-1.17.0
- Merge pull request [#164](https://github.com/kubewarden/kwctl/issues/164) from kubewarden/dependabot/cargo/wasmparser-0.83.0
- Merge pull request [#156](https://github.com/kubewarden/kwctl/issues/156) from kubewarden/renovate/all-patch
- Merge pull request [#157](https://github.com/kubewarden/kwctl/issues/157) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#151](https://github.com/kubewarden/kwctl/issues/151) from ereslibre/bump-dependencies
- Merge pull request [#149](https://github.com/kubewarden/kwctl/issues/149) from kubewarden/dependabot/cargo/tracing-subscriber-0.3.8
- Merge pull request [#147](https://github.com/kubewarden/kwctl/issues/147) from kubewarden/dependabot/cargo/tracing-0.1.30
- Merge pull request [#148](https://github.com/kubewarden/kwctl/issues/148) from kubewarden/dependabot/cargo/clap_complete-3.0.6
- Merge pull request [#146](https://github.com/kubewarden/kwctl/issues/146) from kubewarden/dependabot/cargo/clap-3.0.14


<a name="v0.2.5"></a>
## [v0.2.5] - 2022-02-02

<a name="v0.2.5-rc4"></a>
## [v0.2.5-rc4] - 2022-02-01
### Pull Requests
- Merge pull request [#141](https://github.com/kubewarden/kwctl/issues/141) from ereslibre/windows-path-fixes
- Merge pull request [#143](https://github.com/kubewarden/kwctl/issues/143) from raulcabello/main
- Merge pull request [#140](https://github.com/kubewarden/kwctl/issues/140) from kubewarden/dependabot/cargo/clap-3.0.13
- Merge pull request [#138](https://github.com/kubewarden/kwctl/issues/138) from kubewarden/dependabot/cargo/serde-1.0.136
- Merge pull request [#132](https://github.com/kubewarden/kwctl/issues/132) from kubewarden/dependabot/cargo/clap-3.0.12
- Merge pull request [#131](https://github.com/kubewarden/kwctl/issues/131) from kubewarden/dependabot/cargo/serde-1.0.135
- Merge pull request [#133](https://github.com/kubewarden/kwctl/issues/133) from kubewarden/dependabot/cargo/clap_complete-3.0.5
- Merge pull request [#135](https://github.com/kubewarden/kwctl/issues/135) from kubewarden/dependabot/cargo/serde_json-1.0.78
- Merge pull request [#136](https://github.com/kubewarden/kwctl/issues/136) from kubewarden/dependabot/cargo/anyhow-1.0.53
- Merge pull request [#125](https://github.com/kubewarden/kwctl/issues/125) from flavio/update-clap
- Merge pull request [#128](https://github.com/kubewarden/kwctl/issues/128) from kubewarden/dependabot/cargo/serde_json-1.0.78
- Merge pull request [#129](https://github.com/kubewarden/kwctl/issues/129) from kubewarden/dependabot/cargo/serde-1.0.135
- Merge pull request [#130](https://github.com/kubewarden/kwctl/issues/130) from kubewarden/dependabot/cargo/anyhow-1.0.53
- Merge pull request [#122](https://github.com/kubewarden/kwctl/issues/122) from flavio/update-mdcat-and-pulldown-cmark
- Merge pull request [#111](https://github.com/kubewarden/kwctl/issues/111) from kubewarden/dependabot/cargo/directories-4.0.1
- Merge pull request [#114](https://github.com/kubewarden/kwctl/issues/114) from kubewarden/dependabot/cargo/wasmparser-0.82.0
- Merge pull request [#123](https://github.com/kubewarden/kwctl/issues/123) from ereslibre/bump-dependencies
- Merge pull request [#118](https://github.com/kubewarden/kwctl/issues/118) from kubewarden/dependabot/cargo/tempfile-3.3.0
- Merge pull request [#121](https://github.com/kubewarden/kwctl/issues/121) from ereslibre/bump-dependencies


<a name="v0.2.5-rc3"></a>
## [v0.2.5-rc3] - 2022-01-20
### Pull Requests
- Merge pull request [#108](https://github.com/kubewarden/kwctl/issues/108) from ereslibre/pre-release
- Merge pull request [#110](https://github.com/kubewarden/kwctl/issues/110) from flavio/add-dependabot


<a name="v0.2.5-rc2"></a>
## [v0.2.5-rc2] - 2022-01-20
### Pull Requests
- Merge pull request [#106](https://github.com/kubewarden/kwctl/issues/106) from flavio/enable-more-secure-policy-signing


<a name="v0.2.5-rc1"></a>
## [v0.2.5-rc1] - 2022-01-19
### Pull Requests
- Merge pull request [#103](https://github.com/kubewarden/kwctl/issues/103) from ereslibre/cross-compile
- Merge pull request [#104](https://github.com/kubewarden/kwctl/issues/104) from raulcabello/main
- Merge pull request [#102](https://github.com/kubewarden/kwctl/issues/102) from flavio/update-deps
- Merge pull request [#95](https://github.com/kubewarden/kwctl/issues/95) from ereslibre/rustls-tls
- Merge pull request [#94](https://github.com/kubewarden/kwctl/issues/94) from flavio/small-logging-fixes-and-improvements
- Merge pull request [#92](https://github.com/kubewarden/kwctl/issues/92) from kubewarden/fix-verification-snippets


<a name="v0.2.4"></a>
## [v0.2.4] - 2021-11-18
### Pull Requests
- Merge pull request [#88](https://github.com/kubewarden/kwctl/issues/88) from viccuad/doc-release
- Merge pull request [#90](https://github.com/kubewarden/kwctl/issues/90) from kubewarden/bump-dependencies


<a name="v0.2.3"></a>
## [v0.2.3] - 2021-11-17
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
- Merge pull request [#87](https://github.com/kubewarden/kwctl/issues/87) from viccuad/main
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


[Unreleased]: https://github.com/kubewarden/kwctl/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/kubewarden/kwctl/compare/v0.3.0-rc1...v0.3.0
[v0.3.0-rc1]: https://github.com/kubewarden/kwctl/compare/v0.2.5...v0.3.0-rc1
[v0.2.5]: https://github.com/kubewarden/kwctl/compare/v0.2.5-rc4...v0.2.5
[v0.2.5-rc4]: https://github.com/kubewarden/kwctl/compare/v0.2.5-rc3...v0.2.5-rc4
[v0.2.5-rc3]: https://github.com/kubewarden/kwctl/compare/v0.2.5-rc2...v0.2.5-rc3
[v0.2.5-rc2]: https://github.com/kubewarden/kwctl/compare/v0.2.5-rc1...v0.2.5-rc2
[v0.2.5-rc1]: https://github.com/kubewarden/kwctl/compare/v0.2.4...v0.2.5-rc1
[v0.2.4]: https://github.com/kubewarden/kwctl/compare/v0.2.3...v0.2.4
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
