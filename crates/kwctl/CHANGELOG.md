<a name="unreleased"></a>
## [Unreleased]

<a name="v1.1.2"></a>
## [v1.1.2] - 2022-08-10
### Bug Fixes
- **deps:** update rust crate serde_yaml to 0.9.4
- **deps:** update rust crate pulldown-cmark to 0.9.2

### Features
- Use docker_credential crate instead of DockerConfig
- Added CI Job to release Apple Silicon binary with the release GH Actions flow

### Pull Requests
- Merge pull request [#277](https://github.com/kubewarden/kwctl/issues/277) from raulcabello/docker_credential
- Merge pull request [#276](https://github.com/kubewarden/kwctl/issues/276) from kubewarden/renovate/all-patch
- Merge pull request [#275](https://github.com/kubewarden/kwctl/issues/275) from flavio/upgrade-deps
- Merge pull request [#271](https://github.com/kubewarden/kwctl/issues/271) from kubewarden/dependabot/cargo/wasmparser-0.88.0
- Merge pull request [#272](https://github.com/kubewarden/kwctl/issues/272) from kubewarden/dependabot/cargo/serde_yaml-0.9.1
- Merge pull request [#273](https://github.com/kubewarden/kwctl/issues/273) from kubewarden/renovate/all-patch


<a name="v1.1.1"></a>
## [v1.1.1] - 2022-07-19
### Bug Fixes
- Disable TUF integration test for now
- Warn and continue when Sigstore TUF repository is broken
- **deps:** update rust crate serde_yaml to 0.8.26

### Pull Requests
- Merge pull request [#265](https://github.com/kubewarden/kwctl/issues/265) from viccuad/tuf-fix
- Merge pull request [#263](https://github.com/kubewarden/kwctl/issues/263) from kubewarden/renovate/all-patch
- Merge pull request [#264](https://github.com/kubewarden/kwctl/issues/264) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#262](https://github.com/kubewarden/kwctl/issues/262) from kubewarden/road-to-1.1.0


<a name="v1.1.0"></a>
## [v1.1.0] - 2022-07-14
### Bug Fixes
- **deps:** update rust crate serde_yaml to 0.8.25

### Pull Requests
- Merge pull request [#259](https://github.com/kubewarden/kwctl/issues/259) from viccuad/gha
- Merge pull request [#255](https://github.com/kubewarden/kwctl/issues/255) from kubewarden/dependabot/cargo/wasmparser-0.87.0
- Merge pull request [#257](https://github.com/kubewarden/kwctl/issues/257) from kubewarden/renovate/all-patch
- Merge pull request [#258](https://github.com/kubewarden/kwctl/issues/258) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#256](https://github.com/kubewarden/kwctl/issues/256) from kubewarden/dependabot/cargo/policy-evaluator-v0.4.3
- Merge pull request [#254](https://github.com/kubewarden/kwctl/issues/254) from kubewarden/dependabot/cargo/regex-1.6.0
- Merge pull request [#252](https://github.com/kubewarden/kwctl/issues/252) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#253](https://github.com/kubewarden/kwctl/issues/253) from kubewarden/dependabot/cargo/rstest-0.15.0


<a name="v1.0.1"></a>
## [v1.0.1] - 2022-06-24
### Bug Fixes
- keyless image verification

### Pull Requests
- Merge pull request [#251](https://github.com/kubewarden/kwctl/issues/251) from raulcabello/bump
- Merge pull request [#250](https://github.com/kubewarden/kwctl/issues/250) from raulcabello/bump


<a name="v1.0.0"></a>
## [v1.0.0] - 2022-06-22
### Pull Requests
- Merge pull request [#249](https://github.com/kubewarden/kwctl/issues/249) from flavio/v1.0.0-release


<a name="v1.0.0-rc4"></a>
## [v1.0.0-rc4] - 2022-06-22

<a name="v1.0.0-rc3"></a>
## [v1.0.0-rc3] - 2022-06-21
### Pull Requests
- Merge pull request [#248](https://github.com/kubewarden/kwctl/issues/248) from flavio/update-policy-evaluator
- Merge pull request [#246](https://github.com/kubewarden/kwctl/issues/246) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#247](https://github.com/kubewarden/kwctl/issues/247) from kubewarden/dependabot/cargo/rstest-0.14.0


<a name="v1.0.0-rc2"></a>
## [v1.0.0-rc2] - 2022-06-15
### Features
- scaffold - generate AdmissionPolicy CR
- update scaffold to generate v1 CRD

### Pull Requests
- Merge pull request [#244](https://github.com/kubewarden/kwctl/issues/244) from flavio/update-scaffold
- Merge pull request [#241](https://github.com/kubewarden/kwctl/issues/241) from flavio/suppress-wasmtime-cache-warnings


<a name="v1.0.0-rc1"></a>
## [v1.0.0-rc1] - 2022-06-14
### Pull Requests
- Merge pull request [#239](https://github.com/kubewarden/kwctl/issues/239) from viccuad/main
- Merge pull request [#237](https://github.com/kubewarden/kwctl/issues/237) from kubewarden/dependabot/cargo/wasmparser-0.86.0
- Merge pull request [#238](https://github.com/kubewarden/kwctl/issues/238) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#236](https://github.com/kubewarden/kwctl/issues/236) from flavio/enable-wasmtime-cache
- Merge pull request [#235](https://github.com/kubewarden/kwctl/issues/235) from kubewarden/renovate/lock-file-maintenance


<a name="v0.3.5"></a>
## [v0.3.5] - 2022-05-31
### Pull Requests
- Merge pull request [#234](https://github.com/kubewarden/kwctl/issues/234) from kubewarden/renovate/lock-file-maintenance


<a name="v0.3.4"></a>
## [v0.3.4] - 2022-05-27
### Features
- Explain how to verify kwctl binaries

### Pull Requests
- Merge pull request [#233](https://github.com/kubewarden/kwctl/issues/233) from flavio/release-0.3.4
- Merge pull request [#230](https://github.com/kubewarden/kwctl/issues/230) from raulcabello/sign


<a name="v0.3.3"></a>
## [v0.3.3] - 2022-05-25
### Bug Fixes
- **deps:** update all patchlevel dependencies

### Features
- sign kwctl binary

### Pull Requests
- Merge pull request [#232](https://github.com/kubewarden/kwctl/issues/232) from flavio/update-deps
- Merge pull request [#228](https://github.com/kubewarden/kwctl/issues/228) from raulcabello/sign
- Merge pull request [#221](https://github.com/kubewarden/kwctl/issues/221) from kubewarden/dependabot/cargo/rstest-0.13.0
- Merge pull request [#224](https://github.com/kubewarden/kwctl/issues/224) from kubewarden/dependabot/cargo/wasmparser-0.85.0
- Merge pull request [#220](https://github.com/kubewarden/kwctl/issues/220) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#225](https://github.com/kubewarden/kwctl/issues/225) from kubewarden/renovate/all-patch
- Merge pull request [#212](https://github.com/kubewarden/kwctl/issues/212) from flavio/support-wapc-dns-lookup
- Merge pull request [#217](https://github.com/kubewarden/kwctl/issues/217) from kubewarden/renovate/lock-file-maintenance


<a name="v0.3.2"></a>
## [v0.3.2] - 2022-05-03
### Bug Fixes
- use right version inside of Cargo.toml
- **deps:** update rust crate clap_complete to 3.1.3

### Pull Requests
- Merge pull request [#213](https://github.com/kubewarden/kwctl/issues/213) from kubewarden/renovate/all-patch
- Merge pull request [#214](https://github.com/kubewarden/kwctl/issues/214) from kubewarden/renovate/lock-file-maintenance


<a name="v0.3.1"></a>
## [v0.3.1] - 2022-04-27
### Features
- Support kwctl run for sigstore container verification

### Pull Requests
- Merge pull request [#209](https://github.com/kubewarden/kwctl/issues/209) from raulcabello/main
- Merge pull request [#206](https://github.com/kubewarden/kwctl/issues/206) from kubewarden/renovate/lock-file-maintenance


<a name="v0.3.0"></a>
## [v0.3.0] - 2022-04-21
### Bug Fixes
- Pass tracing levels as LevelFilter type

### Pull Requests
- Merge pull request [#204](https://github.com/kubewarden/kwctl/issues/204) from viccuad/road-to-0.3.0
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


[Unreleased]: https://github.com/kubewarden/kwctl/compare/v1.1.1...HEAD
[v1.1.1]: https://github.com/kubewarden/kwctl/compare/v1.1.0...v1.1.1
[v1.1.0]: https://github.com/kubewarden/kwctl/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/kubewarden/kwctl/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/kubewarden/kwctl/compare/v1.0.0-rc4...v1.0.0
[v1.0.0-rc4]: https://github.com/kubewarden/kwctl/compare/v1.0.0-rc3...v1.0.0-rc4
[v1.0.0-rc3]: https://github.com/kubewarden/kwctl/compare/v1.0.0-rc2...v1.0.0-rc3
[v1.0.0-rc2]: https://github.com/kubewarden/kwctl/compare/v1.0.0-rc1...v1.0.0-rc2
[v1.0.0-rc1]: https://github.com/kubewarden/kwctl/compare/v0.3.5...v1.0.0-rc1
[v0.3.5]: https://github.com/kubewarden/kwctl/compare/v0.3.4...v0.3.5
[v0.3.4]: https://github.com/kubewarden/kwctl/compare/v0.3.3...v0.3.4
[v0.3.3]: https://github.com/kubewarden/kwctl/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/kubewarden/kwctl/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/kubewarden/kwctl/compare/v0.3.0...v0.3.1
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
