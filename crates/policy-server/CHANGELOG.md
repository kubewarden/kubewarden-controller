<a name="unreleased"></a>
## [Unreleased]


<a name="v0.3.1"></a>
## [v0.3.1] - 2022-05-24
### Bug Fixes
- **deps:** update all patchlevel dependencies

### Features
- sign container image
- Allow policy authors to write policies that perform image verification using sigstore

### Pull Requests
- Merge pull request [#259](https://github.com/kubewarden/policy-server/issues/259) from viccuad/main
- Merge pull request [#256](https://github.com/kubewarden/policy-server/issues/256) from raulcabello/main
- Merge pull request [#253](https://github.com/kubewarden/policy-server/issues/253) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#243](https://github.com/kubewarden/policy-server/issues/243) from flavio/support-wapc-dns-lookup
- Merge pull request [#251](https://github.com/kubewarden/policy-server/issues/251) from raulcabello/main
- Merge pull request [#250](https://github.com/kubewarden/policy-server/issues/250) from raulcabello/main
- Merge pull request [#248](https://github.com/kubewarden/policy-server/issues/248) from kubewarden/renovate/all-patch
- Merge pull request [#249](https://github.com/kubewarden/policy-server/issues/249) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#245](https://github.com/kubewarden/policy-server/issues/245) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#238](https://github.com/kubewarden/policy-server/issues/238) from raulcabello/main
- Merge pull request [#234](https://github.com/kubewarden/policy-server/issues/234) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#233](https://github.com/kubewarden/policy-server/issues/233) from kubewarden/dependabot/cargo/rustls-pemfile-1.0.0
- Merge pull request [#229](https://github.com/kubewarden/policy-server/issues/229) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#227](https://github.com/kubewarden/policy-server/issues/227) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#226](https://github.com/kubewarden/policy-server/issues/226) from kubewarden/renovate/lock-file-maintenance


<a name="v0.2.7"></a>
## [v0.2.7] - 2022-03-23
### Bug Fixes
- Enable verification if `--verification-path` is passed
- **deps:** update rust crate tokio-rustls to 0.23.3
- **deps:** update rust crate async-stream to 0.3.3

### Features
- fetch sigstore data from remote TUF repo
- Add keyless verification by supporting verification-config.yml
- add info to traces about why a resource was rejected by a policy
- implement policy modes

### Pull Requests
- Merge pull request [#223](https://github.com/kubewarden/policy-server/issues/223) from ereslibre/consume-policy-fetcher-through-policy-evaluator
- Merge pull request [#221](https://github.com/kubewarden/policy-server/issues/221) from kubewarden/renovate/all-patch
- Merge pull request [#222](https://github.com/kubewarden/policy-server/issues/222) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#215](https://github.com/kubewarden/policy-server/issues/215) from flavio/improve-policy-verification
- Merge pull request [#212](https://github.com/kubewarden/policy-server/issues/212) from kubewarden/renovate/all-patch
- Merge pull request [#213](https://github.com/kubewarden/policy-server/issues/213) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#209](https://github.com/kubewarden/policy-server/issues/209) from flavio/fix-clap-deprecation
- Merge pull request [#201](https://github.com/kubewarden/policy-server/issues/201) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#204](https://github.com/kubewarden/policy-server/issues/204) from kubewarden/renovate/all-patch
- Merge pull request [#200](https://github.com/kubewarden/policy-server/issues/200) from kubewarden/renovate/all-patch
- Merge pull request [#194](https://github.com/kubewarden/policy-server/issues/194) from ereslibre/monitor-mode
- Merge pull request [#193](https://github.com/kubewarden/policy-server/issues/193) from ereslibre/not-flatten-settings
- Merge pull request [#191](https://github.com/kubewarden/policy-server/issues/191) from kubewarden/renovate/all-patch
- Merge pull request [#192](https://github.com/kubewarden/policy-server/issues/192) from kubewarden/renovate/lock-file-maintenance
- Merge pull request [#187](https://github.com/kubewarden/policy-server/issues/187) from ereslibre/bump-dependencies
- Merge pull request [#182](https://github.com/kubewarden/policy-server/issues/182) from kubewarden/dependabot/cargo/rustls-pemfile-0.3.0
- Merge pull request [#183](https://github.com/kubewarden/policy-server/issues/183) from kubewarden/dependabot/cargo/futures-util-0.3.21
- Merge pull request [#159](https://github.com/kubewarden/policy-server/issues/159) from kubewarden/dependabot/cargo/policy-evaluator-v0.2.10
- Merge pull request [#163](https://github.com/kubewarden/policy-server/issues/163) from kubewarden/dependabot/cargo/k8s-openapi-0.14.0
- Merge pull request [#174](https://github.com/kubewarden/policy-server/issues/174) from kubewarden/dependabot/cargo/tokio-1.16.1
- Merge pull request [#180](https://github.com/kubewarden/policy-server/issues/180) from kubewarden/dependabot/cargo/tracing-0.1.30
- Merge pull request [#178](https://github.com/kubewarden/policy-server/issues/178) from kubewarden/dependabot/cargo/clap-3.0.14
- Merge pull request [#175](https://github.com/kubewarden/policy-server/issues/175) from viccuad/enable-verification


<a name="v0.2.6"></a>
## [v0.2.6] - 2022-01-28
### Pull Requests
- Merge pull request [#173](https://github.com/kubewarden/policy-server/issues/173) from kubewarden/dependabot/cargo/clap-3.0.13
- Merge pull request [#172](https://github.com/kubewarden/policy-server/issues/172) from kubewarden/dependabot/cargo/serde-1.0.136
- Merge pull request [#169](https://github.com/kubewarden/policy-server/issues/169) from kubewarden/dependabot/cargo/clap-3.0.12
- Merge pull request [#162](https://github.com/kubewarden/policy-server/issues/162) from flavio/update-clap
- Merge pull request [#164](https://github.com/kubewarden/policy-server/issues/164) from kubewarden/dependabot/cargo/anyhow-1.0.53
- Merge pull request [#165](https://github.com/kubewarden/policy-server/issues/165) from kubewarden/dependabot/cargo/serde_json-1.0.78
- Merge pull request [#166](https://github.com/kubewarden/policy-server/issues/166) from kubewarden/dependabot/cargo/serde-1.0.135


<a name="v0.2.6-rc2"></a>
## [v0.2.6-rc2] - 2022-01-24

<a name="v0.2.6-rc1"></a>
## [v0.2.6-rc1] - 2022-01-21
### Bug Fixes
- Don't default to verification always enabled

### Features
- Integrate the CallbackHandler

### Reverts
- Revert "feat: Sigstore verification of policies on download"
- feat: Sigstore verification of policies on download

### Pull Requests
- Merge pull request [#158](https://github.com/kubewarden/policy-server/issues/158) from ereslibre/bump-dependencies
- Merge pull request [#155](https://github.com/kubewarden/policy-server/issues/155) from ereslibre/create-github-release
- Merge pull request [#156](https://github.com/kubewarden/policy-server/issues/156) from ereslibre/bump-dependencies
- Merge pull request [#152](https://github.com/kubewarden/policy-server/issues/152) from kubewarden/dependabot/cargo/kubewarden-policy-sdk-0.3.2
- Merge pull request [#147](https://github.com/kubewarden/policy-server/issues/147) from kubewarden/dependabot/cargo/hyper-0.14.16
- Merge pull request [#149](https://github.com/kubewarden/policy-server/issues/149) from kubewarden/dependabot/cargo/serde-1.0.133
- Merge pull request [#150](https://github.com/kubewarden/policy-server/issues/150) from kubewarden/dependabot/cargo/serde_yaml-0.8.23
- Merge pull request [#146](https://github.com/kubewarden/policy-server/issues/146) from kubewarden/dependabot/cargo/anyhow-1.0.52
- Merge pull request [#144](https://github.com/kubewarden/policy-server/issues/144) from flavio/add-dependabot
- Merge pull request [#138](https://github.com/kubewarden/policy-server/issues/138) from ereslibre/cross-compile
- Merge pull request [#141](https://github.com/kubewarden/policy-server/issues/141) from viccuad/default-verification
- Merge pull request [#140](https://github.com/kubewarden/policy-server/issues/140) from flavio/verify-sigstore-policies-on-download
- Merge pull request [#134](https://github.com/kubewarden/policy-server/issues/134) from flavio/fix-container-image-build
- Merge pull request [#126](https://github.com/kubewarden/policy-server/issues/126) from flavio/oci-fetch-manifest
- Merge pull request [#133](https://github.com/kubewarden/policy-server/issues/133) from kubewarden/revert-132-policy-verify
- Merge pull request [#132](https://github.com/kubewarden/policy-server/issues/132) from viccuad/policy-verify
- Merge pull request [#131](https://github.com/kubewarden/policy-server/issues/131) from ereslibre/rustls-tls


<a name="v0.2.5"></a>
## [v0.2.5] - 2021-11-18
### Pull Requests
- Merge pull request [#125](https://github.com/kubewarden/policy-server/issues/125) from kubewarden/bump-dependencies
- Merge pull request [#121](https://github.com/kubewarden/policy-server/issues/121) from kubewarden/cargo-audit-config


<a name="v0.2.4"></a>
## [v0.2.4] - 2021-11-05
### Features
- report loaded policies on startup
- Use r.suse.com/bci/minimal for container image
- Bump policy-fetcher v0.1.17, new sources.yml format

### Reverts
- metrics: add KUBEWARDEN_ENABLE_METRICS envvar

### Pull Requests
- Merge pull request [#120](https://github.com/kubewarden/policy-server/issues/120) from ereslibre/pin-base64ct
- Merge pull request [#119](https://github.com/kubewarden/policy-server/issues/119) from ereslibre/report-policies-on-start
- Merge pull request [#118](https://github.com/kubewarden/policy-server/issues/118) from viccuad/bci-image
- Merge pull request [#117](https://github.com/kubewarden/policy-server/issues/117) from ereslibre/enable-metrics
- Merge pull request [#116](https://github.com/kubewarden/policy-server/issues/116) from viccuad/bump-sources


<a name="v0.2.3"></a>
## [v0.2.3] - 2021-10-25
### Bug Fixes
- ensure latest version of wasmtime is used

### Features
- enrich tracing with extra AdmissionReview fields.

### Pull Requests
- Merge pull request [#115](https://github.com/kubewarden/policy-server/issues/115) from ereslibre/enable-metrics-envvar
- Merge pull request [#108](https://github.com/kubewarden/policy-server/issues/108) from ereslibre/metrics
- Merge pull request [#112](https://github.com/kubewarden/policy-server/issues/112) from kubewarden/upgrade-wasmtime
- Merge pull request [#111](https://github.com/kubewarden/policy-server/issues/111) from kubewarden/handle-new-sources-format
- Merge pull request [#100](https://github.com/kubewarden/policy-server/issues/100) from jvanz/enrich-traces
- Merge pull request [#104](https://github.com/kubewarden/policy-server/issues/104) from flavio/remove-jaeger-tracing
- Merge pull request [#101](https://github.com/kubewarden/policy-server/issues/101) from flavio/tracing-local-development


<a name="v0.2.2"></a>
## [v0.2.2] - 2021-10-04
### Pull Requests
- Merge pull request [#93](https://github.com/kubewarden/policy-server/issues/93) from flavio/tracing-improvements


<a name="v0.2.1"></a>
## [v0.2.1] - 2021-09-27
### Pull Requests
- Merge pull request [#92](https://github.com/kubewarden/policy-server/issues/92) from ereslibre/abort-if-builtin-missing


<a name="v0.2.0"></a>
## [v0.2.0] - 2021-09-20
### Features
- Handle policies written using Rego

### Pull Requests
- Merge pull request [#91](https://github.com/kubewarden/policy-server/issues/91) from kubewarden/opa
- Merge pull request [#90](https://github.com/kubewarden/policy-server/issues/90) from flavio/opa
- Merge pull request [#87](https://github.com/kubewarden/policy-server/issues/87) from kubewarden/builtin-report
- Merge pull request [#85](https://github.com/kubewarden/policy-server/issues/85) from flavio/fix-opentelemetry-otlp-integration


<a name="v0.1.10"></a>
## [v0.1.10] - 2021-08-19
### Pull Requests
- Merge pull request [#84](https://github.com/kubewarden/policy-server/issues/84) from ereslibre/bump-dependencies


<a name="v0.1.9"></a>
## [v0.1.9] - 2021-08-19

<a name="v0.1.8"></a>
## [v0.1.8] - 2021-07-13
### Features
- improve logging story

### Pull Requests
- Merge pull request [#75](https://github.com/kubewarden/policy-server/issues/75) from flavio/distributed-tracing


<a name="v0.1.7"></a>
## [v0.1.7] - 2021-06-16

<a name="v0.1.6"></a>
## [v0.1.6] - 2021-06-16
### Reverts
- Bump dependencies in security report

### Pull Requests
- Merge pull request [#74](https://github.com/kubewarden/policy-server/issues/74) from kubewarden/context-aware
- Merge pull request [#72](https://github.com/kubewarden/policy-server/issues/72) from kubewarden/commit-subjects
- Merge pull request [#71](https://github.com/kubewarden/policy-server/issues/71) from flavio/fix-wasmtime-security-warning
- Merge pull request [#69](https://github.com/kubewarden/policy-server/issues/69) from kubewarden/bump-security-dependencies


<a name="v0.1.5"></a>
## [v0.1.5] - 2021-06-03
### Code Refactoring
- due to dependency refactor
- split crates to repositories of their own

### Pull Requests
- Merge pull request [#66](https://github.com/kubewarden/policy-server/issues/66) from ereslibre/image-rebase
- Merge pull request [#65](https://github.com/kubewarden/policy-server/issues/65) from flavio/update-policy-fetcher
- Merge pull request [#63](https://github.com/kubewarden/policy-server/issues/63) from flavio/update-to-latest-policy-evaluator
- Merge pull request [#62](https://github.com/kubewarden/policy-server/issues/62) from kubewarden/bump-policy-fetcher
- Merge pull request [#60](https://github.com/kubewarden/policy-server/issues/60) from kubewarden/bump-dependencies
- Merge pull request [#58](https://github.com/kubewarden/policy-server/issues/58) from kubewarden/refactor
- Merge pull request [#57](https://github.com/kubewarden/policy-server/issues/57) from ereslibre/crates-split


<a name="v0.1.4"></a>
## [v0.1.4] - 2021-04-16
### Code Refactoring
- split internal crates

### Pull Requests
- Merge pull request [#56](https://github.com/kubewarden/policy-server/issues/56) from ereslibre/split-crates
- Merge pull request [#55](https://github.com/kubewarden/policy-server/issues/55) from flavio/fix-testdrive-release
- Merge pull request [#54](https://github.com/kubewarden/policy-server/issues/54) from flavio/update-to-latest-kubewarden-client-sdk


<a name="v0.1.3"></a>
## [v0.1.3] - 2021-04-14
### Features
- add changelog generation tooling

### Pull Requests
- Merge pull request [#52](https://github.com/kubewarden/policy-server/issues/52) from ereslibre/changelog-generation
- Merge pull request [#51](https://github.com/kubewarden/policy-server/issues/51) from ereslibre/remove-threaded-panic


<a name="v0.1.2"></a>
## [v0.1.2] - 2021-04-07
### Pull Requests
- Merge pull request [#48](https://github.com/kubewarden/policy-server/issues/48) from flavio/enforce_settings_validation
- Merge pull request [#49](https://github.com/kubewarden/policy-server/issues/49) from flavio/compress-policy-testdrive-artifact


<a name="v0.1.1"></a>
## [v0.1.1] - 2021-04-06

<a name="v0.1.0"></a>
## v0.1.0 - 2021-04-02
### Pull Requests
- Merge pull request [#45](https://github.com/kubewarden/policy-server/issues/45) from kubewarden/remove-pat
- Merge pull request [#44](https://github.com/kubewarden/policy-server/issues/44) from flavio/update-sdk-dep
- Merge pull request [#43](https://github.com/kubewarden/policy-server/issues/43) from flavio/rename
- Merge pull request [#39](https://github.com/kubewarden/policy-server/issues/39) from ereslibre/context-aware
- Merge pull request [#38](https://github.com/kubewarden/policy-server/issues/38) from flavio/logging
- Merge pull request [#35](https://github.com/kubewarden/policy-server/issues/35) from flavio/settings-validation
- Merge pull request [#36](https://github.com/kubewarden/policy-server/issues/36) from flavio/testdrive-release
- Merge pull request [#34](https://github.com/kubewarden/policy-server/issues/34) from flavio/mutating-policies
- Merge pull request [#26](https://github.com/kubewarden/policy-server/issues/26) from ereslibre/sources-yaml
- Merge pull request [#25](https://github.com/kubewarden/policy-server/issues/25) from flavio/policies-download-dir
- Merge pull request [#24](https://github.com/kubewarden/policy-server/issues/24) from flavio/unwrap-cleanup
- Merge pull request [#16](https://github.com/kubewarden/policy-server/issues/16) from ereslibre/registry-authentication
- Merge pull request [#22](https://github.com/kubewarden/policy-server/issues/22) from flavio/wait-for-workers-to-be-ready
- Merge pull request [#17](https://github.com/kubewarden/policy-server/issues/17) from chimera-kube/policies-settings
- Merge pull request [#15](https://github.com/kubewarden/policy-server/issues/15) from cmurphy/tls
- Merge pull request [#18](https://github.com/kubewarden/policy-server/issues/18) from cmurphy/build-image
- Merge pull request [#11](https://github.com/kubewarden/policy-server/issues/11) from ereslibre/oci-artifacts
- Merge pull request [#10](https://github.com/kubewarden/policy-server/issues/10) from cmurphy/error-handling
- Merge pull request [#9](https://github.com/kubewarden/policy-server/issues/9) from cmurphy/fix-uid


[Unreleased]: https://github.com/kubewarden/policy-server/compare/v0.3.1...HEAD
[v0.3.1]: https://github.com/kubewarden/policy-server/compare/v0.2.7...v0.3.1
[v0.2.7]: https://github.com/kubewarden/policy-server/compare/v0.2.6...v0.2.7
[v0.2.6]: https://github.com/kubewarden/policy-server/compare/v0.2.6-rc2...v0.2.6
[v0.2.6-rc2]: https://github.com/kubewarden/policy-server/compare/v0.2.6-rc1...v0.2.6-rc2
[v0.2.6-rc1]: https://github.com/kubewarden/policy-server/compare/v0.2.5...v0.2.6-rc1
[v0.2.5]: https://github.com/kubewarden/policy-server/compare/v0.2.4...v0.2.5
[v0.2.4]: https://github.com/kubewarden/policy-server/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/kubewarden/policy-server/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/kubewarden/policy-server/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/kubewarden/policy-server/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/kubewarden/policy-server/compare/v0.1.10...v0.2.0
[v0.1.10]: https://github.com/kubewarden/policy-server/compare/v0.1.9...v0.1.10
[v0.1.9]: https://github.com/kubewarden/policy-server/compare/v0.1.8...v0.1.9
[v0.1.8]: https://github.com/kubewarden/policy-server/compare/v0.1.7...v0.1.8
[v0.1.7]: https://github.com/kubewarden/policy-server/compare/v0.1.6...v0.1.7
[v0.1.6]: https://github.com/kubewarden/policy-server/compare/v0.1.5...v0.1.6
[v0.1.5]: https://github.com/kubewarden/policy-server/compare/v0.1.4...v0.1.5
[v0.1.4]: https://github.com/kubewarden/policy-server/compare/v0.1.3...v0.1.4
[v0.1.3]: https://github.com/kubewarden/policy-server/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/kubewarden/policy-server/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/kubewarden/policy-server/compare/v0.1.0...v0.1.1
