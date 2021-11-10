<a name="unreleased"></a>
## [Unreleased]


<a name="v0.4.2"></a>
## [v0.4.2] - 2021-11-04
### Code Refactoring
- Rename vars that are too short
- Reuse parent context for deleting policies

### Features
- Policy counter metric.
- OpenTelemetry integration.
- policy server name label in the deployment.
- add OpenTelemetry integration

### Pull Requests
- Merge pull request [#122](https://github.com/kubewarden/kubewarden-controller/issues/122) from viccuad/golangci-1.42
- Merge pull request [#112](https://github.com/kubewarden/kubewarden-controller/issues/112) from ereslibre/opentelemetry
- Merge pull request [#118](https://github.com/kubewarden/kubewarden-controller/issues/118) from viccuad/main


<a name="v0.4.1"></a>
## [v0.4.1] - 2021-11-03
### Code Refactoring
- Extract sources path into constants pkg

### Features
- Add PolicyServer.spec.sourceAuthorities to CR
- Add spec.insecureSources to PolicyServer CR
- Add spec.imagePullSecrets to PolicyServer

### Pull Requests
- Merge pull request [#117](https://github.com/kubewarden/kubewarden-controller/issues/117) from viccuad/docs-crds
- Merge pull request [#114](https://github.com/kubewarden/kubewarden-controller/issues/114) from viccuad/custom-cas
- Merge pull request [#108](https://github.com/kubewarden/kubewarden-controller/issues/108) from viccuad/insecureregs
- Merge pull request [#106](https://github.com/kubewarden/kubewarden-controller/issues/106) from jvanz/can-update-env
- Merge pull request [#92](https://github.com/kubewarden/kubewarden-controller/issues/92) from ereslibre/development-webhook-wrapper
- Merge pull request [#99](https://github.com/kubewarden/kubewarden-controller/issues/99) from viccuad/main


<a name="v0.4.0"></a>
## [v0.4.0] - 2021-10-05
### Reverts
- Set PolicyStatus "unscheduled" as default in CRD

### Pull Requests
- Merge pull request [#98](https://github.com/kubewarden/kubewarden-controller/issues/98) from kubewarden/viccuad-update-readme
- Merge pull request [#94](https://github.com/kubewarden/kubewarden-controller/issues/94) from ereslibre/policy-server-output
- Merge pull request [#91](https://github.com/kubewarden/kubewarden-controller/issues/91) from viccuad/golangci-lint-gha
- Merge pull request [#90](https://github.com/kubewarden/kubewarden-controller/issues/90) from raulcabello/new-architecture
- Merge pull request [#85](https://github.com/kubewarden/kubewarden-controller/issues/85) from flavio/uninstall-script
- Merge pull request [#82](https://github.com/kubewarden/kubewarden-controller/issues/82) from flavio/new-architecture-crds-docs
- Merge pull request [#83](https://github.com/kubewarden/kubewarden-controller/issues/83) from ereslibre/rename-policy-active-condition
- Merge pull request [#81](https://github.com/kubewarden/kubewarden-controller/issues/81) from viccuad/new-architecture
- Merge pull request [#76](https://github.com/kubewarden/kubewarden-controller/issues/76) from viccuad/webhooks
- Merge pull request [#75](https://github.com/kubewarden/kubewarden-controller/issues/75) from jvanz/how-to-build
- Merge pull request [#66](https://github.com/kubewarden/kubewarden-controller/issues/66) from raulcabello/new-architecture
- Merge pull request [#64](https://github.com/kubewarden/kubewarden-controller/issues/64) from raulcabello/new-architecture


<a name="v0.3.2"></a>
## [v0.3.2] - 2021-08-19
### Pull Requests
- Merge pull request [#46](https://github.com/kubewarden/kubewarden-controller/issues/46) from flavio/policy-server-crd-proposal


<a name="v0.3.1"></a>
## [v0.3.1] - 2021-06-18

<a name="v0.3.0"></a>
## [v0.3.0] - 2021-06-18
### Pull Requests
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/drop-v1alpha1


<a name="v0.2.3"></a>
## [v0.2.3] - 2021-06-04

<a name="v0.2.2"></a>
## [v0.2.2] - 2021-06-04

<a name="v0.2.1"></a>
## [v0.2.1] - 2021-06-03
### Features
- implement ClusterAdmissionPolicy status subresource

### Pull Requests
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status


<a name="v0.2.0"></a>
## [v0.2.0] - 2021-05-24
### Features
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3

### Pull Requests
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main


<a name="v0.1.4"></a>
## [v0.1.4] - 2021-04-14
### Bug Fixes
- update documentation links to use custom domain

### Features
- add changelog generation tooling

### Pull Requests
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links


<a name="v0.1.3"></a>
## [v0.1.3] - 2021-04-12

<a name="v0.1.2"></a>
## [v0.1.2] - 2021-04-12

<a name="v0.1.1"></a>
## [v0.1.1] - 2021-04-10
### Pull Requests
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings


<a name="v0.1.0"></a>
## [v0.1.0] - 2021-04-06
### Pull Requests
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="v0.1.0-rc1"></a>
## [v0.1.0-rc1] - 2021-03-02

<a name="v0.0.1"></a>
## v0.0.1 - 2021-01-18

[Unreleased]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.2...HEAD
[v0.4.2]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/kubewarden/kubewarden-controller/compare/v0.3.2...v0.4.0
[v0.3.2]: https://github.com/kubewarden/kubewarden-controller/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/kubewarden/kubewarden-controller/compare/v0.2.3...v0.3.0
[v0.2.3]: https://github.com/kubewarden/kubewarden-controller/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/kubewarden/kubewarden-controller/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.4...v0.2.0
[v0.1.4]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.3...v0.1.4
[v0.1.3]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.0-rc1...v0.1.0
[v0.1.0-rc1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.0.1...v0.1.0-rc1
