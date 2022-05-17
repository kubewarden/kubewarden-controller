<a name="unreleased"></a>
## [Unreleased]


<a name="v0.5.5"></a>
## [v0.5.5] - 2022-05-17
### Features
- check if policy is deployed before setting it to uniquely reachable
- Reconcile webhook after deployment rollout.


<a name="v0.5.4"></a>
## [v0.5.4] - 2022-05-13
### Pull Requests
- Merge pull request [#220](https://github.com/kubewarden/kubewarden-controller/issues/220) from viccuad/pin-golangci-lint
- Merge pull request [#219](https://github.com/kubewarden/kubewarden-controller/pull/219) from jvanz:skip-kubewarden-namespace

<a name="v0.5.3"></a>
## [v0.5.3] - 2022-05-13
### Pull Requests
- Merge pull request [#216](https://github.com/kubewarden/kubewarden-controller/issues/216) from jvanz/fix-env-var-name
- Merge pull request [#215](https://github.com/kubewarden/kubewarden-controller/issues/215) from kubewarden/renovate/docker-build-push-action-3.x
- Merge pull request [#212](https://github.com/kubewarden/kubewarden-controller/issues/212) from ereslibre/always-accept-admission-reviews-on-namespace


<a name="v0.5.2"></a>
## [v0.5.2] - 2022-04-07

<a name="v0.5.2-rc2"></a>
## [v0.5.2-rc2] - 2022-04-07

<a name="v0.5.2-rc"></a>
## [v0.5.2-rc] - 2022-03-30
### Bug Fixes
- Disable conversion webhooks on CRDs, not needed
- Disable cert-manager ca injection patches in CRDs
- **samples:** jaeger is no longer valid as a log format

### Pull Requests
- Merge pull request [#196](https://github.com/kubewarden/kubewarden-controller/issues/196) from viccuad/fix-crds
- Merge pull request [#195](https://github.com/kubewarden/kubewarden-controller/issues/195) from viccuad/no-cainjection-crds
- Merge pull request [#175](https://github.com/kubewarden/kubewarden-controller/issues/175) from ereslibre/up-to-date-observed-condition


<a name="v0.5.1"></a>
## [v0.5.1] - 2022-03-24
### Features
- set KUBEWARDEN_SIGSTORE_CACHE_DIR on deployment

### Pull Requests
- Merge pull request [#194](https://github.com/kubewarden/kubewarden-controller/issues/194) from viccuad/sigstore-release
- Merge pull request [#193](https://github.com/kubewarden/kubewarden-controller/issues/193) from viccuad/0.5.0-sigstore-cache-dir
- Merge pull request [#191](https://github.com/kubewarden/kubewarden-controller/issues/191) from kubewarden/renovate/actions-upload-artifact-3.x
- Merge pull request [#187](https://github.com/kubewarden/kubewarden-controller/issues/187) from kubewarden/renovate/actions-checkout-3.x
- Merge pull request [#188](https://github.com/kubewarden/kubewarden-controller/issues/188) from kubewarden/renovate/actions-setup-go-3.x
- Merge pull request [#176](https://github.com/kubewarden/kubewarden-controller/issues/176) from ereslibre/policy-reports
- Merge pull request [#183](https://github.com/kubewarden/kubewarden-controller/issues/183) from raulcabello/main


<a name="v0.5.0"></a>
## [v0.5.0] - 2022-03-03
### Reverts
- Group kubernetes dependencies
- Run e2e test in a self-hosted action runner.

### Pull Requests
- Merge pull request [#181](https://github.com/kubewarden/kubewarden-controller/issues/181) from raulcabello/main
- Merge pull request [#177](https://github.com/kubewarden/kubewarden-controller/issues/177) from raulcabello/main
- Merge pull request [#174](https://github.com/kubewarden/kubewarden-controller/issues/174) from flavio/main
- Merge pull request [#172](https://github.com/kubewarden/kubewarden-controller/issues/172) from ereslibre/monitor-mode
- Merge pull request [#168](https://github.com/kubewarden/kubewarden-controller/issues/168) from viccuad/fix-rfc3
- Merge pull request [#156](https://github.com/kubewarden/kubewarden-controller/issues/156) from kubewarden/renovate/configure
- Merge pull request [#147](https://github.com/kubewarden/kubewarden-controller/issues/147) from flavio/sigstore-integration-rfc


<a name="v0.4.5"></a>
## [v0.4.5] - 2022-01-28
### Pull Requests
- Merge pull request [#150](https://github.com/kubewarden/kubewarden-controller/issues/150) from jvanz/main


<a name="v0.4.5-rc1"></a>
## [v0.4.5-rc1] - 2022-01-24
### Bug Fixes
- **policy-server:** Run the policy server with readonly root

### Pull Requests
- Merge pull request [#146](https://github.com/kubewarden/kubewarden-controller/issues/146) from ereslibre/create-github-release
- Merge pull request [#145](https://github.com/kubewarden/kubewarden-controller/issues/145) from flavio/run-policy-server-container-with-readonly-root


<a name="v0.4.4"></a>
## [v0.4.4] - 2022-01-20
### Bug Fixes
- Delete Policies not associated with PolicyServers
- Don't Update Policy.Status if Policy is read-only
- update documentation links to use custom domain

### Code Refactoring
- Drop KUBEWARDEN_ENABLE_VERIFICATION, not needed
- Rename Secret to CASecret for disambiguation
- Move policy-server-{,ca}-secret{,_test}.go
- split watch logic with reconcileOrphanPolicies()
- Drop `make tag`, use git-chglog --next
- Rename vars that are too short
- Reuse parent context for deleting policies
- Extract sources path into constants pkg

### Features
- Add verification options to PolicyServer
- Set missing policiesv1alpha2.PolicyServerCASecretReconciled
- Policy counter metric.
- OpenTelemetry integration.
- policy server name label in the deployment.
- add OpenTelemetry integration
- Add PolicyServer.spec.sourceAuthorities to CR
- Add spec.insecureSources to PolicyServer CR
- Add spec.imagePullSecrets to PolicyServer
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Reverts
- Bump cyclomatix complexity to 16 from 13
- Set PolicyStatus "unscheduled" as default in CRD

### Pull Requests
- Merge pull request [#144](https://github.com/kubewarden/kubewarden-controller/issues/144) from ereslibre/create-policy-server-tmp-volume
- Merge pull request [#139](https://github.com/kubewarden/kubewarden-controller/issues/139) from viccuad/verification-secret
- Merge pull request [#135](https://github.com/kubewarden/kubewarden-controller/issues/135) from viccuad/bug-finalizers
- Merge pull request [#128](https://github.com/kubewarden/kubewarden-controller/issues/128) from kubewarden/report-mode-rfc
- Merge pull request [#124](https://github.com/kubewarden/kubewarden-controller/issues/124) from viccuad/git-chlog-workflow
- Merge pull request [#122](https://github.com/kubewarden/kubewarden-controller/issues/122) from viccuad/golangci-1.42
- Merge pull request [#112](https://github.com/kubewarden/kubewarden-controller/issues/112) from ereslibre/opentelemetry
- Merge pull request [#118](https://github.com/kubewarden/kubewarden-controller/issues/118) from viccuad/main
- Merge pull request [#117](https://github.com/kubewarden/kubewarden-controller/issues/117) from viccuad/docs-crds
- Merge pull request [#114](https://github.com/kubewarden/kubewarden-controller/issues/114) from viccuad/custom-cas
- Merge pull request [#108](https://github.com/kubewarden/kubewarden-controller/issues/108) from viccuad/insecureregs
- Merge pull request [#106](https://github.com/kubewarden/kubewarden-controller/issues/106) from jvanz/can-update-env
- Merge pull request [#92](https://github.com/kubewarden/kubewarden-controller/issues/92) from ereslibre/development-webhook-wrapper
- Merge pull request [#99](https://github.com/kubewarden/kubewarden-controller/issues/99) from viccuad/main
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
- Merge pull request [#46](https://github.com/kubewarden/kubewarden-controller/issues/46) from flavio/policy-server-crd-proposal
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/drop-v1alpha1
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.3.5"></a>
## [kubewarden-controller-0.3.5] - 2021-12-21
### Pull Requests
- Merge pull request [#54](https://github.com/kubewarden/kubewarden-controller/issues/54) from viccuad/main


<a name="kubewarden-controller-0.3.4"></a>
## [kubewarden-controller-0.3.4] - 2021-12-21
### Features
- Expose controller resource limits/requests in Values

### Pull Requests
- Merge pull request [#49](https://github.com/kubewarden/kubewarden-controller/issues/49) from jvanz/bump-policy-server-v0.2.5
- Merge pull request [#47](https://github.com/kubewarden/kubewarden-controller/issues/47) from jvanz/bump-controller-v0.3.2
- Merge pull request [#42](https://github.com/kubewarden/kubewarden-controller/issues/42) from ereslibre/opentelemetry
- Merge pull request [#46](https://github.com/kubewarden/kubewarden-controller/issues/46) from kubewarden/fix-gh-pages
- Merge pull request [#43](https://github.com/kubewarden/kubewarden-controller/issues/43) from viccuad/main
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/new-architecture
- Merge pull request [#33](https://github.com/kubewarden/kubewarden-controller/issues/33) from kubewarden/update-policy-server-with-rego-support
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/bump-controller
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.4.3"></a>
## [v0.4.3] - 2021-12-20
### Bug Fixes
- Delete Policies not associated with PolicyServers
- Don't Update Policy.Status if Policy is read-only
- update documentation links to use custom domain

### Code Refactoring
- split watch logic with reconcileOrphanPolicies()
- Drop `make tag`, use git-chglog --next
- Rename vars that are too short
- Reuse parent context for deleting policies
- Extract sources path into constants pkg

### Features
- Policy counter metric.
- OpenTelemetry integration.
- policy server name label in the deployment.
- add OpenTelemetry integration
- Add PolicyServer.spec.sourceAuthorities to CR
- Add spec.insecureSources to PolicyServer CR
- Add spec.imagePullSecrets to PolicyServer
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Reverts
- Bump cyclomatix complexity to 16 from 13
- Set PolicyStatus "unscheduled" as default in CRD

### Pull Requests
- Merge pull request [#135](https://github.com/kubewarden/kubewarden-controller/issues/135) from viccuad/bug-finalizers
- Merge pull request [#128](https://github.com/kubewarden/kubewarden-controller/issues/128) from kubewarden/report-mode-rfc
- Merge pull request [#124](https://github.com/kubewarden/kubewarden-controller/issues/124) from viccuad/git-chlog-workflow
- Merge pull request [#122](https://github.com/kubewarden/kubewarden-controller/issues/122) from viccuad/golangci-1.42
- Merge pull request [#112](https://github.com/kubewarden/kubewarden-controller/issues/112) from ereslibre/opentelemetry
- Merge pull request [#118](https://github.com/kubewarden/kubewarden-controller/issues/118) from viccuad/main
- Merge pull request [#117](https://github.com/kubewarden/kubewarden-controller/issues/117) from viccuad/docs-crds
- Merge pull request [#114](https://github.com/kubewarden/kubewarden-controller/issues/114) from viccuad/custom-cas
- Merge pull request [#108](https://github.com/kubewarden/kubewarden-controller/issues/108) from viccuad/insecureregs
- Merge pull request [#106](https://github.com/kubewarden/kubewarden-controller/issues/106) from jvanz/can-update-env
- Merge pull request [#92](https://github.com/kubewarden/kubewarden-controller/issues/92) from ereslibre/development-webhook-wrapper
- Merge pull request [#99](https://github.com/kubewarden/kubewarden-controller/issues/99) from viccuad/main
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
- Merge pull request [#46](https://github.com/kubewarden/kubewarden-controller/issues/46) from flavio/policy-server-crd-proposal
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/drop-v1alpha1
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-crds-0.1.1"></a>
## [kubewarden-crds-0.1.1] - 2021-11-22

<a name="kubewarden-controller-0.3.3"></a>
## [kubewarden-controller-0.3.3] - 2021-11-22
### Pull Requests
- Merge pull request [#49](https://github.com/kubewarden/kubewarden-controller/issues/49) from jvanz/bump-policy-server-v0.2.5
- Merge pull request [#47](https://github.com/kubewarden/kubewarden-controller/issues/47) from jvanz/bump-controller-v0.3.2
- Merge pull request [#42](https://github.com/kubewarden/kubewarden-controller/issues/42) from ereslibre/opentelemetry
- Merge pull request [#46](https://github.com/kubewarden/kubewarden-controller/issues/46) from kubewarden/fix-gh-pages
- Merge pull request [#43](https://github.com/kubewarden/kubewarden-controller/issues/43) from viccuad/main
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/new-architecture
- Merge pull request [#33](https://github.com/kubewarden/kubewarden-controller/issues/33) from kubewarden/update-policy-server-with-rego-support
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/bump-controller
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.4.2"></a>
## [v0.4.2] - 2021-11-10
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
### Bug Fixes
- update documentation links to use custom domain

### Code Refactoring
- Extract sources path into constants pkg

### Features
- Add PolicyServer.spec.sourceAuthorities to CR
- Add spec.insecureSources to PolicyServer CR
- Add spec.imagePullSecrets to PolicyServer
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Reverts
- Set PolicyStatus "unscheduled" as default in CRD

### Pull Requests
- Merge pull request [#117](https://github.com/kubewarden/kubewarden-controller/issues/117) from viccuad/docs-crds
- Merge pull request [#114](https://github.com/kubewarden/kubewarden-controller/issues/114) from viccuad/custom-cas
- Merge pull request [#108](https://github.com/kubewarden/kubewarden-controller/issues/108) from viccuad/insecureregs
- Merge pull request [#106](https://github.com/kubewarden/kubewarden-controller/issues/106) from jvanz/can-update-env
- Merge pull request [#92](https://github.com/kubewarden/kubewarden-controller/issues/92) from ereslibre/development-webhook-wrapper
- Merge pull request [#99](https://github.com/kubewarden/kubewarden-controller/issues/99) from viccuad/main
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
- Merge pull request [#46](https://github.com/kubewarden/kubewarden-controller/issues/46) from flavio/policy-server-crd-proposal
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/drop-v1alpha1
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-crds-0.1.0"></a>
## [kubewarden-crds-0.1.0] - 2021-10-05

<a name="kubewarden-controller-0.3.0"></a>
## [kubewarden-controller-0.3.0] - 2021-10-05
### Pull Requests
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/new-architecture
- Merge pull request [#33](https://github.com/kubewarden/kubewarden-controller/issues/33) from kubewarden/update-policy-server-with-rego-support
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/bump-controller
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.4.0"></a>
## [v0.4.0] - 2021-10-05
### Bug Fixes
- update documentation links to use custom domain

### Features
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

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
- Merge pull request [#46](https://github.com/kubewarden/kubewarden-controller/issues/46) from flavio/policy-server-crd-proposal
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/drop-v1alpha1
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.2.4"></a>
## [kubewarden-controller-0.2.4] - 2021-09-27

<a name="kubewarden-controller-0.2.3"></a>
## [kubewarden-controller-0.2.3] - 2021-09-20
### Pull Requests
- Merge pull request [#33](https://github.com/kubewarden/kubewarden-controller/issues/33) from kubewarden/update-policy-server-with-rego-support


<a name="kubewarden-controller-0.2.2"></a>
## [kubewarden-controller-0.2.2] - 2021-08-19
### Pull Requests
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/bump-controller
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.3.2"></a>
## [v0.3.2] - 2021-08-19
### Bug Fixes
- update documentation links to use custom domain

### Features
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Pull Requests
- Merge pull request [#46](https://github.com/kubewarden/kubewarden-controller/issues/46) from flavio/policy-server-crd-proposal
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/drop-v1alpha1
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.2.1"></a>
## [kubewarden-controller-0.2.1] - 2021-06-18
### Pull Requests
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/bump-controller
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.3.1"></a>
## [v0.3.1] - 2021-06-18
### Bug Fixes
- update documentation links to use custom domain

### Features
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Pull Requests
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/drop-v1alpha1
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.2.0"></a>
## [kubewarden-controller-0.2.0] - 2021-06-18
### Pull Requests
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/bump-controller
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.3.0"></a>
## [v0.3.0] - 2021-06-18
### Bug Fixes
- update documentation links to use custom domain

### Features
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Pull Requests
- Merge pull request [#40](https://github.com/kubewarden/kubewarden-controller/issues/40) from kubewarden/drop-v1alpha1
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.1.18"></a>
## [kubewarden-controller-0.1.18] - 2021-06-17

<a name="kubewarden-controller-0.1.17"></a>
## [kubewarden-controller-0.1.17] - 2021-06-04
### Pull Requests
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.2.3"></a>
## [v0.2.3] - 2021-06-04
### Bug Fixes
- update documentation links to use custom domain

### Features
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Pull Requests
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.1.16"></a>
## [kubewarden-controller-0.1.16] - 2021-06-04

<a name="kubewarden-controller-0.1.15"></a>
## [kubewarden-controller-0.1.15] - 2021-06-04
### Pull Requests
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.2.2"></a>
## [v0.2.2] - 2021-06-04
### Bug Fixes
- update documentation links to use custom domain

### Features
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Pull Requests
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.1.14"></a>
## [kubewarden-controller-0.1.14] - 2021-06-04

<a name="kubewarden-controller-0.1.13"></a>
## [kubewarden-controller-0.1.13] - 2021-06-04
### Pull Requests
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.2.1"></a>
## [v0.2.1] - 2021-06-03
### Bug Fixes
- update documentation links to use custom domain

### Features
- implement ClusterAdmissionPolicy status subresource
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Pull Requests
- Merge pull request [#37](https://github.com/kubewarden/kubewarden-controller/issues/37) from ereslibre/policyadmission-status
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.1.12"></a>
## [kubewarden-controller-0.1.12] - 2021-05-24
### Pull Requests
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from kubewarden/upgrade-kubewarden-controller-to-0.2.0
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.2.0"></a>
## [v0.2.0] - 2021-05-24
### Bug Fixes
- update documentation links to use custom domain

### Features
- Introduce new version of ClusterAdmissionPolicy
- Upgrade from kubebuilder v2 -> v3
- add changelog generation tooling

### Pull Requests
- Merge pull request [#29](https://github.com/kubewarden/kubewarden-controller/issues/29) from ereslibre/main
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.1.11"></a>
## [kubewarden-controller-0.1.11] - 2021-04-20

<a name="kubewarden-controller-0.1.10"></a>
## [kubewarden-controller-0.1.10] - 2021-04-20
### Pull Requests
- Merge pull request [#9](https://github.com/kubewarden/kubewarden-controller/issues/9) from ereslibre/rancher-helm-files


<a name="kubewarden-controller-0.1.9"></a>
## [kubewarden-controller-0.1.9] - 2021-04-20

<a name="kubewarden-controller-0.1.8"></a>
## [kubewarden-controller-0.1.8] - 2021-04-20
### Pull Requests
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.1.4"></a>
## [v0.1.4] - 2021-04-14
### Bug Fixes
- update documentation links to use custom domain

### Features
- add changelog generation tooling

### Pull Requests
- Merge pull request [#27](https://github.com/kubewarden/kubewarden-controller/issues/27) from ereslibre/changelog-generation
- Merge pull request [#28](https://github.com/kubewarden/kubewarden-controller/issues/28) from ereslibre/update-links
- Merge pull request [#23](https://github.com/kubewarden/kubewarden-controller/issues/23) from ereslibre/add-release-action
- Merge pull request [#25](https://github.com/kubewarden/kubewarden-controller/issues/25) from ereslibre/service-account
- Merge pull request [#24](https://github.com/kubewarden/kubewarden-controller/issues/24) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#21](https://github.com/kubewarden/kubewarden-controller/issues/21) from ereslibre/expose-all-webhook-settings
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.1.7"></a>
## [kubewarden-controller-0.1.7] - 2021-04-12
### Pull Requests
- Merge pull request [#6](https://github.com/kubewarden/kubewarden-controller/issues/6) from ereslibre/service-account
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


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
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.1.6"></a>
## [kubewarden-controller-0.1.6] - 2021-04-09
### Pull Requests
- Merge pull request [#5](https://github.com/kubewarden/kubewarden-controller/issues/5) from ereslibre/add-mutating-webhook-config-rights


<a name="kubewarden-controller-0.1.5"></a>
## [kubewarden-controller-0.1.5] - 2021-04-08

<a name="kubewarden-controller-0.1.4"></a>
## [kubewarden-controller-0.1.4] - 2021-04-08

<a name="kubewarden-controller-0.1.3"></a>
## [kubewarden-controller-0.1.3] - 2021-04-07

<a name="kubewarden-controller-0.1.2"></a>
## [kubewarden-controller-0.1.2] - 2021-04-06

<a name="kubewarden-controller-0.1.1"></a>
## [kubewarden-controller-0.1.1] - 2021-04-06
### Pull Requests
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="v0.1.0"></a>
## [v0.1.0] - 2021-04-06
### Pull Requests
- Merge pull request [#17](https://github.com/kubewarden/kubewarden-controller/issues/17) from kubewarden/remove-pat
- Merge pull request [#18](https://github.com/kubewarden/kubewarden-controller/issues/18) from kubewarden/rename
- Merge pull request [#16](https://github.com/kubewarden/kubewarden-controller/issues/16) from flavio/mutating-policies
- Merge pull request [#12](https://github.com/kubewarden/kubewarden-controller/issues/12) from flavio/golangci-lint-action
- Merge pull request [#11](https://github.com/kubewarden/kubewarden-controller/issues/11) from drpaneas/panos
- Merge pull request [#8](https://github.com/kubewarden/kubewarden-controller/issues/8) from kkaempf/suppress-make-warning


<a name="kubewarden-controller-0.1.0"></a>
## [kubewarden-controller-0.1.0] - 2021-04-06
### Pull Requests
- Merge pull request [#2](https://github.com/kubewarden/kubewarden-controller/issues/2) from kubewarden/renaming


<a name="chimera-controller-0.1.2"></a>
## [chimera-controller-0.1.2] - 2021-03-25
### Pull Requests
- Merge pull request [#1](https://github.com/kubewarden/kubewarden-controller/issues/1) from chimera-kube/mutating-policies


<a name="chimera-controller-0.1.1"></a>
## [chimera-controller-0.1.1] - 2021-03-03

<a name="chimera-controller-0.1.0"></a>
## [chimera-controller-0.1.0] - 2021-03-03

<a name="v0.1.0-rc1"></a>
## [v0.1.0-rc1] - 2021-03-02

<a name="v0.0.1"></a>
## v0.0.1 - 2021-01-18

[Unreleased]: https://github.com/kubewarden/kubewarden-controller/compare/v0.5.2-rc2...HEAD
[v0.5.2-rc2]: https://github.com/kubewarden/kubewarden-controller/compare/v0.5.2-rc...v0.5.2-rc2
[v0.5.2-rc]: https://github.com/kubewarden/kubewarden-controller/compare/v0.5.1...v0.5.2-rc
[v0.5.1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.5.0...v0.5.1
[v0.5.0]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.5...v0.5.0
[v0.4.5]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.5-rc1...v0.4.5
[v0.4.5-rc1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.4...v0.4.5-rc1
[v0.4.4]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.3.5...v0.4.4
[kubewarden-controller-0.3.5]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.3.4...kubewarden-controller-0.3.5
[kubewarden-controller-0.3.4]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.3...kubewarden-controller-0.3.4
[v0.4.3]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-crds-0.1.1...v0.4.3
[kubewarden-crds-0.1.1]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.3.3...kubewarden-crds-0.1.1
[kubewarden-controller-0.3.3]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.2...kubewarden-controller-0.3.3
[v0.4.2]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-crds-0.1.0...v0.4.1
[kubewarden-crds-0.1.0]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.3.0...kubewarden-crds-0.1.0
[kubewarden-controller-0.3.0]: https://github.com/kubewarden/kubewarden-controller/compare/v0.4.0...kubewarden-controller-0.3.0
[v0.4.0]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.2.4...v0.4.0
[kubewarden-controller-0.2.4]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.2.3...kubewarden-controller-0.2.4
[kubewarden-controller-0.2.3]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.2.2...kubewarden-controller-0.2.3
[kubewarden-controller-0.2.2]: https://github.com/kubewarden/kubewarden-controller/compare/v0.3.2...kubewarden-controller-0.2.2
[v0.3.2]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.2.1...v0.3.2
[kubewarden-controller-0.2.1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.3.1...kubewarden-controller-0.2.1
[v0.3.1]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.2.0...v0.3.1
[kubewarden-controller-0.2.0]: https://github.com/kubewarden/kubewarden-controller/compare/v0.3.0...kubewarden-controller-0.2.0
[v0.3.0]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.18...v0.3.0
[kubewarden-controller-0.1.18]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.17...kubewarden-controller-0.1.18
[kubewarden-controller-0.1.17]: https://github.com/kubewarden/kubewarden-controller/compare/v0.2.3...kubewarden-controller-0.1.17
[v0.2.3]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.16...v0.2.3
[kubewarden-controller-0.1.16]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.15...kubewarden-controller-0.1.16
[kubewarden-controller-0.1.15]: https://github.com/kubewarden/kubewarden-controller/compare/v0.2.2...kubewarden-controller-0.1.15
[v0.2.2]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.14...v0.2.2
[kubewarden-controller-0.1.14]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.13...kubewarden-controller-0.1.14
[kubewarden-controller-0.1.13]: https://github.com/kubewarden/kubewarden-controller/compare/v0.2.1...kubewarden-controller-0.1.13
[v0.2.1]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.12...v0.2.1
[kubewarden-controller-0.1.12]: https://github.com/kubewarden/kubewarden-controller/compare/v0.2.0...kubewarden-controller-0.1.12
[v0.2.0]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.11...v0.2.0
[kubewarden-controller-0.1.11]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.10...kubewarden-controller-0.1.11
[kubewarden-controller-0.1.10]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.9...kubewarden-controller-0.1.10
[kubewarden-controller-0.1.9]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.8...kubewarden-controller-0.1.9
[kubewarden-controller-0.1.8]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.4...kubewarden-controller-0.1.8
[v0.1.4]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.7...v0.1.4
[kubewarden-controller-0.1.7]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.3...kubewarden-controller-0.1.7
[v0.1.3]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.6...v0.1.1
[kubewarden-controller-0.1.6]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.5...kubewarden-controller-0.1.6
[kubewarden-controller-0.1.5]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.4...kubewarden-controller-0.1.5
[kubewarden-controller-0.1.4]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.3...kubewarden-controller-0.1.4
[kubewarden-controller-0.1.3]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.2...kubewarden-controller-0.1.3
[kubewarden-controller-0.1.2]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.1...kubewarden-controller-0.1.2
[kubewarden-controller-0.1.1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.0...kubewarden-controller-0.1.1
[v0.1.0]: https://github.com/kubewarden/kubewarden-controller/compare/kubewarden-controller-0.1.0...v0.1.0
[kubewarden-controller-0.1.0]: https://github.com/kubewarden/kubewarden-controller/compare/chimera-controller-0.1.2...kubewarden-controller-0.1.0
[chimera-controller-0.1.2]: https://github.com/kubewarden/kubewarden-controller/compare/chimera-controller-0.1.1...chimera-controller-0.1.2
[chimera-controller-0.1.1]: https://github.com/kubewarden/kubewarden-controller/compare/chimera-controller-0.1.0...chimera-controller-0.1.1
[chimera-controller-0.1.0]: https://github.com/kubewarden/kubewarden-controller/compare/v0.1.0-rc1...chimera-controller-0.1.0
[v0.1.0-rc1]: https://github.com/kubewarden/kubewarden-controller/compare/v0.0.1...v0.1.0-rc1
