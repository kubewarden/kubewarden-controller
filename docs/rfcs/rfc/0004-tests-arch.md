|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Kubewarden testing architecture  |
| Start Date   | Dec 22th 2021                    |
| Category     | QA                               |
| RFC PR       | [fill this in after opening PR]  |
| State        | **ACCEPTED**                     |

# Summary
[summary]: #summary

Define how, where and whom will trigger, store and run tests for the Kubewarden
stack.

# Motivation
[motivation]: #motivation

Currently in the Kubewarden project we do not have comprehensive tests which check
all the project components together in a automated way. We need to create a testing
architecture that ensure that all changes in any component are tested to work
together with the other components of the project. This should happen in an
automated way with the lowest possible overhead for the developer.

Furthermore, we should provide the minimal infrastructure to run component specific
tests isolated from the rest of the stack. Thus, allowing the developer run checks
ensuring that their changes does not broke something.

## Examples / User Stories
[examples]: #examples

As a developer, I want to run unit tests locally after some code change with
simple commands.

As a developer, I want to run integration tests to ensure the program continue to
behave as expected locally with simple commands.

As a developer, I want to run the end-to-end tests to ensure that my changes impacting
multiple Kubewarden stack components does not break some feature.

As a QA engineer, I want to ensure that developers changes do not break the Kubewarden
features.

As QA engineer, I want to ensure that I can add tests with no impact on the
development cycle.

As a Kubewarden maintainer, I want to run all important tests on PR to minimize
the risk of introducing new bugs and regressions.

As a Kubewarden maintainer, I want to ensure that all the policies will continue
to work as expected, without modifications, on new Kubewarden releases.

# Detailed design
[design]: #detailed-design

In order to ensure the best code and product quality, it is necessary to test a lot.
In different setups, environments and use cases. To make that reality, we can have
tests in different levels of the development. Which are the following:

## Unit tests

This is the simplest test for developers. We should make the efforts to
add tests for every code changed/added into the repositories of the Kubewarden project.
It should test individual pieces of code using the tools available for each
programming language.

When implemented, the developer should run all the test with a single command like:

```bash
# code code code
make unit-tests
```

These tests should be run on every change in the repository (e.g. push, pull request).

## Component tests

These are the tests that validates each Kubewarden component behaviour
independently from the other stack components.

To test the Kubewarden controller, it's possible to use the test infrastructure
from Kubebuilder. It creates a test environment to validates the controller
behaviour using Ginkgo and Gomega. [1](https://github.com/Azure/azure-databricks-operator/blob/0f722a710fea06b86ecdccd9455336ca712bf775/controllers/suite_test.go)
[2](https://github.com/Azure/azure-databricks-operator/blob/0f722a710fea06b86ecdccd9455336ca712bf775/controllers/secretscope_controller_test.go)
[3](https://book.kubebuilder.io/cronjob-tutorial/writing-tests.html)

For the policy server and other Rust components, we can use the language features
for integrations tests.[3](https://doc.rust-lang.org/rust-by-example/testing/integration_testing.html)

When implemented the developer should run all the tests with a single command like:

```bash
# code code code
make acceptance-tests
# or
make integration-tests
```

These tests should also run on every change proposed in the component
repository (e.g. push, pull request).


## End-to-end tests

These are the most complex tests. They will simulate what Kubewarden users will
do to install, upgrade, configure and uninstall Kubewarden stack.

In these tests, different components versions would be tested together.
Therefore, ensuring that the user will not face issues when using different
components configuration and versions together. This should ensure that
Kubernetes operator will have the expected features working.

These tests are triggered when we have new releases (or release candidate) of
any of the Kubewarden stack components.  It should follow some steps:

1. Setup Kubernetes cluster
  Kubewarden is expected to run in multiple Kubernetes versions and machine
  architectures. So, the end-to-end tests should ensure that all the supported
  versions and architectures are tested. The initial versions of the tests can
  be simple in a single arch and version.
2. Install the Kuberwarden stack on the cluster from step 1
  The version to be tested should be installed. This means that when a component
  is released. It should be tested against all the other components versions which
it is supposed to work together.
3. Run basic end-to-end tests
  Validate if the basic features are working as expected
4. Run reconfiguration tests
  Validates if the user is able to reconfigure a Kubewarden stack installed
5. Run upgrade tests
  Validate if the user is able to upgrade and continue to work with the latest release.

Steps 3,4 and 5 may run in parallel when necessary (e.g. time to execute all tests
is too long)

Considering the tests will validate multiple components of the Kubewarden stack
together (controller and Policy Server), it desirable to keep all the
end-to-end test files in a separated repository. This repository should contain
all the yaml files, scripts, and helper code to run the tests. This also helps
to avoid duplicating tests that validate some feature that impacts multiple
components.

The end-to-end tests repository should be independent. Which means that it should
run the tests independently of the tests and development cycle of the other
Kubewarden repositories. But every time a new component release is available
for testing, the end-to-end tests should be triggered automatically with no human
intervention.  Besides that, running the end-to-end test on demand and in pre defined
periods is also desirable.

We could also configure the end-to-end tests to run against the latest version of
all Kubewarden components. Thus, spotting some possible issues before a official
release candidate. As well as I nightly run to allow developers stop issues as
soon as possible.

Considering the high workload nature of the end-to-end tests it is necessary
run them in a dedicated runner outside from Github hosted runners. From past
experiences, the runners from Github could be slow and the tests failed due to
timeout issues.

These tests can be written using bash and frameworks similar to [bats](https://github.com/bats-core/bats-core/).

The developers should be able to run the same end-to-end tests locally with simple
commands like:

```bash
# in the end-to-end test respository directory
make test
```

It also desirable to allow run the end-to-end tests during development locally
under the repository of the component which under development. For that, each
component repository can have a script to download the end to end tests
repository and run them using the current under development version. To enable
this, it is necessary to define which is the interface used to setup the testing
environment and run the tests. To address this issue, we can define the following
Makefile targets:

- `create-k8s-cluster`: set up a local testing Kubernetes cluster. This could be
optional once we can define the context used in the `kubectl` command in the rest
of the command.
- `install-kubewarden`: install the Kuberwarden stack on the testing cluster
- `run-e2e-tests`: run the end to end tests

Therefore, the components Makefiles can call the targets available in the
end to end tests repository to setup and run the tests.

All the targets make use of variables to parametrize the testing environment and
testing execution. Some suggested variables are:

- `KUBEWARDEN_CONTROLLER_IMAGE`: Kubewarden controller container image using
in the deployment
- `POLICY_SERVER_IMAGE`: Kubewarden Policy Server container image using in the
deployment
- `KUBECTL_CONTEXT`: `kubectl` context which we will use in all the command call
during the setup and tests execution.
- `TEST_FILTER`: some string to filter which tests should be run

One example of execution from a component repository could be:

```bash
KUBEWARDEN_CONTROLLER_IMAGE=ghcr.io/developer/kubewarden-controller:latest TEST_FILTER=basic-tests make create-k8s-cluster install-kubewarden run-e2e-tests
```

or

```bash
KUBEWARDEN_CONTROLLER_IMAGE=ghcr.io/developer/kubewarden-controller:latest TEST_FILTER=basic-tests KUBECTL_CONTEXT=testingcluster make install-kubewarden run-e2e-tests
```

The team should also provide Github actions to run the tests among all the
repositories which can trigger the tests.

## Policy tests

It's also desirable to have tests to validate policies behaviour. So, it is
necessary provide policy authors some tools to help them testing their policies.
There is an initial [tool](https://github.com/kubewarden/setup-kubewarden-cluster-action)
for that. It's a Github action which creates a K3D cluster and installs Kubewarden
on it.

The policy templates should be updated to have a template workflow file with
the basic steps to setup the test infrastructure.

# Drawbacks
[drawbacks]: #drawbacks

* We need considerable initial effort to build the test infrastructure.
* Additional effort to keep in sync the scripts to run the end to end test among
all the components repositories and the tests repository.

# Alternatives
[alternatives]: #alternatives

# Unresolved questions
[unresolved]: #unresolved-questions

* We need to be responsible to keep the tests stable. Otherwise, people will ignore
the tests results.
* Can we use the Rancher infrastructure already in place to run our tests?
If so, we can save time setting up the infrastructure.

