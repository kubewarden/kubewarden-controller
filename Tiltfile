tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

update_settings(k8s_upsert_timeout_secs=300)

# Create the kubewarden namespace
# This is required since the helm() function doesn't support the create_namespace flag
load("ext://namespace", "namespace_create")
namespace_create("kubewarden")

# Install the CRDs Helm chart first
crds_yaml = helm(
    "./charts/kubewarden-crds",
    name="kubewarden-crds",
    namespace="kubewarden",
)
k8s_yaml(crds_yaml)

# Group all CRDs under a single resource name for dependency tracking
k8s_resource(
    new_name='kubewarden-crds',
    objects=[
        'policyservers.policies.kubewarden.io:CustomResourceDefinition',
        'admissionpolicies.policies.kubewarden.io:CustomResourceDefinition',
        'clusteradmissionpolicies.policies.kubewarden.io:CustomResourceDefinition',
        'admissionpolicygroups.policies.kubewarden.io:CustomResourceDefinition',
        'clusteradmissionpolicygroups.policies.kubewarden.io:CustomResourceDefinition',
    ],
)

registry = settings.get("registry")
controller_image = settings.get("controller").get("image")
audit_scanner_image = settings.get("audit-scanner").get("image")
policy_server_image = settings.get("policy-server").get("image")

kubewarden_controller_yaml = helm(
    "./charts/kubewarden-controller",
    name="kubewarden-controller",
    namespace="kubewarden",
    set=[
        "global.cattle.systemDefaultRegistry=null",
        "image.repository=" + registry + "/" + controller_image,
        "replicas=1",
        "logLevel=debug",
        "podSecurityContext=null",
        "containerSecurityContext=null",
        "auditScanner.image.repository=" + registry + "/" + audit_scanner_image,
        "auditScanner.logLevel=debug", 
    ],
)
k8s_yaml(kubewarden_controller_yaml)

# Wait for kubewarden-controller deployment to be ready before applying defaults
# This ensures the webhook is running before PolicyServer resources are created
k8s_resource(
    'kubewarden-controller:deployment',
    new_name='kubewarden-controller',
    resource_deps=['kubewarden-crds'],
)

kubewarden_defaults_yaml = helm(
    "./charts/kubewarden-defaults",
    name="kubewarden-defaults",
    namespace="kubewarden",
    set=[
        "global.cattle.systemDefaultRegistry=null",
        "policyServer.image.repository=" + registry + "/" + policy_server_image,
        "policyServer.env[0].name=KUBEWARDEN_LOG_LEVEL",
        "policyServer.env[0].value=debug",
    ],
)
k8s_yaml(kubewarden_defaults_yaml)

k8s_resource(
    'default',
    resource_deps=['kubewarden-controller', 'policy_server_tilt'],
)

# Tell tilt about the image used by the PolicyServer CRD
# so that it can update it when needed
k8s_kind("PolicyServer", image_json_path='{.spec.image}')


# Hot reloading containers
local_resource(
    "controller_tilt",
    "make controller",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/controller",
        "api",
        "internal/certs",
        "internal/constants",
        "internal/controller",
        "internal/featuregates",
        "internal/metrics",
    ],
)

entrypoint = ["/controller"]
dockerfile = "./hack/Dockerfile.kubewarden-controller.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    registry + "/" + controller_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/controller",
    ],
    live_update=[
        sync("./bin/controller", "/controller"),
    ],
)

local_resource(
    "audit_scanner_tilt",
    "make audit-scanner",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/audit-scanner",
        "api",
        "internal/audit-scanner",
        "internal/constants",
    ],
)

# We use a specific Dockerfile since tilt can't run on a scratch container.
dockerfile = "./hack/Dockerfile.audit-scanner.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build(
    registry + "/" + audit_scanner_image,
    ".",
    dockerfile=dockerfile,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/audit-scanner",
    ],
)


local_resource(
    "policy_server_tilt",
    "make policy-server",
    deps=[
        "Cargo.toml",
        "Cargo.lock",
        "crates/burrego",
        "crates/policy-evaluator",
        "crates/policy-fetcher",
        "crates/policy-server",
    ],
)

dockerfile = "./hack/Dockerfile.policy-server.tilt"

# Note: Using docker_build instead of docker_build_with_restart because PolicyServer
# is a CRD and Tilt cannot inject restart wrappers into CRD-managed containers
# Instead, we trigger a restart by updating the PolicyServer `.spec.annotation`
docker_build(
    registry + "/" + policy_server_image,
    ".",
    dockerfile=dockerfile,
    only=[
        "./bin/policy-server",
    ],
)

# Trigger PolicyServer pod restart by updating annotations when image changes
# Runs automatically whenever the policy-server image is rebuilt
local_resource(
    "restart_policy_server",
    "kubectl get policyserver default >/dev/null 2>&1 && kubectl patch policyserver default --type=merge -p '{\"spec\":{\"annotations\":{\"restart\":\"'$(date +%s)'\"}}}'  || true",
    resource_deps=["default"],
    trigger_mode=TRIGGER_MODE_AUTO,
)
