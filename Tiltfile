# -*- mode: Python -*-

tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

kubectl_cmd = "kubectl"

# verify kubectl command exists
if str(local("command -v " + kubectl_cmd + " || true", quiet = True)) == "":
    fail("Required command '" + kubectl_cmd + "' not found in PATH")

# Install cert manager
load('ext://cert_manager', 'deploy_cert_manager')
deploy_cert_manager()

# Create the kubewarden namespace
# This is required since the helm() function doesn't support the create_namespace flag
load('ext://namespace', 'namespace_create')
namespace_create('kubewarden')

# Install CRDs
crd = kustomize('config/crd')
k8s_yaml(crd)
roles = decode_yaml_stream(kustomize('config/rbac'))
cluster_rules = []
namespace_rules = []
roles_rules_mapping = {
	"ClusterRole": {},
	"Role": {},
}

for role in roles:
    if role.get('kind') == 'ClusterRole':
	roles_rules_mapping["ClusterRole"][role.get('metadata').get('name')] = role.get('rules')
    elif role.get('kind') == 'Role':
        roles_rules_mapping["Role"][role.get('metadata').get('name')] = role.get('rules')

if len(roles_rules_mapping["ClusterRole"]) == 0 or len(roles_rules_mapping["Role"]) == 0:
    fail("Failed to load cluster and namespace roles")


# Install kubewarden-controller helm chart
install = helm(
    settings.get('helm_charts_path') + '/charts/kubewarden-controller/', 
    name='kubewarden-controller', 
    namespace='kubewarden', 
    set=['image.repository=' + settings.get('image'), 'global.cattle.SystemDefaultRegistry=' + settings.get('registry')]
)

objects = decode_yaml_stream(install)
for o in objects:
    # Update the root security group. Tilt requires root access to update the
    # running process.
    if o.get('kind') == 'Deployment' and o.get('metadata').get('name') == 'kubewarden-controller':
        o['spec']['template']['spec']['securityContext']['runAsNonRoot'] = False
        # Disable the leader election to speed up the startup time.
        o['spec']['template']['spec']['containers'][0]['args'].remove('--leader-elect')

    # Update the cluster and namespace roles used by the controller. This ensures
    # that always we have the latest roles applied to the cluster.
    if o.get('kind') == 'ClusterRole' and o.get('metadata').get('name') == 'kubewarden-controller-manager-cluster-role':
	o['rules'] = roles_rules_mapping["ClusterRole"]["manager-role"]
    if o.get('kind') == 'Role' and o.get('metadata').get('name') == 'kubewarden-controller-manager-namespaced-role':
	o['rules'] = roles_rules_mapping["Role"]["manager-role"]
    if o.get('kind') == 'Role' and o.get('metadata').get('name') == 'kubewarden-controller-leader-election-role':
	o['rules'] = roles_rules_mapping["Role"]["leader-election-role"]

updated_install = encode_yaml_stream(objects)
k8s_yaml(updated_install)

# enable hot reloading by doing the following:
# - locally build the whole project
# - create a docker imagine using tilt's hot-swap wrapper
# - push that container to the local tilt registry
# Once done, rebuilding now should be a lot faster since only the relevant
# binary is rebuilt and the hot swat wrapper takes care of the rest.
local_resource(
    'manager',
    "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/manager ./",
    deps = [
        "main.go",
        "go.mod",
        "go.sum",
        "internal",
        "controllers",
        "pkg",
    ],
)

# Build the docker image for our controller. We use a specific Dockerfile
# since tilt can't run on a scratch container.
entrypoint = ['/manager', '-zap-devel']
dockerfile = 'tilt.dockerfile'

load('ext://restart_process', 'docker_build_with_restart')
docker_build_with_restart(
    settings.get('registry') + '/' + settings.get('image'),
    '.',
    dockerfile = dockerfile,
    entrypoint = entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
      './bin',
    ],
    live_update = [
        sync('./bin/manager', '/manager'),
    ],
)

