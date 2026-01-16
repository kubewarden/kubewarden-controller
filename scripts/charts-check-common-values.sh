#!/bin/bash
set -euo pipefail

# Check that there's no divergence between ./common-values.yaml, key `global`,
# and the `global` key on the helm-chart values.yaml

diff <(yq eval '(.global // {}) | sort_keys(.)' charts/common-values.yaml) <(yq eval '(.global // {}) | sort_keys(.)' charts/kubewarden-controller/values.yaml) || (
	echo
	echo "kubewarden-controller values.yaml diverges from common-values.yaml"
	exit 1
)
diff <(yq eval '(.global // {}) | sort_keys(.)' charts/common-values.yaml) <(yq eval '(.global // {}) | sort_keys(.)' charts/kubewarden-defaults/values.yaml) || (
	echo
	echo "kubewarden-defaults values.yaml diverges from charts/common-values.yaml"
	exit 1
)
