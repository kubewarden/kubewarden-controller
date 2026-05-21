#!/bin/bash
set -euo pipefail

CHART_DIR="$1"
POLICYLIST_FILENAME=policylist.txt

helm template --values "$CHART_DIR"/values.yaml --set recommendedPolicies.enabled=true "$CHART_DIR/" \
	| yq '. | select(.kind=="ConfigMap" and .metadata.name=="kubewarden-defaults") | .data[]' \
	| grep '^\s*module:' | sed 's/.*module:\s*//' \
	| while read -r line; do
		if ! echo "$line" | grep -qE '(https://|registry://)'; then
			echo "registry://$line"
		else
			echo "$line"
		fi
	done | sort -u > "$POLICYLIST_FILENAME"
