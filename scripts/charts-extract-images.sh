#!/bin/bash
set -euo pipefail

CHART_DIR="$1"
IMAGELIST_FILENAME=imagelist.txt

RENDERED=$(helm template --values "$CHART_DIR"/values.yaml --set auditScanner.policyReporter=true "$CHART_DIR/")

{
	echo "$RENDERED" | yq -r '..|.image?' | grep -v "null"
	echo "$RENDERED" | yq '. | select(.kind=="ConfigMap" and .metadata.name=="kubewarden-defaults") | .data[]' \
		| yq -r '..|.image?' | grep -v "null"
} | grep -E '^[a-zA-Z0-9].*/' | sort -u > "$IMAGELIST_FILENAME"
