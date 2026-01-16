#!/bin/bash
set -euo pipefail

CHART_DIR=$1
IMAGELIST_FILENAME=$2
TMP_CHANGELOG_FILE_PATH=/tmp/changelog.md

CONTROLLER_VERSION=$(grep "kubewarden-controller" <"$IMAGELIST_FILENAME" | sed "s/.*kubewarden-controller:\(\)/\1/g")
CONTROLLER_URL=$(gh release view "$CONTROLLER_VERSION" --repo kubewarden/kubewarden-controller --json "url" | jq -r ".url")
{
  echo "Kubewarden Admission Controller [changelog]($CONTROLLER_URL)"
} >>$TMP_CHANGELOG_FILE_PATH
cp $TMP_CHANGELOG_FILE_PATH "$CHART_DIR/kubewarden-controller/CHANGELOG.md"
cp $TMP_CHANGELOG_FILE_PATH "$CHART_DIR/kubewarden-defaults/CHANGELOG.md"
cp $TMP_CHANGELOG_FILE_PATH "$CHART_DIR/kubewarden-crds/CHANGELOG.md"
