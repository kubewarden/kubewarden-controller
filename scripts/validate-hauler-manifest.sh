#!/usr/bin/env bash

# This script validates that the Hauler manifest
# (`charts/hauler_manifest.yaml`) stays in sync with Helm chart definitions. It
# compares versions of container images and Helm charts between the chart
# definitions and the Hauler manifest to prevent version mismatches that could
# cause issues in air-gapped deployments.
# 
# The script runs automatically in CI when the `ci-full` label is added to a
# PR, on pushes to the main branch, and on manual workflow triggers. It
# validates all container images (kubewarden-controller, audit-scanner,
# policy-server, kuberlr-kubectl, policy modules and third-party images:
# policy-reporter, policy-reporter-ui ) and Helm charts (kubewarden-crds,
# kubewarden-controller, kubewarden-defaults, policy-reporter, openreports).
# 
# The weekly updatecli workflow automatically updates both Helm chart values
# and the Hauler manifest. This validation serves as a safety check to catch
# any manual changes or update failures.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HAULER_MANIFEST="$REPO_ROOT/charts/hauler_manifest.yaml"
CONTROLLER_VALUES="$REPO_ROOT/charts/kubewarden-controller/values.yaml"
DEFAULTS_VALUES="$REPO_ROOT/charts/kubewarden-defaults/values.yaml"
CONTROLLER_CHART="$REPO_ROOT/charts/kubewarden-controller/Chart.yaml"
DEFAULTS_CHART="$REPO_ROOT/charts/kubewarden-defaults/Chart.yaml"
CRDS_CHART="$REPO_ROOT/charts/kubewarden-crds/Chart.yaml"

ERRORS=0

echo "🔍 Validating Hauler manifest against Helm charts..."
echo

# Check if yq is installed
if ! command -v yq &> /dev/null; then
    echo -e "${RED}❌ Error: yq is not installed. Please install yq v4.x${NC}"
    echo "   Install: https://github.com/mikefarah/yq#install"
    exit 1
fi

# Function to extract image version from Hauler manifest
get_hauler_image_version() {
    local image_name=$1
    yq eval ".spec.images[] | select(.name | contains(\"$image_name\")) | .name" "$HAULER_MANIFEST" | sed 's/.*://'
}

# Function to compare versions
compare_version() {
    local name=$1
    local chart_version=$2
    local hauler_version=$3
    local location=$4

    if [[ "$chart_version" != "$hauler_version" ]]; then
        echo -e "${RED}❌ Mismatch: $name${NC}"
        echo "   Chart ($location): $chart_version"
        echo "   Hauler manifest: $hauler_version"
        echo
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${GREEN}✅ Match: $name = $chart_version${NC}"
    fi
}

echo "📦 Validating Container Images..."
echo "=================================="
echo

# Validate kubewarden-controller image
CONTROLLER_CHART_VERSION=$(yq eval '.image.tag' "$CONTROLLER_VALUES")
CONTROLLER_HAULER_VERSION=$(get_hauler_image_version "kubewarden-controller")
compare_version "kubewarden-controller" "$CONTROLLER_CHART_VERSION" "$CONTROLLER_HAULER_VERSION" "$CONTROLLER_VALUES"

# Validate audit-scanner image
AUDIT_SCANNER_CHART_VERSION=$(yq eval '.auditScanner.image.tag' "$CONTROLLER_VALUES")
AUDIT_SCANNER_HAULER_VERSION=$(get_hauler_image_version "audit-scanner")
compare_version "audit-scanner" "$AUDIT_SCANNER_CHART_VERSION" "$AUDIT_SCANNER_HAULER_VERSION" "$CONTROLLER_VALUES"

# Validate policy-server image
POLICY_SERVER_CHART_VERSION=$(yq eval '.policyServer.image.tag' "$DEFAULTS_VALUES")
POLICY_SERVER_HAULER_VERSION=$(get_hauler_image_version "policy-server")
compare_version "policy-server" "$POLICY_SERVER_CHART_VERSION" "$POLICY_SERVER_HAULER_VERSION" "$DEFAULTS_VALUES"

# Validate kuberlr-kubectl image
KUBERLR_CHART_VERSION=$(yq eval '.preDeleteJob.image.tag' "$CONTROLLER_VALUES")
KUBERLR_HAULER_VERSION=$(get_hauler_image_version "kuberlr-kubectl")
compare_version "kuberlr-kubectl" "$KUBERLR_CHART_VERSION" "$KUBERLR_HAULER_VERSION" "$CONTROLLER_VALUES"

echo
echo "🌐 Validating Third-Party Images..."
echo "===================================="
echo

# Extract policy-reporter chart metadata from the vendored chart
POLICY_REPORTER_CHART_PATH="$REPO_ROOT/charts/kubewarden-controller/charts"
POLICY_REPORTER_CHART_VERSION=$(yq eval '.dependencies[0].version' "$CONTROLLER_CHART")
POLICY_REPORTER_TGZ="$POLICY_REPORTER_CHART_PATH/policy-reporter-${POLICY_REPORTER_CHART_VERSION}.tgz"

# Check if the vendored chart exists
if [[ ! -f "$POLICY_REPORTER_TGZ" ]]; then
    echo -e "${RED}❌ Error: policy-reporter chart tarball not found at $POLICY_REPORTER_TGZ${NC}"
    ERRORS=$((ERRORS + 1))
else
    # Validate policy-reporter image (should match appVersion from Chart.yaml)
    POLICY_REPORTER_APP_VERSION=$(tar -xzf "$POLICY_REPORTER_TGZ" policy-reporter/Chart.yaml --to-stdout 2>/dev/null | yq eval '.appVersion' -)
    POLICY_REPORTER_HAULER_VERSION=$(get_hauler_image_version "policy-reporter:")
    compare_version "policy-reporter" "$POLICY_REPORTER_APP_VERSION" "$POLICY_REPORTER_HAULER_VERSION" "policy-reporter chart (appVersion)"

    # Validate policy-reporter-ui image (should match ui.image.tag from values.yaml)
    POLICY_REPORTER_UI_VERSION=$(tar -xzf "$POLICY_REPORTER_TGZ" policy-reporter/values.yaml --to-stdout 2>/dev/null | yq eval '.ui.image.tag' -)
    POLICY_REPORTER_UI_HAULER_VERSION=$(get_hauler_image_version "policy-reporter-ui")
    compare_version "policy-reporter-ui" "$POLICY_REPORTER_UI_VERSION" "$POLICY_REPORTER_UI_HAULER_VERSION" "policy-reporter chart (ui.image.tag)"
fi

echo
echo "🔐 Validating Policy Images..."
echo "==============================="
echo

# Validate allow-privilege-escalation-psp policy
POLICY_VERSION=$(yq eval '.recommendedPolicies.allowPrivilegeEscalationPolicy.module.tag' "$DEFAULTS_VALUES")
HAULER_VERSION=$(get_hauler_image_version "allow-privilege-escalation-psp")
compare_version "allow-privilege-escalation-psp" "$POLICY_VERSION" "$HAULER_VERSION" "$DEFAULTS_VALUES"

# Validate capabilities-psp policy
POLICY_VERSION=$(yq eval '.recommendedPolicies.capabilitiesPolicy.module.tag' "$DEFAULTS_VALUES")
HAULER_VERSION=$(get_hauler_image_version "capabilities-psp")
compare_version "capabilities-psp" "$POLICY_VERSION" "$HAULER_VERSION" "$DEFAULTS_VALUES"

# Validate host-namespaces-psp policy
POLICY_VERSION=$(yq eval '.recommendedPolicies.hostNamespacePolicy.module.tag' "$DEFAULTS_VALUES")
HAULER_VERSION=$(get_hauler_image_version "host-namespaces-psp")
compare_version "host-namespaces-psp" "$POLICY_VERSION" "$HAULER_VERSION" "$DEFAULTS_VALUES"

# Validate hostpaths-psp policy
POLICY_VERSION=$(yq eval '.recommendedPolicies.hostPathsPolicy.module.tag' "$DEFAULTS_VALUES")
HAULER_VERSION=$(get_hauler_image_version "hostpaths-psp")
compare_version "hostpaths-psp" "$POLICY_VERSION" "$HAULER_VERSION" "$DEFAULTS_VALUES"

# Validate pod-privileged policy
POLICY_VERSION=$(yq eval '.recommendedPolicies.podPrivilegedPolicy.module.tag' "$DEFAULTS_VALUES")
HAULER_VERSION=$(get_hauler_image_version "pod-privileged")
compare_version "pod-privileged" "$POLICY_VERSION" "$HAULER_VERSION" "$DEFAULTS_VALUES"

# Validate user-group-psp policy
POLICY_VERSION=$(yq eval '.recommendedPolicies.userGroupPolicy.module.tag' "$DEFAULTS_VALUES")
HAULER_VERSION=$(get_hauler_image_version "user-group-psp")
compare_version "user-group-psp" "$POLICY_VERSION" "$HAULER_VERSION" "$DEFAULTS_VALUES"

echo
echo "📋 Validating Helm Charts..."
echo "============================="
echo

# Function to extract chart version from Hauler manifest
get_hauler_chart_version() {
    local chart_name=$1
    yq eval ".spec.charts[] | select(.name == \"$chart_name\") | .version" "$HAULER_MANIFEST"
}

# Validate kubewarden-crds chart
CHART_VERSION=$(yq eval '.version' "$CRDS_CHART")
HAULER_VERSION=$(get_hauler_chart_version "kubewarden-crds")
compare_version "kubewarden-crds chart" "$CHART_VERSION" "$HAULER_VERSION" "$CRDS_CHART"

# Validate kubewarden-controller chart
CHART_VERSION=$(yq eval '.version' "$CONTROLLER_CHART")
HAULER_VERSION=$(get_hauler_chart_version "kubewarden-controller")
compare_version "kubewarden-controller chart" "$CHART_VERSION" "$HAULER_VERSION" "$CONTROLLER_CHART"

# Validate kubewarden-defaults chart
CHART_VERSION=$(yq eval '.version' "$DEFAULTS_CHART")
HAULER_VERSION=$(get_hauler_chart_version "kubewarden-defaults")
compare_version "kubewarden-defaults chart" "$CHART_VERSION" "$HAULER_VERSION" "$DEFAULTS_CHART"

# Validate policy-reporter chart (from kubewarden-controller dependencies)
CHART_VERSION=$(yq eval '.dependencies[0].version' "$CONTROLLER_CHART")
HAULER_VERSION=$(get_hauler_chart_version "policy-reporter")
compare_version "policy-reporter chart" "$CHART_VERSION" "$HAULER_VERSION" "$CONTROLLER_CHART dependencies"

# Validate openreports chart (from kubewarden-crds dependencies)
CHART_VERSION=$(yq eval '.dependencies[0].version' "$CRDS_CHART")
HAULER_VERSION=$(get_hauler_chart_version "openreports")
compare_version "openreports chart" "$CHART_VERSION" "$HAULER_VERSION" "$CRDS_CHART dependencies"

echo
echo "=================================="
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}✅ All validations passed! Hauler manifest is in sync with Helm charts.${NC}"
    exit 0
else
    echo -e "${RED}❌ Found $ERRORS version mismatch(es). Please update the Hauler manifest.${NC}"
    echo
    echo -e "${YELLOW}💡 Tip: The updatecli workflow should automatically keep these in sync.${NC}"
    echo "   If you're seeing this error, you may need to run updatecli manually or"
    echo "   wait for the next scheduled run (Mondays at 3:30 AM)."
    exit 1
fi
