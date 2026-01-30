## Issue Description for #1400: Update hauler manifest

### Problem Statement

The Kubewarden Controller project currently lacks a Hauler manifest file and automated tooling to keep it synchronized with Helm chart versions during releases. This creates a maintenance burden for users deploying Kubewarden in air-gapped environments, as they must manually track and update component versions.

### Background

Hauler is a tool designed to help users prepare and manage air-gapped Kubernetes deployments by:
- Syncing container images and Helm charts to local storage
- Managing dependencies for offline installation
- Supporting keyless validation and signature verification

For Kubewarden deployments in air-gapped environments, users need a manifest file that:
1. Lists all required container images (kubewarden-controller, policy-server, audit-scanner, policies)
2. Specifies Helm chart versions for all Kubewarden components
3. Stays synchronized with official release versions

### Current State

- No Hauler manifest exists in the repository
- The release automation (updatecli script) does not update any Hauler manifest during the release process
- Users must manually maintain their Hauler configurations for air-gapped deployments
- Version mismatches between Helm charts and Hauler manifests can occur

### Proposed Solution

1. **Create a Hauler manifest** (`charts/hauler.yaml`) that includes:
   - Container images for kubewarden-controller, policy-server, audit-scanner
   - Default policy images
   - Supporting images (policy-reporter, kuberlr, etc.)
   - Helm chart references with versions
   - Keyless verification configuration for signed images

2. **Update release automation** to automatically sync the Hauler manifest:
   - Modify `updatecli/updatecli.release.d/open-release-pr.yaml` to include Hauler manifest updates
   - Add targets for kubewarden-crds, kubewarden-controller, and kubewarden-defaults chart versions
   - Ensure Hauler manifest is updated when release PRs are created
   - Fix environment variable handling for GitHub owner in updatecli configuration

3. **Maintain consistency** between Helm chart versions and Hauler manifest versions

### Benefits

- **Simplified air-gap deployments**: Users get a maintained, version-synchronized manifest
- **Reduced maintenance burden**: Automation ensures Hauler manifest stays current with releases
- **Better security posture**: Manifest includes keyless verification configuration for signed images
- **Improved documentation**: Clear reference for all required components in a release

### Implementation Details

The solution involves:
- Creating `charts/hauler.yaml` with three image sections:
  - Signed kubewarden images (with certificate verification)
  - Signed policy images (with certificate verification)
  - Unsigned supporting images
- Helm chart definitions for all Kubewarden components
- Updatecli configuration updates to automatically bump versions during release PR creation
- GitHub workflow updates to pass required environment variables

### Testing

Users can validate the Hauler manifest by running:
```bash
hauler store sync --filename charts/hauler.yaml
```

This should successfully sync all images and charts to Hauler's local storage.

### Related

- PR #1405 implements this solution
- Example generated PR: https://github.com/jvanz/kubewarden-controller/pull/126
