# Releasing OWASP Dependency-Track

This document describes the process of releasing a new version of Dependency-Track.

## Releasing

### Stable Version

To release a new stable version such as `5.7.0` or `5.7.1`:

1. Ensure the current state in the target branch is ready to be released.
2. Navigate to the [Release CI] workflow.
3. Run the workflow with the following parameters:
   * **Branch**: Select the branch to release from (e.g. `main` for new releases, `5.6.x` for bugfixes).
   * **Release version**: Leave empty to use current `SNAPSHOT` version (e.g. `5.7.0-SNAPSHOT` becomes `5.7.0`), or specify a custom version.
   * **Development version**: Leave empty (in which case the patch version will be bumped, e.g. `5.7.0` -> `5.7.1-SNAPSHOT`), or specify a custom next `SNAPSHOT` version.
   * **Dry run**: Enable to test the release process without making any changes.

### Release Candidate

To release a prerelease such as `5.7.0-rc.1`:

1. Ensure the current state in the target branch is ready to be released.
2. Navigate to the [Release CI] workflow.
3. Run the workflow with the following parameters:
   * **Branch**: Select the branch (usually `main`).
   * **Release version**: Enter the prerelease version (e.g. `5.7.0-rc.1`).
   * **Development version**: Leave empty (in which case it will be bumped to `5.7.0-rc.2-SNAPSHOT`), or explicitly set to `5.7.0-SNAPSHOT`.

[Release CI]: https://github.com/DependencyTrack/dependency-track/actions/workflows/ci-release.yaml
