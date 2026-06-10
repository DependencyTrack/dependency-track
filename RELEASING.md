# Releasing OWASP Dependency-Track

This document describes the process of releasing a new version of Dependency-Track.

## Patch Releases

Patch releases (e.g. `5.0.1`) ship bugfixes and security fixes off a release branch.
No new features, no breaking changes.

> [!IMPORTANT]
> Backport, don't forward-port. Merge the fix on `main` first, then cherry-pick onto the patch branch.
> Direct commits on the patch branch are fine for fixes that no longer apply to `main`.

### 1. Cut or check out the patch branch

First patch in a series, branched from the GA tag:

```shell
git checkout -b 5.0.x 5.0.0
git push -u origin 5.0.x
```

Subsequent patches:

```shell
git checkout 5.0.x
git pull
```

### 2. Bump the Maven version (first patch only)

Run from the repository root:

```shell
mvn versions:set -DnewVersion=5.0.1-SNAPSHOT -DgenerateBackupPoms=false
```

Commit (signed off, i.e. with `--signoff`). Follow-up patches are bumped automatically by the [Release CI].

### 3. Cherry-pick backports

Open one PR per backport against the patch branch, using the branch name `backport-pr-<original-PR-number>`:

```shell
git checkout -b backport-pr-1234 5.0.x
git cherry-pick -s <sha>
```

Resolve any conflicts, then `git cherry-pick --continue`.

### 4. Flyway migrations

When backporting a migration, cherry-pick the file as-is. **Do not rename or re-timestamp it**.
Out-of-order execution is enabled, so users upgrading from a patch release to the next minor
will still get any older mainline migrations applied. See [Flyway: `outOfOrder`][flyway-ooo].

Prefer cherry-picking the same migration from `main` over authoring a new patch-only one.

### 5. Run the release

Once CI is green on the patch branch, follow the [Stable Version](#stable-version) workflow below,
selecting the patch branch (e.g. `5.0.x`) for the **Branch** parameter.

## Releasing

### Stable Version

To release a new stable version such as `5.7.0` or `5.7.1`:

1. Ensure the current state in the target branch is ready to be released.
2. Navigate to the [Release CI] workflow.
3. Run the workflow with the following parameters:
   * **Branch**: Select the branch to release from (e.g. `main` for new releases, `5.6.x` for bugfixes, see [Patch Releases](#patch-releases)).
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
[flyway-ooo]: https://documentation.red-gate.com/fd/out-of-order-184127574.html
