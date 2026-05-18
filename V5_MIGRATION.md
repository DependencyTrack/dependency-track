# Migrating to Dependency-Track v5

Dependency-Track v5 is the next major version of the project, previously developed under the codename *Hyades*.
For what is actually new in v5, including architecture, schema, configuration, and API surface, see
[About changes in v5](https://dependencytrack.github.io/docs/next/concepts/changes-in-v5/).

This document covers the GA cutover itself. It describes what changes for operators,
contributors, and downstream consumers as v5 moves to GA, and what your options are for staying on v4.

> [!IMPORTANT]
> Please read this document end-to-end **before** updating any image pin, Helm value, or CI reference.
> The image name changes, and the `:latest` and `:snapshot` tag policies are deliberately conservative
> to avoid moving consumers across a major version without an explicit decision.

## Contents

- [Phases](#phases)
- [What is moving](#what-is-moving)
  - [Source repositories](#source-repositories)
  - [Container images](#container-images)
- [Tag policy](#tag-policy)
  - [`:latest`](#latest)
  - [`:snapshot`](#snapshot)
  - [v5 tags](#v5-tags)
- [Pin recommendations](#pin-recommendations)
- [Action items by audience](#action-items-by-audience)
  - [Operators](#operators)
    - [Required action today](#required-action-today)
    - [v4 maintenance window](#v4-maintenance-window)
    - [After v4 EOL](#after-v4-eol)
    - [Migrating to v5](#migrating-to-v5)
    - [Helm](#helm)
  - [Contributors and PR authors](#contributors-and-pr-authors)
    - [If you have an open PR](#if-you-have-an-open-pr)
    - [Re-targeting a PR's base branch](#re-targeting-a-prs-base-branch)
    - [Moving a local branch to the new repo](#moving-a-local-branch-to-the-new-repo)
    - [Forks](#forks)
    - [Where things live after cutover](#where-things-live-after-cutover)
    - [Issues and discussions on `hyades-*` repos](#issues-and-discussions-on-hyades--repos)
    - [ADRs (new in v5)](#adrs-new-in-v5)
- [Historical artifacts](#historical-artifacts)
- [What is **not** changing](#what-is-not-changing)

## Phases

The cutover proceeds in ordered phases. Timing is best-effort and community-driven.
Each phase advances only when its preconditions are met. Do not plan around fixed dates.

> [!IMPORTANT]
> v4 will receive bugfixes and security patches for **at least ~6 months past v5 GA**.
> This minimum is committed, regardless of how cutover-day timing shifts.

| Phase        | Precondition                              | What happens                                                                                                              |
|--------------|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| Announcement | Maintainers agree the cutover is imminent | Public notice. v4 `master` enters freeze on a date named in the notice.                                                   |
| Cutover      | v5 `5.0.0-rc.1` ready to publish          | v4 `master` (both repos) renamed to `v4-master-archived`. v5 imported as `main`. RC published. `hyades-*` repos archived. |
| GA           | RC soak completes with no blockers        | v5 `5.0.0` GA published.                                                                                                  |
| v4 EOL       | At least ~6 months elapsed since v5 GA    | v4 patches stop. `:snapshot` discontinued. `:latest` flips to v5.                                                         |

Each phase is announced ahead of time on the
[GitHub Discussions](https://github.com/DependencyTrack/dependency-track/discussions), 
and `#dependency-track` channel in the OWASP Slack.

## What is moving

### Source repositories

| Before (v4 / pre-GA v5)                     | After (v5 GA onwards)                                           |
|---------------------------------------------|-----------------------------------------------------------------|
| `DependencyTrack/dependency-track` (v4)     | `DependencyTrack/dependency-track:4.14.x` (v4)                  |
| `DependencyTrack/dependency-track:master`   | Renamed to `:v4-master-archived` (frozen, no merges accepted)   |
| `DependencyTrack/frontend` (v4)             | `DependencyTrack/frontend:4.14.x` (v4)                          |
| `DependencyTrack/frontend:master`           | Renamed to `:v4-master-archived` (frozen, no merges accepted)   |
| `DependencyTrack/hyades-apiserver` (v5 dev) | `DependencyTrack/dependency-track:main` (v5)                    |
| `DependencyTrack/hyades-frontend` (v5 dev)  | `DependencyTrack/frontend:main` (v5)                            |

`hyades-apiserver` and `hyades-frontend` are **archived** at cutover. They remain readable.
No new pushes, no new issues, no new PRs.

### Container images

| Before                                       | After                                  |
|----------------------------------------------|----------------------------------------|
| `dependencytrack/hyades-apiserver:<tag>`     | `dependencytrack/apiserver:<tag>`      |
| `ghcr.io/dependencytrack/hyades-apiserver`   | `ghcr.io/dependencytrack/apiserver`    |
| `dependencytrack/hyades-frontend:<tag>`      | `dependencytrack/frontend:<tag>`       |
| `ghcr.io/dependencytrack/hyades-frontend`    | `ghcr.io/dependencytrack/frontend`     |

v4 images (`dependencytrack/apiserver`, `dependencytrack/frontend`, `dependencytrack/bundled`)
**do not change name**. v4 has always published to these names. Only the pre-GA v5 (`hyades-*`) images are renamed.

> [!NOTE]
> `dependencytrack/bundled` is **v4-only**. There is no v5 equivalent. It follows the v4 lifecycle and stops receiving
> updates at v4 EOL along with the other v4 images.

## Tag policy

`:latest` and `:snapshot` deliberately do **not** flip on the GA date.
This is to prevent unpinned v4 deployments from silently jumping to v5 on the next `docker pull` and breaking.

### `:latest`

| Period                  | Resolves to                |
|-------------------------|----------------------------|
| Today through v4 EOL    | Latest v4 release          |
| After v4 EOL            | Latest v5 release          |

If you run `:latest` in production today, **pin to an explicit version before v4 EOL**.
After v4 EOL, `:latest` advances across the major boundary in one pull.

### `:snapshot`

| Tag           | Period               | Resolves to                |
|---------------|----------------------|----------------------------|
| `:snapshot`   | Today through v4 EOL | v4 nightly                 |
| `:snapshot`   | After v4 EOL         | **Discontinued**           |
| `:4-snapshot` | From cutover onwards | v4 nightly (frozen at EOL) |
| `:5-snapshot` | From v5 GA onwards   | v5 nightly                 |

`:snapshot` is **not flipped to v5** at v4 EOL. Migrate to `:4-snapshot` or `:5-snapshot` explicitly.

### v5 tags

| Tag           | Resolves to                    |
|---------------|--------------------------------|
| `:5.x.y`      | Exact v5 release. Immutable.   |
| `:5.x.y-rc.N` | Exact RC. Immutable.           |
| `:5-snapshot` | v5 `main` nightly              |
| `:latest`     | See [`:latest`](#latest).      |

No floating major (`:5`) or minor (`:5.0`) tags are published. This matches v4's tagging surface and steers operators
toward digest or exact-version pins (see [Pin recommendations](#pin-recommendations)).

## Pin recommendations

For production, in order of preference:

1. **Digest pin** (`@sha256:...`). Strongest guarantee. Survives tag mutation, repo deletion, and registry mirroring.
2. **Exact version** (`:4.14.3` or `:5.0.0`). Survives the cutover unchanged.

Use Renovate, Dependabot, or equivalent to bump exact pins on a schedule you control.

Do **not** use `:latest` or `:snapshot` in production. Both move under you without notice.

## Action items by audience

### Operators

#### Required action today

None, **if you pin image tags by an exact version or digest.**
v4 keeps shipping on its existing image names and tags until v4 EOL (~6 months post-v5 GA).

If you currently pull `:latest` or `:snapshot`, switch before v4 EOL:

| Today                                | Pin to                                        |
|--------------------------------------|-----------------------------------------------|
| `dependencytrack/apiserver:latest`   | An exact version (e.g. `:4.14.3`) or a digest |
| `dependencytrack/apiserver:snapshot` | `:4-snapshot` or a digest                     |
| `dependencytrack/frontend:latest`    | An exact version (e.g. `:4.14.3`) or a digest |
| `dependencytrack/frontend:snapshot`  | `:4-snapshot` or a digest                     |

`:4-snapshot` becomes available at cutover. Until then, pin to a digest to escape `:snapshot`.

#### v4 maintenance window

- v4 continues to receive `4.14.x` patch releases. There will be **no further v4 minor releases** (no `4.15.0`).
- Patch cadence is best-effort and community-driven, focused on security and high-severity fixes.
- File v4 bugs against `DependencyTrack/dependency-track` with the `v4` label.

#### After v4 EOL

- No further patches, including for CVEs in v4 itself or its dependencies.
- New issues that apply **only** to v4 are closed with a pointer to v5. Existing `v4`-labeled issues remain as-is
  and readable for reference.

#### Migrating to v5

> [!WARNING]
> There is no in-place upgrade. v5 runs on its own PostgreSQL cluster and ingests v4 data via an offline,
> one-shot migrator. Plan downtime accordingly.

- [About changes in v5](https://dependencytrack.github.io/docs/next/concepts/changes-in-v5/) for the architectural,
  schema, and configuration deltas.
- [Migrating from v4 to v5](https://dependencytrack.github.io/docs/next/guides/administration/migrating-from-v4/)
  for the step-by-step migrator procedure, prerequisites, and post-migration audit checklist.
- [Rehearsing the v4 migration](https://dependencytrack.github.io/docs/next/tutorials/rehearsing-the-v4-migration/)
  to dry-run against a production copy before scheduling the cutover.
- [Running v4 and v5 in parallel](https://dependencytrack.github.io/docs/next/guides/administration/running-v4-and-v5-in-parallel/)
  for parallel-validation strategies.

#### Helm

The official chart updates together with v5 GA. See [`helm-charts`](https://github.com/DependencyTrack/helm-charts).
Diff your values file against the v5 chart defaults before bumping.

### Contributors and PR authors

> [!IMPORTANT]
> v4 `master` is frozen ahead of cutover and renamed at cutover. Open PRs follow the rename but cannot be merged.
> See [If you have an open PR](#if-you-have-an-open-pr) for what to do.

#### If you have an open PR

Re-target your PR before cutover. If you do not, the PR survives but ends up against `v4-master-archived`,
which accepts no merges. You will have to re-target it yourself afterwards.

**Against `dependency-track:master`** (pre-cutover v4 repo):

- **v4 patch**: re-target the base branch to `4.14.x` (see [re-targeting](#re-targeting-a-prs-base-branch) below).
- **v5-bound**: close and re-open against `hyades-apiserver:main` (pre-cutover) or `dependency-track:main`
  (post-cutover). Link the original PR in the new description.

**Against `hyades-apiserver:main` or `hyades-frontend:main`**:

- Pre-cutover: business as usual. Land before cutover if you can.
- At cutover: the repo is archived. Existing PRs are not auto-migrated and cannot be merged.
  Re-open against `dependency-track:main` (or `frontend:main`) once v5 GA is published.

#### Re-targeting a PR's base branch

GitHub UI: open the PR, click **Edit** next to the title, pick the new base branch. Works only if the new base lives
in the same repo. For cross-repo moves (`hyades-apiserver` -> `dependency-track`), open a new PR.

#### Moving a local branch to the new repo

After cutover, point your fork and clone at `dependency-track`. The archived `hyades-apiserver` remote still works
read-only but will not accept pushes.

```sh
# 1. Rename your fork on GitHub: Settings -> Repository name -> "dependency-track"
#    (GitHub keeps redirects, but update the remote anyway.)

# 2. Update the upstream remote
git remote set-url upstream https://github.com/DependencyTrack/dependency-track.git

# 3. Update your fork remote
git remote set-url origin git@github.com:<you>/dependency-track.git

# 4. Fetch the new default branch and rebase your work
git fetch upstream
git rebase upstream/main

# 5. Push and open the PR against dependency-track:main
git push -u origin <your-branch>
```

> [!NOTE]
> After the rename, `upstream/master` resolves to `upstream/v4-master-archived`.
> That branch is frozen and accepts no merges. Rebase v5-bound work onto
> `upstream/main` and v4-patch work onto `upstream/4.14.x`.

#### Forks

GitHub does **not** auto-rename or auto-archive forks.

- Your fork still exists under its old name and still tracks the archived repo.
- Rename it via **Settings -> Repository name** to keep PRs tidy.
- Branches you pushed before cutover are preserved.

#### Where things live after cutover

| Concern                              | Location                                                  |
|--------------------------------------|-----------------------------------------------------------|
| v5 apiserver code, issues, PRs       | `DependencyTrack/dependency-track` (branch `main`)        |
| v5 frontend code, issues, PRs        | `DependencyTrack/frontend` (branch `main`)                |
| v4 maintenance patches               | `DependencyTrack/dependency-track` (branch `4.14.x`)      |
| `CONTRIBUTING.md`, `SECURITY.md`     | `DependencyTrack/dependency-track:main` (root)            |
| ADRs                                 | `DependencyTrack/dependency-track:main` under `docs/adr/` |
| Helm charts                          | `DependencyTrack/helm-charts` (unaffected)                |
| User docs                            | `DependencyTrack/docs` (unaffected)                       |

#### Issues and discussions on `hyades-*` repos

- Both repos are archived at cutover. Existing issues and discussions stay readable but become read-only.
- Open issues are not auto-migrated. Maintainers will move the ones they judge relevant for v5 to
  `DependencyTrack/dependency-track` at their own discretion. No guarantees on which or when.
- If your issue is not moved, and you believe it should be, you have two options:
  - Ask a maintainer to move it via OWASP Slack `#dependency-track` or GitHub Discussions, linking the original.
  - Re-file on `DependencyTrack/dependency-track` and link the old issue.
- v4 bug reports go on `DependencyTrack/dependency-track` with the `v4` label.

#### ADRs (new in v5)

v5 introduces Architecture Decision Records. Substantial changes now require an ADR that reaches **Accepted**
before the implementation PR merges. v4 had no such requirement. See
`CONTRIBUTING.md#architecture-decision-records` for trigger criteria.

## Historical artifacts

> [!WARNING]
> **The `5.0.0` tag exists in two places with different content.** The archived `hyades-apiserver` repo published
> release tags `5.0.0` through `5.6.0` (and `5.7.0-alpha.X`) during pre-GA development. This was a mistake in hindsight.
> v5 GA restarts numbering at `5.0.0` on `dependency-track:main`. The two are **not** the same artifact. Disambiguate
> by repo and registry path:
>
> | Tag     | Source                                                      | Meaning        |
> |---------|-------------------------------------------------------------|----------------|
> | `5.0.0` | `DependencyTrack/hyades-apiserver` (archived)               | Pre-GA, frozen |
> | `5.0.0` | `DependencyTrack/dependency-track` (and `apiserver` images) | v5 GA          |
>
> Pre-GA images and source remain pullable from the archived repo for reference. Do not consume them as v5 GA.

## What is **not** changing

To keep expectations grounded:

- The Helm chart repository (`DependencyTrack/helm-charts`) is **not** renamed or archived.
- The documentation repository (`DependencyTrack/docs`) is **not** renamed.
- The project website (`dependencytrack.org`) does not change URL.
- The OWASP project page does not change URL.
