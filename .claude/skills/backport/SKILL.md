---
name: backport
description: >-
  Backports a merged pull request from `main` onto a patch-release branch, e.g. `5.0.x`.
  Activates on `/backport <PR-number> [target-branch]`, and whenever the user asks to
  backport, port, or cherry-pick a merged PR, commit, or fix onto a patch, release,
  or maintenance branch, including phrasings like "backport #1234 to 5.0.x",
  "cherry-pick that fix onto 5.0.x", or "get this into the next patch release".
  Not for forward-porting onto `main`!
allowed-tools: Bash, AskUserQuestion, Read, Edit
---

# Backporting a Pull Request

Automates the patch-release backport flow from [`RELEASING.md`](../../../RELEASING.md) §Patch Releases. Invoke as:

```
/backport <PR-number> [target-branch]
```

Requires an authenticated [`gh`](https://cli.github.com/) CLI (`gh auth status`).

## Rules (DO NOT VIOLATE)

- **Never** `git push`. Print the push command at the end and let the user run it.
- **Never** add `Co-Authored-By: Claude ...` to any commit.
- **Always** cherry-pick with `git cherry-pick -x -s` (records origin SHA, adds signoff, matches existing patch-branch history).
- **Always** work in `.claude/worktrees/backport-pr-<N>`, never in the primary checkout.
- Flyway migrations: cherry-pick as-is. DO NOT RENAME OR RE-TIMESTAMP (see `RELEASING.md` §Flyway migrations).
- If a conflict cannot be resolved unambiguously and does not apply conceptually, ask the user via `AskUserQuestion`. DO NOT IMPROVISE.

## Resolving the canonical remote

`origin` may point at a fork. Resolve the canonical remote once and use `$CANON` everywhere below:

```sh
CANON=$(git remote -v | awk '/DependencyTrack\/dependency-track.*\(fetch\)/ {print $1; exit}')
```

If empty, ask the user which remote tracks the canonical repo.

## Workflow

### 1. Validate state

- Confirm CWD is the primary repo (not already a worktree).
- Resolve `$CANON` per §Resolving the canonical remote, then `git fetch $CANON`.
- If `target-branch` was omitted, derive it from the PR's backport label:

  ```sh
  gh pr view <N> --json labels -q '.labels[].name | select(startswith("backport/"))'
  ```

  If `backport/5.0.5`, the target branch is `5.0.x`. On zero or multiple matches,
  ask the user via `AskUserQuestion`, offering branches matching `[0-9]+\.[0-9]+\.x`.

### 2. Locate the PR's commits

```sh
gh pr view <N> --json state,baseRefName,mergeCommit
```

- `state` is not `MERGED`: abort. DO NOT GUESS.
- `baseRefName` is not `main`: tell the user which branch the PR targeted and ask before continuing.

Take `MERGE` from `mergeCommit.oid`, then check how it was merged:

```sh
git rev-parse --verify --quiet "${MERGE}^2"
```

- **Merge commit** (`^2` resolves): the PR's commits are preserved in `main`.
  ```sh
  git log --reverse --format=%H "${MERGE}^1..${MERGE}^2"  # oldest first
  ```
- **Squash or rebase merge** (`^2` missing): `MERGE` itself is the only commit to pick.

### 3. Set up the worktree

Path: `.claude/worktrees/backport-pr-<N>` (in-tree, git-ignored).

- **Reuse** (path exists, worktree registered): `cd` in, verify `git status` is clean (else ask the user), then `git checkout -B backport-pr-<N> $CANON/<target-branch>`.
- **Fresh**: `git worktree add -b backport-pr-<N> .claude/worktrees/backport-pr-<N> $CANON/<target-branch>`.
- **Leftover branch** (worktree gone, branch remains, `git worktree add` errors with `a branch named '…' already exists`): glance at `git log backport-pr-<N> ^$CANON/<target-branch>` to confirm nothing valuable, `git branch -D backport-pr-<N>`, retry.
- If `git worktree add` half-succeeded (partial directory plus a stale branch), delete both and `git worktree prune` before retrying.

### 4. Apply each commit

For each SHA from step 2, in order.

First, skip what is already there:

```sh
git log $CANON/<target-branch> --grep="cherry picked from commit <sha>" --format=%H
```

Non-empty means already backported. Skip it and note that in the summary.

Otherwise `git cherry-pick -x -s <sha>`.

- **Clean**: continue.
- **Trivial conflict** (import order, non-overlapping adjacent edits): resolve, `git add`, `GIT_EDITOR=true git cherry-pick --continue` (`--continue` opens `$EDITOR` and hangs otherwise).
- **Non-trivial but conceptually applies**: `git cherry-pick --abort`, recreate manually, commit per §Manual commit format.
- **Does not apply conceptually** (target refactored/removed): `git cherry-pick --abort`, then `AskUserQuestion` with options (skip / reduced port / port differently). DO NOT INVENT A RESOLUTION.

#### Inspecting a conflict before resolving

Conflict markers can include unrelated `main`-only lines that anchored the hunk's context. Naively accepting "incoming" smuggles those into the backport.

Before resolving, run `git show <sha> -- <conflicted-file>` to show the authoritative diff. If the `>>>>>>>` side has extra lines `git show` doesn't list, drop them.

### 5. Manual commit format

For manually-recreated commits (not cherry-picked):

- Mirror the original subject + body.
- Add `Co-Authored-By: <Name> <email>` for the original commit's author. Omit if that email equals `git config user.email`. Never add `Co-Authored-By: Claude ...`.
- `git commit -s` (adds `Signed-off-by`). Author identity = default git config. Pass the message via HEREDOC.

### 6. Post-backport checks

Run from the worktree. Flyway lints must be pinned to the patch branch. The default `BASE_REF` is `origin/main`,
which would compare against the wrong history here.

| If any commit touches | Run |
| --- | --- |
| `migration/src/main/resources/org/dependencytrack/migration/**` | `make lint-migrations BASE_REF=$CANON/<target-branch> AGENT=1` |
| `dex/engine-migration/src/main/resources/org/dependencytrack/dex/engine/migration/**` | `make lint-dex-migration BASE_REF=$CANON/<target-branch> AGENT=1` |
| tests | those tests, via `make test-single` |
| anything | `make build AGENT=1` |

On failure, report and stop.

### 7. Summary

Print, in this order:

1. The worktree path.
2. One row per commit from step 2. Every commit gets a row, including skipped ones:

   | Status | Commit | Subject |
   | --- | --- | --- |
   | `picked` / `manual` / `skipped` / `already` | `<short-sha>` | ... |

   `<short-sha>` is the source commit on `main`, not the new one. For `skipped`, give the reason.
3. The push command (DO NOT RUN IT):

   ```sh
   cd .claude/worktrees/backport-pr-<N> && git push -u origin backport-pr-<N>
   ```

If any row is not `picked`, state that on one line above the table.
