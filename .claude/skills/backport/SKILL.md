---
name: backport
description: >-
  Backports a merged `main` PR onto a patch-release branch (e.g. `5.0.x`): cherry-picks, runs checks,
  pushes to the fork, opens the PR. Use on `/backport <PR> [branch]` or any request to backport
  or cherry-pick a merged PR, commit, or fix onto a patch branch. Not for porting onto `main`.
allowed-tools: Bash, AskUserQuestion, Read, Edit
---

# Backporting a pull request

Automates the patch-release backport flow from [`RELEASING.md` §Patch Releases](../../../RELEASING.md#patch-releases).

Requires an authenticated [`gh`](https://cli.github.com/) CLI (`gh auth status`).

## Rules

- Push only after the user approves §5's preview: only the backport branch, only to `origin` (the fork), without force.
- This skill is the one exception to [`AGENTS.md` §GitHub Issues and PRs](../../../AGENTS.md#github-issues-and-prs):
  a backport request, via `/backport` or in words, authorizes one PR per target branch for that backport,
  and nothing else: no issues, comments, or edits to existing PRs.
- After §1, run every command in `.claude/worktrees/backport-pr-<N>`, not the primary checkout.
- Cherry-pick Flyway migrations as-is, keeping their names and timestamps.
  See [`RELEASING.md` §Flyway migrations](../../../RELEASING.md#4-flyway-migrations).

## Workflow

### 1. Run the script

From the primary checkout:

```sh
.claude/skills/backport/backport.sh <N> [target-branch]
```

The script sets up the worktree and cherry-picks; don't repeat its steps by hand.

Act on the exit code:

| Exit | Meaning | Do |
| --- | --- | --- |
| 0 | All commits applied | Run the printed checks (§3), summarize (§4), then open the PR (§5). |
| 0 | `Nothing to push` printed | Summarize (§4) and stop. |
| 1 | Error | Report the message and stop. A failed `--empty=drop` means git is older than 2.45. |
| 2 | Needs a decision | Relay the printed question and options via `AskUserQuestion`, then re-run as the message says. Run destructive cleanup it suggests only after the user agrees. |
| 3 | A cherry-pick stopped | Handle per §2. |

### 2. Handling a stopped cherry-pick

On exit 3 the cherry-pick is still in progress in the worktree.

Run `--continue` as `GIT_EDITOR=true git cherry-pick --continue`. Without it, git opens `$EDITOR` and the command hangs.
`--continue` and `--skip` go on to the remaining commits, and may stop again. Handle each stop the same way.
On a later stop, get the authoritative diff with `git show --format= CHERRY_PICK_HEAD -- <conflicted files>`.

Before resolving, compare each conflict against the authoritative diff.
Conflict hunks can include unrelated `main`-only lines that git used as context,
so taking the incoming side wholesale copies them into the backport.
If the `>>>>>>>` side has lines the authoritative diff doesn't list, drop them.

- **Trivial conflict**, such as import order or adjacent non-overlapping edits. Resolve it, `git add`, `--continue`.
- **Non-trivial conflict, but the change still applies.** Recreate the change in the working tree, `git add`, `--continue`.
  The commit keeps the original author, message, and `-x` trailer.
- **The change does not apply**, because the target refactored or removed the code.
  Ask via `AskUserQuestion` whether to skip, port a reduced version, or port it differently.
  The user picks the resolution.
  To skip, run `git cherry-pick --skip`.
- **The resolution leaves nothing to commit**, because the change is already on the target. `git cherry-pick --skip`, report as `skipped (empty)`.
- **No conflicts, but the commit failed**, e.g. on signing.
  Report git's error to the user and stop; the commit stays pending.

Once `git status` shows no cherry-pick in progress, go to §3.

### 3. Post-backport checks

Run the `make` commands the script printed, from the worktree.

On failure, report and stop.

If any commit was `resolved`, review those commits per [`AGENTS.md` §Review](../../../AGENTS.md#review),
scoped to the resolutions.
Clean picks need no review; the source PR was reviewed.

### 4. Summary

Print, in this order:

1. The worktree path.
2. The script's table, with `stopped` and `pending` rows replaced by what happened. Every commit gets a row, including skipped ones:

   | Status | Commit | Subject |
   | --- | --- | --- |
   | `picked` / `resolved` / `skipped (<reason>)` / `already` | `<short-sha>` | ... |

   `<short-sha>` is the source commit on `main`, not the new one. `resolved` means a conflict was resolved by hand.
   Give every skip a reason, like the script's `merge` and `empty`.

If any row is not `picked`, state that on one line above the table.

### 5. Open the PR

Gather from the source PR: `gh pr view <N> --repo DependencyTrack/dependency-track --json title,body,labels`.

- **Title**: `Backport: <source PR title>`.
- **Labels**: the source PR's labels minus `backport/*`.
- **Milestone**: the version of the `backport/*` label matching the target,
  e.g. label `backport/5.2.1`, target `5.2.x` → `5.2.1`.
  No matching label: ask via `AskUserQuestion` for the version.
- **Body**: [`.github/PULL_REQUEST_TEMPLATE.md`](../../../.github/PULL_REQUEST_TEMPLATE.md) read from the worktree,
  comments kept, sections filled:
  - *Description*: the source PR title in third person, one sentence ("Fix X" → "Fixes X.").
  - *Addressed Issue*: every issue reference from the source PR's *Addressed Issue* section, keyword verbatim
    (`Closes`, `Fixes`, `Relates to`, ...), one per line, then `Backports #<N>`. Drop `N/A`.
  - *Additional Details*: `N/A`, then a blank line and `🤖 Opened by an agent via the backport skill.`
    If any commit was `resolved` or `skipped`, list those commits above that line instead of `N/A`.
  - *Checklist*: template text, not the source's. Tick the items the source PR ticked, always tick the first, strike through the rest with `~...~`.

Preview title, labels, milestone, and body via `AskUserQuestion`. Only on approval, push and open the PR:

```sh
git -C <worktree> push -u origin <branch>
gh pr create --repo DependencyTrack/dependency-track --base <target> \
  --head <fork-owner>:<branch> --title "<title>" --body-file - \
  --label <l1> --label <l2> --milestone <ver> <<'EOF'
<body>
EOF
```

`<fork-owner>` comes from `origin`'s URL. Print the PR URL.
