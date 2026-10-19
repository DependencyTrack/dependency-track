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

# Backporting a pull request

Automates the patch-release backport flow from [`RELEASING.md`](../../../RELEASING.md) §Patch Releases. Invoke as:

```
/backport <PR-number> [target-branch]
```

Requires an authenticated [`gh`](https://cli.github.com/) CLI (`gh auth status`).

## Rules (DO NOT VIOLATE)

- **Never** `git push`. Print the push command at the end and let the user run it.
- **Always** work in `.claude/worktrees/backport-pr-<N>`, never in the primary checkout.
- Cherry-pick Flyway migrations as-is. DO NOT RENAME OR RE-TIMESTAMP them, see `RELEASING.md` §Flyway migrations.

## Workflow

### 1. Run the script

From the primary checkout:

```sh
.claude/skills/backport/backport.sh <N> [target-branch]
```

The script resolves the canonical remote, fetches it, and reads the PR via `gh`.
It derives the target branch from the `backport/*` label and sets up the worktree.
It then cherry-picks every commit not yet on the target in one `git cherry-pick -x -s --empty=drop`.
It prints one row per commit, the post-backport checks, and the push command.
Do not redo any of that by hand.

Act on the exit code:

| Exit | Meaning | Do |
| --- | --- | --- |
| 0 | All commits applied, or nothing left to push | Run the printed checks (§3), then summarize (§4). |
| 1 | Error, e.g. PR not merged, or git too old for `--empty=drop` (needs 2.45) | Report the message and stop. DO NOT GUESS. |
| 2 | Needs a decision (no/multiple labels, unknown target branch, non-`main` base, dirty worktree, unfinished cherry-pick, branch already has commits, no canonical remote) | Relay the printed options via `AskUserQuestion`, then re-run with the chosen flag or target. Run destructive cleanup it suggests only after the user agrees. |
| 3 | A cherry-pick stopped | Handle per §2. |

### 2. Handling a stopped cherry-pick

On exit 3 the cherry-pick is still in progress in the worktree. The script prints git's output.
For conflicts it also prints the conflicted files and the source commit's diff of them.

Run `--continue` as `GIT_EDITOR=true git cherry-pick --continue`. Without it, git opens `$EDITOR` and the command hangs.
`--continue` and `--skip` go on to the remaining commits, and may stop again. Handle each stop the same way.
On a later stop, get the authoritative diff with `git show --format= CHERRY_PICK_HEAD -- <conflicted files>`.

- **Trivial conflict**, such as import order or adjacent non-overlapping edits. Resolve it, `git add`, `--continue`.
- **Non-trivial conflict, but the change still applies.** Recreate the change in the working tree, `git add`, `--continue`.
  The commit keeps the original author, message, and `-x` trailer.
- **The change does not apply**, because the target refactored or removed the code.
  Ask via `AskUserQuestion` whether to skip, port a reduced version, or port it differently. DO NOT INVENT A RESOLUTION.
  To skip, run `git cherry-pick --skip`.
- **The resolution leaves nothing to commit**, because the change is already on the target. `git cherry-pick --skip`, report as `skipped (empty)`.
- **No conflicts, but the commit failed**, e.g. on signing. Report git's error to the user. NEVER `--skip` past it.

Once `git status` shows no cherry-pick in progress, go to §3.

#### Inspecting a conflict before resolving

Conflict hunks can include unrelated `main`-only lines that git used as context. Taking the incoming side wholesale copies those lines into the backport.

Compare against the authoritative diff. If the `>>>>>>>` side has extra lines that diff doesn't list, drop them.

### 3. Post-backport checks

Run the `make` commands the script printed, from the worktree.

On failure, report and stop.

### 4. Summary

Print, in this order:

1. The worktree path.
2. The script's table, with `stopped` and `pending` rows replaced by what happened. Every commit gets a row, including skipped ones:

   | Status | Commit | Subject |
   | --- | --- | --- |
   | `picked` / `resolved` / `skipped (<reason>)` / `already` | `<short-sha>` | ... |

   `<short-sha>` is the source commit on `main`, not the new one. `resolved` means a conflict was resolved by hand.
   The script's `skipped` rows carry the reason: `merge` for merge commits inside the PR, `empty` for commits with no change left to apply.
   Give commits you skip a reason the same way.
   `already` only means the target has a commit with a matching `-x` trailer. A later revert on the target goes unnoticed.
3. The push command the script printed (DO NOT RUN IT). Omit it if the script said there is nothing to push.

If any row is not `picked`, state that on one line above the table.

## Changing the script

Run `.claude/skills/backport/backport-test.sh`. It exercises `backport.sh` against throwaway repos and a fake `gh`.

Then run `shellcheck .claude/skills/backport/*.sh` and fix its findings.
