#!/usr/bin/env bash
# Tests for backport.sh against throwaway repos and a fake `gh`. Usage: backport-test.sh [test-name...]
# shellcheck disable=SC2329,SC2207 # test functions are invoked by name
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/backport.sh"

setup() {
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/bin" "$tmp/DependencyTrack"
  cat > "$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do
  case $1 in --jq) q=$2; shift ;; esac
  shift
done
jq -r "$q" "$GH_FIXTURE"
EOF
  chmod +x "$tmp/bin/gh"
  export PATH="$tmp/bin:$PATH" GH_FIXTURE="$tmp/pr.json"

  git init -q --bare -b main "$tmp/DependencyTrack/dependency-track.git"
  git clone -q -o upstream "$tmp/DependencyTrack/dependency-track.git" "$tmp/work" 2>/dev/null
  cd "$tmp/work" || exit 1
  git config user.name Tester
  git config user.email tester@example.com
  git config commit.gpgsign false
  git config core.hooksPath /dev/null
  git checkout -q -b main
  commit a.txt base "Initial commit" >/dev/null
  git branch 5.0.x
  git push -q upstream main 5.0.x
}

# commit <file> <content> <subject>: prints the new SHA
commit() {
  mkdir -p "$(dirname "$1")"
  printf '%s\n' "$2" > "$1"
  git add "$1"
  git commit -q -m "$3"
  git rev-parse HEAD
}

# pr_fixture <state> <base> <merge-sha> [label...]
pr_fixture() {
  local state=$1 base=$2 merge=$3 labels=
  shift 3
  for l in "$@"; do labels="$labels${labels:+,}{\"name\":\"$l\"}"; done
  printf '{"state":"%s","baseRefName":"%s","mergeCommit":{"oid":"%s"},"labels":[%s]}\n' \
    "$state" "$base" "$merge" "$labels" > "$GH_FIXTURE"
}

# merge_pr <branch>: merges <branch> into main with a merge commit, pushes, prints the merge SHA
merge_pr() {
  git checkout -q main
  git merge -q --no-ff -m "Merge pull request from $1" "$1"
  git push -q upstream main
  git rev-parse HEAD
}

run() {
  out=$("$SCRIPT" "$@" 2>&1)
  rc=$?
}

wt() {
  git -C "$tmp/work/.claude/worktrees/backport-pr-1" "$@"
}

fail() {
  printf 'FAIL: %s\n--- output (rc=%s) ---\n%s\n' "$1" "${rc:-}" "${out:-}"
  exit 1
}

test_merge_commit_pr_picks_all_commits_oldest_first() {
  git checkout -q -b feature
  local c1
  c1=$(commit b.txt one "Add b")
  commit c.txt two "Add c" >/dev/null
  pr_fixture MERGED main "$(merge_pr feature)"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  [ "$(wt log --format=%s upstream/5.0.x..HEAD)" = "$(printf 'Add c\nAdd b')" ] || fail "picked commits"
  wt log -1 --format=%B HEAD~1 | grep -q "cherry picked from commit $c1" || fail "-x trailer"
  wt log -1 --format=%B HEAD | grep -q "Signed-off-by: Tester" || fail "signoff"
  [ "$(wt rev-parse --abbrev-ref HEAD)" = backport-pr-1 ] || fail "branch name"
}

test_merge_commit_inside_pr_is_listed_as_skipped() {
  git checkout -q -b feature
  local c1 m
  c1=$(commit b.txt one "Add b")
  git checkout -q main
  commit c.txt two "Add c on main" >/dev/null
  git checkout -q feature
  git merge -q --no-ff -m "Merge main into feature" main
  m=$(git rev-parse HEAD)
  pr_fixture MERGED main "$(merge_pr feature)"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  grep -qF "| picked | $(git rev-parse --short "$c1") | Add b |" <<< "$out" || fail "picked row"
  grep -qF "| skipped (merge) | $(git rev-parse --short "$m") | Merge main into feature |" <<< "$out" || fail "merge row"
}

test_initially_empty_commit_is_skipped() {
  git checkout -q -b feature
  local c1 e
  c1=$(commit b.txt one "Add b")
  git commit -q --allow-empty -m "Retrigger CI"
  e=$(git rev-parse HEAD)
  pr_fixture MERGED main "$(merge_pr feature)"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  grep -qF "| picked | $(git rev-parse --short "$c1") | Add b |" <<< "$out" || fail "picked row"
  grep -qF "| skipped (empty) | $(git rev-parse --short "$e") | Retrigger CI |" <<< "$out" || fail "empty row"
}

test_squash_merged_pr_picks_the_merge_commit() {
  local squash
  squash=$(commit b.txt one "Add b | c (#1)")
  git push -q upstream main
  pr_fixture MERGED main "$squash"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  wt log -1 --format=%B HEAD | grep -q "cherry picked from commit $squash" || fail "picked squash commit"
  grep -qF "| picked | $(git rev-parse --short "$squash") | Add b \| c (#1) |" <<< "$out" || fail "row escapes pipe"
}

test_already_backported_commit_is_skipped() {
  git checkout -q -b feature
  local c1 c2
  c1=$(commit b.txt one "Add b")
  c2=$(commit c.txt two "Add c")
  git checkout -q 5.0.x
  git cherry-pick -x "$c1" >/dev/null
  git push -q upstream 5.0.x
  pr_fixture MERGED main "$(merge_pr feature)"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  [ "$(wt log --format=%s upstream/5.0.x..HEAD)" = "Add c" ] || fail "picked commits"
  grep -qF "| already | $(git rev-parse --short "$c1") | Add b |" <<< "$out" || fail "already row"
  grep -qF "| picked | $(git rev-parse --short "$c2") | Add c |" <<< "$out" || fail "picked row"
}

test_unmerged_pr_aborts() {
  pr_fixture OPEN main ""

  run 1 5.0.x

  [ "$rc" = 1 ] || fail "exit code"
  grep -q "not merged" <<< "$out" || fail "message"
  [ ! -e .claude/worktrees/backport-pr-1 ] || fail "worktree created"
}

test_non_main_base_needs_confirmation() {
  local squash
  squash=$(commit b.txt one "Add b (#1)")
  git push -q upstream main
  pr_fixture MERGED some-feature "$squash"

  run 1 5.0.x
  [ "$rc" = 2 ] || fail "exit code without --any-base"
  grep -q "some-feature" <<< "$out" || fail "message names base"
  [ ! -e .claude/worktrees/backport-pr-1 ] || fail "worktree created"

  run 1 5.0.x --any-base
  [ "$rc" = 0 ] || fail "exit code with --any-base"
}

test_target_derived_from_backport_label() {
  local squash
  squash=$(commit b.txt one "Add b (#1)")
  git push -q upstream main
  pr_fixture MERGED main "$squash" enhancement backport/5.0.5

  run 1

  [ "$rc" = 0 ] || fail "exit code"
  [ "$(wt log --format=%s upstream/5.0.x..HEAD)" = "Add b (#1)" ] || fail "based on 5.0.x"
}

test_ambiguous_target_lists_patch_branches() {
  local squash
  git push -q upstream 5.0.x:5.1.x 5.0.x:unrelated
  squash=$(commit b.txt one "Add b (#1)")
  git push -q upstream main

  pr_fixture MERGED main "$squash"
  run 1
  [ "$rc" = 2 ] || fail "exit code without label"
  [ "$(grep -o '[a-z0-9.]*\.x' <<< "$out" | sort | tr '\n' ' ')" = "5.0.x 5.1.x " ] || fail "candidates"

  pr_fixture MERGED main "$squash" backport/5.0.5 backport/5.1.2
  run 1
  [ "$rc" = 2 ] || fail "exit code with two labels"
}

# Sets c1 (conflicts with 5.0.x) and c2 (applies cleanly), merged via merge commit.
conflicting_pr() {
  git checkout -q 5.0.x
  commit a.txt patch-side "Change a on 5.0.x" >/dev/null
  git push -q upstream 5.0.x
  git checkout -q -b feature main
  c1=$(commit a.txt main-side "Change a")
  c2=$(commit c.txt two "Add c")
  pr_fixture MERGED main "$(merge_pr feature)"
}

test_conflict_stops_with_push_command() {
  conflicting_pr

  run 1 5.0.x

  [ "$rc" = 3 ] || fail "exit code"
  wt rev-parse -q --verify CHERRY_PICK_HEAD >/dev/null || fail "cherry-pick in progress"
  grep -qF "| stopped | $(git rev-parse --short "$c1") | Change a |" <<< "$out" || fail "stopped row"
  grep -qF "| pending | $(git rev-parse --short "$c2") | Add c |" <<< "$out" || fail "pending row"
  grep -qx "a.txt" <<< "$out" || fail "conflicted file listed"
  grep -qx "+main-side" <<< "$out" || fail "authoritative diff shown"
  grep -qF "git push -u origin backport-pr-1" <<< "$out" || fail "push command"
  [ -z "$(wt log --format=%s upstream/5.0.x..HEAD)" ] || fail "nothing picked yet"
}

test_continue_picks_remaining_commits() {
  conflicting_pr
  run 1 5.0.x
  [ "$rc" = 3 ] || fail "setup: expected conflict"
  echo resolved > .claude/worktrees/backport-pr-1/a.txt
  wt add a.txt

  GIT_EDITOR=true wt cherry-pick --continue >/dev/null

  [ "$(wt log --format=%s upstream/5.0.x..HEAD)" = "$(printf 'Add c\nChange a')" ] || fail "resolved commit kept, rest picked"
  wt log -1 --format=%B HEAD~1 | grep -q "cherry picked from commit $c1" || fail "-x trailer on resolved commit"
  wt log -1 --format=%B HEAD~1 | grep -q "Signed-off-by: Tester" || fail "signoff on resolved commit"
  wt log -1 --format=%B HEAD | grep -q "cherry picked from commit $c2" || fail "-x trailer"
  wt log -1 --format=%B HEAD | grep -q "Signed-off-by: Tester" || fail "signoff"
}


test_cherry_pick_failing_to_start_is_an_error() {
  squash_pr
  cat > "$tmp/bin/git" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [ "\$a" != --empty=drop ] || { echo "error: unknown option \\\`empty=drop'" >&2; exit 129; }; done
exec $(command -v git) "\$@"
EOF
  chmod +x "$tmp/bin/git"

  run 1 5.0.x

  [ "$rc" = 1 ] || fail "exit code"
  grep -q "unknown option" <<< "$out" || fail "shows git error"
  ! grep -q "^| " <<< "$out" || fail "prints table"
}

test_unfinished_cherry_pick_needs_decision() {
  conflicting_pr
  run 1 5.0.x
  [ "$rc" = 3 ] || fail "setup: expected conflict"
  wt reset -q --hard

  run 1 5.0.x

  [ "$rc" = 2 ] || fail "exit code"
  grep -q "git cherry-pick --abort" <<< "$out" || fail "suggests abort"
  ! grep -q "^| " <<< "$out" || fail "prints table"
}

squash_pr() {
  local squash
  squash=$(commit b.txt one "Add b (#1)")
  git push -q upstream main
  pr_fixture MERGED main "$squash"
}

test_existing_branch_with_commits_needs_decision() {
  squash_pr
  run 1 5.0.x
  [ "$rc" = 0 ] || fail "setup: first run"
  local head
  head=$(wt rev-parse HEAD)

  run 1 5.0.x

  [ "$rc" = 2 ] || fail "exit code"
  grep -q "Add b (#1)" <<< "$out" || fail "lists branch commits"
  [ "$(wt rev-parse HEAD)" = "$head" ] || fail "branch changed"
}

test_leftover_branch_without_commits_is_replaced() {
  squash_pr
  git worktree add -q -b backport-pr-1 .claude/worktrees/backport-pr-1 upstream/5.0.x
  rm -rf .claude/worktrees/backport-pr-1

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  [ "$(wt log --format=%s upstream/5.0.x..HEAD)" = "Add b (#1)" ] || fail "picked"
}

test_existing_worktree_reused_only_when_clean() {
  squash_pr
  git worktree add -q -b backport-pr-1 .claude/worktrees/backport-pr-1 upstream/5.0.x
  echo dirty > .claude/worktrees/backport-pr-1/a.txt

  run 1 5.0.x
  [ "$rc" = 2 ] || fail "exit code when dirty"
  grep -q "uncommitted changes" <<< "$out" || fail "message"

  wt checkout -q a.txt
  run 1 5.0.x
  [ "$rc" = 0 ] || fail "exit code when clean"
  [ "$(wt log --format=%s upstream/5.0.x..HEAD)" = "Add b (#1)" ] || fail "picked"
}

test_prints_checks_for_touched_paths() {
  git checkout -q -b feature
  commit migration/src/main/resources/org/dependencytrack/migration/V1__x.sql "select 1;" "Add migration" >/dev/null
  commit apiserver/src/test/java/org/foo/FooTest.java "class FooTest {}" "Add FooTest" >/dev/null
  commit apiserver/src/test/java/org/foo/BazTest.java "class BazTest {}" "Add BazTest" >/dev/null
  commit apiserver/src/test/java/org/foo/Helper.java "class Helper {}" "Add Helper" >/dev/null
  commit vuln-analysis/internal/src/test/java/x/BarTest.java "class BarTest {}" "Add BarTest" >/dev/null
  commit apiserver/src/test/java/org/foo/GoneTest.java "class GoneTest {}" "Add GoneTest" >/dev/null
  git rm -q apiserver/src/test/java/org/foo/GoneTest.java
  git commit -q -m "Remove GoneTest"
  pr_fixture MERGED main "$(merge_pr feature)"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  local expected
  expected=$(cat <<'EOF'
make lint-migrations BASE_REF=upstream/5.0.x AGENT=1
make test-single MODULE=apiserver TEST="BazTest,FooTest" AGENT=1
make test-single MODULE=vuln-analysis/internal TEST="BarTest" AGENT=1
make build AGENT=1
EOF
)
  [ "$(grep '^make ' <<< "$out")" = "$expected" ] || fail "checks"
}

test_nothing_to_push_when_all_already_backported() {
  local squash
  squash=$(commit b.txt one "Add b (#1)")
  git push -q upstream main
  git checkout -q 5.0.x
  git cherry-pick -x "$squash" >/dev/null
  git push -q upstream 5.0.x
  pr_fixture MERGED main "$squash"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  ! grep -q "git push" <<< "$out" || fail "suggests push"
  grep -q "Nothing to push" <<< "$out" || fail "message"
}

test_empty_pick_is_skipped() {
  local squash
  squash=$(commit b.txt one "Add b (#1)")
  git push -q upstream main
  git checkout -q 5.0.x
  commit b.txt one "Add b without trailer" >/dev/null
  git push -q upstream 5.0.x
  pr_fixture MERGED main "$squash"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  grep -qF "| skipped (empty) | $(git rev-parse --short "$squash") | Add b (#1) |" <<< "$out" || fail "skipped row"
  grep -q "Nothing to push" <<< "$out" || fail "message"
}

test_failed_commit_without_conflict_shows_git_error() {
  squash_pr
  git config commit.gpgsign true
  git config gpg.format openpgp
  git config gpg.program false

  run 1 5.0.x

  [ "$rc" = 3 ] || fail "exit code"
  grep -q "gpg failed to sign" <<< "$out" || fail "shows git error"
  grep -qF "| stopped | $(git rev-parse --short main) | Add b (#1) |" <<< "$out" || fail "stopped row"
  ! grep -q "cherry-pick --skip" <<< "$out" || fail "suggests skip"
}




test_unknown_target_lists_patch_branches() {
  squash_pr

  run 1 5.9.x

  [ "$rc" = 2 ] || fail "exit code"
  grep -qx "5.0.x" <<< "$out" || fail "candidates"
  [ ! -e .claude/worktrees/backport-pr-1 ] || fail "worktree created"
}

test_unrelated_missing_worktree_stays_registered() {
  squash_pr
  git worktree add -q -b other "$tmp/unmounted" upstream/main
  mv "$tmp/unmounted" "$tmp/elsewhere"

  run 1 5.0.x

  [ "$rc" = 0 ] || fail "exit code"
  git worktree list --porcelain | grep -q "^worktree .*/unmounted$" || fail "unrelated worktree pruned"
}



names=("$@")
[ ${#names[@]} -gt 0 ] || names=($(declare -F | awk '$3 ~ /^test_/ {print $3}'))
failed=0
for t in "${names[@]}"; do
  if (setup && "$t"); then
    echo "ok   $t"
  else
    echo "FAIL $t"
    failed=1
  fi
done
exit $failed
