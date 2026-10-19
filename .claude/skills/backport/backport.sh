#!/usr/bin/env bash
# Usage: backport.sh <PR-number> [target-branch] [--any-base]
# Exit codes: 0 all commits applied, 1 error, 2 needs a user decision, 3 a cherry-pick stopped.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
ask() { printf '%s\n' "needs decision:" "$@" >&2; exit 2; }
usage() { die "usage: backport.sh <PR-number> [target-branch] [--any-base]"; }

pr='' target='' any_base=''
while [ $# -gt 0 ]; do
  case $1 in
    --any-base) any_base=1 ;;
    -*) usage ;;
    *) if [ -z "$pr" ]; then pr=$1; elif [ -z "$target" ]; then target=$1; else usage; fi ;;
  esac
  shift
done
[ -n "$pr" ] || usage

cd "$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
CANON=${CANON:-$(git remote -v | awk '/DependencyTrack\/dependency-track.*\(fetch\)/ {print $1; exit}')}
[ -n "$CANON" ] || ask "No remote points at DependencyTrack/dependency-track. Re-run with CANON=<remote>."
git fetch -q "$CANON"

info=$(gh pr view "$pr" --repo DependencyTrack/dependency-track --json state,baseRefName,mergeCommit,labels \
  --jq '[.state, .baseRefName, (.mergeCommit.oid // ""),
         ([.labels[].name | select(startswith("backport/"))] | join(" "))] | join("\u001f")') ||
  die "gh pr view $pr failed"
IFS=$'\x1f' read -r state base merge labels <<< "$info"
[ "$state" = MERGED ] || die "PR #$pr is not merged (state: $state)"
[ "$base" = main ] || [ -n "$any_base" ] ||
  ask "PR #$pr targeted '$base', not 'main'. Re-run with --any-base to backport anyway."

patch_branches() {
  echo "Patch branches on $CANON:"
  git for-each-ref --format='%(refname:lstrip=3)' "refs/remotes/$CANON/" | grep -E '^[0-9]+\.[0-9]+\.x$'
}

if [ -z "$target" ]; then
  # backport/5.0.5 -> 5.0.x
  target=$(for l in $labels; do v=${l#backport/}; echo "${v%.*}.x"; done | sort -u)
  if [ -z "$target" ] || [ "$(wc -l <<< "$target")" -gt 1 ]; then
    ask "PR #$pr needs exactly one backport/* label, found: '${labels}'. Pass the target branch explicitly." \
      "$(patch_branches)"
  fi
fi
git rev-parse -q --verify "refs/remotes/$CANON/$target" >/dev/null ||
  ask "Branch '$target' does not exist on $CANON. Pass an existing target branch." "$(patch_branches)"

if git rev-parse -q --verify "$merge^2" >/dev/null; then
  shas=$(git log --reverse --format=%H "$merge^1..$merge^2")
else
  # Squash merge. Rebase merging is disabled on the repo, so a single-parent merge commit is the whole PR.
  shas=$merge
fi

branch=backport-pr-$pr
wt=.claude/worktrees/$branch
if git rev-parse -q --verify "refs/heads/$branch" >/dev/null; then
  ahead=$(git log --oneline "$branch" "^$CANON/$target")
  [ -z "$ahead" ] || ask "Branch $branch already has commits not on $CANON/$target:" "$ahead" \
    "If they are disposable: git worktree remove --force $wt; git branch -D $branch"
fi
[ -e "$wt" ] || git worktree remove --force "$wt" 2>/dev/null || true
if [ -e "$wt/.git" ]; then
  [ -z "$(git -C "$wt" status --porcelain)" ] || ask "$wt has uncommitted changes. Clean it up or remove it first."
  [ ! -e "$(git -C "$wt" rev-parse --path-format=absolute --git-path sequencer)" ] ||
    ask "$wt has an unfinished cherry-pick. Finish it, or run \`git cherry-pick --abort\` there first."
  git -C "$wt" checkout -q -B "$branch" "$CANON/$target"
else
  git worktree add -q -B "$branch" "$wt" "$CANON/$target"
fi

checks() {
  local paths
  paths=$(git diff --name-only --diff-filter=d "$merge^1" "$merge")
  echo
  echo "Checks, to run from $wt once all commits are applied:"
  if grep -q '^migration/src/main/resources/org/dependencytrack/migration/' <<< "$paths"; then
    echo "make lint-migrations BASE_REF=$CANON/$target AGENT=1"
  fi
  if grep -q '^dex/engine-migration/src/main/resources/org/dependencytrack/dex/engine/migration/' <<< "$paths"; then
    echo "make lint-dex-migration BASE_REF=$CANON/$target AGENT=1"
  fi
  sed -nE 's#^(.+)/src/test/java/.*/([A-Za-z0-9_]+Test)\.java$#\1 \2#p' <<< "$paths" | sort |
    awk 'function out() { if (m) printf "make test-single MODULE=%s TEST=\"%s\" AGENT=1\n", m, t }
         $1 != m { out(); m = $1; t = $2; next }
         { t = t "," $2 }
         END { out() }'
  echo "make build AGENT=1"
}

push_hint() {
  echo
  echo "Push (after checks pass): cd $wt && git push -u origin $branch"
}

row() { local h s; IFS=$'\x1f' read -r h s < <(git log -1 --format='%h%x1f%s' "$2"); echo "| $1 | $h | ${s//|/\\|} |"; }

picked_in() { [ -n "$(git -C "$wt" log -1 --format=%H --grep="cherry picked from commit $1" "$2")" ]; }

not_to_pick() {
  if git rev-parse -q --verify "$1^2" >/dev/null; then
    echo "skipped (merge)"
  elif git diff --quiet "$1^" "$1"; then
    echo "skipped (empty)"
  elif picked_in "$1" "$CANON/$target"; then
    echo already
  fi
}

todo=$(for sha in $shas; do [ -n "$(not_to_pick "$sha")" ] || echo "$sha"; done)
stopped=''
# shellcheck disable=SC2086
if [ -n "$todo" ] && ! err=$(git -C "$wt" cherry-pick -x -s --empty=drop $todo 2>&1); then
  stopped=$(git -C "$wt" rev-parse -q --verify CHERRY_PICK_HEAD) || die "$err"
fi

echo "| Status | Commit | Subject |"
echo "| --- | --- | --- |"
seen_stop=''
for sha in $shas; do
  reason=$(not_to_pick "$sha")
  if [ -n "$reason" ]; then
    row "$reason" "$sha"
  elif [ "$sha" = "$stopped" ]; then
    row stopped "$sha"
    seen_stop=1
  elif picked_in "$sha" "$CANON/$target..HEAD"; then
    row picked "$sha"
  elif [ -n "$seen_stop" ]; then
    row pending "$sha"
  else
    row "skipped (empty)" "$sha"
  fi
done

if [ -n "$stopped" ]; then
  files=$(git -C "$wt" diff --name-only --diff-filter=U)
  echo
  echo "Cherry-pick stopped in $wt:"
  echo "$err"
  echo
  if [ -n "$files" ]; then
    echo "Resolve, then \`GIT_EDITOR=true git cherry-pick --continue\`. Git then picks the remaining commits."
    echo
    echo "Conflicted files:"
    echo "$files"
    echo
    echo "Authoritative diff:"
    # shellcheck disable=SC2086
    git show --format= "$stopped" -- $files
  else
    echo "No conflicts, but committing failed. Fix the cause above, then \`GIT_EDITOR=true git cherry-pick --continue\`."
  fi
  checks
  push_hint
  exit 3
fi
if [ -z "$(git -C "$wt" log --oneline "$CANON/$target..HEAD")" ]; then
  echo
  echo "Nothing to push: $branch has no commits beyond $CANON/$target."
  exit 0
fi
checks
push_hint
