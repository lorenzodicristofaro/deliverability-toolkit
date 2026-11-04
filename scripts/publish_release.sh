#!/usr/bin/env bash
# Build a clean release commit in a separate (public) repository from a tag of this (private) repository.
# Usage: scripts/publish_release.sh <tag> <path-to-public-repo>
# Never pushes. Review the result, then push yourself.
set -euo pipefail

TAG="${1:?usage: publish_release.sh <tag> <public-repo-dir>}"
DEST="${2:?usage: publish_release.sh <tag> <public-repo-dir>}"

SRC="$(git rev-parse --show-toplevel)"
cd "$SRC"

git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || { echo "Tag $TAG not found" >&2; exit 1; }
[ -d "$DEST/.git" ] || { echo "$DEST is not a git repository" >&2; exit 1; }
if [ -n "$(git -C "$DEST" status --porcelain)" ]; then
  echo "Public repo has uncommitted changes: aborting" >&2; exit 1
fi
if git -C "$DEST" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "Tag $TAG already exists in the public repo: aborting" >&2; exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. export the tagged tree
git archive "$TAG" | tar -x -C "$TMP"

# 2. drop internal paths (the ignore list is read from the tagged tree itself)
if [ -f "$TMP/.release-ignore" ]; then
  while IFS= read -r p || [ -n "$p" ]; do
    case "$p" in ''|'#'*) continue ;; esac
    case "$p" in /*|*..*) echo "Refusing unsafe ignore entry: $p" >&2; exit 1 ;; esac
    rm -rf "${TMP:?}/$p"
  done < "$TMP/.release-ignore"
fi

# 3. optional secret scan of the snapshot
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks dir "$TMP" --no-banner || { echo "Secret scan failed: aborting" >&2; exit 1; }
else
  echo "WARNING: gitleaks not installed, secret scan skipped. Do it manually before pushing." >&2
fi

# 4. replace the public working tree (keep .git)
find "$DEST" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -a "$TMP"/. "$DEST"/

# 5. commit and tag
git -C "$DEST" add -A
if git -C "$DEST" diff --cached --quiet; then
  echo "No changes compared to the previous public release: nothing to commit" >&2; exit 1
fi
git -C "$DEST" commit -q -m "Release $TAG"
git -C "$DEST" tag -a "$TAG" -m "Release $TAG"
echo "Created release commit and tag $TAG in $DEST. Review it, then push manually."
