#!/usr/bin/env bash
set -euo pipefail

origin_remote="${1:-origin}"

repo_root="$(git rev-parse --show-toplevel)"
wiki_source="$repo_root/wiki"

if [[ ! -d "$wiki_source" ]]; then
  echo "Missing 'wiki/' folder at repo root."
  exit 1
fi

origin_url="$(git remote get-url "$origin_remote")"
if [[ "$origin_url" =~ github\.com[:/]+([^/]+)/([^/.]+)(\.git)?$ ]]; then
  owner="${BASH_REMATCH[1]}"
  repo="${BASH_REMATCH[2]}"
else
  echo "Unsupported remote URL format: $origin_url"
  exit 1
fi

wiki_remote="https://github.com/${owner}/${repo}.wiki.git"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "Cloning wiki repo: $wiki_remote"
if ! git clone "$wiki_remote" "$tmp_dir"; then
  echo ""
  echo "Wiki repo not initialised yet."
  echo "Create the first wiki page in GitHub (Repo -> Wiki -> Create the first page)."
  echo "Re-run this script after saving the first page."
  exit 1
fi

rm -f "$tmp_dir"/*.md
cp "$wiki_source"/*.md "$tmp_dir"/

cd "$tmp_dir"
git add -A

if git diff --cached --quiet; then
  echo "Wiki is already up to date."
  exit 0
fi

git commit -m "Update wiki"
git push
echo "Wiki published."

