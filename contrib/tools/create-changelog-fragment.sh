#!/usr/bin/env bash
set -euo pipefail

# Creates a changelog fragment interactively and stages it.

# Detect the current branch and try to extract a PR number
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
PR_NUM=""
if [[ "$BRANCH" =~ ([0-9]+) ]]; then
  PR_NUM="${BASH_REMATCH[1]}"
fi

# --- Location ---
echo ""
echo "📝 No changelog fragment detected in staged files."
echo ""
echo "Where should the fragment go?"
echo "  1) changelog.d/          (node / stackslib changes)"
echo "  2) stacks-signer/changelog.d/  (signer changes)"
echo "  s) skip (no fragment needed)"
echo ""
read -rp "Location [1/2/s]: " loc_choice

case "$loc_choice" in
  1) FRAG_DIR="changelog.d" ;;
  2) FRAG_DIR="stacks-signer/changelog.d" ;;
  s|S)
    echo "Skipping changelog fragment."
    echo "  Remember to add the \"no changelog\" label to your PR."
    exit 0
    ;;
  *)
    echo "Invalid choice. Aborting."
    exit 1
    ;;
esac

# --- Category ---
echo ""
echo "Category:"
echo "  1) added"
echo "  2) changed"
echo "  3) fixed"
echo "  4) removed"
echo ""
read -rp "Category [1/2/3/4]: " cat_choice

case "$cat_choice" in
  1) CATEGORY="added" ;;
  2) CATEGORY="changed" ;;
  3) CATEGORY="fixed" ;;
  4) CATEGORY="removed" ;;
  *)
    echo "Invalid choice. Aborting."
    exit 1
    ;;
esac

# --- Filename ---
DEFAULT_DESC=""
# Try to derive a short description from the branch name
# Strip common prefixes like feat/, fix/, chore/, etc. and the PR number
STRIPPED_BRANCH=$(echo "$BRANCH" | sed -E 's|^[a-z]+/||' | sed -E 's|^[0-9]+-?||')
if [[ -n "$STRIPPED_BRANCH" ]]; then
  DEFAULT_DESC="$STRIPPED_BRANCH"
fi

echo ""
if [[ -n "$PR_NUM" && -n "$DEFAULT_DESC" ]]; then
  DEFAULT_NAME="${PR_NUM}-${DEFAULT_DESC}.${CATEGORY}"
elif [[ -n "$DEFAULT_DESC" ]]; then
  DEFAULT_NAME="${DEFAULT_DESC}.${CATEGORY}"
else
  DEFAULT_NAME=""
fi

if [[ -n "$DEFAULT_NAME" ]]; then
  read -rp "Filename [${DEFAULT_NAME}]: " FILENAME
  FILENAME="${FILENAME:-$DEFAULT_NAME}"
else
  read -rp "Filename (e.g. 1234-short-desc.${CATEGORY}): " FILENAME
fi

# Ensure the filename ends with the category extension
if [[ "$FILENAME" != *.${CATEGORY} ]]; then
  FILENAME="${FILENAME}.${CATEGORY}"
fi

FRAG_PATH="${FRAG_DIR}/${FILENAME}"

# --- Content ---
echo ""
echo "Enter the changelog entry (one or more lines, finish with an empty line):"
CONTENT=""
while IFS= read -r line; do
  [[ -z "$line" ]] && break
  if [[ -n "$CONTENT" ]]; then
    CONTENT="${CONTENT}"$'\n'"${line}"
  else
    CONTENT="${line}"
  fi
done

if [[ -z "$CONTENT" ]]; then
  echo "No content entered. Aborting."
  exit 1
fi

# --- Write and stage ---
echo "$CONTENT" > "$FRAG_PATH"
git add "$FRAG_PATH"

echo ""
echo "✓ Created and staged ${FRAG_PATH}"
