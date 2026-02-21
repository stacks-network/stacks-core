#!/usr/bin/env bash

# Discovers available `bitcoin/bitcoin` Docker Hub tags and returns a JSON payload
#
# Usage:
#   docker-bitcoin-majors.sh [START_MAJOR]
#
# Arguments:
#   START_MAJOR  Optional integer major version to start discovery from.
#                Defaults to 25.
#
# Output (stdout):
#   {
#     "start_major": <number>,
#     "major_versions": [<major>, ...],
#     "versions": [<resolved_tag>, ...]
#   }
#
# Resolution rules:
# - Includes tags matching `X` and `X.Y` only.
# - For each major X, prefers highest discovered minor (`X.Y`) over bare `X`.
# - Validates discovered majors are contiguous from START_MAJOR to latest.
#
# Failure behavior:
# - Exits non-zero and prints an error to stderr on invalid input, API/read
#   failures, no matching tags, or non-contiguous major discovery.
#
# Requirements: `curl`, `jq`, `sort`, Bash 4+.
set -euo pipefail

main() {
  local start_major="${1:-25}"
  local -A resolved_tags

  if ! [[ "$start_major" =~ ^[0-9]+$ ]]; then
    echo "START_MAJOR must be an integer (got: $start_major)" >&2
    exit 1
  fi

  # Retrieves tags, filters them and creates a map [major]=[highest major.minor]
  local next_url="https://hub.docker.com/v2/repositories/bitcoin/bitcoin/tags?page_size=100"
  while [[ -n "$next_url" && "$next_url" != "null" ]]; do
    local response_json
    response_json="$(curl -fsSL "$next_url")"

    mapfile -t tags < <(jq -r '.results[].name' <<< "$response_json")

    for tag in "${tags[@]}"; do
      if [[ "$tag" =~ ^([0-9]+)(\.([0-9]+))?$ ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[3]}"

        if (( major >= start_major )); then
          set_resolved_tag resolved_tags "$major" "$minor"
        fi
      fi
    done

    next_url="$(jq -r '.next' <<< "$response_json")"
  done

  if (( ${#resolved_tags[@]} == 0 )); then
    echo "No bitcoind major tags found from version $start_major upward." >&2
    exit 1
  fi

  mapfile -t sorted_majors < <(printf '%s\n' "${!resolved_tags[@]}" | sort -n)

  # Validation: 
  # - start_major exists in discovered majors, and 
  if [[ "${sorted_majors[0]}" != "$start_major" ]]; then
    echo "Expected start_major=$start_major to be present, but first discovered major is ${sorted_majors[0]}." >&2
    exit 1
  fi
  # - majors are contiguous with no gaps from start_major to the highest found.
  local expected_major="$start_major"
  for major in "${sorted_majors[@]}"; do
    if (( major != expected_major )); then
      echo "Discovered major versions are not contiguous: expected $expected_major but found $major." >&2
      exit 1
    fi
    expected_major=$((expected_major + 1))
  done

  # Create json result
  local major_versions_json="$(printf '%s\n' "${sorted_majors[@]}" | jq -R . | jq -s -c .)"
  local full_versions_json="$({
    for major in "${sorted_majors[@]}"; do
      printf '%s\n' "${resolved_tags[$major]}"
    done
  } | jq -R . | jq -s -c .)"

  jq -cn \
    --argjson start_major "$start_major" \
    --argjson major_versions "$major_versions_json" \
    --argjson versions "$full_versions_json" \
    '{start_major: $start_major, major_versions: $major_versions, versions: $versions}'
}

set_resolved_tag() {
  local map_name="$1"
  local major="$2"
  local minor="${3:-}"
  declare -n resolved_tags_ref="$map_name"

  if [[ ! -v resolved_tags_ref[$major] ]]; then
    resolved_tags_ref["$major"]="$major"
  fi

  local current="${resolved_tags_ref[$major]}"

  if [[ -z "$minor" ]]; then
    return
  fi

  local candidate="${major}.${minor}"

  if [[ "$current" == "$major" ]]; then
    resolved_tags_ref["$major"]="$candidate"
    return
  fi

  local current_minor="${current#*.}"
  if (( minor > current_minor )); then
    resolved_tags_ref["$major"]="$candidate"
  fi
}

main "$@"
