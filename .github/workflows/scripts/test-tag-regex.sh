#!/usr/bin/env bash

# Builds a regex (compatible with `grep -P`) that matches test names carrying a pinny tag.
#
# Usage:
#   test-tag-regex.sh <tag>
#
# Example:
#   test-tag-regex.sh my_tag   # outputs :t::(?:.*::)?my_tag::

set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "Usage: $0 <tag>" >&2
  exit 1
fi

echo ":t::(?:.*::)?${1}::"
