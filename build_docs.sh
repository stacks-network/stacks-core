#!/usr/bin/env bash
set -e

PREVIOUS_BRANCH=$(git branch | grep ^\* | awk '{print $2}')
aglio -i docs/api-specs.md --theme-template docs/aglio_templates/core.jade -o /tmp/index.html
git checkout gh-pages
cp /tmp/index.html .
git add index.html
git commit -m "$1"
git push
git checkout $PREVIOUS_BRANCH
