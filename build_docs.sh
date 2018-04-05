#!/usr/bin/env bash
set -e

COMMAND=$1

if [ "$1" = "public_api" ]; then
    version=$(python2 -c 'exec(open("blockstack/version.py").read()) ; print "{}.{}.{}".format(__version_major__, __version_minor__, __version_patch__)')
    cp docs/api-specs.md /tmp/
    sed -i "s/###version###/$version/g" /tmp/api-specs.md
    aglio -i /tmp/api-specs.md --theme-template docs/aglio_templates/public.jade -o api/templates/index.html
elif [ "$1" = "core_api" ]; then
    aglio -i docs/api-specs.md --theme-template docs/aglio_templates/core.jade -o /tmp/index.html
elif [ "$1" = "deploy_gh" ]; then
    PREVIOUS_BRANCH=$(git branch | grep ^\* | awk '{print $2}')
    aglio -i docs/api-specs.md --theme-template docs/aglio_templates/core.jade -o /tmp/index.html
    git checkout gh-pages
    cp /tmp/index.html .
    git add index.html
    git commit -m "updating generated doc outputs"
    git push
    git checkout $PREVIOUS_BRANCH
fi
