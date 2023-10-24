#!/bin/bash
# Script to do the release and check things
set -e
: ${VERSION?}

TAG="v${VERSION}"
URL="https://github.com/synfinatic/aws-sso-cli"
ERROR=0

if [ -n "$(git status -s)" ]; then
    echo "Error: git status is not clean."
    ERROR=1
fi 

if [ -z "$(git describe --tags HEAD | grep "^${TAG}$")" ]; then 
    echo "Error: git HEAD does not have our tag: $TAG"
    ERROR=1
fi

DATE=$(date +%Y-%m-%d)
if [ -z "$(grep -F "## [${TAG}] - " CHANGELOG.md)" ]; then
    echo "Error: CHANGELOG.md is missing our [$TAG]"
    ERROR=1
elif [ -z "$(grep -F "## [${TAG}] - $DATE" CHANGELOG.md)" ]; then
    echo "Error: CHANGELOG.md has [${TAG}] but wrong date"
    ERROR=1
fi

if [ -z "$(grep -F "[Unreleased]: ${URL}/compare/${TAG}...main" CHANGELOG.md)" ]; then
    echo "Error: CHANGELOG.md [Unreleased] compare does not point to $VERSION"
    ERROR=1
fi

if [ -z "$(grep -F "[${TAG}]: ${URL}/releases/tag/${TAG}" CHANGELOG.md)" ]; then
    echo "Error: CHANGELOG.md missing [${TAG}] tag url"
    ERROR=1
fi

exit $ERROR
