#!/bin/bash

set -e

gradle_version=$( ./gradlew properties -q | grep "version:" | awk '{print $2}' )
if [[ "${CIRCLE_TAG}" == "" ]]; then
    echo "Git tag not defined, version check skipped."
elif [[ "v${gradle_version}" != "${CIRCLE_TAG}" ]]; then
    echo "To publish, gradle project version must match git tag"
    exit 1
fi

echo "Version check passed."