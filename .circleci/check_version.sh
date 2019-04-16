#!/bin/bash

set -e

gradle_version=$( ./gradlew properties -q | grep "version:" | awk '{print $2}' )
if [[ "${gradle_version}" != "${CIRCLE_TAG}" ]]; then
    echo "To publish, gradle project version must match git tag"
    exit 1
fi

echo "Version check passed."