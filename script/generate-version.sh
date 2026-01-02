#!/bin/bash
set -e

# generate-version.sh
# Generates semantic version based on git tags and commits
#
# Usage:
#   ./script/generate-version.sh
#
# Environment variables (optional):
#   VERSION_PREFIX - Prefix for version tags (default: v)
#   FALLBACK_VERSION - Version to use if no tags found (default: 0.0.0)

VERSION_PREFIX="${VERSION_PREFIX:-v}"
FALLBACK_VERSION="${FALLBACK_VERSION:-0.0.0}"

# Try to get version from git describe
if git describe --tags --abbrev=0 2>/dev/null >/dev/null; then
    # Get the latest tag
    LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null)

    # Remove prefix if present
    VERSION="${LATEST_TAG#$VERSION_PREFIX}"

    # Get commits since last tag
    COMMITS_SINCE_TAG=$(git rev-list ${LATEST_TAG}..HEAD --count 2>/dev/null || echo "0")

    # Get current commit hash
    COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

    # If there are commits since the last tag, add pre-release identifier
    if [ "$COMMITS_SINCE_TAG" != "0" ]; then
        # Increment patch version and add pre-release identifier
        # Parse the version
        IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"

        # Increment patch for next development version
        NEXT_PATCH=$((PATCH + 1))

        # Generate pre-release version
        VERSION="${MAJOR}.${MINOR}.${NEXT_PATCH}-dev.${COMMITS_SINCE_TAG}+${COMMIT_HASH}"
    fi
else
    # No tags found, use fallback
    COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    COMMIT_COUNT=$(git rev-list --count HEAD 2>/dev/null || echo "0")
    VERSION="${FALLBACK_VERSION}-dev.${COMMIT_COUNT}+${COMMIT_HASH}"
fi

# Check if working directory is dirty
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    VERSION="${VERSION}-dirty"
fi

echo "$VERSION"
