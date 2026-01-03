#!/bin/bash
# Workflow prepare script for CI/CD
# Installs CGO dependencies for SQLite support

set -e

echo "=== GoHoarder Workflow Prepare ==="
echo "Host OS: $(uname -s)"
echo "Target GOOS: ${TARGET_GOOS:-auto}"
echo "Target GOARCH: ${TARGET_GOARCH:-auto}"

# Detect host OS
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Install SQLite development headers based on platform
case "$HOST_OS" in
    linux*)
        echo "Installing SQLite development headers for Linux..."
        if command -v apt-get &> /dev/null; then
            # Ubuntu/Debian
            sudo apt-get update -qq
            sudo apt-get install -y -qq libsqlite3-dev
        elif command -v yum &> /dev/null; then
            # RHEL/CentOS
            sudo yum install -y sqlite-devel
        elif command -v apk &> /dev/null; then
            # Alpine
            sudo apk add --no-cache sqlite-dev
        fi
        echo "✓ SQLite headers installed"
        ;;

    darwin*)
        echo "Installing SQLite for macOS..."
        # macOS usually has SQLite via Xcode Command Line Tools
        # but ensure it's available via Homebrew if needed
        if ! pkg-config --exists sqlite3; then
            brew install sqlite3
        fi
        echo "✓ SQLite available"
        ;;

    mingw*|msys*|cygwin*)
        echo "Installing SQLite for Windows..."
        # Download SQLite amalgamation for Windows
        SQLITE_VERSION="3470200"
        SQLITE_YEAR="2024"
        SQLITE_DIR="/c/sqlite"
        SQLITE_URL="https://www.sqlite.org/${SQLITE_YEAR}/sqlite-amalgamation-${SQLITE_VERSION}.zip"

        mkdir -p "$SQLITE_DIR"
        curl -sSL "$SQLITE_URL" -o /tmp/sqlite.zip
        unzip -q /tmp/sqlite.zip -d /tmp/
        cp /tmp/sqlite-amalgamation-${SQLITE_VERSION}/* "$SQLITE_DIR/"
        rm -rf /tmp/sqlite.zip /tmp/sqlite-amalgamation-${SQLITE_VERSION}

        echo "CGO_CFLAGS=-I${SQLITE_DIR}" >> "$GITHUB_ENV"
        echo "CGO_LDFLAGS=-L${SQLITE_DIR}" >> "$GITHUB_ENV"
        echo "✓ SQLite setup complete"
        ;;

    *)
        echo "Unknown OS: $HOST_OS - skipping SQLite setup"
        ;;
esac

# Verify SQLite is available
echo ""
echo "=== Verifying SQLite availability ==="
if pkg-config --exists sqlite3; then
    echo "✓ SQLite pkg-config found"
    pkg-config --modversion sqlite3
else
    echo "⚠ SQLite pkg-config not found (may still work via system headers)"
fi

echo ""
echo "=== Workflow prepare complete ==="
