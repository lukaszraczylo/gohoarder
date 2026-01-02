#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
GOHOARDER_URL="${GOHOARDER_URL:-}"
TEMP_DIR="/tmp/gohoarder-test-$$"

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up temporary directories..."
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Auto-detect gohoarder URL if not set
if [ -z "$GOHOARDER_URL" ]; then
    # Try to read port from config.yaml
    if [ -f "config.yaml" ]; then
        PORT=$(grep "^  port:" config.yaml | awk '{print $2}')
        if [ -n "$PORT" ]; then
            GOHOARDER_URL="http://localhost:$PORT"
        fi
    fi

    # Fallback to default
    if [ -z "$GOHOARDER_URL" ]; then
        GOHOARDER_URL="http://localhost:8080"
    fi
fi

echo "========================================="
echo "Downloading test packages through gohoarder"
echo "GoHoarder URL: $GOHOARDER_URL"
echo "========================================="
echo ""

# Check if gohoarder is running
if ! curl -s -f "$GOHOARDER_URL/api/stats" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: gohoarder is not running at $GOHOARDER_URL${NC}"
    echo ""
    echo "Please start gohoarder first with: make run"
    echo ""
    echo "If gohoarder is running on a different port, set GOHOARDER_URL:"
    echo "  GOHOARDER_URL=http://localhost:9090 make test-packages"
    exit 1
fi

echo -e "${GREEN}✓ gohoarder is running${NC}"
echo ""

# Create temp directories
mkdir -p "$TEMP_DIR/npm" "$TEMP_DIR/pypi" "$TEMP_DIR/go"

#
# npm packages
#
echo -e "${YELLOW}Testing npm packages...${NC}"

npm_packages=(
    "axios@0.21.1:has vulnerabilities (SSRF, ReDoS)"
    "lodash@4.17.15:has vulnerabilities (prototype pollution)"
    "express@4.17.1:has vulnerabilities (open redirect)"
    "react@18.2.0:clean package"
)

for pkg_info in "${npm_packages[@]}"; do
    IFS=':' read -r pkg desc <<< "$pkg_info"
    IFS='@' read -r pkg_name pkg_version <<< "$pkg"
    echo -n "  • $pkg ($desc)... "

    # Download tarball directly to ensure it goes through proxy
    # npm/pnpm may use local cache and bypass the proxy
    tarball_filename="${pkg_name##*/}-${pkg_version}.tgz"
    tarball_url="$GOHOARDER_URL/npm/$pkg_name/-/$tarball_filename"

    if curl -f -s "$tarball_url" -o "$TEMP_DIR/npm/$tarball_filename" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
done

echo ""

#
# PyPI packages
#
echo -e "${YELLOW}Testing PyPI packages...${NC}"

pypi_packages=(
    "requests==2.25.0:older version, may have vulnerabilities"
    "django==2.2.0:old version with known security issues"
    "flask==0.12.0:old version with XSS vulnerabilities"
    "certifi==2023.7.22:clean package"
)

for pkg_info in "${pypi_packages[@]}"; do
    IFS=':' read -r pkg desc <<< "$pkg_info"
    echo -n "  • $pkg ($desc)... "
    if pip install --index-url "$GOHOARDER_URL/pypi/simple/" \
        --trusted-host localhost \
        "$pkg" \
        --target "$TEMP_DIR/pypi" \
        --quiet > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
done

echo ""

#
# Go packages
#
echo -e "${YELLOW}Testing Go packages...${NC}"

cd "$TEMP_DIR/go"
go mod init test > /dev/null 2>&1

go_packages=(
    "github.com/gin-gonic/gin@v1.7.0:may have vulnerabilities"
    "github.com/dgrijalva/jwt-go@v3.2.0:known JWT signing vulnerabilities"
    "golang.org/x/crypto@v0.0.0-20200622213623-75b288015ac9:old version"
    "github.com/google/uuid@v1.6.0:clean package"
)

for pkg_info in "${go_packages[@]}"; do
    IFS=':' read -r pkg desc <<< "$pkg_info"
    echo -n "  • $pkg ($desc)... "
    # Removed ",direct" fallback to enforce security scanning
    # Packages will fail if blocked (same behavior as pip/npm/pnpm/yarn)
    if GOPROXY="$GOHOARDER_URL/go" go get "$pkg" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
done

echo ""
echo "========================================="
echo -e "${GREEN}Test package downloads complete!${NC}"
echo ""
echo "Next steps:"
echo "  • Visit $GOHOARDER_URL to view packages"
echo "  • Check vulnerability scan results"
echo "  • Compare clean vs vulnerable packages"
echo "========================================="
