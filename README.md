# GoHoarder

**A universal, security-first caching proxy for package managers with automated vulnerability scanning.**

GoHoarder is a transparent pass-through cache proxy that supports npm, pip, and Go modules. It caches packages locally, scans them for vulnerabilities using multiple security scanners, and blocks packages that exceed your security thresholds—all without requiring changes to your existing workflows.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg)](https://golang.org)

---

## ✨ Features

### 🔒 **Security-First**
- **Automated vulnerability scanning** with multiple scanners (Trivy, OSV, Grype, npm-audit, pip-audit, GitHub Advisory Database, govulncheck)
- **Configurable blocking thresholds** by severity (CRITICAL, HIGH, MODERATE, LOW)
- **CVE bypass system** for managing false positives or accepted risks
- **Real-time scanning** before package delivery - blocks vulnerable packages on **first download**
- **403 Forbidden responses** for blocked packages (not 502 errors)
- **No fallback mechanisms** - security is enforced across all package managers

### 🚀 **Performance**
- **Intelligent caching** reduces bandwidth and speeds up builds
- **Scan-once, serve-many** - packages scanned once, results cached
- **Background rescanning** keeps security assessments up-to-date
- **Multi-backend storage** (filesystem, S3, SMB/CIFS)
- **Connection pooling** and **rate limiting** for upstream registries
- **Circuit breaker** pattern for resilience

### 📊 **Observability**
- **Web dashboard** with Vue 3 frontend for package management
- **Detailed vulnerability reports** with CVE information and severity breakdown
- **Download analytics** and usage statistics
- **Health check endpoints** for monitoring
- **Prometheus metrics** integration
- **Structured JSON logging** with zerolog

### 🌐 **Universal Support**
- **npm/pnpm/yarn** - Full npm registry protocol support
- **pip** - PyPI Simple API (PEP 503) implementation
- **Go modules** - GOPROXY protocol with sumdb support
- **Transparent proxying** - Works with existing tools without modification

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Package Manager Setup](#-package-manager-setup)
- [Private Repository Support](#-private-repository-support)
- [Kubernetes Deployment](#️-kubernetes-deployment)
- [Security Scanning](#-security-scanning)
- [Web Dashboard](#-web-dashboard)
- [API Reference](#-api-reference)
- [Architecture](#-architecture)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## 🚀 Quick Start

### 1. Install and Run

```bash
# Clone the repository
git clone https://github.com/lukaszraczylo/gohoarder.git
cd gohoarder

# Build
make build

# Run (starts both backend and frontend)
make run
```

GoHoarder will start on **http://localhost:8080**

### 2. Configure Your Package Manager

**npm/pnpm:**
```bash
npm config set registry http://localhost:8080/npm
```

**pip:**
```bash
pip install --index-url http://localhost:8080/pypi/simple/ \
            --trusted-host localhost \
            package-name
```

**Go:**
```bash
# ⚠️ IMPORTANT: Do NOT use ",direct" fallback - it bypasses security!
export GOPROXY="http://localhost:8080/go"
```

### 3. Install Packages Normally

```bash
# npm
npm install axios

# pip
pip install requests

# Go
go get github.com/gin-gonic/gin
```

**Vulnerable packages are automatically blocked:**
```
npm install axios@0.21.1
❌ ERROR: 403 Forbidden - Package has 3 HIGH vulnerabilities (threshold: 0)
```

---

## 📦 Installation

### Prerequisites

- **Go 1.22+** for building the backend
- **Node.js 18+** and **pnpm** for building the frontend
- **Security scanners** (optional, but recommended):
  - [Trivy](https://github.com/aquasecurity/trivy) - Container and package scanning
  - [Grype](https://github.com/anchore/grype) - Vulnerability scanner
  - [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Go-specific scanner

### Building from Source

```bash
# Clone repository
git clone https://github.com/lukaszraczylo/gohoarder.git
cd gohoarder

# Build backend only
make build

# Build backend + frontend
make build-all

# Run with frontend
make run

# Run backend only
./bin/gohoarder serve
```

### Install Security Scanners

**Trivy:**
```bash
# macOS
brew install aquasecurity/trivy/trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

**Grype:**
```bash
# macOS
brew tap anchore/grype
brew install grype

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

**govulncheck:**
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

---

## ⚙️ Configuration

### Configuration File

Create `config.yaml` in the project root:

```yaml
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "5m"
  write_timeout: "5m"

storage:
  backend: "filesystem"  # Options: filesystem, s3, smb
  path: "./data/storage"

metadata:
  backend: "sqlite"      # Options: sqlite, postgresql
  path: "./data/gohoarder.db"

security:
  enabled: true
  update_db_on_startup: true

  # Block packages based on vulnerability counts
  block_thresholds:
    critical: 0    # Block if ANY critical vulnerabilities
    high: 0        # Block if ANY high vulnerabilities
    medium: 5      # Block if MORE than 5 medium vulnerabilities
    low: -1        # -1 = don't block based on low severity

  # Or block based on highest severity present
  block_on_severity: "high"  # Options: critical, high, moderate, low, none

  scanners:
    trivy:
      enabled: true
    osv:
      enabled: true
    grype:
      enabled: true
    govulncheck:
      enabled: true
    npm_audit:
      enabled: true
    pip_audit:
      enabled: true
    ghsa:
      enabled: true

cache:
  default_ttl: 86400  # 24 hours in seconds

logging:
  level: "info"  # debug, info, warn, error
  format: "json"

upstream:
  npm: "https://registry.npmjs.org"
  pypi: "https://pypi.org/simple"
  go: "https://proxy.golang.org"
```

### Environment Variables

All configuration values can be overridden with environment variables:

```bash
# Server
export GOHOARDER_SERVER_PORT=8080
export GOHOARDER_SERVER_HOST="0.0.0.0"

# Storage
export GOHOARDER_STORAGE_BACKEND="filesystem"
export GOHOARDER_STORAGE_PATH="./data/storage"

# Security
export GOHOARDER_SECURITY_ENABLED=true
export GOHOARDER_SECURITY_BLOCK_CRITICAL=0
export GOHOARDER_SECURITY_BLOCK_HIGH=0

# Logging
export GOHOARDER_LOG_LEVEL="info"
```

---

## 🔧 Package Manager Setup

### npm / pnpm / yarn

#### ⚠️ Security Notice

**All three package managers enforce security correctly - no fallback mechanisms.**

#### Configuration

**npm:**
```bash
npm config set registry http://localhost:8080/npm
```

**pnpm:**
```bash
pnpm config set registry http://localhost:8080/npm
```

**yarn (v4+):**
```yaml
# .yarnrc.yml
npmRegistryServer: "http://localhost:8080/npm"
unsafeHttpWhitelist:
  - localhost
```

#### Usage

```bash
# Install packages normally
npm install express
pnpm add react
yarn add lodash

# Vulnerable packages will fail with 403 Forbidden
npm install axios@0.21.1
# ❌ ERROR: 403 Forbidden - Package has 3 HIGH vulnerabilities (threshold: 0)
```

#### Clear Cache

```bash
npm cache clean --force
pnpm store prune
yarn cache clean --all
```

---

### Python (pip)

#### Configuration

**Per-install:**
```bash
pip install --index-url http://localhost:8080/pypi/simple/ \
            --trusted-host localhost \
            package-name
```

**Global configuration:**
```ini
# ~/.pip/pip.conf (Linux/macOS)
# %APPDATA%\pip\pip.ini (Windows)

[global]
index-url = http://localhost:8080/pypi/simple/
trusted-host = localhost
```

#### Usage

```bash
# Install packages normally
pip install requests

# Vulnerable packages will fail
pip install flask==0.12.0
# ❌ ERROR: HTTP error 403 while getting ...
# ❌ ERROR: 403 Client Error: Forbidden
```

#### Clear Cache

```bash
pip cache purge
```

---

### Go Modules

#### ⚠️ CRITICAL: No Fallback Configuration

**The `,direct` fallback completely bypasses security scanning and must NEVER be used!**

**❌ INSECURE (bypasses security):**
```bash
export GOPROXY="http://localhost:8080/go,direct"
#                                        ^^^^^^^ NEVER USE THIS!
```

**✅ SECURE (enforces scanning):**
```bash
export GOPROXY="http://localhost:8080/go"
```

**Persistent configuration:**
```bash
# Add to ~/.bashrc, ~/.zshrc, or ~/.profile
echo 'export GOPROXY="http://localhost:8080/go"' >> ~/.bashrc
source ~/.bashrc
```

#### Usage

```bash
# Download packages normally
go get github.com/gin-gonic/gin@v1.7.0
go mod download

# Vulnerable packages will fail with 403 Forbidden
# (if vulnerability databases detect issues)
```

#### Clear Cache

```bash
go clean -modcache
```

## 🔐 Private Repository Support

GoHoarder supports private packages through **automatic credential forwarding** - no server-side configuration needed! Your existing authentication automatically works through the proxy.

### How It Works

1. **Client Authentication** → Your package manager sends credentials to GoHoarder
2. **Credential Forwarding** → GoHoarder forwards credentials to upstream registry
3. **Package Caching** → Packages are cached with credential-aware keys
4. **Access Validation** → For private packages, credentials are validated on every request (cached for 5 minutes)
5. **Multi-User Isolation** → Different users with different credentials get separate cache entries

### Security Model

- **Per-Request Validation**: Private packages verify credentials with upstream before serving
- **Credential Isolation**: Each user's credentials create separate cache entries
- **Validation Caching**: Validation results cached for 5 minutes to reduce upstream load
- **Access Control**: 403 Forbidden if credentials are invalid or missing

### Setup

#### npm Private Packages

**GitHub Packages:**

```bash
# Configure .npmrc for GitHub Packages
echo "@yourorg:registry=https://npm.pkg.github.com" >> ~/.npmrc
echo "//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN" >> ~/.npmrc

# Use GoHoarder proxy
npm config set registry http://localhost:8080/npm
npm install @yourorg/private-package
```

**GitLab Packages:**

```bash
# Configure .npmrc for GitLab
echo "@yourgroup:registry=https://gitlab.com/api/v4/packages/npm/" >> ~/.npmrc
echo "//gitlab.com/api/v4/packages/npm/:_authToken=YOUR_GITLAB_TOKEN" >> ~/.npmrc

# Use GoHoarder proxy
npm config set registry http://localhost:8080/npm
```

**Private Artifactory / Nexus:**

```bash
# Configure .npmrc with Basic auth
echo "//your-registry.com/:_auth=BASE64_CREDENTIALS" >> ~/.npmrc

# Use GoHoarder proxy
npm config set registry http://localhost:8080/npm
```

#### PyPI Private Packages

**Private PyPI Index:**

```bash
# Configure pip with credentials in URL
pip config set global.index-url http://localhost:8080/pypi/simple

# Install with credentials in request (pip handles auth)
pip install --index-url http://username:password@localhost:8080/pypi/simple private-package //trufflehog:ignore
```

**AWS CodeArtifact:**

```bash
# Get CodeArtifact token
export CODEARTIFACT_AUTH_TOKEN=$(aws codeartifact get-authorization-token --domain your-domain --query authorizationToken --output text)

# Use with pip
pip install --index-url http://aws:$CODEARTIFACT_AUTH_TOKEN@localhost:8080/pypi/simple private-package
```

**GitHub Packages (PyPI):**

```bash
# Configure pip to use GitHub Packages through GoHoarder
pip install --index-url http://USERNAME:GITHUB_TOKEN@localhost:8080/pypi/simple your-private-package //trufflehog:ignore
```

#### Go Private Modules

**GitHub Private Repositories:**

```bash
# Configure .netrc with GitHub credentials
cat >> ~/.netrc <<EOF
machine github.com
login oauth2
password YOUR_GITHUB_TOKEN
EOF
chmod 600 ~/.netrc

# Configure Go to use GoHoarder
export GOPROXY=http://localhost:8080/go
export GOPRIVATE=github.com/yourorg/*

# Install private module
go get github.com/yourorg/private-module@v1.0.0
```

**GitLab Private Repositories:**

```bash
# Configure .netrc with GitLab credentials
cat >> ~/.netrc <<EOF
machine gitlab.com
login oauth2
password YOUR_GITLAB_TOKEN
EOF
chmod 600 ~/.netrc

# Configure Go to use GoHoarder
export GOPROXY=http://localhost:8080/go
export GOPRIVATE=gitlab.com/yourgroup/*

# Install private module
go get gitlab.com/yourgroup/private-module@v1.0.0
```

**How Go Private Modules Work:**

GoHoarder implements intelligent fallback for Go modules:

1. **Fast Path (Public Modules)**: Tries `proxy.golang.org` first for maximum speed
2. **Git Fallback (Private Modules)**: On 404/403, fetches directly from git repository:
   - Clones repository with credentials from `.netrc`
   - Checks out specified version (tag, branch, or commit)
   - Builds Go module zip following official spec
   - Caches for future requests
3. **Full Integration**: Works seamlessly with `go get`, `go mod download`, etc.

**Supported Version Formats:**
- Semantic versions: `v1.2.3`, `v2.0.0`
- Branches: `main`, `develop`, `feature/xyz`
- Commits: Full commit SHA
- Pseudo-versions: Generated automatically by Go

### Access Control Examples

**Scenario 1: Public Package**
- No credentials required
- Cached once, served to all users
- No validation needed

**Scenario 2: Private Package - Authorized User**
- User provides valid credentials
- First request: validates with upstream (~100-200ms), caches package
- Subsequent requests: uses validation cache (~1ms), serves package
- Validation cache expires after 5 minutes

**Scenario 3: Private Package - Unauthorized User**
- User provides invalid/missing credentials
- Request denied with 403 Forbidden (npm/PyPI) or 404 Not Found (Go)
- No cache created for this user

**Scenario 4: Multiple Users - Same Private Package**
- User A (valid credentials): gets package from cache A
- User B (different credentials): gets package from cache B
- User C (no credentials): denied with 403/404
- Each user isolated in separate cache

### Credential Security

- **Never Stored**: Credentials are never persisted to disk
- **Hash-Based Keys**: Cache keys use SHA256 hash (not raw credentials)
- **In-Transit Only**: Credentials used only for upstream validation
- **Per-Request**: Each request carries its own credentials
- **No Logging**: Credentials never appear in logs

### Supported Providers

| Provider | npm | PyPI | Go |
|----------|-----|------|-----|
| GitHub Packages | ✅ | ✅ | ✅ |
| GitLab Packages | ✅ | ✅ | ✅ |
| Bitbucket | ✅ | ✅ | ✅ |
| Artifactory | ✅ | ✅ | ✅ |
| Self-Hosted Git | ⚠️ | ⚠️ | ✅ |
| AWS CodeArtifact | ✅ | ✅ | ⚠️ |
| Azure Artifacts | ✅ | ✅ | ⚠️ |
| Private Registries | ✅ | ✅ | ✅ |

✅ = Fully Supported | ⚠️ = Requires additional setup

**Go Module Notes:**
- Direct git access means GoHoarder works with ANY git-based hosting
- Supports GitHub, GitLab, Bitbucket, self-hosted GitLab/Gitea/Gogs, etc.
- Only requirement: git repository must be accessible via HTTPS
- Authentication via `.netrc` file (standard git credential mechanism)

---

## ☸️ Kubernetes Deployment

GoHoarder is designed for production deployment in Kubernetes environments with built-in support for pattern-based credential management.

### Pattern-Based Credential Management

In Kubernetes, GoHoarder uses **organization-based credential mapping** to support multi-org, multi-team deployments with a single proxy instance:

```yaml
{
  "credentials": [
    {
      "pattern": "github.com/mycompany/*",
      "host": "github.com",
      "token": "ghp_company_service_account"
    },
    {
      "pattern": "github.com/external-vendor/*",
      "host": "github.com",
      "token": "ghp_vendor_access_token"
    },
    {
      "pattern": "gitlab.com/backend-team/*",
      "host": "gitlab.com",
      "token": "glpat_backend_token"
    }
  ]
}
```

### How It Works

1. **Module Request**: `go get github.com/mycompany/private-module`
2. **Pattern Match**: GoHoarder matches `github.com/mycompany/*` pattern
3. **Credential Selection**: Uses corresponding service account token
4. **Git Clone**: Fetches module with appropriate credentials
5. **Caching**: Packages cached for all users with access

### Quick Start

```bash
# Deploy to Kubernetes
kubectl apply -f deployments/kubernetes/pvc.yaml
kubectl apply -f deployments/kubernetes/secret-git-credentials.yaml
kubectl apply -f deployments/kubernetes/configmap-config.yaml
kubectl apply -f deployments/kubernetes/deployment.yaml
kubectl apply -f deployments/kubernetes/service.yaml

# Configure Go client in your pods
ENV GOPROXY=http://gohoarder.default.svc.cluster.local:8080/go
```

### Key Features

- **Pattern-Based Matching**: Glob patterns for flexible credential assignment
- **Multi-Organization Support**: Different tokens for different organizations
- **Kubernetes Secret Integration**: Standard Kubernetes Secret for credential storage
- **External Secrets Operator**: Compatible with ESO for secret management
- **Service Account Pattern**: Industry-standard approach for multi-tenant scenarios
- **Zero Client Changes**: Works with standard `go get`, npm, pip commands

### Configuration

**Kubernetes Secret:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gohoarder-git-credentials
stringData:
  credentials.json: |
    {
      "credentials": [
        {
          "pattern": "github.com/myorg/*",
          "host": "github.com",
          "username": "oauth2",
          "token": "YOUR_GITHUB_TOKEN"
        }
      ]
    }
```

**ConfigMap:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gohoarder-config
data:
  config.yaml: |
    handlers:
      go:
        enabled: true
        git_credentials_file: /etc/gohoarder/git-credentials.json
```

### Pattern Examples

| Pattern | Matches | Use Case |
|---------|---------|----------|
| `github.com/myorg/*` | All repos under myorg | Organization-wide access |
| `github.com/myorg/specific-repo` | Specific repo only | Granular control |
| `gitlab.com/backend-team/*` | All GitLab backend repos | Team-based access |
| `*` (with `fallback: true`) | Everything else | Default readonly token |

### Credential Priority

1. **Most Specific Pattern**: Longest matching pattern wins
2. **Fallback Credential**: Pattern with `"fallback": true`
3. **System Git Config**: Falls back to system `.netrc` if no match

### Security Best Practices

- **Token Scoping**: Use fine-grained tokens with minimal permissions
- **Secret Rotation**: Regularly rotate tokens using Kubernetes secrets
- **RBAC**: Limit who can read git-credentials secret
- **Audit Logging**: Monitor credential usage in logs
- **Read-Only Tokens**: Use read-only tokens when possible

### External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: gohoarder-git-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: gohoarder-git-credentials
  data:
  - secretKey: credentials.json
    remoteRef:
      key: secret/gohoarder/git-credentials
```

### Complete Documentation

For detailed Kubernetes deployment instructions, including:
- Multi-organization setups
- Performance tuning
- High availability configuration
- Monitoring and troubleshooting
- Integration with CI/CD pipelines

See: **[deployments/kubernetes/README.md](deployments/kubernetes/README.md)**

---

## 🔒 Security Scanning

### How It Works

GoHoarder implements a **security-first caching model**:

1. **Package Requested** → Client requests a package
2. **Download & Cache** → GoHoarder downloads and stores the package
3. **Multi-Scanner Analysis** → All enabled scanners analyze the package in parallel:
   - **Trivy** - General-purpose vulnerability scanner
   - **OSV** - Open Source Vulnerabilities database
   - **Grype** - Anchore vulnerability scanner
   - **govulncheck** - Go-specific vulnerability checker
   - **npm-audit** - npm's official audit tool
   - **pip-audit** - Python package auditing
   - **GitHub Advisory Database** - GitHub's security advisories
4. **Wait for Completion** → Request waits up to 30 seconds for **ALL** scanners to complete
5. **Consolidation** → Results merged and deduplicated by CVE
6. **Threshold Check** → Package evaluated against security thresholds
7. **Decision**:
   - **Clean** → 200 OK, package delivered
   - **Blocked** → 403 Forbidden, installation fails

### Key Security Features

✅ **No race conditions** - Wait loop ensures all scanners complete before serving
✅ **Block on first download** - Vulnerable packages never reach your system
✅ **Scan-once, cache-forever** - Subsequent requests blocked instantly (< 1ms)
✅ **Proper HTTP status codes** - 403 Forbidden (not 502 Bad Gateway)
✅ **Clear error messages** - "Package blocked: [reason]"

### Blocking Thresholds

**Two blocking modes:**

#### 1. Count-Based Thresholds

Block if vulnerability counts exceed thresholds:

```yaml
security:
  block_thresholds:
    critical: 0    # Block if ANY critical vulnerabilities
    high: 0        # Block if ANY high vulnerabilities
    medium: 5      # Block if MORE than 5 medium vulnerabilities
    low: -1        # -1 = don't block based on low severity
```

#### 2. Severity-Based Blocking

Block if ANY vulnerability at or above specified severity:

```yaml
security:
  block_on_severity: "high"  # Block if ANY high or critical vulnerabilities
```

### CVE Bypass System

Manage false positives or accepted risks:

```bash
# Bypass specific CVE
curl -X POST http://localhost:8080/api/cve-bypass \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cve",
    "target": "CVE-2023-12345",
    "reason": "False positive - not exploitable in our use case",
    "expires_at": "2024-12-31T23:59:59Z",
    "applies_to": "npm/axios@0.21.1"
  }'

# Bypass entire package
curl -X POST http://localhost:8080/api/cve-bypass \
  -H "Content-Type: application/json" \
  -d '{
    "type": "package",
    "target": "npm/axios@0.21.1",
    "reason": "Approved by security team",
    "expires_at": "2024-12-31T23:59:59Z"
  }'
```

---

## 🖥️ Web Dashboard

Access the web dashboard at **http://localhost:8080**

### Features

- ✅ **Package Browser** - View all cached packages with filtering and search
- ✅ **Vulnerability Details** - Click on any package to see detailed CVE information
- ✅ **Security Status** - Color-coded severity badges (CRITICAL, HIGH, MODERATE, LOW)
- ✅ **Download Statistics** - Track package usage and download counts
- ✅ **System Health** - Monitor scanner status and system components
- ✅ **Responsive Design** - Works on desktop, tablet, and mobile

### Dashboard Preview

```
┌─────────────────────────────────────────────────────┐
│ GoHoarder Dashboard                    🔍 Search    │
├─────────────────────────────────────────────────────┤
│ Package                    | Status     | Vulns     │
├─────────────────────────────────────────────────────┤
│ axios@0.21.1 (npm)        | VULNERABLE | 4 (3 HIGH)│
│ react@18.2.0 (npm)        | CLEAN      | 0         │
│ requests@2.31.0 (pypi)    | CLEAN      | 0         │
│ gin-gonic/gin@v1.7.0 (go) | CLEAN      | 0         │
└─────────────────────────────────────────────────────┘
```

---

## 📡 API Reference

### Packages

**List Packages:**
```bash
GET /api/packages
GET /api/packages?registry=npm
GET /api/packages?status=vulnerable
```

**Package Details:**
```bash
GET /api/packages/:registry/:name/:version
```

**Response:**
```json
{
  "packages": [
    {
      "id": "abc-123",
      "name": "axios",
      "version": "0.21.1",
      "registry": "npm",
      "size": 95962,
      "cached_at": "2026-01-02T15:00:00Z",
      "download_count": 6,
      "vulnerabilities": {
        "status": "vulnerable",
        "total": 4,
        "counts": {
          "critical": 0,
          "high": 3,
          "moderate": 1,
          "low": 0
        }
      }
    }
  ],
  "total": 42
}
```

### Vulnerabilities

**Scan Results:**
```bash
GET /api/scan-results/:registry/:name/:version
```

### CVE Bypasses

**List Bypasses:**
```bash
GET /api/cve-bypasses
```

**Create Bypass:**
```bash
POST /api/cve-bypass
Content-Type: application/json

{
  "type": "cve",
  "target": "CVE-2023-12345",
  "reason": "Accepted risk",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

### Statistics

**Get Stats:**
```bash
GET /api/stats
```

**Response:**
```json
{
  "total_packages": 42,
  "total_size": 12458960,
  "total_downloads": 156,
  "scanned_packages": 42,
  "vulnerable_packages": 8
}
```

### Health Check

```bash
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "components": {
    "cache": {"status": "healthy"},
    "metadata": {"status": "healthy"},
    "scanner": {"status": "healthy"},
    "storage": {"status": "healthy"}
  }
}
```

---

## 🏗️ Architecture

### Design Principles

1. **Security-First** - Vulnerable packages blocked on first download
2. **Interface-Driven** - All major components use Go interfaces
3. **No Fallbacks** - No backdoors that bypass security scanning
4. **Race-Condition Free** - Wait loop ensures all scanners complete
5. **Production-Ready** - Comprehensive testing, metrics, and resilience

### Component Overview

```
┌─────────────────────────────────────────────────────┐
│              Web Dashboard (Vue 3 + TS)             │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│           Fiber Web Server (HTTP + WebSocket)       │
└─────────────────────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌─────────┐    ┌─────────┐    ┌─────────┐
    │   npm   │    │  PyPI   │    │   Go    │
    │  Proxy  │    │  Proxy  │    │  Proxy  │
    └─────────┘    └─────────┘    └─────────┘
          │              │              │
          └──────────────┼──────────────┘
                         ▼
              ┌─────────────────────┐
              │   Cache Manager     │
              │  (Scan Wait Loop)   │
              └─────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌─────────┐    ┌─────────┐    ┌─────────┐
    │ Storage │    │Metadata │    │ Scanner │
    │ Backend │    │  Store  │    │ Manager │
    └─────────┘    └─────────┘    └─────────┘
                                        │
                          ┌─────────────┼─────────────┐
                          ▼             ▼             ▼
                     ┌────────┐   ┌────────┐   ┌────────┐
                     │ Trivy  │   │  OSV   │   │ Grype  │
                     └────────┘   └────────┘   └────────┘
```

### Security Scanning Flow

1. **Package Downloaded** → Stored in cache
2. **Scanner Manager Triggered** → Spawns background scan
3. **Wait Loop Started** → Request waits for scan completion
4. **All Scanners Run** → Trivy, OSV, Grype, npm-audit, etc. (parallel)
5. **Poll SecurityScanned Flag** → Check every 100ms (max 30 seconds)
6. **All Scanners Complete** → Consolidated result saved, flag set to true
7. **Check Vulnerabilities** → Evaluate against thresholds
8. **Serve or Block** → 200 OK or 403 Forbidden

### Project Structure

```
gohoarder/
├── cmd/gohoarder/          # Main application entry point
├── pkg/
│   ├── app/                # HTTP handlers and application setup
│   ├── cache/              # Cache manager with scan wait loop
│   ├── config/             # Configuration management
│   ├── errors/             # Structured error handling
│   ├── metadata/           # Metadata storage (SQLite, PostgreSQL)
│   ├── network/            # HTTP client with resilience patterns
│   ├── proxy/              # Registry-specific proxy handlers
│   │   ├── npm/
│   │   ├── pypi/
│   │   └── goproxy/
│   ├── scanner/            # Vulnerability scanning
│   │   ├── trivy/
│   │   ├── osv/
│   │   ├── grype/
│   │   ├── govulncheck/
│   │   ├── npmaudit/
│   │   ├── pipaudit/
│   │   └── ghsa/
│   └── storage/            # Storage backends
│       ├── filesystem/
│       ├── s3/
│       └── smb/
├── frontend/               # Vue 3 dashboard
│   ├── src/
│   │   ├── components/
│   │   ├── views/
│   │   └── stores/
│   └── package.json
├── data/                   # Runtime data (gitignored)
│   ├── storage/            # Cached packages
│   └── gohoarder.db        # SQLite metadata
└── config.yaml             # Configuration file
```

---

## 🛠️ Development

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Test package downloads
make test-packages
```

### Building

```bash
# Build backend only
make build

# Build frontend only
make build-frontend

# Build everything
make build-all

# Clean build artifacts
make clean
```

### Development Mode

```bash
# Run backend + frontend together
make run

# Run backend only
./bin/gohoarder serve

# Run frontend dev server (separate terminal)
cd frontend
pnpm dev
```

---

## 🐛 Troubleshooting

### Common Issues

#### Packages not showing in dashboard

**Cause:** Go packages downloaded with `,direct` fallback bypass the proxy.

**Solution:** Remove `,direct` from GOPROXY:
```bash
export GOPROXY="http://localhost:8080/go"  # ✅ Correct
# NOT: export GOPROXY="http://localhost:8080/go,direct"  # ❌ Wrong
```

#### 403 Forbidden for clean packages

**Cause:** Security scanner detected a vulnerability, or threshold is too strict.

**Solution:**
1. Check scan results: `curl http://localhost:8080/api/scan-results/npm/package/version`
2. Adjust thresholds in `config.yaml`
3. Create CVE bypass if needed

#### Scanners not working

**Cause:** Scanner binaries not in PATH.

**Solution:**
```bash
# Check scanner status
curl http://localhost:8080/health | jq '.components.scanner'

# Install missing scanners
brew install trivy grype
go install golang.org/x/vuln/cmd/govulncheck@latest
```

#### npm/pip using local cache

**Cause:** Package managers cache packages locally.

**Solution:**
```bash
# Clear caches
npm cache clean --force
pip cache purge
go clean -modcache
```

### Logs

```bash
# View logs (if running with make run)
tail -f /tmp/gohoarder.log

# Adjust log level in config.yaml
logging:
  level: "debug"  # debug, info, warn, error
```

---

## 🎯 Package Manager Behavior Comparison

| Package Manager | Fallback? | Security Enforced? | Blocked Package Result |
|----------------|-----------|-------------------|----------------------|
| **Go** (with `,direct`) | ✅ Yes | ❌ **BYPASSED** | Downloads anyway 🔴 |
| **Go** (without fallback) | ❌ No | ✅ **ENFORCED** | 403 Forbidden ✅ |
| **pip** | ❌ No | ✅ **ENFORCED** | 403 Forbidden ✅ |
| **npm** | ❌ No | ✅ **ENFORCED** | 403 Forbidden ✅ |
| **pnpm** | ❌ No | ✅ **ENFORCED** | 403 Forbidden ✅ |
| **yarn** | ❌ No | ✅ **ENFORCED** | 403 Forbidden ✅ |

**⚠️ KEY TAKEAWAY:** Never use fallback mechanisms (like Go's `,direct`) as they completely bypass security scanning!

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `make test`
5. Commit: `git commit -m 'Add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Development Guidelines

- Write tests for all new code
- Follow Go best practices and `gofmt` formatting
- Use meaningful variable and function names
- Add comments for complex logic
- Maintain security-first principles

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanning
- [Grype](https://github.com/anchore/grype) - Vulnerability scanning
- [OSV](https://osv.dev) - Open Source Vulnerabilities database
- [Fiber](https://github.com/gofiber/fiber) - Web framework
- [Vue 3](https://vuejs.org) - Frontend framework
- [shadcn-vue](https://www.shadcn-vue.com/) - UI components
- Inspired by [Harbor](https://github.com/goharbor/harbor) proxy architecture

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/lukaszraczylo/gohoarder/issues)
- **Discussions:** [GitHub Discussions](https://github.com/lukaszraczylo/gohoarder/discussions)
- **Documentation:** [Wiki](https://github.com/lukaszraczylo/gohoarder/wiki)

---

**Made with ❤️ for the developer community**

**Security First. Performance Second. Everything Else After.**
