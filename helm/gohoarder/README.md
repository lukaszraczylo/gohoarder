# GoHoarder Helm Chart

A universal package cache proxy supporting npm, PyPI, and Go modules with integrated security scanning.

## Features

- **Multi-Registry Support**: Proxy for npm, PyPI, and Go modules
- **Security Scanning**: Integrated vulnerability scanning with multiple scanners
- **Flexible Storage**: Support for filesystem, S3, and SMB storage backends
- **Metadata Storage**: SQLite or PostgreSQL for metadata
- **Auto-Configuration**: Generates configuration from Helm values
- **Production Ready**: Includes health checks, resource limits, and security contexts

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PV provisioner support in the underlying infrastructure (for persistent storage)

## Installation

### Add Helm Repository

```bash
helm repo add gohoarder https://lukaszraczylo.github.io/gohoarder
helm repo update
```

### Install Chart

```bash
# Install with default values
helm install gohoarder gohoarder/gohoarder

# Install with custom values
helm install gohoarder gohoarder/gohoarder -f values.yaml

# Install in a specific namespace
helm install gohoarder gohoarder/gohoarder -n gohoarder --create-namespace
```

## Quick Start Examples

### Minimal Installation

```bash
helm install gohoarder gohoarder/gohoarder \
  --set global.domain=example.com \
  --set ingress.enabled=true
```

### With Security Scanning

```bash
helm install gohoarder gohoarder/gohoarder \
  --set security.enabled=true \
  --set security.scanners.trivy.enabled=true \
  --set security.scanners.osv.enabled=true
```

### With S3 Storage

```bash
helm install gohoarder gohoarder/gohoarder \
  --set storage.backend=s3 \
  --set storage.s3.bucket=my-bucket \
  --set storage.s3.region=us-east-1 \
  --set storage.s3.accessKeyId=AKIAIOSFODNN7EXAMPLE \
  --set storage.s3.secretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### With Private Container Registry

If using images from a private registry, create an image pull secret and reference it:

```bash
# Create a Docker registry secret
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=<your-username> \
  --docker-password=<your-token> \
  --docker-email=<your-email> \
  -n gohoarder

# Install with the secret
helm install gohoarder gohoarder/gohoarder \
  --set global.imagePullSecrets[0].name=ghcr-secret \
  -n gohoarder
```

Or using a values file to reference existing secrets:

```yaml
global:
  imagePullSecrets:
    - name: ghcr-secret
    - name: dockerhub-secret  # Multiple secrets supported
```

**Auto-create secrets** (chart will create them for you):

```yaml
imageCredentials:
  ghcr-secret:
    registry: ghcr.io
    username: myusername
    password: mytoken
    email: myemail@example.com

global:
  imagePullSecrets:
    - name: ghcr-secret
```

> **Note**: Storing credentials in values files is less secure than creating secrets manually. Consider using external secret management solutions like Sealed Secrets or External Secrets Operator for production.

## Configuration Methods

GoHoarder supports two configuration methods that can be used together:

### 1. ConfigMap (Default)

The chart automatically generates a `config.yaml` from Helm values and mounts it as a ConfigMap. This is the default approach and works out of the box.

### 2. Environment Variables

You can override any configuration using environment variables with the format `GOHOARDER_<CONFIG_KEY>` where dots are replaced with underscores.

**Example using values file:**

```yaml
server:
  env:
    - name: GOHOARDER_STORAGE_BACKEND
      value: "s3"
    - name: GOHOARDER_STORAGE_S3_BUCKET
      value: "my-bucket"
    # Reference secrets for sensitive data
    - name: GOHOARDER_STORAGE_S3_SECRET_ACCESS_KEY
      valueFrom:
        secretKeyRef:
          name: aws-credentials
          key: secret-access-key
    - name: GOHOARDER_METADATA_POSTGRESQL_PASSWORD
      valueFrom:
        secretKeyRef:
          name: postgres-secret
          key: password
```

**Example using command line:**

```bash
helm install gohoarder gohoarder/gohoarder \
  --set server.env[0].name=GOHOARDER_STORAGE_BACKEND \
  --set server.env[0].value=s3 \
  --set server.env[1].name=GOHOARDER_LOGGING_LEVEL \
  --set server.env[1].value=debug
```

**Benefits of environment variables:**
- Better integration with Kubernetes secrets
- Override specific values without modifying ConfigMap
- Support for secret references (no plain-text passwords)
- Compatible with external secret management (External Secrets Operator, Sealed Secrets)

**Common environment variable mappings:**

| Config Path | Environment Variable |
|-------------|---------------------|
| `storage.backend` | `GOHOARDER_STORAGE_BACKEND` |
| `storage.s3.bucket` | `GOHOARDER_STORAGE_S3_BUCKET` |
| `storage.s3.region` | `GOHOARDER_STORAGE_S3_REGION` |
| `storage.s3.access_key_id` | `GOHOARDER_STORAGE_S3_ACCESS_KEY_ID` |
| `storage.s3.secret_access_key` | `GOHOARDER_STORAGE_S3_SECRET_ACCESS_KEY` |
| `metadata.backend` | `GOHOARDER_METADATA_BACKEND` |
| `metadata.postgresql.host` | `GOHOARDER_METADATA_POSTGRESQL_HOST` |
| `metadata.postgresql.password` | `GOHOARDER_METADATA_POSTGRESQL_PASSWORD` |
| `security.enabled` | `GOHOARDER_SECURITY_ENABLED` |
| `security.scanners.trivy.enabled` | `GOHOARDER_SECURITY_SCANNERS_TRIVY_ENABLED` |
| `logging.level` | `GOHOARDER_LOGGING_LEVEL` |
| `logging.format` | `GOHOARDER_LOGGING_FORMAT` |

## Configuration Reference

The following table lists the configurable parameters and their default values.

### Global Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nameOverride` | Override the name of the chart | `""` |
| `fullnameOverride` | Override the full name of the chart | `""` |
| `global.domain` | Base domain for the deployment | `gohoarder.local` |
| `global.imagePullSecrets` | Image pull secrets (reference existing) | `[]` |
| `imageCredentials` | Auto-create image pull secrets from credentials | `{}` |

### Replica Count

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount.server` | Number of server replicas | `1` |
| `replicaCount.frontend` | Number of frontend replicas | `1` |
| `replicaCount.scanner` | Number of scanner replicas | `1` |

### Image Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.server.repository` | Server image repository | `ghcr.io/lukaszraczylo/gohoarder-server` |
| `image.server.tag` | Server image tag | `latest` |
| `image.server.pullPolicy` | Server image pull policy | `IfNotPresent` |
| `image.frontend.repository` | Frontend image repository | `ghcr.io/lukaszraczylo/gohoarder-frontend` |
| `image.frontend.tag` | Frontend image tag | `latest` |
| `image.frontend.pullPolicy` | Frontend image pull policy | `IfNotPresent` |
| `image.scanner.repository` | Scanner image repository | `ghcr.io/lukaszraczylo/gohoarder-scanner` |
| `image.scanner.tag` | Scanner image tag | `latest` |
| `image.scanner.pullPolicy` | Scanner image pull policy | `IfNotPresent` |

### Environment Variables

| Parameter | Description | Default |
|-----------|-------------|---------|
| `server.env` | Additional environment variables for server | `[]` |
| `frontend.env` | Additional environment variables for frontend | `[]` |
| `scanner.env` | Additional environment variables for scanner | `[]` |

### Storage Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `storage.backend` | Storage backend (filesystem, s3, smb) | `filesystem` |
| `storage.filesystem.storageClass` | Storage class for PVC | `""` |
| `storage.filesystem.size` | Storage size | `100Gi` |
| `storage.filesystem.useHostPath` | Use hostPath instead of PVC | `false` |
| `storage.filesystem.hostPath` | Host path for storage | `/var/lib/gohoarder` |
| `storage.s3.endpoint` | S3 endpoint | `s3.amazonaws.com` |
| `storage.s3.bucket` | S3 bucket name | `gohoarder-cache` |
| `storage.s3.region` | S3 region | `us-east-1` |

### Metadata Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metadata.backend` | Metadata backend (sqlite, postgresql) | `sqlite` |
| `metadata.sqlite.persistence.enabled` | Enable persistence for SQLite | `true` |
| `metadata.sqlite.persistence.size` | SQLite storage size | `10Gi` |
| `metadata.postgresql.host` | PostgreSQL host | `localhost` |
| `metadata.postgresql.database` | PostgreSQL database | `gohoarder` |

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security.enabled` | Enable security scanning | `false` |
| `security.blockOnSeverity` | Block packages on severity | `high` |
| `security.scanners.trivy.enabled` | Enable Trivy scanner | `false` |
| `security.scanners.osv.enabled` | Enable OSV scanner | `false` |
| `security.scanners.grype.enabled` | Enable Grype scanner | `false` |

### Authentication

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auth.enabled` | Enable authentication | `true` |
| `auth.adminApiKey` | Admin API key (auto-generated if empty) | `""` |
| `auth.existingSecret` | Use existing secret for admin key | `""` |

### Ingress

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `nginx` |
| `ingress.frontend.enabled` | Enable frontend ingress | `true` |
| `ingress.frontend.host` | Frontend hostname | `gohoarder.local` |
| `ingress.frontend.tls.enabled` | Enable TLS for frontend | `false` |

## High Availability & Scaling

### Running Multiple Server Replicas

GoHoarder can run with multiple server replicas for high availability and load distribution, but the configuration must be set correctly to avoid data inconsistency.

#### ✅ Compatible Configurations (Safe for Multiple Replicas)

**Storage:**
- ✅ **S3** - Fully compatible, recommended for production HA setups
- ✅ **SMB** - Compatible, shared network storage
- ✅ **Filesystem with RWX** - Compatible when using ReadWriteMany storage classes
  - ✅ Examples: Longhorn RWX, NFS, CephFS, GlusterFS, Azure Files
  - ✅ Uses atomic rename operations for safe concurrent writes
  - ✅ Packages are static/immutable - perfect for shared storage
  - ❌ Not compatible with local storage or ReadWriteOnce (RWO) PVCs

**Metadata:**
- ✅ **PostgreSQL** - Fully compatible, handles concurrent writes, recommended for HA
- ⚠️ **SQLite** - Limited compatibility:
  - Uses WAL mode which supports concurrent reads
  - Multiple writers can cause lock contention
  - Works but may have performance issues under high concurrency
  - Only if using shared storage (NFS, etc.)

#### 📋 Recommended HA Configurations

**Option 1: Cloud Storage (S3)**

Best for cloud deployments, object storage:

```yaml
replicaCount:
  server: 3

storage:
  backend: s3
  s3:
    endpoint: s3.amazonaws.com
    region: us-east-1
    bucket: gohoarder-cache

metadata:
  backend: postgresql
  postgresql:
    host: postgres.database.svc.cluster.local
    database: gohoarder

podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

**Option 2: Shared Filesystem (Longhorn/NFS)**

Best for on-premises or self-hosted Kubernetes:

```yaml
replicaCount:
  server: 3

storage:
  backend: filesystem
  filesystem:
    # Use RWX storage class (Longhorn, NFS, CephFS, etc.)
    storageClass: "longhorn"  # or "nfs-client", "cephfs", etc.
    size: "500Gi"
    accessMode: "ReadWriteMany"  # RWX - Critical for multiple replicas!

metadata:
  backend: postgresql  # Or SQLite with RWX storage
  postgresql:
    host: postgres.database.svc.cluster.local
    database: gohoarder

podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

**Why Filesystem with RWX Works:**
- Packages are immutable once cached (static files)
- Filesystem backend uses atomic `rename()` operations
- Race condition safe: If two replicas cache same package, one wins
- Performance: Local filesystem often faster than object storage for reads

#### ⚠️ What Won't Work with Multiple Replicas

**Filesystem storage with local volumes:**
```yaml
# ❌ DON'T DO THIS with multiple replicas
storage:
  backend: filesystem
  filesystem:
    useHostPath: true  # Each replica gets different storage
```

**SQLite with local storage:**
```yaml
# ⚠️ AVOID with multiple replicas
metadata:
  backend: sqlite
  sqlite:
    persistence:
      enabled: true  # Each replica gets its own database
```

#### 🔄 How It Works

**Request Deduplication:**
- Single replica: Uses `singleflight` to prevent duplicate upstream fetches
- Multiple replicas: Each replica may fetch the same package independently
- **Mitigation**: Package metadata in shared database prevents duplicate downloads once one replica completes

**Cache Consistency:**
- Storage backend (S3/SMB) ensures all replicas see the same cached packages
- Metadata database ensures consistent package information across replicas
- First replica to cache a package wins, others will use the cached version

**Session Affinity:**
- Not required - GoHoarder is stateless
- Load balancer can distribute requests randomly

**Scanner Replicas:**
- Scanner can run as a single replica or multiple
- If multiple scanners enabled, they share work through the metadata database
- Package scans are deduplicated via database state

#### 🔬 Technical Details: Concurrent Write Safety

**Filesystem Backend with RWX Storage:**

The filesystem storage backend uses a **temp-file + atomic rename** pattern:

```go
1. Write package to: /cache/npm/package@1.0.0.tmp
2. Calculate checksums (MD5, SHA256)
3. Atomic rename: .tmp → /cache/npm/package@1.0.0
```

**Why this is safe for concurrent writes:**
- `os.Rename()` is atomic on POSIX filesystems
- If two replicas cache the same package simultaneously:
  - Both write to separate `.tmp` files
  - Both attempt atomic rename
  - One succeeds, one gets "file exists" error
  - Result: Same file content, no corruption

**Package immutability:**
- Packages are versioned and immutable (npm/pypi/go semantics)
- Same package@version always has identical content
- Concurrent writes produce identical results
- No risk of partial/corrupted files

**Quota tracking:**
- Per-process mutex (minor inaccuracy across replicas)
- Conservative: May undercount slightly
- Not critical for operation

## Uninstallation

```bash
helm uninstall gohoarder -n gohoarder
```

## Upgrading

```bash
helm upgrade gohoarder gohoarder/gohoarder -f values.yaml
```

## Package Manager Configuration

After installation, configure your package managers to use GoHoarder:

### NPM

```bash
npm config set registry http://<gohoarder-url>/npm/
```

### Go

```bash
export GOPROXY=http://<gohoarder-url>/go,direct
```

### PyPI

```bash
pip config set global.index-url http://<gohoarder-url>/pypi/simple
```

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -n gohoarder
kubectl logs -n gohoarder <pod-name>
```

### Verify Configuration

```bash
kubectl get configmap -n gohoarder <release-name>-gohoarder-config -o yaml
```

### Get Admin API Key

```bash
kubectl get secret -n gohoarder <release-name>-gohoarder-auth -o jsonpath='{.data.admin-api-key}' | base64 -d
```

## Contributing

Contributions are welcome! Please visit [GitHub](https://github.com/lukaszraczylo/gohoarder) for more information.

## License

See the [LICENSE](https://github.com/lukaszraczylo/gohoarder/blob/main/LICENSE) file.
