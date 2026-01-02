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

## Configuration

The following table lists the configurable parameters and their default values.

### Global Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.domain` | Base domain for the deployment | `gohoarder.local` |
| `global.imagePullSecrets` | Image pull secrets | `[]` |

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
| `image.frontend.repository` | Frontend image repository | `ghcr.io/lukaszraczylo/gohoarder-frontend` |
| `image.frontend.tag` | Frontend image tag | `latest` |
| `image.scanner.repository` | Scanner image repository | `ghcr.io/lukaszraczylo/gohoarder-scanner` |
| `image.scanner.tag` | Scanner image tag | `latest` |

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
