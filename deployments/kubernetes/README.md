# Kubernetes Deployment Guide

This directory contains Kubernetes manifests for deploying GoHoarder in a production environment.

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   Kubernetes Pod                     │
│  ┌────────────────────────────────────────────────┐ │
│  │            GoHoarder Container                 │ │
│  │  ┌──────────────────────────────────────────┐ │ │
│  │  │  Pattern-Based Credential Store          │ │ │
│  │  │  ├─ github.com/myorg/* → token_A         │ │ │
│  │  │  ├─ gitlab.com/team/* → token_B          │ │ │
│  │  │  └─ * → fallback_token                   │ │ │
│  │  └──────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────┘ │
│                                                       │
│  Mounted Volumes:                                    │
│  • config.yaml (ConfigMap)                           │
│  • git-credentials.json (Secret)                     │
│  • /var/lib/gohoarder/cache (PVC)                    │
│  • /var/lib/gohoarder (PVC for metadata DB)          │
└─────────────────────────────────────────────────────┘
```

## Files

- `secret-git-credentials.yaml` - Git credentials for private repositories
- `configmap-config.yaml` - Application configuration
- `pvc.yaml` - Persistent volume claims for cache and metadata
- `deployment.yaml` - Main application deployment
- `service.yaml` - Service and optional ingress configuration

## Quick Start

### 1. Configure Git Credentials

Edit `secret-git-credentials.yaml` and replace the placeholder tokens with your actual tokens:

```yaml
{
  "credentials": [
    {
      "pattern": "github.com/mycompany/*",
      "host": "github.com",
      "username": "oauth2",
      "token": "ghp_YOUR_ACTUAL_TOKEN_HERE"
    }
  ]
}
```

**Pattern Matching Examples:**
- `github.com/myorg/*` - Matches all repos under myorg
- `github.com/myorg/specific-repo` - Matches only specific-repo
- `gitlab.com/backend-team/*` - Matches all GitLab repos under backend-team
- `*` - Fallback pattern (matches everything)

**Credential Priority:**
1. Most specific pattern wins (longest match)
2. Fallback credential (`"fallback": true`)
3. System git config (if no matches)

### 2. Customize Configuration

Edit `configmap-config.yaml` to adjust:
- Cache size (`max_size_bytes`)
- Security scanning settings
- Upstream registries
- Logging level

### 3. Deploy to Kubernetes

```bash
# Create namespace (optional)
kubectl create namespace gohoarder

# Apply manifests
kubectl apply -f pvc.yaml
kubectl apply -f secret-git-credentials.yaml
kubectl apply -f configmap-config.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Verify deployment
kubectl get pods -l app=gohoarder
kubectl logs -l app=gohoarder -f
```

### 4. Configure Go Client

```bash
# Set GOPROXY environment variable
export GOPROXY=http://gohoarder.default.svc.cluster.local:8080/go,direct

# Or in your Dockerfile
ENV GOPROXY=http://gohoarder.default.svc.cluster.local:8080/go,direct

# Test with a private module
go get github.com/mycompany/private-module@latest
```

## Advanced Configuration

### Using External Secrets Operator (ESO)

If you're using External Secrets Operator, uncomment the ExternalSecret section in `secret-git-credentials.yaml` and configure your SecretStore:

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

### Storage Classes

For production deployments, specify appropriate storage classes:

```yaml
# In pvc.yaml
storageClassName: fast-ssd  # For cache (needs fast I/O)
storageClassName: standard  # For metadata (smaller, less critical)
```

### Horizontal Pod Autoscaling

```bash
kubectl autoscale deployment gohoarder \
  --cpu-percent=70 \
  --min=2 \
  --max=10
```

### Monitoring

Check health and metrics:

```bash
# Health check
kubectl port-forward svc/gohoarder 8080:8080
curl http://localhost:8080/health

# Metrics (Prometheus format)
curl http://localhost:8080/metrics
```

## Multi-Organization Setup

### Example 1: Multiple GitHub Organizations

```json
{
  "credentials": [
    {
      "pattern": "github.com/company-frontend/*",
      "host": "github.com",
      "username": "oauth2",
      "token": "ghp_frontend_team_token"
    },
    {
      "pattern": "github.com/company-backend/*",
      "host": "github.com",
      "username": "oauth2",
      "token": "ghp_backend_team_token"
    },
    {
      "pattern": "github.com/company-infra/*",
      "host": "github.com",
      "username": "oauth2",
      "token": "ghp_infra_team_token"
    },
    {
      "pattern": "*",
      "host": "*",
      "username": "oauth2",
      "token": "ghp_readonly_default_token",
      "fallback": true
    }
  ]
}
```

### Example 2: GitHub + GitLab

```json
{
  "credentials": [
    {
      "pattern": "github.com/myorg/*",
      "host": "github.com",
      "username": "oauth2",
      "token": "ghp_github_token"
    },
    {
      "pattern": "gitlab.com/myteam/*",
      "host": "gitlab.com",
      "username": "oauth2",
      "token": "glpat_gitlab_token"
    }
  ]
}
```

### Example 3: Enterprise GitHub

```json
{
  "credentials": [
    {
      "pattern": "github.enterprise.com/engineering/*",
      "host": "github.enterprise.com",
      "username": "oauth2",
      "token": "ghp_enterprise_token"
    }
  ]
}
```

## Security Best Practices

1. **Token Scoping**: Use fine-grained personal access tokens with minimal permissions
   - GitHub: Only `repo` scope needed for private repos
   - GitLab: Only `read_repository` scope needed

2. **Secret Rotation**: Regularly rotate tokens
   ```bash
   # Update secret
   kubectl create secret generic gohoarder-git-credentials \
     --from-file=credentials.json=./new-credentials.json \
     --dry-run=client -o yaml | kubectl apply -f -

   # Restart pods to pick up new credentials
   kubectl rollout restart deployment gohoarder
   ```

3. **RBAC**: Limit who can read the secret
   ```bash
   kubectl create role secret-reader \
     --verb=get,list \
     --resource=secrets \
     --resource-name=gohoarder-git-credentials
   ```

4. **Audit Logging**: Enable Kubernetes audit logging for secret access

5. **Network Policies**: Restrict which pods can access GoHoarder
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: allow-from-build-namespace
   spec:
     podSelector:
       matchLabels:
         app: gohoarder
     ingress:
     - from:
       - namespaceSelector:
           matchLabels:
             name: build-namespace
   ```

## Troubleshooting

### Check if credentials are loaded

```bash
# Check logs for credential loading
kubectl logs -l app=gohoarder | grep "Loaded git credentials"

# Expected output:
# {"level":"info","file":"/etc/gohoarder/git-credentials.json","credentials":3,"message":"Loaded git credentials from file"}
# {"level":"debug","pattern":"github.com/myorg/*","host":"github.com","message":"Registered credential pattern"}
```

### Test credential pattern matching

```bash
# Enable debug logging
kubectl set env deployment/gohoarder LOG_LEVEL=debug

# Watch logs during a go get request
kubectl logs -l app=gohoarder -f
```

### Common Issues

**Issue**: `git clone failed: authentication required`
- **Cause**: No matching credential pattern
- **Solution**: Check pattern syntax in credentials.json, ensure it matches the module path

**Issue**: `Failed to load git credentials`
- **Cause**: Secret not mounted or JSON syntax error
- **Solution**: Verify secret exists and JSON is valid
  ```bash
  kubectl get secret gohoarder-git-credentials
  kubectl get secret gohoarder-git-credentials -o jsonpath='{.data.credentials\.json}' | base64 -d | jq .
  ```

**Issue**: Module fetch slow
- **Cause**: Git clone timeout or large repository
- **Solution**: Increase timeout in config.yaml or use upstream proxy for public modules

## Performance Tuning

### Cache Configuration

```yaml
cache:
  max_size_bytes: 107374182400  # 100GB for large organizations
  default_ttl: 168h              # 7 days for stable modules
```

### Resource Limits

For high-traffic deployments:

```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "8Gi"
    cpu: "4000m"
```

### Replicas

Run multiple replicas for high availability:

```yaml
spec:
  replicas: 3
```

## Backup and Recovery

### Backup Metadata Database

```bash
# Backup SQLite database
kubectl exec -it deployment/gohoarder -- \
  sqlite3 /var/lib/gohoarder/gohoarder.db ".backup /tmp/backup.db"

kubectl cp gohoarder-pod:/tmp/backup.db ./gohoarder-backup-$(date +%Y%m%d).db
```

### Restore from Backup

```bash
kubectl cp ./gohoarder-backup-20260102.db gohoarder-pod:/var/lib/gohoarder/gohoarder.db
kubectl rollout restart deployment gohoarder
```

## Integration Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'

    - name: Configure GOPROXY
      run: |
        echo "GOPROXY=http://gohoarder.company.internal:8080/go,direct" >> $GITHUB_ENV

    - name: Build
      run: go build ./...
```

### Dockerfile

```dockerfile
FROM golang:1.21-alpine

# Configure proxy
ENV GOPROXY=http://gohoarder.default.svc.cluster.local:8080/go,direct
ENV GONOPROXY=none
ENV GONOSUMDB=github.com/yourcompany

WORKDIR /app
COPY . .
RUN go build -o myapp ./cmd/myapp

CMD ["/app/myapp"]
```

## Support

For issues or questions:
- Check logs: `kubectl logs -l app=gohoarder`
- Enable debug logging: Set `logging.level: debug` in ConfigMap
- Review credential patterns in Secret
