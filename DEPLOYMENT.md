# Deployment Guide

## Production deployment (Kubernetes)

Project Raven 0.2+ is designed for Kubernetes via the bundled Helm chart at
`deployment/helm/raven`.

### Prerequisites

| Component | Notes |
|---|---|
| Kubernetes 1.27+ | EKS / GKE / AKS / k3s all supported |
| Helm 3.14+ | `brew install helm` |
| cert-manager | TLS termination at the ingress |
| Prometheus Operator | For `ServiceMonitor` (optional) |
| External Secrets Operator | Pulls API keys from AWS Secrets Manager / Vault |
| ingress-nginx | Or any other IngressClass |

### Bootstrap secrets

Generate a strong `SECRET_KEY` and bootstrap admin password:

```bash
openssl rand -hex 32   # SECRET_KEY (>=32 chars required in prod)
openssl rand -base64 24   # BOOTSTRAP_ADMIN_PASSWORD (>=12 chars)
```

Then create the K8s Secret (or use ESO to sync from your secrets backend):

```bash
kubectl create namespace raven

kubectl -n raven create secret generic raven \
    --from-literal=SECRET_KEY="<32+ char value>" \
    --from-literal=BOOTSTRAP_ADMIN_PASSWORD="<12+ char value>" \
    --from-literal=AI_API_KEY="<provider key, optional>" \
    --from-literal=SHODAN_API_KEY="<shodan key, optional>" \
    --from-literal=DATABASE_URL="postgresql://raven:...@db:5432/raven" \
    --from-literal=REDIS_URL="redis://redis:6379/0"
```

### Install

```bash
helm install raven deployment/helm/raven \
  --namespace raven \
  --set secrets.existingSecret=raven \
  --set ingress.hosts[0].host=raven.your-domain.com \
  --set config.corsOrigins[0]=https://raven.your-domain.com
```

The chart applies:
- 3 replicas + HPA (3–12 on CPU/mem)
- PodDisruptionBudget `minAvailable: 2`
- NetworkPolicy: ingress only from `ingress-nginx` + `monitoring`, egress allowlisted to AI providers
- Non-root container (uid 10001), read-only rootfs, `drop ALL` capabilities, seccomp `RuntimeDefault`
- Probes: startup (`/health/startup`), liveness (`/health`), readiness (`/health/ready`)
- ServiceMonitor for Prometheus

### First login

The bootstrap admin is created on first startup if `BOOTSTRAP_ADMIN_PASSWORD`
is set. Log in via:

```bash
curl -X POST https://raven.your-domain.com/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"<bootstrap password>"}'
```

The response contains `access_token` (15 min) and `refresh_token` (7 days).
Treat both as secrets.

### Upgrade

```bash
helm upgrade raven deployment/helm/raven --reuse-values
```

`maxUnavailable: 0, maxSurge: 1` means upgrades roll one pod at a time with
zero downtime.

### Rollback

```bash
helm rollback raven      # one revision back
helm history raven       # list revisions
```

## Local development

For local development, use the bundled `docker-compose.yml`:

```bash
cp .env.example .env
# Generate SECRET_KEY and POSTGRES_PASSWORD in .env
docker compose up -d
```

The compose file mirrors the production K8s security topology:
non-root user, read-only rootfs, dropped capabilities, healthchecks.

---

## Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker (optional, for containerized deployment)
- NMAP (for network scanning)
- Metasploit Framework (optional, for vulnerability assessment)

## Installation

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/daemon/project-raven.git
cd project-raven
```

2. Create virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize database:
```bash
# Create database
createdb raven

# Run migrations (if using Alembic)
alembic upgrade head
```

6. Start the API server:
```bash
uvicorn raven.api.main:app --reload
```

### Docker Deployment

1. Build and start services:
```bash
docker-compose up -d
```

2. Access the API:
- API: http://localhost:8000
- Metrics: http://localhost:9090
- Dashboard: http://localhost:8000/dashboard

## Configuration

### Environment Variables

See `.env.example` for all available configuration options.

Key settings:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: Secret key for JWT tokens
- `ANOMALY_THRESHOLD`: Threshold for anomaly detection (default: 0.95)
- `ZERO_DAY_CONFIDENCE`: Confidence threshold for zero-day detection (default: 0.85)

### Model Training

Before using ML features, train the models:

```python
from raven.core.anomaly_detector import AnomalyDetector
from raven.ml.zero_day_detector import ZeroDayDetector

# Train anomaly detector
anomaly_detector = AnomalyDetector(config)
anomaly_detector.train(normal_data)

# Train zero-day detector
zero_day_detector = ZeroDayDetector(config)
zero_day_detector.train(normal_data, attack_data)

# Save models
anomaly_detector.save_model("models/anomaly_detector.pkl")
zero_day_detector.save_models("models/zero_day_detector.pkl")
```

## Security Considerations

### Production Deployment

1. **Change default secrets**: Always change the default `SECRET_KEY` in production
2. **Enable HTTPS**: Use a reverse proxy (nginx) with SSL/TLS
3. **Network isolation**: Run behind a firewall with restricted access
4. **Authentication**: Implement proper authentication for API access
5. **Audit logging**: Enable comprehensive audit logging
6. **Rate limiting**: Implement rate limiting on API endpoints

### Tool Integration

When integrating with security tools:
- **SSH**: Use key-based authentication, not passwords
- **Metasploit**: Run in isolated environment
- **NMAP**: Limit scan scope to authorized networks
- **Bash**: Implement command validation and sandboxing

## Monitoring

### Metrics

Prometheus metrics are exposed on port 9090:
- `raven_threats_detected_total`: Total threats detected
- `raven_threats_blocked_total`: Total threats blocked
- `raven_detection_duration_seconds`: Detection time distribution
- `raven_active_hypotheses`: Active threat hunting hypotheses
- `raven_system_health`: System health score

### Logging

Logs are written to `./logs/raven.log` by default. Configure log level in `.env`.

### Alerts

Critical alerts trigger registered handlers. Configure handlers in the AlertManager.

## Scaling

### Horizontal Scaling

For high-volume deployments:
1. Deploy multiple API instances behind a load balancer
2. Use Redis for shared state
3. Use PostgreSQL for persistent storage
4. Deploy workers on separate nodes for background tasks

### Performance Optimization

- Use connection pooling for database
- Implement caching for frequently accessed data
- Optimize ML model inference with batching
- Use async operations where possible

## Troubleshooting

### Common Issues

**Database connection failed**:
- Check DATABASE_URL in .env
- Ensure PostgreSQL is running
- Verify network connectivity

**ML models not loading**:
- Ensure models are trained before use
- Check MODEL_PATH configuration
- Verify file permissions

**Tool integration failures**:
- Verify tool installation (nmap, metasploit)
- Check tool configuration
- Review tool-specific logs

## Backup and Recovery

### Database Backup

```bash
pg_dump raven > backup_$(date +%Y%m%d).sql
```

### Model Backup

Models are stored in `./models/`. Regularly backup this directory.

### Configuration Backup

Backup `.env` and any configuration files.

## Support

For issues and questions:
- GitHub Issues: https://github.com/daemon/project-raven/issues
- Documentation: See ARCHITECTURE.md for system design
