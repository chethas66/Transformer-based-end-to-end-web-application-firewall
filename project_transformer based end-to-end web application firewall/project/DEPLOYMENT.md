# Deployment Guide - Transformer-Based WAF

## System Requirements

### Hardware
- **Minimum**: 2 CPU cores, 4GB RAM
- **Recommended**: 4 CPU cores, 8GB RAM
- **With GPU**: CUDA-compatible GPU with 2GB+ VRAM (optional, for faster inference)

### Software
- Python 3.10 or higher
- Node.js 18+ (for frontend dashboard)
- PostgreSQL database (provided by Supabase)

## Quick Deployment

### Step 1: Clone and Setup

```bash
git clone <repository>
cd <project-directory>
```

### Step 2: Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Required: Supabase Configuration
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key

# WAF Configuration
WAF_MODE=shadow          # Options: shadow, active, learning
WAF_THRESHOLD=0.95       # Confidence threshold for blocking
WAF_MAX_LATENCY_MS=10    # Target inference latency

# Optional: Redis for caching
REDIS_URL=redis://localhost:6379/0

# Model paths (default values shown)
MODEL_PATH=./models/waf_model.onnx
TOKENIZER_PATH=./models/tokenizer
```

### Step 3: Run Setup Script

```bash
chmod +x setup.sh
./setup.sh
```

This will:
1. Install Python dependencies
2. Train the Transformer model
3. Export to ONNX format
4. Run component tests

### Step 4: Start the API

```bash
python waf_api.py
```

The API will be available at `http://localhost:8000`

### Step 5: Start the Dashboard (Optional)

```bash
npm install
npm run dev
```

Dashboard available at `http://localhost:5173`

## Production Deployment

### Using Docker

Create `Dockerfile`:

```dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python waf_training.py

EXPOSE 8000

CMD ["python", "waf_api.py"]
```

Build and run:

```bash
docker build -t transformer-waf .
docker run -p 8000:8000 --env-file .env transformer-waf
```

### Using Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  waf-api:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env
    volumes:
      - ./models:/app/models
    restart: unless-stopped

  waf-dashboard:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    ports:
      - "80:80"
    depends_on:
      - waf-api
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped
```

Start services:

```bash
docker-compose up -d
```

### Deployment Checklist

#### Phase 1: Shadow Mode (Week 1-2)
- [ ] Deploy with `WAF_MODE=shadow`
- [ ] Monitor all traffic without blocking
- [ ] Collect baseline metrics
- [ ] Review flagged requests daily
- [ ] Adjust thresholds based on false positives

#### Phase 2: Learning Mode (Week 3-4)
- [ ] Switch to `WAF_MODE=learning`
- [ ] Enable feedback submission
- [ ] Collect human-verified labels
- [ ] Retrain model with real data
- [ ] Validate false positive rate < 5%

#### Phase 3: Active Mode (Production)
- [ ] Switch to `WAF_MODE=active`
- [ ] Enable real-time blocking
- [ ] Set up alerting for high attack volumes
- [ ] Monitor latency metrics continuously
- [ ] Implement log rotation

## Integration with Existing Infrastructure

### Nginx Reverse Proxy

Add to your nginx config:

```nginx
upstream waf_backend {
    server localhost:8000;
}

server {
    listen 80;
    server_name yourdomain.com;

    location /api/ {
        # Forward to WAF for analysis
        proxy_pass http://waf_backend/api/waf/analyze;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # ... rest of your config
}
```

### Apache Integration

```apache
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so

<VirtualHost *:80>
    ServerName yourdomain.com

    ProxyPass /api/ http://localhost:8000/api/waf/analyze/
    ProxyPassReverse /api/ http://localhost:8000/api/waf/analyze/

    # ... rest of your config
</VirtualHost>
```

### Application-Level Integration (Python)

```python
import httpx

async def check_request_with_waf(request):
    waf_url = "http://localhost:8000/api/waf/analyze"

    payload = {
        "method": request.method,
        "path": request.url.path,
        "headers": dict(request.headers),
        "body": await request.body(),
        "source_ip": request.client.host
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(waf_url, json=payload)
        result = response.json()

        if result["action"] == "block":
            return {"error": "Request blocked by WAF"}, 403

    return None
```

## Monitoring and Alerting

### Prometheus Metrics

Add to `waf_api.py`:

```python
from prometheus_client import Counter, Histogram, generate_latest

requests_total = Counter('waf_requests_total', 'Total requests')
requests_blocked = Counter('waf_requests_blocked', 'Blocked requests')
inference_latency = Histogram('waf_inference_latency_seconds', 'Inference latency')

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### Grafana Dashboard

Import the provided `grafana-dashboard.json` for pre-built visualizations:
- Request volume over time
- Block/flag rates
- Inference latency percentiles
- Top attack patterns
- Geographic distribution of attacks

### Alert Rules

Example Prometheus alert rules:

```yaml
groups:
  - name: waf_alerts
    rules:
      - alert: HighAttackVolume
        expr: rate(waf_requests_blocked[5m]) > 100
        for: 5m
        annotations:
          summary: "High attack volume detected"

      - alert: HighLatency
        expr: waf_inference_latency_seconds{quantile="0.95"} > 0.01
        for: 5m
        annotations:
          summary: "WAF inference latency is high"
```

## Performance Optimization

### 1. Enable Redis Caching

```bash
# Install Redis
apt-get install redis-server

# Update .env
REDIS_URL=redis://localhost:6379/0
```

Expected improvement: 30-40% cache hit rate, reducing latency by 60%

### 2. GPU Acceleration (Optional)

```bash
# Install CUDA toolkit
# Install ONNX Runtime GPU
pip install onnxruntime-gpu

# Update waf_inference.py
engine = ONNXInferenceEngine(
    model_path=model_path,
    tokenizer_path=tokenizer_path,
    use_gpu=True  # Enable GPU
)
```

Expected improvement: 3-5x faster inference

### 3. Horizontal Scaling

Deploy multiple WAF API instances behind a load balancer:

```yaml
# docker-compose.scale.yml
services:
  waf-api:
    deploy:
      replicas: 4
    # ... rest of config
```

```bash
docker-compose -f docker-compose.scale.yml up --scale waf-api=4
```

### 4. Database Optimization

Add indexes for frequent queries:

```sql
CREATE INDEX idx_waf_requests_timestamp ON waf_requests(timestamp DESC);
CREATE INDEX idx_waf_requests_action ON waf_requests(action_taken);
CREATE INDEX idx_waf_requests_source_ip ON waf_requests(source_ip);
```

## Maintenance

### Daily Tasks
- Review dashboard for anomalies
- Check system health metrics
- Validate latency targets

### Weekly Tasks
- Export and analyze false positive reports
- Update attack pattern signatures
- Review top attacking IPs and consider IP blocking

### Monthly Tasks
- Retrain model with latest data
- Update dependencies
- Security audit and penetration testing
- Capacity planning review

### Model Retraining

```bash
# Export training data with feedback
python waf_monitoring.py --export training_data.csv

# Retrain model
python waf_training.py --data training_data.csv

# Test new model
python waf_inference.py --benchmark

# Deploy if metrics improve
cp models/waf_transformer/model.onnx /production/models/
systemctl restart waf-api
```

## Troubleshooting

### High False Positive Rate

**Symptoms**: Legitimate requests being blocked/flagged

**Solutions**:
1. Lower the `WAF_THRESHOLD` in `.env`
2. Review and submit feedback for false positives
3. Retrain model with corrected labels
4. Add whitelist rules for known-good patterns

### High Latency

**Symptoms**: Inference time > 10ms consistently

**Solutions**:
1. Enable Redis caching
2. Use GPU acceleration
3. Reduce `max_length` in model config
4. Scale horizontally with load balancer
5. Optimize ONNX model with quantization

### Memory Issues

**Symptoms**: Out of memory errors

**Solutions**:
1. Reduce cache size in `CachedInferenceEngine`
2. Lower batch size in inference
3. Use model quantization (FP16 instead of FP32)
4. Increase system RAM

### Database Connection Errors

**Symptoms**: Supabase connection failures

**Solutions**:
1. Verify `.env` credentials
2. Check network connectivity
3. Implement connection pooling
4. Add retry logic with exponential backoff

## Security Considerations

### API Authentication

Add JWT authentication to WAF API:

```python
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

security = HTTPBearer()

async def verify_token(credentials = Depends(security)):
    # Implement JWT verification
    pass

@app.post("/api/waf/analyze", dependencies=[Depends(verify_token)])
async def analyze_request(...):
    # ... existing code
```

### Rate Limiting

Implement rate limiting to prevent abuse:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/waf/analyze")
@limiter.limit("100/minute")
async def analyze_request(...):
    # ... existing code
```

### TLS/SSL

Always use HTTPS in production:

```bash
# Generate SSL certificate (Let's Encrypt)
certbot --nginx -d yourdomain.com

# Or use reverse proxy with SSL termination
```

## Support and Updates

### Getting Help
1. Review README.md for architecture details
2. Check logs in `./logs/` directory
3. Run diagnostic: `python waf_api.py --health-check`
4. Review Supabase dashboard for database issues

### Staying Updated
1. Monitor model performance metrics weekly
2. Update attack signatures monthly
3. Retrain model quarterly with production data
4. Review security advisories for dependencies

### Backup Strategy
```bash
# Backup model files
tar -czf waf_backup_$(date +%Y%m%d).tar.gz models/

# Backup database (Supabase handles this automatically)
# Export critical data periodically
python waf_monitoring.py --export-all backup_$(date +%Y%m%d).csv
```

## Cost Optimization

### Supabase
- Use connection pooling
- Implement data retention policies
- Archive old logs to cold storage

### Compute
- Use spot instances for training
- Scale down during low-traffic periods
- Enable auto-scaling based on request volume

### Expected Costs (Monthly)
- Supabase (Pro): $25
- AWS t3.medium (API): $30
- Redis Cache: $15
- Total: ~$70/month for 10M requests
