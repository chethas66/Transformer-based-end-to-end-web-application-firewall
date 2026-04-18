# Quick Start Guide

Get the Transformer-based WAF running in 5 minutes!

## Prerequisites

- Python 3.10+
- Node.js 18+
- Supabase account (free tier is fine)

## Step 1: Get Supabase Credentials

1. Go to [supabase.com](https://supabase.com)
2. Create a new project
3. Go to Settings → API
4. Copy your:
   - Project URL
   - Anon/Public key

## Step 2: Configure Environment

```bash
# Copy example config
cp .env.example .env

# Edit .env and add your Supabase credentials
nano .env
```

Paste your credentials:
```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key_here
```

## Step 3: Install & Train

```bash
# Make setup script executable
chmod +x setup.sh

# Run setup (installs deps + trains model)
./setup.sh
```

This takes 5-10 minutes. It will:
- Install Python packages
- Train a DistilBERT model
- Export to ONNX format
- Run tests

## Step 4: Start the API

```bash
python waf_api.py
```

You should see:
```
✅ Supabase client initialized
✅ Normalizer initialized
✅ Fast-path filter initialized
✅ Decision engine initialized (mode: shadow)
✅ ONNX inference engine loaded
✅ WAF API ready
```

API is now running at `http://localhost:8000`

## Step 5: Test It

Open a new terminal and run:

```bash
python example_client.py
```

This will:
- Test benign requests (should be allowed)
- Test malicious requests (should be blocked/flagged)
- Test polyglot attacks
- Run performance benchmark

## Step 6: View Dashboard (Optional)

```bash
# In a new terminal
npm install
npm run dev
```

Open browser to `http://localhost:5173`

You'll see:
- Real-time metrics
- Request history
- Attack statistics

## Test the API Manually

### Test a Normal Request

```bash
curl -X POST http://localhost:8000/api/waf/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "/api/users/123",
    "headers": {"user-agent": "curl"},
    "body": "",
    "source_ip": "192.168.1.100"
  }'
```

Expected response:
```json
{
  "action": "allow",
  "threat_level": "safe",
  "confidence": 0.05,
  "reasoning": "Request appears safe"
}
```

### Test a SQL Injection Attack

```bash
curl -X POST http://localhost:8000/api/waf/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "/api/users?id=1 OR 1=1--",
    "headers": {},
    "body": "",
    "source_ip": "10.0.0.50"
  }'
```

Expected response:
```json
{
  "action": "flag",  # or "block" in active mode
  "threat_level": "critical",
  "confidence": 1.0,
  "fast_path_blocked": true,
  "fast_path_rule": "SQLi:SQL_OR_TAUTOLOGY",
  "reasoning": "Blocked by fast-path filter: SQLi:SQL_OR_TAUTOLOGY"
}
```

## Understanding the Modes

### Shadow Mode (Default)
- **What it does**: Analyzes all traffic but never blocks
- **Use when**: First deployment, building baseline
- **Duration**: 1-2 weeks
- **Output**: Flags suspicious requests for review

### Learning Mode
- **What it does**: Flags suspicious requests, collects feedback
- **Use when**: After shadow mode, tuning phase
- **Duration**: 1-2 weeks
- **Output**: Training data for model improvement

### Active Mode
- **What it does**: Actively blocks malicious traffic
- **Use when**: After validation, production deployment
- **Output**: Real-time protection

### Switch Modes

```bash
curl -X POST http://localhost:8000/api/waf/config?mode=active
```

## View System Statistics

```bash
# Get current stats
curl http://localhost:8000/api/waf/stats

# Health check
curl http://localhost:8000/api/waf/health
```

## Monitor the System

```bash
python waf_monitoring.py
```

This generates a report showing:
- Total requests analyzed
- Block/flag/allow rates
- Average latency
- Top attack patterns
- Top attacking IPs

## Common Issues

### "Model files not found"

Run the training script:
```bash
python waf_training.py
```

### "Supabase connection failed"

Check your `.env` file has correct credentials:
```bash
cat .env
```

### High latency (>10ms)

Enable caching or use GPU:
```bash
# Install Redis (optional)
sudo apt-get install redis-server

# Update .env
echo "REDIS_URL=redis://localhost:6379/0" >> .env
```

## Next Steps

1. **Run in shadow mode for 1 week**
   - Let it analyze your real traffic
   - Review flagged requests daily

2. **Check false positives**
   - Look at dashboard → Requests → Flagged
   - Submit feedback for any mistakes

3. **Switch to learning mode**
   - Collect human-verified labels
   - Export and retrain model

4. **Go to active mode**
   - Enable real blocking
   - Monitor closely for first 48 hours

## Integration with Your App

### Python/FastAPI

```python
import httpx

async def check_with_waf(request):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/waf/analyze",
            json={
                "method": request.method,
                "path": str(request.url),
                "headers": dict(request.headers),
                "body": await request.body(),
                "source_ip": request.client.host
            }
        )
        result = response.json()

        if result["action"] == "block":
            raise HTTPException(403, "Request blocked by WAF")
```

### Node.js/Express

```javascript
const axios = require('axios');

async function checkWithWAF(req, res, next) {
    const response = await axios.post('http://localhost:8000/api/waf/analyze', {
        method: req.method,
        path: req.path,
        headers: req.headers,
        body: JSON.stringify(req.body),
        source_ip: req.ip
    });

    if (response.data.action === 'block') {
        return res.status(403).json({ error: 'Request blocked by WAF' });
    }

    next();
}

app.use(checkWithWAF);
```

## Documentation

- **Full documentation**: See [README.md](./README.md)
- **Deployment guide**: See [DEPLOYMENT.md](./DEPLOYMENT.md)
- **Project overview**: See [PROJECT_SUMMARY.md](./PROJECT_SUMMARY.md)

## Support

If you run into issues:

1. Check the logs in terminal where API is running
2. Review health endpoint: `curl http://localhost:8000/api/waf/health`
3. Run tests: `python example_client.py`
4. Check Supabase dashboard for database issues

## Success Indicators

After setup, you should see:

✅ API responds on port 8000
✅ Model loaded successfully
✅ Test requests return predictions
✅ Dashboard shows real-time data
✅ Latency < 10ms for most requests

---

**You're now running a production-grade ML-powered WAF!** 🎉

Start with shadow mode, monitor for a week, then gradually move to active protection.
