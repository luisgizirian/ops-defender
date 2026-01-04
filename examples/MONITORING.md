# Ops Defender Monitoring and Visualization Guide

This guide covers all monitoring and visualization options available for Ops Defender.

## Quick Start

Ops Defender provides multiple endpoints for monitoring:

- **`/metrics`** - Prometheus/OpenMetrics format for Prometheus, Grafana, etc.
- **`/stats`** - JSON statistics snapshot
- **`/report`** - Detailed JSON report with historical data
- **`/timeseries`** - Time-series data in JSON format
- **`/events`** - Real-time Server-Sent Events (SSE) stream

## Monitoring Options

### 1. Prometheus + Grafana (Recommended for Production)

**Why:** Industry standard, powerful visualization, alerting, and long-term storage.

**Setup:**

1. **Configure Prometheus** (see `examples/prometheus.yml`):
   ```yaml
   scrape_configs:
     - job_name: 'ops-defender'
       scrape_interval: 5s
       static_configs:
         - targets: ['localhost:8080']
       metrics_path: '/metrics'
   ```

2. **Start Prometheus**:
   ```bash
   prometheus --config.file=prometheus.yml
   ```

3. **Import Grafana Dashboard** (see `examples/grafana-dashboard.json`):
   - Open Grafana → Dashboards → Import
   - Upload `grafana-dashboard.json`
   - Select Prometheus data source

**Available Metrics:**
- `ops_defender_total_requests` - Total requests processed
- `ops_defender_blocked_requests` - Blocked requests count
- `ops_defender_active_ips` - Currently tracked IPs
- `ops_defender_blocked_ips` - Currently blocked IPs
- `ops_defender_dropped_ips` - IPs dropped due to memory limits
- `ops_defender_memory_usage_percent` - Memory utilization
- `ops_defender_block_rate_percent` - Block rate percentage

**Example Queries:**
```promql
# Block rate over time
rate(ops_defender_blocked_requests[5m]) / rate(ops_defender_total_requests[5m]) * 100

# Memory pressure
ops_defender_memory_usage_percent > 80

# Request rate
rate(ops_defender_total_requests[1m])
```

### 2. Azure Application Insights

**Why:** Deep integration with Azure, automatic correlation, AI-powered analytics.

**Setup:**

1. Create Application Insights resource in Azure Portal
2. Get instrumentation key
3. Configure Ops Defender:
   ```bash
   export APPINSIGHTS_ENABLED=true
   export APPINSIGHTS_INSTRUMENTATION_KEY=your-key
   ```

See `examples/AZURE-INSIGHTS.md` for detailed guide including:
- Custom KQL queries
- Alert configuration
- Dashboard creation
- Cost optimization

### 3. Real-Time Dashboard (SSE)

**Why:** Live updates without polling, perfect for NOC displays.

**Setup:**

Create a simple HTML dashboard:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Ops Defender Live Monitor</title>
    <script>
        const eventSource = new EventSource('http://localhost:8080/events');
        
        eventSource.onmessage = function(event) {
            const data = JSON.parse(event.data);
            console.log('Event:', data);
            
            if (data.type === 'stats_update') {
                document.getElementById('activeIPs').textContent = data.data.active_ips;
                document.getElementById('blockedIPs').textContent = data.data.blocked_ips;
                document.getElementById('totalRequests').textContent = data.data.total_requests;
            }
            
            if (data.type === 'ip_blocked') {
                const log = document.getElementById('blockLog');
                log.innerHTML = `<div>🚫 Blocked ${data.data.ip} - ${data.data.reason}</div>` + log.innerHTML;
            }
        };
    </script>
</head>
<body>
    <h1>Ops Defender Live Monitor</h1>
    <div>
        <h2>Stats</h2>
        <p>Active IPs: <span id="activeIPs">-</span></p>
        <p>Blocked IPs: <span id="blockedIPs">-</span></p>
        <p>Total Requests: <span id="totalRequests">-</span></p>
    </div>
    <div>
        <h2>Block Events</h2>
        <div id="blockLog"></div>
    </div>
</body>
</html>
```

**Features:**
- Updates every 2 seconds
- Real-time block event notifications
- Zero polling overhead

### 4. Time-Series API

**Why:** Custom dashboards, data export, integration with other tools.

**Endpoint:** `GET /timeseries?period=24&interval=1h`

**Parameters:**
- `period` - Hours of historical data (default: 24)
- `interval` - Bucket size: `5m`, `15m`, `30m`, `1h`, `6h`, `1d` (default: `1h`)

**Example Response:**
```json
{
  "start_time": "2025-12-20T16:00:00Z",
  "end_time": "2025-12-21T16:00:00Z",
  "interval": "1h",
  "time_series": [
    {
      "metric": "block_events",
      "data_points": [
        {"timestamp": "2025-12-20T16:00:00Z", "value": 5},
        {"timestamp": "2025-12-20T17:00:00Z", "value": 12}
      ]
    }
  ]
}
```

**Use Cases:**
- Custom charts in web applications
- Data export for compliance reports
- Integration with BI tools (Tableau, Power BI)
- ML model training on attack patterns

### 5. JSON Stats API (Original)

**Why:** Simple, no dependencies, works everywhere.

**Endpoint:** `GET /stats`

**Example:**
```bash
curl http://localhost:8080/stats | jq
```

**Response:**
```json
{
  "total_ips": 150,
  "blocked_ips": 12,
  "active_ips": 138,
  "total_requests": 45000,
  "blocked_requests": 234,
  "memory_usage": {
    "tracked_ips": 138,
    "max_tracked_ips": 10000,
    "dropped_ips": 0,
    "usage_percent": 1.38
  }
}
```

## Monitoring Comparison

| Feature | Prometheus | App Insights | SSE Stream | Time-Series API | Stats API |
|---------|-----------|--------------|------------|----------------|-----------|
| Real-time | ✅ | ⚠️ (2-5min delay) | ✅ | ❌ | ❌ |
| Historical | ✅ | ✅ | ❌ | ✅ (limited) | ❌ |
| Alerting | ✅ | ✅ | ❌ | ❌ | ❌ |
| Cost | Free | Paid | Free | Free | Free |
| Setup | Medium | Medium | Easy | Easy | Easy |
| Cloud | Any | Azure | Any | Any | Any |

## Alerting Strategies

### Prometheus Alerts

Create `alerts.yml`:
```yaml
groups:
  - name: ops_defender
    interval: 30s
    rules:
      - alert: HighBlockRate
        expr: ops_defender_block_rate_percent > 20
        for: 5m
        annotations:
          summary: "High block rate detected"
          description: "Block rate is {{ $value }}%"
      
      - alert: MemoryPressure
        expr: ops_defender_memory_usage_percent > 85
        for: 2m
        annotations:
          summary: "Memory usage high"
          description: "Memory at {{ $value }}%"
```

### Azure Alerts

See `examples/AZURE-INSIGHTS.md` for KQL-based alerts.

### Custom Webhook Alerts

Monitor the `/events` stream and trigger webhooks:

```python
import requests
from sseclient import SSEClient

messages = SSEClient('http://localhost:8080/events')
for msg in messages:
    data = json.loads(msg.data)
    if data['type'] == 'ip_blocked':
        # Send to Slack, Teams, PagerDuty, etc.
        requests.post('https://hooks.slack.com/...', json={
            'text': f"🚫 IP {data['data']['ip']} blocked: {data['data']['reason']}"
        })
```

## Best Practices

1. **Use multiple monitoring methods**:
   - Prometheus for metrics and alerting
   - SSE stream for real-time NOC displays
   - Application Insights for correlation with app logs

2. **Set appropriate scrape intervals**:
   - Prometheus: 5-15 seconds for production
   - SSE: Already optimized at 2 seconds

3. **Configure retention**:
   - Prometheus: 15-30 days for metrics
   - Application Insights: 90 days default (configurable)

4. **Create meaningful dashboards**:
   - Overview page with key metrics
   - Detailed page with time-series
   - Alert dashboard showing active issues

5. **Monitor the monitor**:
   - Alert on metrics endpoint failures
   - Track telemetry delivery success rate

## Troubleshooting

**Metrics endpoint returns no data:**
- Ensure service is running: `curl http://localhost:8080/health`
- Check for firewall blocking port 8080

**Prometheus not scraping:**
- Verify target in Prometheus UI: `http://prometheus:9090/targets`
- Check network connectivity: `curl http://ops-defender:8080/metrics`

**SSE connection drops:**
- Normal behavior if no data flows for 30s
- Client should reconnect automatically
- Check proxy/load balancer timeout settings

**Application Insights events missing:**
- Wait 2-5 minutes for ingestion
- Verify instrumentation key is correct
- Check outbound HTTPS connectivity to Azure

## Next Steps

1. **Set up Prometheus and Grafana** using the example configurations
2. **Import the Grafana dashboard** for instant visualization
3. **Configure alerts** for high block rate and memory pressure
4. **Enable Application Insights** if using Azure
5. **Create a live dashboard** using SSE for your NOC

## Example: Full Monitoring Stack

```yaml
# docker-compose.yml
version: '3.8'

services:
  ops-defender:
    image: ops-defender
    ports:
      - "8080:8080"
    environment:
      - REDIS_URL=redis://redis:6379/0
      - APPINSIGHTS_ENABLED=true
      - APPINSIGHTS_INSTRUMENTATION_KEY=${INSTRUMENTATION_KEY}
  
  redis:
    image: redis:7-alpine
  
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
  
  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

Start everything:
```bash
docker-compose up -d
```

Access:
- Ops Defender: http://localhost:8080
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)
