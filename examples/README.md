# Ops Defender - Examples

This directory contains configuration examples, dashboards, integration guides, and how-to examples for Ops Defender's extension system.

## Quick Links

- **[MONITORING.md](MONITORING.md)** - Complete monitoring guide with all integration options
- **[AZURE-INSIGHTS.md](AZURE-INSIGHTS.md)** - Azure Application Insights integration guide
- **[EXTENSION-EXAMPLE.md](EXTENSION-EXAMPLE.md)** - PreHandler extension guide
- **[grafana-dashboard.json](grafana-dashboard.json)** - Grafana dashboard template
- **[prometheus.yml](prometheus.yml)** - Prometheus scrape configuration
- **[live-dashboard.html](live-dashboard.html)** - Real-time HTML dashboard using SSE

## Extension Examples

| Directory | Extension Point | What It Demonstrates |
|-----------|----------------|----------------------|
| [`external-extension/`](external-extension/) | PreHandler | IP allowlist — bypass defense for trusted IPs |
| [`sql-injection-detector/`](sql-injection-detector/) | PatternAnalyzer | Custom SQL injection pattern detection |
| [`posthandler-example/`](posthandler-example/) | PostHandler | Override block decisions (emergency access, health checks) |
| [`stats-provider-example/`](stats-provider-example/) | StatsDataProvider | Expose custom metrics in `/stats`, `/report`, `/timeseries`, `/metrics`, `/events` |

## What's Available

### 1. Prometheus + Grafana Integration

**Files:**
- `prometheus.yml` - Prometheus configuration
- `grafana-dashboard.json` - Pre-built dashboard

**Setup:**
1. Add Ops Defender to your Prometheus scrape targets
2. Import the Grafana dashboard JSON
3. Enjoy instant visualization

**Metrics:**
- Request counts (total, blocked)
- IP tracking (active, blocked, dropped)
- Memory usage and block rate
- All metrics use `ops_defender_` prefix

### 2. Azure Application Insights

**Files:**
- `AZURE-INSIGHTS.md` - Complete integration guide

**Features:**
- Automatic event batching
- Custom KQL queries
- Alert configuration examples
- Cost optimization tips

**Events Tracked:**
- IP block events with reason and URI
- Defender stats (every 30 seconds)
- Custom properties for filtering

### 3. Real-Time Dashboards

**Files:**
- `live-dashboard.html` - Ready-to-use HTML dashboard

**Features:**
- Server-Sent Events (SSE) streaming
- Updates every 2 seconds
- Real-time block notifications
- Zero polling overhead
- Works in any modern browser

**Usage:**
```bash
# Start Ops Defender
./ops-defender

# Open live-dashboard.html in browser
# Or serve it:
python -m http.server 8000
# Navigate to http://localhost:8000/live-dashboard.html
```

### 4. Time-Series Data API

**Endpoint:** `GET /timeseries?period=24&interval=1h`

**Use Cases:**
- Custom dashboards
- Data export for reporting
- Integration with BI tools
- ML model training

**Example:**
```bash
# Get last 24 hours in 1-hour intervals
curl "http://localhost:8080/timeseries?period=24&interval=1h" | jq

# Get last week in 6-hour intervals
curl "http://localhost:8080/timeseries?period=168&interval=6h" | jq
```

## Integration Scenarios

### Scenario 1: Small Deployment (Single Instance)

**Recommended:**
- Use built-in `/stats` endpoint for quick checks
- Set up Prometheus + Grafana for visualization
- Enable email reports for daily summaries

**Configuration:**
```bash
# No special monitoring config needed
# Just set up Prometheus scraping
```

### Scenario 2: Medium Deployment (Multiple Instances)

**Recommended:**
- Prometheus + Grafana for aggregated metrics
- Real-time SSE dashboard for NOC
- Optional: Application Insights for correlation

**Configuration:**
```bash
# Enable Application Insights
APPINSIGHTS_ENABLED=true
APPINSIGHTS_INSTRUMENTATION_KEY=your-key
```

### Scenario 3: Enterprise (Cloud-Native)

**Recommended:**
- Azure Application Insights for full observability
- Grafana for custom dashboards
- Alerts via Azure Monitor
- SSE stream for critical events

**Configuration:**
```bash
# Full monitoring stack
APPINSIGHTS_ENABLED=true
APPINSIGHTS_INSTRUMENTATION_KEY=your-key
REDIS_URL=redis://redis-cluster:6379/0
```

## Testing Monitoring

### 1. Test Prometheus Endpoint
```bash
curl http://localhost:8080/metrics
```

### 2. Test SSE Stream
```bash
# In terminal (will stream forever)
curl -N http://localhost:8080/events

# Or use the HTML dashboard
open live-dashboard.html
```

### 3. Test Time-Series
```bash
# Get block events over last hour
curl "http://localhost:8080/timeseries?period=1&interval=5m" | jq '.time_series[0]'
```

### 4. Generate Test Traffic
```bash
# Trigger a block event
for i in {1..6}; do
  curl -H "X-Real-IP: 10.0.0.1" \
       -H "X-Original-URI: /../etc/passwd" \
       http://localhost:8080/check
done

# Check stats
curl http://localhost:8080/stats | jq
```

## Common Prometheus Queries

```promql
# Request rate (req/sec)
rate(ops_defender_total_requests[1m])

# Block rate percentage
(ops_defender_blocked_requests / ops_defender_total_requests) * 100

# Memory usage alert
ops_defender_memory_usage_percent > 85

# Active IPs trend
ops_defender_active_ips
```

## Common Azure Insights Queries (KQL)

```kql
// All blocks in last 24h
customEvents
| where name == "IPBlocked"
| where timestamp > ago(24h)
| project timestamp, ip=customDimensions.ip, reason=customDimensions.reason

// Block rate over time
customEvents
| where name == "DefenderStats"
| project timestamp, block_rate=todouble(customMeasurements.block_rate)
| render timechart

// Top attacking IPs
customEvents
| where name == "IPBlocked"
| summarize count() by tostring(customDimensions.ip)
| top 10 by count_
```

## Troubleshooting

**Metrics endpoint returns empty:**
- Ensure Ops Defender is processing requests
- Check that service started successfully
- Verify network connectivity

**SSE stream disconnects:**
- Normal if no data for 30+ seconds
- Client should auto-reconnect
- Check proxy/LB timeout settings

**Application Insights events missing:**
- Wait 2-5 minutes for ingestion
- Verify instrumentation key
- Check outbound HTTPS to Azure

**Grafana shows no data:**
- Verify Prometheus is scraping successfully
- Check Prometheus targets page
- Ensure data source configured correctly

## Next Steps

1. Start with the [MONITORING.md](MONITORING.md) guide
2. Choose your monitoring stack (Prometheus, Azure, or both)
3. Import the Grafana dashboard or use the live HTML dashboard
4. Set up alerts based on your requirements
5. Review metrics regularly to tune block thresholds

## Support

For monitoring setup issues or questions:
- **GitHub Issues**: https://github.com/luisgizirian/ops-defender/issues
- Check [MONITORING.md](MONITORING.md) for detailed troubleshooting
- Review [AZURE-INSIGHTS.md](AZURE-INSIGHTS.md) for Azure-specific issues
- See main [README.md](../README.md) for general documentation
- Tag monitoring-related issues with `monitoring` label
