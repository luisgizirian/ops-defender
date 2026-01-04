# Azure Application Insights Integration Guide

This guide explains how to integrate Ops Defender with Azure Application Insights for monitoring and visualization.

## Configuration

Set the following environment variables:

```bash
# Enable Application Insights telemetry
APPINSIGHTS_ENABLED=true

# Your Application Insights instrumentation key
APPINSIGHTS_INSTRUMENTATION_KEY=your-instrumentation-key-here

# Optional: Custom endpoint (defaults to Azure public cloud)
# APPINSIGHTS_ENDPOINT=https://dc.services.visualstudio.com/v2/track
```

## Getting Your Instrumentation Key

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your Application Insights resource (or create a new one)
3. Go to "Properties" section
4. Copy the "Instrumentation Key"

## Telemetry Events

Ops Defender sends the following events to Application Insights:

### 1. IP Block Events
- **Event Name**: `IPBlocked`
- **Properties**:
  - `ip`: Blocked IP address
  - `reason`: Reason for blocking (e.g., "Suspicious URL pattern detected")
  - `uri`: The suspicious URI that triggered the block
- **Metrics**:
  - `request_count`: Number of requests from this IP

### 2. Defender Stats
- **Event Name**: `DefenderStats`
- **Metrics**:
  - `active_ips`: Current number of actively tracked IPs
  - `blocked_ips`: Current number of blocked IPs
  - `total_requests`: Total requests processed
  - `blocked_requests`: Total blocked requests
  - `block_rate`: Percentage of requests blocked

## Viewing Data in Application Insights

### Custom Queries (KQL)

**View all block events in the last 24 hours:**
```kql
customEvents
| where name == "IPBlocked"
| where timestamp > ago(24h)
| project timestamp, ip=customDimensions.ip, reason=customDimensions.reason, uri=customDimensions.uri
| order by timestamp desc
```

**Block rate over time:**
```kql
customEvents
| where name == "DefenderStats"
| where timestamp > ago(24h)
| project timestamp, block_rate=todouble(customMeasurements.block_rate)
| render timechart
```

**Top blocked IPs:**
```kql
customEvents
| where name == "IPBlocked"
| where timestamp > ago(24h)
| summarize count() by tostring(customDimensions.ip)
| top 10 by count_
| render barchart
```

**Block reasons distribution:**
```kql
customEvents
| where name == "IPBlocked"
| where timestamp > ago(7d)
| summarize count() by tostring(customDimensions.reason)
| render piechart
```

### Create Alerts

1. Go to your Application Insights resource
2. Click "Alerts" → "New alert rule"
3. Example alert conditions:

**Alert on high block rate:**
- **Condition**: Custom log search
- **Query**:
  ```kql
  customEvents
  | where name == "DefenderStats"
  | where customMeasurements.block_rate > 20
  ```
- **Alert logic**: Number of results > 0
- **Evaluation frequency**: 5 minutes

**Alert on multiple blocks from same IP:**
- **Condition**: Custom log search
- **Query**:
  ```kql
  customEvents
  | where name == "IPBlocked"
  | where timestamp > ago(1h)
  | summarize count() by tostring(customDimensions.ip)
  | where count_ > 5
  ```

### Create Dashboard

1. Go to Application Insights → "Dashboards"
2. Click "New dashboard"
3. Add tiles for:
   - Total blocked IPs (metric)
   - Block rate over time (chart)
   - Top blocked IPs (table)
   - Block reasons (pie chart)

## Integration with Azure Monitor

Application Insights is part of Azure Monitor, so you can:

1. **Create workbooks**: Custom interactive reports
2. **Set up action groups**: Send notifications via email, SMS, webhook
3. **Export data**: To Log Analytics workspace for long-term storage
4. **Integrate with Logic Apps**: Automate responses to security events

## Best Practices

1. **Monitor telemetry costs**: Each event counts against your Application Insights quota
2. **Set sampling rate**: For high-volume deployments, consider sampling to reduce costs
3. **Use alerts wisely**: Don't over-alert; focus on actionable events
4. **Regular reviews**: Check dashboards weekly to identify attack trends
5. **Correlation IDs**: Use Application Insights features to correlate defender events with application logs

## Troubleshooting

**Events not appearing:**
- Verify `APPINSIGHTS_INSTRUMENTATION_KEY` is correct
- Check Ops Defender logs for telemetry errors
- Ensure outbound HTTPS traffic to Azure is allowed
- Wait 2-5 minutes for events to appear in Azure (ingestion delay)

**High costs:**
- Review sampling configuration
- Consider filtering less critical events
- Use retention policies to manage data storage

## Example: Running with Application Insights

```bash
docker run -d \
  -p 8080:8080 \
  -e APPINSIGHTS_ENABLED=true \
  -e APPINSIGHTS_INSTRUMENTATION_KEY=your-key \
  -e REDIS_URL=redis://redis:6379/0 \
  ops-defender
```
