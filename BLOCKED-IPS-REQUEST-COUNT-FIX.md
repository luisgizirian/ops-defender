# Blocked IPs Request Count Fix

## Issue
Blocked IPs in the `/stats` endpoint were always displaying `requests: 0` even when they had multiple requests before being blocked.

## Root Cause
The `/stats` endpoint only retrieved blocked IP information from `storage.GetBlockedIPs()`, which contains:
- IP address
- Reason for blocking
- BlockedAt timestamp
- ExpiresAt timestamp

However, the **request counts** are stored separately in the `d.ipTrackers` in-memory map, which was not being consulted when building the stats response.

## Solution
Modified the `GetStats()` method in `pkg/defender/defender.go` to:

1. **Capture request counts** from `ipTrackers` while holding the read lock
2. **Store counts in a map** (`ipRequestCounts`) indexed by IP address
3. **Cross-reference** this map when building the `TopIPs` list
4. **Display actual count** if available, otherwise default to 0

### Code Changes
```go
// Capture request counts from ipTrackers while holding lock
ipRequestCounts := make(map[string]int) // ip -> request count
for ip, tracker := range d.ipTrackers {
    ipRequestCounts[ip] = len(tracker.RequestLogs)
}
```

```go
// Add blocked IPs from storage with actual request counts from ipTrackers
for _, info := range blockedIPs {
    requestCount := 0
    // Check if this blocked IP still has tracker data in memory
    if count, exists := ipRequestCounts[info.IP]; exists {
        requestCount = count
    }
    
    stats.TopIPs = append(stats.TopIPs, IPStats{
        IP:        info.IP,
        Requests:  requestCount, // Now shows actual count if available in memory
        Blocked:   true,
        BlockedAt: info.BlockedAt.Format(time.RFC3339),
    })
}
```

## Expected Behavior

### Immediately After Blocking
When an IP is blocked, it exists in both:
- `storage` (blocked IPs list)
- `ipTrackers` (in-memory tracker)

**Result**: `/stats` endpoint shows the **actual request count** from `ipTrackers`

### After Cleanup (>1 hour)
When the IP tracker is cleaned up (after 1 hour of inactivity):
- IP still exists in `storage` (blocked IPs list)
- IP removed from `ipTrackers`

**Result**: `/stats` endpoint shows **0 requests** (tracker data no longer available)

This is expected behavior and documented in the code.

## Testing

### Unit Test
Added `TestDefender_GetStats_BlockedIPsShowRequestCount` which:
- Sends 3 malicious requests to trigger blocking
- Verifies the IP is blocked
- Checks `/stats` endpoint shows `requests: 3` (not 0)

### Manual Testing
Use the included `demo-fix.sh` script:
```bash
./demo-fix.sh
```

Expected output:
```
Blocked IP shows: 3 requests
✓ SUCCESS: Request count is correctly showing 3 (not 0!)
```

### Example API Response
**Before fix:**
```json
{
  "top_ips": [
    {"ip": "181.46.71.39", "requests": 0, "blocked": true}
  ]
}
```

**After fix:**
```json
{
  "top_ips": [
    {"ip": "181.46.71.39", "requests": 15, "blocked": true}
  ]
}
```

## Technical Notes

### Thread Safety
The fix maintains thread safety by:
- Capturing `ipRequestCounts` under the existing `d.mu.RLock()`
- Using a snapshot of the data (map copy) after releasing the lock
- No additional locking required

### Performance Impact
Minimal performance impact:
- Single iteration over `ipTrackers` map (already being accessed for count)
- Simple map lookup during blocked IP processing
- No additional I/O or expensive operations

### Memory Impact
Negligible:
- `ipRequestCounts` map is created per request and garbage collected immediately
- Typical size: ~40 bytes per blocked IP
- Map lifetime: duration of `GetStats()` function call only

## Files Changed
1. `pkg/defender/defender.go` - Core fix implementation
2. `pkg/defender/defender_test.go` - Unit test
3. `demo-fix.sh` - Demo script

## Related Issues
Fixes #33
