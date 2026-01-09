# Fix for 500 Internal Server Error with Blocked IPs

## Problem

When a blocked IP makes a request, Nginx returns **500 Internal Server Error** instead of the expected block response.

## Root Cause

**This was an issue with Nginx `auth_request` behavior, NOT an Ops Defender bug.**

### Nginx auth_request Status Code Handling

From the [Nginx documentation](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html):

- **200-299**: Access allowed, continue to backend
- **401/403**: Access denied, return that status code to client
- **404 and other codes**: **Treated as an error, returns 500**

Ops Defender was returning **404 Not Found** for blocked IPs, which Nginx interpreted as an error condition and converted to 500.

## Solution

Changed Ops Defender to return **403 Forbidden** for blocked requests instead of 404.

### Code Changes

**File: `internal/defender/defender.go`**

```go
// Before (INCORRECT):
func (d *Defender) handleBlockedRequest(w http.ResponseWriter, ip, uri, source string) {
    if d.simulationMode {
        log.Printf("[SIMULATION] Would block IP %s...", ip)
        w.WriteHeader(http.StatusOK)
    } else {
        w.WriteHeader(http.StatusNotFound)  // ❌ 404 causes 500 in Nginx
    }
}

// After (CORRECT):
func (d *Defender) handleBlockedRequest(w http.ResponseWriter, ip, uri, source string) {
    if d.simulationMode {
        log.Printf("[SIMULATION] Would block IP %s...", ip)
        w.WriteHeader(http.StatusOK)
    } else {
        w.WriteHeader(http.StatusForbidden)  // ✅ 403 works with auth_request
    }
}
```

### Updated HTTP API Contract

**Ops Defender `/check` endpoint now returns:**
- **200 OK** = Allow request (proxy continues to backend)
- **403 Forbidden** = Block request (malicious IP detected)

### Nginx Behavior with Fixed Code

```
Client (blocked IP) → Nginx → Ops Defender /check
                                     ↓
                                 403 Forbidden
                                     ↓
                     Nginx ← auth_request sees 403
                                     ↓
              Client ← 403 Forbidden (correct blocking)
```

## Files Updated

1. **`internal/defender/defender.go`**
   - Changed `StatusNotFound` to `StatusForbidden` in `handleBlockedRequest()`
   - Added comment explaining Nginx compatibility

2. **`nginx.conf.example`**
   - Added documentation about status code behavior
   - Clarified 403 is used for blocks

3. **`scripts/test-attacks.sh`**
   - Updated all test assertions from expecting 404 to expecting 403

4. **`README.md`**
   - Updated all documentation references from 404 to 403
   - Updated API documentation
   - Updated troubleshooting guides
   - Updated example flows

5. **`.github/copilot-instructions.md`**
   - Updated internal development guidelines
   - Updated debugging examples
   - Updated HTTP API contract documentation

## Testing

Run the updated test suite to verify:

```bash
# Build with changes
./scripts/build.sh

# Run ops-defender
./ops-defender

# In another terminal, run attack tests
./scripts/test-attacks.sh

# Expected results:
# - All malicious requests return 403 (not 404)
# - Tests should pass
# - No 500 errors
```

### Manual Testing with Nginx

```bash
# Send malicious request through Nginx
curl -v http://your-nginx-server/../../../etc/passwd

# Send 5+ requests to trigger analysis threshold
for i in {1..6}; do
  curl -v http://your-nginx-server/../../etc/passwd
  sleep 0.5
done

# Expected: 403 Forbidden (NOT 500 Internal Server Error)
```

## Why 403 Instead of 404?

**403 Forbidden** is the semantically correct status code because:

1. **HTTP Spec Compliance**: 
   - 403 = "The server understood the request but refuses to authorize it"
   - 404 = "The requested resource could not be found"

2. **Nginx auth_request Compatibility**:
   - 403 is explicitly supported by `auth_request`
   - 404 is treated as a subrequest error

3. **Security Best Practice**:
   - 403 clearly indicates intentional blocking
   - Distinguishes from missing resources (404)

4. **Client Clarity**:
   - Blocked clients see 403 Forbidden (clear message)
   - Not confused with 500 errors (server issues)

## Migration Notes

If you're upgrading from an earlier version:

1. **No Nginx config changes required** - Nginx handles 403 properly by default
2. **Update monitoring/alerts** if you were watching for 404 responses
3. **Update tests** if you have custom integration tests expecting 404
4. **No breaking changes** to `/check` endpoint behavior - still accepts same headers

## Validation Checklist

- [ ] Build succeeds: `./scripts/build.sh`
- [ ] Unit tests pass: `go test ./...`
- [ ] Attack tests pass: `./scripts/test-attacks.sh`
- [ ] Blocked IPs return 403 (not 500)
- [ ] Legitimate requests return 200
- [ ] Nginx properly blocks on 403 responses
- [ ] No 500 errors in Nginx logs
- [ ] Live monitor shows blocks with 403 status

## Related Documentation

- [Nginx auth_request Module Documentation](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
- [HTTP 403 Forbidden Specification](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/403)
- [RFC 7231 - HTTP Semantics](https://tools.ietf.org/html/rfc7231#section-6.5.3)
