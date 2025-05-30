# API Reference

## Authentication Endpoints

| Endpoint | Method | Purpose | Parameters |
|----------|---------|---------|------------|
| `/oauth2/sign_in` | GET | Display sign-in page or initiate OAuth flow | `provider` (google/apple), `redirect_url` (optional) |
| `/oauth2/callback` | GET/POST | OAuth callback handler | Auto-handled by OAuth providers |
| `/oauth2/sign_out` | GET/POST | Sign out user and clear session | `redirect_url` (optional) |

## Health Check

| Endpoint | Method | Purpose |
|----------|---------|---------|
| `/` | GET | Health check and service status |

## Usage Examples

### Initiate Google OAuth
```bash
curl "http://localhost:8080/oauth2/sign_in?provider=google"
# Returns: Redirect to Google OAuth authorization URL
```

### Initiate Apple OAuth
```bash
curl "http://localhost:8080/oauth2/sign_in?provider=apple"
# Returns: Redirect to Apple OAuth authorization URL
```

### Sign In with Redirect
```bash
curl "http://localhost:8080/oauth2/sign_in?provider=google&redirect_url=https://example.com/dashboard"
# After successful auth, redirects to: https://example.com/dashboard
```

### Sign Out
```bash
curl "http://localhost:8080/oauth2/sign_out"
# Returns: Redirect to sign-in page
```

### Sign Out with Redirect
```bash
curl "http://localhost:8080/oauth2/sign_out?redirect_url=https://example.com/home"
# Returns: Redirect to: https://example.com/home
```

## Response Formats

### Success Responses
- **OAuth Initiation**: `302 Redirect` to provider authorization URL
- **Successful Authentication**: `302 Redirect` to original URL or custom redirect
- **Sign Out**: `302 Redirect` to sign-in page or custom redirect

### Error Responses
- **400 Bad Request**: Invalid provider or malformed request
- **401 Unauthorized**: Authentication failed or invalid session
- **500 Internal Server Error**: Server configuration or provider errors

## Integration Examples

### JavaScript Frontend
```javascript
// Initiate Google OAuth
window.location.href = '/oauth2/sign_in?provider=google&redirect_url=' + 
  encodeURIComponent(window.location.href);

// Check authentication status
fetch('/api/user')
  .then(response => {
    if (response.status === 401) {
      // Not authenticated, redirect to sign-in
      window.location.href = '/oauth2/sign_in?provider=google';
    }
    return response.json();
  });
```

### Reverse Proxy Integration
```nginx
# Nginx configuration example
location /protected/ {
    auth_request /auth;
    proxy_pass http://upstream-service/;
}

location = /auth {
    internal;
    proxy_pass http://vouchr:8080/oauth2/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}
```
