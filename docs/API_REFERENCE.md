# API Reference

## Authentication Endpoints

| Endpoint | Method | Purpose | Parameters |
|----------|---------|---------|------------|
| `/auth/sign_in` | GET | Display sign-in page or initiate OAuth flow | `provider` (google/apple), `rd` (optional) |
| `/auth/oauth2/callback` | GET/POST | OAuth callback handler | Auto-handled by OAuth providers |
| `/oauth2/sign_out` | GET/POST | Sign out user and clear session | `rd` (optional) |

## Health Check

| Endpoint | Method | Purpose |
|----------|---------|---------|
| `/ping` | GET | Health check and service status |

## Usage Examples

### Initiate Google OAuth
```bash
curl "http://localhost:8080/auth/sign_in?provider=google"
# Returns: Redirect to Google OAuth authorization URL
```

### Initiate Apple OAuth
```bash
curl "http://localhost:8080/auth/sign_in?provider=apple"
# Returns: Redirect to Apple OAuth authorization URL
```

### Sign In with Redirect
```bash
curl "http://localhost:8080/auth/sign_in?provider=google&rd=https://example.com/dashboard"
# After successful auth, redirects to: https://example.com/dashboard
```

### Sign Out
```bash
curl "http://localhost:8080/oauth2/sign_out"
# Returns: Redirect to sign-in page
```

### Sign Out with Redirect
```bash
curl "http://localhost:8080/oauth2/sign_out?rd=https://example.com/home"
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
window.location.href = '/auth/sign_in?provider=google&rd=' +
  encodeURIComponent(window.location.href);

// Check authentication status
fetch('/api/user')
  .then(response => {
    if (response.status === 401) {
      // Not authenticated, redirect to sign-in
      window.location.href = '/auth/sign_in?provider=google';
    }
    return response.json();
  });
```

### Reverse Proxy Integration

Vouchrs acts as a transparent reverse proxy. Configure your load balancer or reverse proxy to route requests through Vouchrs:

```nginx
# Nginx configuration example for routing through Vouchrs
upstream vouchrs {
    server vouchrs:8080;
}

upstream backend {
    server backend:3000;
}

server {
    listen 80;
    location / {
        # All requests go through Vouchrs for authentication
        proxy_pass http://vouchrs;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
