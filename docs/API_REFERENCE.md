# API Reference

## Authentication Endpoints

| Endpoint | Method | Purpose | Parameters |
|----------|---------|---------|------------|
| `/auth/sign_in` | GET | Display sign-in page or initiate OAuth flow | `provider` (google/apple), `rd` (optional) |
| `/auth/oauth2/callback` | GET/POST | OAuth callback handler | Auto-handled by OAuth providers |
| `/auth/oauth2/sign_out` | GET/POST | Sign out user and clear session | `rd` (optional) |
| `/auth/userinfo` | GET | Get user data from encrypted cookie (JSON) | None |
| `/auth/debug` | GET | Debug endpoint with session and user data | Requires `OAUTH_DEBUG_ENABLED=true` |

## Passkey Endpoints

| Endpoint | Method | Purpose | Parameters |
|----------|---------|---------|------------|
| `/auth/passkey/register/start` | POST | Start passkey registration | `name`, `email` (JSON body) |
| `/auth/passkey/register/complete` | POST | Complete passkey registration | WebAuthn credential response (JSON body) |
| `/auth/passkey/auth/start` | POST | Start passkey authentication | Empty JSON body for usernameless auth |
| `/auth/passkey/auth/complete` | POST | Complete passkey authentication | WebAuthn credential response (JSON body) |

## Static Files

| Endpoint | Method | Purpose |
|----------|---------|---------|
| `/auth/static/{filename}` | GET | Serve static files (HTML, CSS, JS, images) |

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
curl "http://localhost:8080/auth/oauth2/sign_out"
# Returns: Redirect to sign-in page
```

### Sign Out with Redirect
```bash
curl "http://localhost:8080/auth/oauth2/sign_out?rd=https://example.com/home"
# Returns: Redirect to: https://example.com/home
```

### Get User Information
```bash
curl "http://localhost:8080/auth/userinfo"
# Returns: JSON with user data from encrypted cookie
```

### Debug Endpoint (requires OAUTH_DEBUG_ENABLED=true)
```bash
curl "http://localhost:8080/auth/debug"
# Returns: JSON with session and debug information
```

### Passkey Registration
```bash
# Start registration
curl -X POST "http://localhost:8080/auth/passkey/register/start" \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'

# Complete registration (after WebAuthn ceremony)
curl -X POST "http://localhost:8080/auth/passkey/register/complete" \
  -H "Content-Type: application/json" \
  -d '{"credential_response": {...}, "registration_state": "..."}'
```

### Passkey Authentication
```bash
# Start authentication (usernameless)
curl -X POST "http://localhost:8080/auth/passkey/auth/start" \
  -H "Content-Type: application/json" \
  -d '{}'

# Complete authentication (after WebAuthn ceremony)
curl -X POST "http://localhost:8080/auth/passkey/auth/complete" \
  -H "Content-Type: application/json" \
  -d '{"credential_response": {...}, "authentication_state": "..."}'
```

## Response Formats

### Success Responses
- **OAuth Initiation**: `302 Redirect` to provider authorization URL
- **Successful Authentication**: `302 Redirect` to original URL or custom redirect
- **Sign Out**: `302 Redirect` to sign-in page or custom redirect
- **User Info**: `200 OK` with JSON user data
- **Debug Info**: `200 OK` with JSON session and debug data
- **Passkey Operations**: `200 OK` with JSON response containing WebAuthn options or success confirmation
- **Health Check**: `200 OK` with JSON health status

### Error Responses
- **400 Bad Request**: Invalid provider, malformed request, or missing required parameters
- **401 Unauthorized**: Authentication failed, invalid session, or missing debug permissions
- **404 Not Found**: Passkey not found or invalid endpoint
- **500 Internal Server Error**: Server configuration, provider errors, or passkey service errors

## Proxy Endpoints

All requests to paths not starting with `/auth` or `/ping` are automatically proxied to the configured upstream service after authentication validation.

| Pattern | Method | Purpose |
|---------|---------|---------|
| `/*` | ALL | Proxy to upstream service with authentication validation |

**Examples:**
- `GET /api/users` → Proxied to `{UPSTREAM_URL}/api/users`
- `POST /api/data` → Proxied to `{UPSTREAM_URL}/api/data`
- `PUT /dashboard` → Proxied to `{UPSTREAM_URL}/dashboard`

**Authentication Flow:**
1. Request is intercepted by Vouchrs
2. Session cookie is validated
3. If authenticated: Request is forwarded to upstream with user context
4. If not authenticated: Browser requests are redirected to `/auth/sign_in`, API requests receive 401

## Integration Examples

### JavaScript Frontend
```javascript
// Initiate Google OAuth
window.location.href = '/auth/sign_in?provider=google&rd=' +
  encodeURIComponent(window.location.href);

// Check authentication status
fetch('/auth/userinfo')
  .then(response => {
    if (response.status === 401) {
      // Not authenticated, redirect to sign-in
      window.location.href = '/auth/sign_in?provider=google';
    }
    return response.json();
  })
  .then(userData => {
    console.log('User:', userData);
  });

// Passkey authentication
async function authenticateWithPasskey() {
  try {
    // Start authentication
    const options = await fetch('/auth/passkey/auth/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    }).then(r => r.json());

    // Use WebAuthn API (simplified)
    const credential = await navigator.credentials.get({
      publicKey: options.request_options.publicKey
    });

    // Complete authentication
    const result = await fetch('/auth/passkey/auth/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential_response: credential,
        authentication_state: options.authentication_state
      })
    }).then(r => r.json());

    // Redirect on success
    window.location.href = result.redirect_url || '/';
  } catch (error) {
    console.error('Passkey authentication failed:', error);
  }
}
```

### Reverse Proxy Integration

Vouchrs acts as a transparent reverse proxy. Configure your load balancer or reverse proxy to route requests through Vouchrs:

```nginx
# Nginx configuration example for routing through Vouchrs
upstream vouchrs {
    server vouchrs:8080;
}

server {
    listen 80;
    server_name your-domain.com;

    location / {
        # All requests go through Vouchrs for authentication
        proxy_pass http://vouchrs;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Important: Preserve original URI for proper routing
        proxy_set_header X-Original-URI $request_uri;
    }
}
```

**Docker Compose Example:**
```yaml
version: '3.8'
services:
  vouchrs:
    image: ghcr.io/vouchrs/vouchrs:latest
    ports:
      - "8080:8080"
    environment:
      - UPSTREAM_URL=http://backend:3000
      - SESSION_SECRET=your-secret-key
      - REDIRECT_BASE_URL=https://your-domain.com
    volumes:
      - ./Settings.toml:/app/Settings.toml

  backend:
    image: your-app:latest
    expose:
      - "3000"
```
