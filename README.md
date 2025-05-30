# Vouchrs

A lightweight, high-performance OIDC reverse proxy built in Rust. Vouchrs acts as an authentication gateway, protecting your applications by requiring OIDC authentication before allowing access to upstream services.

## Features

- 🔐 **OIDC Authentication**: Configurable OAuth providers with OpenID Connect support
- 🛡️ **Secure Sessions**: AES-GCM encrypted cookie-based sessions
- 🎨 **Customizable UI**: Docker volume-mountable sign-in pages with dynamic provider lists
- ⚡ **High Performance**: Rust-based with minimal dependencies and optimized architecture
- 🔄 **Reverse Proxy**: Transparent upstream request forwarding with custom JWT injection
- 🚀 **Lightweight**: Optimized binary size and memory footprint
- 📦 **Self-Contained**: No external dependencies required
- 🏗️ **Config-Driven**: Flexible provider configuration through Settings.toml
- 🔧 **Extensible**: Easy to add new OAuth providers via configuration
- 🔑 **Custom JWT**: Standardized JWT generation with HMAC-SHA256 signing
- 🌐 **Client Context**: Automatic client IP and user agent detection for security and analytics

## Quick Start

### Docker (Recommended)

1. **Create environment file:**
   ```bash
   # Create .env file with your OAuth credentials
   GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   APPLE_CLIENT_ID=your.apple.service.id
   APPLE_TEAM_ID=YOUR_TEAM_ID
   APPLE_KEY_ID=YOUR_KEY_ID
   APPLE_PRIVATE_KEY_PATH=/app/AuthKey_YOUR_KEY_ID.p8
   SESSION_SECRET=your-256-bit-secret-key-here
   REDIRECT_BASE_URL=https://your-domain.com
   ```

2. **Run with Docker:**
   ```bash
   docker run -d \
     --name vouchrs \
     -p 8080:8080 \
     --env-file .env \
     -v $(pwd)/AuthKey_YOUR_KEY_ID.p8:/app/AuthKey_YOUR_KEY_ID.p8:ro \
     vouchrs:latest
   ```

### From Source

1. **Build and run:**
   ```bash
   git clone <repository-url>
   cd vouchrs
   cargo build --release
   cargo run
   ```

## Configuration

Vouchrs uses a config-driven approach for OAuth providers. Configuration is done through `Settings.toml` and environment variables.

### Provider Configuration

OAuth providers must be configured in `Settings.toml`. At least one provider is required for Vouchrs to start.

```toml
# Settings.toml
[[providers]]
name = "google"
display_name = "Google"
discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
signout_url = "https://accounts.google.com/logout"
scopes = ["openid", "email", "profile"]
client_id_env = "GOOGLE_CLIENT_ID"
client_secret_env = "GOOGLE_CLIENT_SECRET"
enabled = true

[providers.extra_auth_params]
access_type = "offline"
prompt = "consent"

[[providers]]
name = "apple"
display_name = "Apple"
discovery_url = "https://appleid.apple.com/.well-known/openid-configuration"
scopes = ["openid", "email", "name"]
client_id_env = "APPLE_CLIENT_ID"
enabled = true

[providers.extra_auth_params]
response_mode = "form_post"

[providers.jwt_signing]
team_id_env = "APPLE_TEAM_ID"
key_id_env = "APPLE_KEY_ID"
private_key_path_env = "APPLE_PRIVATE_KEY_PATH"

# Add custom providers easily
[[providers]]
name = "microsoft"
display_name = "Microsoft"
discovery_url = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
scopes = ["openid", "email", "profile"]
client_id_env = "MICROSOFT_CLIENT_ID"
client_secret_env = "MICROSOFT_CLIENT_SECRET"
enabled = false  # Set to true to enable
```

### Provider Configuration Options

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Unique provider identifier |
| `display_name` | String | Yes | Human-readable provider name |
| `discovery_url` | String | No* | OpenID Connect discovery URL |
| `auth_url` | String | No* | Authorization endpoint (if no discovery) |
| `token_url` | String | No* | Token endpoint (if no discovery) |
| `scopes` | Array | Yes | OAuth scopes to request |
| `client_id_env` | String | Yes | Environment variable for client ID |
| `client_secret_env` | String | No | Environment variable for client secret |
| `enabled` | Boolean | Yes | Whether provider is enabled |
| `extra_auth_params` | Table | No | Additional OAuth parameters |
| `jwt_signing` | Table | No | JWT signing config (for Apple) |

*Either `discovery_url` OR both `auth_url` and `token_url` are required.

### Environment Variables

#### Core Settings
| Variable | Required | Description |
|----------|----------|-------------|
| `SESSION_SECRET` | Yes | 256-bit secret for session encryption |
| `REDIRECT_BASE_URL` | Yes | Base URL for OAuth callbacks |

#### Provider Credentials  
| Variable | Required For | Description |
|----------|-------------|-------------|
| `GOOGLE_CLIENT_ID` | Google | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google | Google OAuth client secret |
| `APPLE_CLIENT_ID` | Apple | Apple OAuth service ID |
| `APPLE_TEAM_ID` | Apple | Apple Developer Team ID |
| `APPLE_KEY_ID` | Apple | Apple private key ID |
| `APPLE_PRIVATE_KEY_PATH` | Apple | Path to Apple private key (.p8) file |

#### Optional Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `UPSTREAM_URL` | `http://localhost:3000` | URL to proxy authenticated requests to |
| `RUST_LOG` | `info` | Log level (error, warn, info, debug, trace) |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8080` | Server port |

2. **Configure environment:**
   ```bash
   export SESSION_SECRET="your-256-bit-secret-key"
   export GOOGLE_CLIENT_ID="your-google-client-id"
   export GOOGLE_CLIENT_SECRET="your-google-client-secret"
   export REDIRECT_BASE_URL="http://localhost:8080"
   # Add other OAuth variables as needed
   ```

The service will start on `http://localhost:8080`.

## API Endpoints

| Endpoint | Method | Purpose |
|----------|---------|---------|
| `/oauth2/sign_in` | GET | Display sign-in page or initiate OAuth flow |
| `/oauth2/callback` | GET/POST | OAuth callback handler (Google=GET, Apple=POST) |
| `/oauth2/sign_out` | GET/POST | Sign out user and clear session |
| `/ping` | GET | Health check and service status |

## Dynamic Provider Support

The sign-in page automatically generates buttons for all enabled providers. When no static HTML file is found, Vouchrs generates a dynamic page with:

- Provider buttons based on configuration
- Automatic styling for common providers (Google, Apple, Microsoft)
- Responsive design with modern UI

## Documentation

- 📖 **[Complete Documentation](./docs/README.md)** - Full documentation index
- 🚀 **[Deployment Guide](./docs/DEPLOYMENT.md)** - Docker, environment setup, and production deployment
- 🔌 **[API Reference](./docs/API_REFERENCE.md)** - Endpoint documentation and examples
- 🎨 **[UI Customization](./docs/UI_CUSTOMIZATION.md)** - Custom branding and theming
- 🔧 **[Implementation Details](./docs/IMPLEMENTATION_DETAILS.md)** - Technical details on config-driven providers and JWT system
| `RUST_LOG` | No | Log level (error, warn, info, debug, trace) |

## Authentication Flow

1. **User visits protected resource** → Redirected to `/oauth2/sign_in`
2. **User selects provider** → Redirected to OAuth provider (Google/Apple)
3. **User authorizes** → Provider redirects to `/oauth2/callback`
4. **Token exchange** → User info retrieved and encrypted session created
5. **JWT generation** → Custom JWT created with standardized claims and HMAC-SHA256 signature
6. **User authenticated** → JWT injected in Authorization header, request forwarded to upstream

## Custom JWT Integration

Vouchrs injects a standardized JWT (signed with your session secret) instead of forwarding provider tokens. This provides:

- **Standardized Format**: Consistent JWT structure regardless of OAuth provider
- **Enhanced Security**: JWT signed with your own secret, not external providers
- **Rich Context**: Includes client IP, user agent, platform, and language information
- **Simplified Validation**: Single JWT format for all upstream APIs to validate

### JWT Claims Structure
```json
{
  "iss": "https://auth.mycompany.com",     // Your auth service
  "aud": "https://api.mycompany.com",      // Your upstream API
  "sub": "user@example.com",               // User email
  "idp": "google",                         // OAuth provider
  "name": "Alice Johnson",                 // User display name
  "client_ip": "203.0.113.42",            // Original client IP
  "user_agent": "Mozilla/5.0...",         // Browser/device info
  "platform": "Windows",                  // Operating system
  "lang": "en-US",                        // Preferred language
  "mobile": 0                              // Mobile device indicator
}
```

See [`docs/IMPLEMENTATION_DETAILS.md`](./docs/IMPLEMENTATION_DETAILS.md) for complete technical details.

## Development

### Build and Test
```bash
cargo build          # Development build
cargo test           # Run tests
cargo run            # Start development server
cargo build --release # Production build
```

### Development Environment
```bash
export RUST_LOG=debug
export SESSION_SECRET="your-development-secret-key"   export REDIRECT_BASE_URL="http://localhost:8080"
# Add OAuth provider credentials
cargo run
```

## Troubleshooting

### Common Issues

**"Missing environment variable"**
- Ensure all required environment variables are set
- Generate a secure session secret: `openssl rand -hex 32`

**"OAuth callback error"**
- Verify redirect URI matches provider configuration exactly
- Check OAuth provider credentials are correct

**"Apple JWT signing failed"**
- Ensure Apple private key file exists and is readable
- Verify `APPLE_PRIVATE_KEY_PATH` points to correct `.p8` file

## License

This project is licensed under the MIT License.
