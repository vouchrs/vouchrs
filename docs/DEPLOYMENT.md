# Deployment Guide

## Quick Start

### Prerequisites
- Docker and Docker Compose installed
- OAuth2 credentials from Google and/or Apple

### Environment Setup
Create a `.env` file with your OAuth credentials:

```bash
# Required OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
APPLE_CLIENT_ID=your.apple.service.id
APPLE_TEAM_ID=YOUR_TEAM_ID
APPLE_KEY_ID=YOUR_KEY_ID
APPLE_PRIVATE_KEY_PATH=/app/AuthKey_YOUR_KEY_ID.p8

# Required Session Configuration
SESSION_SECRET=your-256-bit-secret-key-here
REDIRECT_BASE_URL=http://localhost:8080

# Optional
RUST_LOG=info
UPSTREAM_URL=http://localhost:3000
```

## Docker Deployment

### Using Docker Compose

1. **Create docker-compose.yml:**
```yaml
version: '3.8'
services:
  vouchrs:
    image: ghcr.io/vouchrs/vouchrs:latest
    ports:
      - "8080:8080"
    env_file:
      - .env
    volumes:
      # Mount secrets directory containing Settings.toml and Apple private key
      - ./secrets:/usr/share/vouchrs/secrets:ro
    restart: unless-stopped
    # Health check (external tool required for distroless)
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:8080/ping || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
      disable: true  # Enable if you have wget available
```

2. **Start services:**
```bash
docker-compose up -d
```

### Using Docker Run

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/vouchrs/vouchrs:latest

# Run with environment file
docker run -d \
  --name vouchrs \
  -p 8080:8080 \
  --env-file .env \
  -v $(pwd)/AuthKey_YOUR_KEY_ID.p8:/app/AuthKey_YOUR_KEY_ID.p8:ro \
  ghcr.io/vouchrs/vouchrs:latest
```

## Building from Source

### Development Build
```bash
git clone https://github.com/vouchrs/vouchrs.git
cd vouchrs
cargo build
cargo run
```

### Production Build
```bash
cargo build --release
# Binary will be at: target/release/vouchrs
```

### Docker Build
```bash
# Build locally
docker build -t vouchrs:latest .

# Build for production with registry tagging
docker build -t ghcr.io/vouchrs/vouchrs:latest .
```

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | `123456789.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | `GOCSPX-xxxxxxxxxxxxxxxxxxxxx` |
| `APPLE_CLIENT_ID` | Apple OAuth service ID | `com.yourcompany.yourapp` |
| `APPLE_TEAM_ID` | Apple Developer Team ID | `ABCDEFGHIJ` |
| `APPLE_KEY_ID` | Apple private key ID | `AB12CDEFGH` |
| `APPLE_PRIVATE_KEY_PATH` | Path to Apple private key file | `/app/AuthKey_AB12CDEFGH.p8` |
| `SESSION_SECRET` | 256-bit secret for session encryption | `your-very-secure-256-bit-secret-here` |
| `REDIRECT_BASE_URL` | Base URL for OAuth callbacks | `https://auth.example.com` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level (error, warn, info, debug, trace) |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8080` | Server bind port |
| `UPSTREAM_URL` | None | URL to proxy authenticated requests to |

## OAuth Provider Setup

### Google OAuth Setup

1. **Create OAuth 2.0 credentials** in [Google Cloud Console](https://console.cloud.google.com/):
   - Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
   - Application type: "Web application"
   - Authorized redirect URIs: `https://yourdomain.com/oauth2/callback`

2. **Configure OAuth consent screen**:
   - Add your domain to authorized domains
   - Set application name and support email

### Apple OAuth Setup

1. **Create App ID** in [Apple Developer Portal](https://developer.apple.com/):
   - Register an App ID with "Sign in with Apple" capability

2. **Create Service ID**:
   - Create a Services ID for web authentication
   - Configure "Sign in with Apple" with your callback URL

3. **Create Private Key**:
   - Generate a private key for "Sign in with Apple"
   - Download the `.p8` file and note the Key ID

4. **Get Team ID**:
   - Found in Apple Developer account membership details

## Production Deployment

### Security Considerations

1. **Use HTTPS**: Always serve over HTTPS in production
2. **Secure Session Secret**: Use a cryptographically secure 256-bit key
3. **Key Management**: Protect Apple private key file with appropriate permissions
4. **Environment Variables**: Never commit secrets to version control

### Docker Production Setup

```yaml
version: '3.8'
services:
  vouchrs:
    image: ghcr.io/vouchrs/vouchrs:latest
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=warn
    env_file:
      - .env
    volumes:
      - ./keys/AuthKey_YOUR_KEY_ID.p8:/app/AuthKey_YOUR_KEY_ID.p8:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Reverse Proxy Setup (Nginx)

```nginx
upstream vouchrs {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://vouchrs;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Development Tools

### Code Quality
```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Run tests
cargo test

# Check without building
cargo check
```

### Docker Development
```bash
# Build development image
docker build -t vouchrs:dev .

# Run with live reload (bind mount source)
docker run -v $(pwd):/app vouchrs:dev cargo watch -x run
```
