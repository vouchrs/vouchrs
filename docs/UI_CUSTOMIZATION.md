# UI Customization Guide

Vouchrs OIDC Reverse Proxy supports complete UI customization through Docker volume mounting, allowing you to brand and customize the sign-in page without rebuilding the application.

## 🎨 How It Works

The application serves static files from the `/static` directory with automatic fallback to embedded content:

1. **Primary**: Serves files from `static/` directory (customizable via Docker volumes)
2. **Fallback**: Uses embedded HTML/CSS when static files are unavailable
3. **MIME Types**: Automatically detects content types (HTML, CSS, JS, images)

## 📁 File Structure

```
static/
├── sign-in.html    # Main sign-in page
├── sign-in.css     # Stylesheet
└── [custom files]  # Additional assets (images, JS, etc.)
```

## 🐳 Docker Volume Mounting

### Basic Usage

```bash
# Mount custom static files
docker run -v /path/to/custom/static:/app/static:ro ghcr.io/vouchrs/vouchrs:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  vouchrs:
    image: ghcr.io/vouchrs/vouchrs:latest
    ports:
      - "8080:8080"
    volumes:
      - ./custom-ui:/app/static:ro  # Mount custom UI files
    environment:
      - GOOGLE_CLIENT_ID=your_google_client_id
      - GOOGLE_CLIENT_SECRET=your_google_client_secret
      # ... other env vars
```

## 🎯 Customization Examples

### 1. Corporate Branding

Create `custom-ui/sign-in.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACME Corp - Secure Login</title>
    <link rel="stylesheet" href="/oauth2/static/sign-in.css">
    <style>
        .container { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); }
        .login-box { border: 3px solid #ff6b35; }
        .title::before { content: "🏢 "; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <h1 class="title">ACME CORP PORTAL</h1>
            <p class="subtitle">Corporate OAuth2 Gateway</p>
            
            <div class="provider-buttons">
                <a href="/oauth2/google" class="oauth-button google">
                    <!-- Google SVG icon -->
                    Sign in with Google
                </a>
                <a href="/oauth2/apple" class="oauth-button apple">
                    <!-- Apple SVG icon -->
                    Sign in with Apple
                </a>
            </div>

            <div class="footer-text">
                <p>🏢 ACME Corporation Internal Portal</p>
            </div>
        </div>
    </div>
</body>
</html>
```

### 2. Custom CSS Overrides

Create `custom-ui/sign-in.css`:
```css
/* Custom theme overrides */
.container {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
}

.login-box {
    border: 2px solid #gold !important;
    box-shadow: 0 15px 35px rgba(102, 126, 234, 0.4) !important;
}

.title {
    color: #ffd700 !important;
    font-family: 'Georgia', serif !important;
}

.oauth-button:hover {
    transform: translateY(-3px) !important;
}
```

### 3. Adding Custom Assets

```
custom-ui/
├── sign-in.html
├── sign-in.css
├── logo.png        # Custom logo
├── favicon.ico     # Custom favicon
└── custom.js       # Custom JavaScript
```

Reference in HTML:
```html
<link rel="icon" href="/oauth2/static/favicon.ico">
<img src="/oauth2/static/logo.png" alt="Company Logo">
<script src="/oauth2/static/custom.js"></script>
```

## 🚀 Deployment Workflow

### 1. Development

```bash
# Create custom UI
mkdir -p custom-ui
cp -r static/* custom-ui/

# Edit custom-ui/sign-in.html and custom-ui/sign-in.css
# Test locally:
docker run -v $(pwd)/custom-ui:/app/static:ro -p 8080:8080 ghcr.io/vouchrs/vouchrs:latest
```

### 2. Production Deployment

```bash
# Deploy with custom UI
docker run -d \
  --name vouchrs-prod \
  -p 8080:8080 \
  -v /opt/vouchrs/custom-ui:/app/static:ro \
  -e GOOGLE_CLIENT_ID="$GOOGLE_CLIENT_ID" \
  -e GOOGLE_CLIENT_SECRET="$GOOGLE_CLIENT_SECRET" \
  ghcr.io/vouchrs/vouchrs:latest
```

### 3. Updates

```bash
# Update UI without rebuilding
vim /opt/vouchrs/custom-ui/sign-in.html
docker restart vouchrs-prod
```

## 🔍 Testing

Run the included test script:
```bash
./test-ui-customization.sh
```

This script:
- ✅ Tests embedded fallback functionality
- ✅ Tests Docker volume mounting
- ✅ Verifies static file serving
- ✅ Compares default vs custom UI

## 📋 Available Endpoints

| Endpoint | Description |
|----------|-------------|
| `/oauth2/sign_in` | Main sign-in page (uses static files) |
| `/oauth2/static/sign-in.html` | Direct access to HTML file |
| `/oauth2/static/sign-in.css` | Direct access to CSS file |
| `/oauth2/static/*` | Any file in static directory |

## ⚠️ Important Notes

1. **Read-Only Volumes**: Always mount static volumes as read-only (`:ro`)
2. **Fallback Safety**: Application continues working even if static files are missing
3. **MIME Types**: Automatically detected for proper browser rendering
4. **Security**: Static files are served directly, ensure they don't contain sensitive data
5. **Performance**: Static files are read from disk on each request (consider caching for high traffic)

## 🎉 Benefits

- 🎨 **No Rebuild Required**: Update UI without recompiling
- 🔒 **Safe Fallback**: Embedded content ensures service availability
- 🚀 **Hot Updates**: Change files and restart container
- 🏢 **Enterprise Ready**: Perfect for corporate branding
- 📱 **Responsive**: Maintain mobile compatibility
- 🔧 **Flexible**: Support for any web assets (images, JS, fonts)
