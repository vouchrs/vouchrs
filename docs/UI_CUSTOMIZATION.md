# UI Customization Guide

Vouchrs Authentication Gateway and Reverse Proxy supports complete UI customization through Docker volume mounting, allowing you to brand and customize the sign-in page without rebuilding the application.
<img src="/auth/static/logo.png" alt="Company Logo">
<script src="/auth/static/custom.js"></script>thout rebuilding the application.

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

> **Example**: See the `/custom-ui` folder in the repository for a ready-to-use dark mode theme with Google and Apple provider styling.

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

### 1. Dark Mode Theme with Brand-Specific Provider Styling

Our repository includes a ready-to-use dark mode example in the `/custom-ui` folder that you can use as a starting point.

Example `sign-in.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouchrs Authentication Gateway - Sign In</title>
    <link rel="stylesheet" href="/auth/static/sign-in.css">
</head>
<body>
    <div class="container">
        <div class="login-box">
            <h1>🔐 Secure Authentication</h1>
            <p class="subtitle">Choose a provider to continue</p>

            <div class="provider-buttons">
                <a href="/auth/sign_in?provider=google" class="provider-btn google-btn">
                    <svg class="provider-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                        <!-- Google SVG icon path data -->
                    </svg>
                    <span>Sign in with Google</span>
                </a>

                <a href="/auth/sign_in?provider=apple" class="provider-btn apple-btn">
                    <svg class="provider-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                        <!-- Apple SVG icon path data -->
                    </svg>
                    <span>Sign in with Apple</span>
                </a>
            </div>

            <div class="footer">
                <p>Secured by <a href="https://github.com/vouchrs/vouchrs" target="_blank">Vouchrs</a> <span class="version">OIDC Proxy</span></p>
            </div>
        </div>
    </div>
</body>
</html>
```

### 2. Custom CSS Overrides

Our dark mode theme in the `/custom-ui` folder provides complete styling:

```css
/* Dark mode theme with provider-specific styling */
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #121212; /* Dark mode background */
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #e0e0e0;
}

.login-box {
    background: #1e1e1e; /* Dark card background */
    padding: 2.5rem;
    border-radius: 12px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
}

/* Provider-specific styling */
.google-btn {
    background-color: #4285F4; /* Google blue */
}

.apple-btn {
    background-color: #000; /* Apple black */
}
```

### 3. Corporate Branding

For corporate branding, you can create custom CSS:

```css
/* Custom corporate theme */
body {
    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
}

.login-box {
    border: 3px solid #ff6b35;
    background-color: #ffffff;
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
<link rel="icon" href="/auth/static/favicon.ico">
<img src="/auth/static/logo.png" alt="Company Logo">
<script src="/auth/static/custom.js"></script>
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
| `/auth/sign_in` | Main sign-in page (uses static files) |
| `/auth/static/sign-in.html` | Direct access to HTML file |
| `/auth/static/sign-in.css` | Direct access to CSS file |
| `/auth/static/*` | Any file in static directory |

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
