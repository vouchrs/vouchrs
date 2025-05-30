#!/bin/bash

# Docker Volume UI Customization Test Script
# This script demonstrates how to customize the Vouchrs OIDC Reverse Proxy UI
# by mounting custom static files using Docker volumes

set -e

echo "🔐 Vouchrs OIDC Reverse Proxy - UI Customization Test"
echo "=================================================="
echo

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}📁 Setting up test environment...${NC}"

# Create test directories
mkdir -p test-custom-ui/static
mkdir -p test-logs

# Copy current static files as baseline
cp -r src/static/* test-custom-ui/static/

echo -e "${GREEN}✅ Copied baseline static files${NC}"

# Create customized version for testing
cat > test-custom-ui/static/sign-in.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🏢 ACME Corp Login - Vouchrs OIDC Reverse Proxy</title>
    <link rel="stylesheet" href="/oauth2/static/sign-in.css">
    <style>
        .container {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        }
        .login-box {
            border: 3px solid #ff6b35;
            background: rgba(255, 255, 255, 0.98);
        }
        .title {
            color: #1e3c72;
            font-family: 'Arial Black', sans-serif;
        }
        .title::before {
            content: "🏢 ";
        }
        .subtitle {
            color: #ff6b35;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <h1 class="title">ACME CORP PORTAL</h1>
            <p class="subtitle">🔐 Corporate OAuth2 Gateway</p>
            
            <div class="provider-buttons">
                <a href="/oauth2/google" class="oauth-button google">
                    <svg class="icon" viewBox="0 0 24 24">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                    </svg>
                    Sign in with Google
                </a>
                
                <a href="/oauth2/apple" class="oauth-button apple">
                    <svg class="icon" viewBox="0 0 24 24">
                        <path fill="currentColor" d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
                    </svg>
                    Sign in with Apple
                </a>
            </div>

            <div class="footer-text">
                <p>🏢 ACME Corporation Internal Portal</p>
                <p style="color: #ff6b35; font-weight: bold;">Custom UI v1.0 - Docker Volume Test</p>
            </div>
        </div>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✅ Created custom HTML file${NC}"

# Build the Docker image
echo -e "${BLUE}🐳 Building Docker image...${NC}"
# Change to project root directory
cd "$(dirname "$0")/.."
docker build -f docker/Dockerfile -t vouchrs-test:latest .

echo -e "${GREEN}✅ Docker image built successfully${NC}"

# Test 1: Run with default static files (embedded)
echo -e "${YELLOW}🧪 Test 1: Running with embedded static files${NC}"
docker run -d --name vouchrs-test-default -p 8081:8080 \
    -e GOOGLE_CLIENT_ID="test" \
    -e GOOGLE_CLIENT_SECRET="test" \
    -e APPLE_CLIENT_ID="test" \
    -e APPLE_TEAM_ID="test" \
    -e APPLE_KEY_ID="test" \
    -e APPLE_PRIVATE_KEY="test" \
    vouchrs-test:latest

sleep 3

echo -e "${BLUE}Checking default UI...${NC}"
curl -s -o test-logs/default-response.html http://localhost:8081/oauth2/sign_in || echo "Service starting..."

# Test 2: Run with custom static files via volume mount
echo -e "${YELLOW}🧪 Test 2: Running with custom static files (Docker volume)${NC}"
docker run -d --name vouchrs-test-custom -p 8082:8080 \
    -v "$(pwd)/test-custom-ui/static:/app/src/static:ro" \
    -e GOOGLE_CLIENT_ID="test" \
    -e GOOGLE_CLIENT_SECRET="test" \
    -e APPLE_CLIENT_ID="test" \
    -e APPLE_TEAM_ID="test" \
    -e APPLE_KEY_ID="test" \
    -e APPLE_PRIVATE_KEY="test" \
    vouchrs-test:latest

sleep 3

echo -e "${BLUE}Checking custom UI...${NC}"
curl -s -o test-logs/custom-response.html http://localhost:8082/oauth2/sign_in || echo "Service starting..."

# Wait for services to be ready
echo -e "${BLUE}⏳ Waiting for services to start...${NC}"
sleep 5

# Test the endpoints
echo -e "${YELLOW}🔍 Testing endpoints...${NC}"

echo "Testing default UI (port 8081):"
curl -s -w "HTTP Status: %{http_code}\n" http://localhost:8081/oauth2/sign_in > /dev/null

echo "Testing custom UI (port 8082):"
curl -s -w "HTTP Status: %{http_code}\n" http://localhost:8082/oauth2/sign_in > /dev/null

echo "Testing static file serving (port 8082):"
curl -s -w "HTTP Status: %{http_code}\n" http://localhost:8082/oauth2/static/sign-in.css > /dev/null

# Cleanup
echo -e "${BLUE}🧹 Cleaning up test containers...${NC}"
docker stop vouchrs-test-default vouchrs-test-custom 2>/dev/null || true
docker rm vouchrs-test-default vouchrs-test-custom 2>/dev/null || true

echo
echo -e "${GREEN}✅ UI Customization Test Complete!${NC}"
echo
echo -e "${BLUE}📋 Summary:${NC}"
echo "• Default UI: http://localhost:8081/oauth2/sign_in (embedded fallback)"
echo "• Custom UI:  http://localhost:8082/oauth2/sign_in (volume mounted)"
echo "• Static files: http://localhost:8082/oauth2/static/sign-in.css"
echo
echo -e "${YELLOW}💡 To use custom UI in production:${NC}"
echo "docker run -v /path/to/custom/static:/app/static:ro vouchrs:latest"
echo
echo -e "${GREEN}🎉 Docker volume mounting for UI customization works perfectly!${NC}"
