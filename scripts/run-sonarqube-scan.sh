#!/bin/bash

# SonarQube Scanner Script for Vouchr
# This script runs SonarQube analysis using Docker Compose with automated token management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SONAR_URL="http://localhost:9000"
SONAR_TOKEN="${SONAR_TOKEN:-}"  # Read from environment variable
PROJECT_KEY="vouchr"

# Check if token is provided
if [ -z "$SONAR_TOKEN" ]; then
    echo "SONAR_TOKEN environment variable is required"
    echo "Please set SONAR_TOKEN with a valid SonarQube authentication token:"
    echo "  export SONAR_TOKEN='your_sonarqube_token_here'"
    echo
    echo "To generate a token:"
    echo "  1. Login to SonarQube at $SONAR_URL"
    echo "  2. Go to Administration > Security > Users"
    echo "  3. Click on your user and generate a new token"
    exit 1
fi

print_step() {
    echo -e "${BLUE}🔧 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

echo -e "${BLUE}🔐 Starting SonarQube analysis for Vouchr...${NC}"
echo

# Change to project root directory
cd "$(dirname "$0")/.."

# Check if SonarQube services are running
print_step "Checking SonarQube status..."
if ! curl -s "$SONAR_URL/api/system/status" > /dev/null 2>&1; then
    print_warning "SonarQube is not running. Starting services..."
    docker-compose -f docker/docker-compose.sonarqube.yml up -d

    print_step "Waiting for SonarQube to be ready..."
    for i in {1..30}; do
        if curl -s "$SONAR_URL/api/system/status" | grep -q '"status":"UP"'; then
            print_success "SonarQube is ready!"
            break
        fi
        echo -n "."
        sleep 2
    done
    echo

    if [ $i -eq 30 ]; then
        print_error "SonarQube failed to start within 60 seconds"
        exit 1
    fi
else
    print_success "SonarQube is already running"
fi

# Verify token authentication
print_step "Verifying authentication token..."
AUTH_RESPONSE=$(curl -s -H "Authorization: Bearer $SONAR_TOKEN" \
    "$SONAR_URL/api/authentication/validate")

if echo "$AUTH_RESPONSE" | grep -q '"valid":true'; then
    print_success "Authentication token is valid"
else
    print_error "Authentication token is invalid or expired"
    echo "Response: $AUTH_RESPONSE"
    echo "Please ensure SONAR_TOKEN contains a valid authentication token"
    exit 1
fi

# Run the scanner using Docker Compose
print_step "Running SonarQube analysis..."

# Run scanner with all configuration passed as command-line arguments
SONAR_TOKEN="$SONAR_TOKEN" docker-compose -f docker/docker-compose.sonarqube.yml \
    --profile scan run --rm \
    sonarqube-scanner \
    sonar-scanner \
    -Dsonar.projectKey=vouchr \
    -Dsonar.projectName="Vouchr OAuth2 Reverse Proxy" \
    -Dsonar.projectVersion=1.0 \
    -Dsonar.sources=src \
    -Dsonar.sourceEncoding=UTF-8 \
    -Dsonar.exclusions="target/**,**/*.md,**/*.txt,**/*.yml,**/*.yaml,**/*.json,**/*.toml,scripts/**,docker/**,docs/**" \
    -Dsonar.scm.provider=git \
    -Dsonar.scm.disabled=false

# Check if analysis was successful
if [ $? -eq 0 ]; then
    echo
    print_success "SonarQube analysis completed successfully!"
    echo -e "${BLUE}📊 View results at: $SONAR_URL/dashboard?id=$PROJECT_KEY${NC}"
    echo
    echo -e "${BLUE}To open in browser, run: \$BROWSER $SONAR_URL/dashboard?id=$PROJECT_KEY${NC}"
else
    print_error "SonarQube analysis failed!"
    exit 1
fi
