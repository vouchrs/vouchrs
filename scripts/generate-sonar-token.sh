#!/bin/bash

# SonarQube Token Generator for Vouchr
# This script generates a new SonarQube authentication token using curl

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SONAR_URL="http://localhost:9000"
SONAR_USER="${SONAR_USER:-admin}"
SONAR_PASS="${SONAR_PASS:-admin}"
TOKEN_NAME="${TOKEN_NAME:-vouchr-analysis-$(date +%s)}"

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

echo -e "${BLUE}🔑 SonarQube Token Generator${NC}"
echo

# Check if SonarQube is running
print_step "Checking SonarQube status..."
if ! curl -s "$SONAR_URL/api/system/status" > /dev/null 2>&1; then
    print_error "SonarQube is not running at $SONAR_URL"
    echo "Please start SonarQube first:"
    echo "  docker-compose -f docker/docker-compose.sonarqube.yml up -d"
    exit 1
fi

print_success "SonarQube is running"

# Generate authentication token
print_step "Generating authentication token..."
TOKEN_RESPONSE=$(curl -s -u "$SONAR_USER:$SONAR_PASS" \
    -X POST "$SONAR_URL/api/user_tokens/generate" \
    -d "name=$TOKEN_NAME")

if echo "$TOKEN_RESPONSE" | grep -q '"token"'; then
    SONAR_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    print_success "Token generated successfully!"
    echo
    echo -e "${GREEN}Token Name: $TOKEN_NAME${NC}"
    echo -e "${GREEN}Token: $SONAR_TOKEN${NC}"
    echo
    echo -e "${BLUE}💡 Usage:${NC}"
    echo "  export SONAR_TOKEN=\"$SONAR_TOKEN\""
    echo "  ./scripts/run-sonarqube-scan.sh"
    echo "  ./scripts/get-sonarqube-results.sh"
    echo
    echo -e "${BLUE}🔒 Add to .env file:${NC}"
    echo "  echo 'SONAR_TOKEN=$SONAR_TOKEN' >> .env"
    echo
    echo -e "${YELLOW}⚠️  Save this token securely - you won't see it again!${NC}"
    
    # Verify the token works
    print_step "Verifying token..."
    AUTH_CHECK=$(curl -s -H "Authorization: Bearer $SONAR_TOKEN" \
        "$SONAR_URL/api/authentication/validate")
    
    if echo "$AUTH_CHECK" | grep -q '"valid":true'; then
        print_success "Token verification successful!"
    else
        print_warning "Token generated but verification failed"
        echo "Response: $AUTH_CHECK"
    fi
else
    print_error "Failed to generate token"
    echo "Response: $TOKEN_RESPONSE"
    echo
    echo -e "${YELLOW}💡 Troubleshooting:${NC}"
    echo "  1. Check username/password (current: $SONAR_USER)"
    echo "  2. Verify SonarQube is fully initialized"
    echo "  3. Check if user has token generation permissions"
    exit 1
fi

echo
echo -e "${BLUE}🔄 Token Management:${NC}"
echo "To list all tokens:"
echo "  curl -u '$SONAR_USER:$SONAR_PASS' '$SONAR_URL/api/user_tokens/search'"
echo
echo "To revoke this token:"
echo "  curl -u '$SONAR_USER:$SONAR_PASS' -X POST '$SONAR_URL/api/user_tokens/revoke' -d 'name=$TOKEN_NAME'"
