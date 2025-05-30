#!/bin/bash

# SonarQube Results Fetcher for Vouchr
# This script retrieves and displays the latest SonarQube analysis results

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SONAR_URL="http://localhost:9000"
SONAR_TOKEN="${SONAR_TOKEN:-}"  # Read from environment variable
PROJECT_KEY="vouchr"

# Check if token is provided
if [ -z "$SONAR_TOKEN" ]; then
    echo -e "${RED}❌ SONAR_TOKEN environment variable is required${NC}"
    echo "Please set SONAR_TOKEN with a valid SonarQube authentication token:"
    echo "  export SONAR_TOKEN='your_sonarqube_token_here'"
    echo
    echo "To generate a token:"
    echo "  1. Login to SonarQube at $SONAR_URL"
    echo "  2. Go to Administration > Security > Users"
    echo "  3. Click on your user and generate a new token"
    exit 1
fi

print_header() {
    echo -e "${BLUE}===============================================${NC}"
    echo -e "${BLUE}🧙‍♂️ $1${NC}"
    echo -e "${BLUE}===============================================${NC}"
}

print_section() {
    echo -e "\n${CYAN}📊 $1${NC}"
    echo -e "${CYAN}-------------------------------------------${NC}"
}

print_metric() {
    local name="$1"
    local value="$2"
    local status="$3"
    
    case "$status" in
        "OK"|"A") echo -e "${GREEN}✅ $name: $value${NC}" ;;
        "ERROR"|"E") echo -e "${RED}❌ $name: $value${NC}" ;;
        "WARN"|"C"|"D") echo -e "${YELLOW}⚠️  $name: $value${NC}" ;;
        *) echo -e "   $name: $value" ;;
    esac
}

# Check if SonarQube is running
if ! curl -s "$SONAR_URL/api/system/status" > /dev/null 2>&1; then
    echo -e "${RED}❌ SonarQube is not running at $SONAR_URL${NC}"
    echo -e "${YELLOW}💡 Start it with: docker-compose -f docker/docker-compose.sonarqube.yml up -d${NC}"
    exit 1
fi

print_header "Latest SonarQube Results for Vouchr"

# Get Quality Gate Status
print_section "Quality Gate Status"
QG_RESPONSE=$(curl -s -H "Authorization: Bearer $SONAR_TOKEN" \
    "$SONAR_URL/api/qualitygates/project_status?projectKey=$PROJECT_KEY")

if echo "$QG_RESPONSE" | grep -q '"status"'; then
    QG_STATUS=$(echo "$QG_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    case "$QG_STATUS" in
        "OK") echo -e "${GREEN}✅ Quality Gate: PASSED${NC}" ;;
        "ERROR") echo -e "${RED}❌ Quality Gate: FAILED${NC}" ;;
        "WARN") echo -e "${YELLOW}⚠️  Quality Gate: WARNING${NC}" ;;
        *) echo -e "   Quality Gate: $QG_STATUS" ;;
    esac
else
    echo -e "${YELLOW}⚠️  No quality gate data found${NC}"
fi

# Get Project Measures
print_section "Code Quality Metrics"
MEASURES_RESPONSE=$(curl -s -H "Authorization: Bearer $SONAR_TOKEN" \
    "$SONAR_URL/api/measures/component?component=$PROJECT_KEY&metricKeys=alert_status,bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density,ncloc,sqale_rating,reliability_rating,security_rating,sqale_index")

if echo "$MEASURES_RESPONSE" | grep -q '"measures"'; then
    # Parse individual metrics - handle both "value" and "bestValue" fields
    parse_metric() {
        local metric="$1"
        local response="$2"
        echo "$response" | grep -o "\"metric\":\"$metric\"[^}]*" | grep -o "\"value\":\"[^\"]*\"" | cut -d'"' -f4 | head -1
    }
    
    BUGS=$(parse_metric "bugs" "$MEASURES_RESPONSE")
    VULNERABILITIES=$(parse_metric "vulnerabilities" "$MEASURES_RESPONSE")
    HOTSPOTS=$(parse_metric "security_hotspots" "$MEASURES_RESPONSE")
    CODE_SMELLS=$(parse_metric "code_smells" "$MEASURES_RESPONSE")
    COVERAGE=$(parse_metric "coverage" "$MEASURES_RESPONSE")
    DUPLICATED=$(parse_metric "duplicated_lines_density" "$MEASURES_RESPONSE")
    NCLOC=$(parse_metric "ncloc" "$MEASURES_RESPONSE")
    TECH_DEBT=$(parse_metric "sqale_index" "$MEASURES_RESPONSE")
    
    # Ratings
    MAINTAINABILITY=$(parse_metric "sqale_rating" "$MEASURES_RESPONSE")
    RELIABILITY=$(parse_metric "reliability_rating" "$MEASURES_RESPONSE")
    SECURITY=$(parse_metric "security_rating" "$MEASURES_RESPONSE")
    
    # Set defaults for empty values
    BUGS=${BUGS:-0}
    VULNERABILITIES=${VULNERABILITIES:-0}
    HOTSPOTS=${HOTSPOTS:-0}
    CODE_SMELLS=${CODE_SMELLS:-0}
    NCLOC=${NCLOC:-0}

    # Display metrics with safe integer comparisons
    print_metric "Lines of Code" "$NCLOC"
    print_metric "Bugs" "$BUGS" $([ "$BUGS" -eq 0 ] 2>/dev/null && echo "OK" || echo "ERROR")
    print_metric "Vulnerabilities" "$VULNERABILITIES" $([ "$VULNERABILITIES" -eq 0 ] 2>/dev/null && echo "OK" || echo "ERROR")
    print_metric "Security Hotspots" "$HOTSPOTS" $([ "$HOTSPOTS" -eq 0 ] 2>/dev/null && echo "OK" || echo "WARN")
    print_metric "Code Smells" "$CODE_SMELLS" $([ "$CODE_SMELLS" -lt 10 ] 2>/dev/null && echo "OK" || echo "WARN")
    
    if [ -n "$COVERAGE" ] && [ "$COVERAGE" != "0" ]; then
        COV_INT=${COVERAGE%.*}
        print_metric "Test Coverage" "${COVERAGE}%" $([ "$COV_INT" -gt 80 ] 2>/dev/null && echo "OK" || echo "WARN")
    else
        print_metric "Test Coverage" "No data" "WARN"
    fi
    
    if [ -n "$DUPLICATED" ] && [ "$DUPLICATED" != "0" ]; then
        DUP_INT=${DUPLICATED%.*}
        print_metric "Duplicated Lines" "${DUPLICATED}%" $([ "$DUP_INT" -lt 5 ] 2>/dev/null && echo "OK" || echo "WARN")
    else
        print_metric "Duplicated Lines" "0%" "OK"
    fi
    
    if [ -n "$TECH_DEBT" ] && [ "$TECH_DEBT" != "0" ]; then
        # Convert minutes to hours/days
        MINUTES=$TECH_DEBT
        if [ "$MINUTES" -gt 1440 ] 2>/dev/null; then
            DAYS=$((MINUTES / 1440))
            print_metric "Technical Debt" "${DAYS}d" $([ "$DAYS" -lt 1 ] && echo "OK" || echo "WARN")
        elif [ "$MINUTES" -gt 60 ] 2>/dev/null; then
            HOURS=$((MINUTES / 60))
            print_metric "Technical Debt" "${HOURS}h" $([ "$HOURS" -lt 8 ] && echo "OK" || echo "WARN")
        else
            print_metric "Technical Debt" "${MINUTES}min" "OK"
        fi
    else
        print_metric "Technical Debt" "0min" "OK"
    fi
else
    echo -e "${YELLOW}⚠️  No measures data found${NC}"
fi

# Get Rating Details
print_section "Quality Ratings"
case "$MAINTAINABILITY" in
    "1") print_metric "Maintainability" "A" "OK" ;;
    "2") print_metric "Maintainability" "B" "OK" ;;
    "3") print_metric "Maintainability" "C" "WARN" ;;
    "4") print_metric "Maintainability" "D" "WARN" ;;
    "5") print_metric "Maintainability" "E" "ERROR" ;;
    *) print_metric "Maintainability" "No data" ;;
esac

case "$RELIABILITY" in
    "1") print_metric "Reliability" "A" "OK" ;;
    "2") print_metric "Reliability" "B" "OK" ;;
    "3") print_metric "Reliability" "C" "WARN" ;;
    "4") print_metric "Reliability" "D" "WARN" ;;
    "5") print_metric "Reliability" "E" "ERROR" ;;
    *) print_metric "Reliability" "No data" ;;
esac

case "$SECURITY" in
    "1") print_metric "Security" "A" "OK" ;;
    "2") print_metric "Security" "B" "OK" ;;
    "3") print_metric "Security" "C" "WARN" ;;
    "4") print_metric "Security" "D" "WARN" ;;
    "5") print_metric "Security" "E" "ERROR" ;;
    *) print_metric "Security" "No data" ;;
esac

# Get Recent Issues
print_section "Recent Issues (Top 10)"
ISSUES_RESPONSE=$(curl -s -H "Authorization: Bearer $SONAR_TOKEN" \
    "$SONAR_URL/api/issues/search?componentKeys=$PROJECT_KEY&ps=10&s=CREATION_DATE&asc=false")

if echo "$ISSUES_RESPONSE" | grep -q '"issues"'; then
    echo "$ISSUES_RESPONSE" | grep -o '"type":"[^"]*","rule":"[^"]*","severity":"[^"]*","component":"[^"]*","line":[0-9]*,"message":"[^"]*"' | head -10 | while read -r issue; do
        TYPE=$(echo "$issue" | grep -o '"type":"[^"]*"' | cut -d'"' -f4)
        SEVERITY=$(echo "$issue" | grep -o '"severity":"[^"]*"' | cut -d'"' -f4)
        LINE=$(echo "$issue" | grep -o '"line":[0-9]*' | cut -d':' -f2)
        MESSAGE=$(echo "$issue" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
        
        case "$SEVERITY" in
            "BLOCKER"|"CRITICAL") echo -e "${RED}  ❌ $TYPE: $MESSAGE (line $LINE)${NC}" ;;
            "MAJOR") echo -e "${YELLOW}  ⚠️  $TYPE: $MESSAGE (line $LINE)${NC}" ;;
            *) echo -e "     $TYPE: $MESSAGE (line $LINE)" ;;
        esac
    done
else
    echo -e "${GREEN}✅ No issues found${NC}"
fi

# Get Analysis Date
print_section "Analysis Information"
ANALYSIS_RESPONSE=$(curl -s -H "Authorization: Bearer $SONAR_TOKEN" \
    "$SONAR_URL/api/project_analyses/search?project=$PROJECT_KEY&ps=1")

if echo "$ANALYSIS_RESPONSE" | grep -q '"date"'; then
    ANALYSIS_DATE=$(echo "$ANALYSIS_RESPONSE" | grep -o '"date":"[^"]*"' | head -1 | cut -d'"' -f4)
    echo -e "   Last Analysis: $ANALYSIS_DATE"
fi

# Footer
echo -e "\n${BLUE}===============================================${NC}"
echo -e "${BLUE}📊 View detailed results at:${NC}"
echo -e "${BLUE}   $SONAR_URL/dashboard?id=$PROJECT_KEY${NC}"
echo -e "${BLUE}===============================================${NC}"
