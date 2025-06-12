#!/bin/bash

# Clear problematic GitHub Actions caches that might be causing hangs
# This script uses the GitHub CLI to clear caches

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🧹 Clearing GitHub Actions caches to resolve Docker build hangs${NC}"

# Get repository info
REPO=$(gh repo view --json owner,name -q '.owner.login + "/" + .name')
echo -e "${GREEN}Repository: ${REPO}${NC}"

# List current caches
echo -e "\n${YELLOW}📋 Current caches:${NC}"
gh api repos/${REPO}/actions/caches --paginate -q '.actions_caches[] | select(.key | test("vouchrs")) | {key, size_in_bytes, created_at}'

# Cache keys to clear (the problematic ones)
CACHE_KEYS=(
    "vouchrs-docker"
    "vouchrs-docker-dev"
    "vouchrs-docker-release"
    "vouchrs-docker-deps"
)

echo -e "\n${YELLOW}🗑️  Clearing problematic cache scopes...${NC}"

for key in "${CACHE_KEYS[@]}"; do
    echo -e "Clearing caches matching: ${key}"

    # Get cache IDs matching the key pattern
    CACHE_IDS=$(gh api repos/${REPO}/actions/caches --paginate -q ".actions_caches[] | select(.key | startswith(\"${key}\")) | .id")

    if [ -n "$CACHE_IDS" ]; then
        while IFS= read -r cache_id; do
            if [ -n "$cache_id" ]; then
                echo -e "  Deleting cache ID: $cache_id"
                gh api --method DELETE repos/${REPO}/actions/caches/${cache_id} || echo -e "  ${RED}Failed to delete cache ${cache_id}${NC}"
            fi
        done <<< "$CACHE_IDS"
    else
        echo -e "  No caches found matching: ${key}"
    fi
done

echo -e "\n${GREEN}✅ Cache cleanup completed!${NC}"
echo -e "${YELLOW}💡 Tip: Your next Docker build will start fresh and should not hang.${NC}"

# Show remaining caches
echo -e "\n${YELLOW}📋 Remaining caches:${NC}"
gh api repos/${REPO}/actions/caches --paginate -q '.actions_caches[] | select(.key | test("vouchrs")) | {key, size_in_bytes, created_at}'
