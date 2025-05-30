#!/bin/bash

# Build and run script for Vouchrs OIDC Reverse Proxy

set -e

IMAGE_NAME="vouchrs"
TAG="latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [build|run|push|clean] [options]"
    echo ""
    echo "Commands:"
    echo "  build    Build the Docker image"
    echo "  run      Run the container"
    echo "  push     Push to registry (requires TAG environment variable)"
    echo "  clean    Remove the Docker image"
    echo ""
    echo "Options:"
    echo "  --alpine     Use Alpine-based Dockerfile"
    echo "  --static     Use distroless static Dockerfile (smallest)"
    echo "  --tag TAG    Set image tag (default: latest)"
    echo ""
    echo "Environment variables for run:"
    echo "  GOOGLE_CLIENT_ID     - Required for Google OAuth"
    echo "  GOOGLE_CLIENT_SECRET - Required for Google OAuth"
    echo "  PORT                 - Port to run on (default: 8080)"
}

build_image() {
    local dockerfile="docker/Dockerfile"
    local build_desc="distroless Debian"
    
    if [[ "$1" == "--alpine" ]]; then
        dockerfile="docker/Dockerfile.alpine"
        build_desc="Alpine Linux"
        echo -e "${YELLOW}Building with Alpine-based Dockerfile...${NC}"
    elif [[ "$1" == "--static" ]]; then
        dockerfile="docker/Dockerfile.distroless-static"
        build_desc="distroless static"
        echo -e "${YELLOW}Building with distroless static Dockerfile (smallest)...${NC}"
    else
        echo -e "${YELLOW}Building with distroless Debian Dockerfile...${NC}"
    fi

    echo -e "${GREEN}Building image: ${IMAGE_NAME}:${TAG} (${build_desc})${NC}"
    # Change to parent directory to build from project root
    cd "$(dirname "$0")/.." && docker build -f "$dockerfile" -t "${IMAGE_NAME}:${TAG}" .
    
    # Show image size
    echo -e "${GREEN}Image built successfully!${NC}"
    docker images "${IMAGE_NAME}:${TAG}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
}

run_container() {
    echo -e "${GREEN}Running container: ${IMAGE_NAME}:${TAG}${NC}"
    
    # Check for required environment variables
    if [[ -z "$GOOGLE_CLIENT_ID" || -z "$GOOGLE_CLIENT_SECRET" ]]; then
        echo -e "${RED}Error: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables are required${NC}"
        echo "Please set them before running:"
        echo "export GOOGLE_CLIENT_ID='your-client-id'"
        echo "export GOOGLE_CLIENT_SECRET='your-client-secret'"
        exit 1
    fi
    
    local port="${PORT:-8080}"
    
    docker run -it --rm \
        -p "${port}:8080" \
        -e GOOGLE_CLIENT_ID="$GOOGLE_CLIENT_ID" \
        -e GOOGLE_CLIENT_SECRET="$GOOGLE_CLIENT_SECRET" \
        -e REDIRECT_BASE_URL="http://localhost:${port}" \
        -e COOKIE_SECURE="false" \
        "${IMAGE_NAME}:${TAG}"
}

push_image() {
    if [[ -z "$REGISTRY" ]]; then
        echo -e "${RED}Error: REGISTRY environment variable not set${NC}"
        echo "Example: export REGISTRY=ghcr.io/username"
        exit 1
    fi
    
    local full_image="${REGISTRY}/${IMAGE_NAME}:${TAG}"
    echo -e "${GREEN}Tagging and pushing to: ${full_image}${NC}"
    
    docker tag "${IMAGE_NAME}:${TAG}" "$full_image"
    docker push "$full_image"
}

clean_image() {
    echo -e "${YELLOW}Removing image: ${IMAGE_NAME}:${TAG}${NC}"
    docker rmi "${IMAGE_NAME}:${TAG}" 2>/dev/null || echo "Image not found"
}

# Parse arguments
ALPINE_FLAG=""
STATIC_FLAG=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --alpine)
            ALPINE_FLAG="--alpine"
            shift
            ;;
        --static)
            STATIC_FLAG="--static"
            shift
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        build|run|push|clean)
            COMMAND="$1"
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Execute command
case "${COMMAND:-}" in
    build)
        if [[ -n "$STATIC_FLAG" ]]; then
            build_image "$STATIC_FLAG"
        else
            build_image "$ALPINE_FLAG"
        fi
        ;;
    run)
        run_container
        ;;
    push)
        push_image
        ;;
    clean)
        clean_image
        ;;
    *)
        echo -e "${RED}Error: No command specified${NC}"
        print_usage
        exit 1
        ;;
esac
