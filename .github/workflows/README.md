# GitHub Actions Workflows

This repository uses GitHub Actions for continuous integration, continuous deployment, and automated Docker image builds.

## Workflows

### 1. CI/CD (`ci.yml`)

**Triggers:** Push to `main`/`dev` branches, Pull requests to `main`

**Jobs:**
- **Test**: Runs Rust formatting checks, Clippy linting, and tests
- **Security Audit**: Performs security vulnerability scanning with `cargo audit`
- **Docker Build Test**: Builds Docker image without pushing to verify it works

### 2. Docker Build and Push (`docker.yml`)

**Triggers:** 
- Push to `main`/`dev` branches
- Push of version tags (`v*`)
- Pull requests to `main`/`dev`

**Features:**
- Builds multi-platform images (linux/amd64, linux/arm64)
- Pushes to GitHub Container Registry (ghcr.io)
- Uses intelligent tagging based on git refs
- Includes build provenance attestation for security
- Leverages GitHub Actions cache for faster builds

**Tags Generated:**
- `main` branch → `latest` tag
- `dev` branch → `dev` tag
- Version tags (`v1.2.3`) → `1.2.3`, `1.2`, `1`, `latest`
- PR branches → `pr-123` (not pushed, build only)

### 3. Release (`release.yml`)

**Triggers:** GitHub release published

**Features:**
- Builds and pushes production Docker images
- Creates semantic version tags (`1.0.0`, `1.0`, `1`, `latest`)
- Adds Docker pull instructions to release notes
- Includes comprehensive OCI labels
- Generates signed build attestations

## Docker Image Registry

Images are published to GitHub Container Registry:

```bash
# Pull the latest version
docker pull ghcr.io/vouchrs/vouchrs:latest

# Pull a specific version
docker pull ghcr.io/vouchrs/vouchrs:1.0.0
```

## Setup Requirements

### Repository Settings

1. **Enable GitHub Packages**: Go to repository Settings → General → Features → Packages (should be enabled by default)

2. **GITHUB_TOKEN Permissions**: The workflows use the built-in `GITHUB_TOKEN` which automatically has the required permissions for GHCR.

### Branch Protection (Recommended)

Consider setting up branch protection rules for `main`:

1. Go to Settings → Branches
2. Add rule for `main` branch
3. Enable:
   - Require status checks to pass before merging
   - Require branches to be up to date before merging
   - Select the CI jobs as required status checks

## Image Features

- **Multi-platform**: Built for both AMD64 and ARM64 architectures
- **Ultra-minimal**: Uses distroless static base image for security
- **Statically linked**: No runtime dependencies required
- **Optimized**: Built with size optimization flags
- **Secure**: Runs as non-root user, includes build attestations

## Local Testing

To test the Docker build locally:

```bash
# Build the image
docker build -f docker/Dockerfile -t vouchrs:test .

# Run the container
docker run -p 8080:8080 vouchrs:test
```

## Troubleshooting

### Build Failures

1. **Rust compilation errors**: Check the CI workflow logs, ensure code compiles locally
2. **Docker build failures**: Verify Dockerfile syntax and that all copied files exist
3. **Registry push failures**: Check repository permissions and GITHUB_TOKEN scope

### Cache Issues

If builds are slow or failing due to cache issues:

1. Go to Actions → Caches in your repository
2. Delete relevant caches to force a clean build
3. The next build will recreate the cache

## Security

- All images include build provenance attestations
- Images are signed and can be verified
- Uses minimal attack surface with distroless base
- Runs as non-root user
- Regular security audits via `cargo audit`
