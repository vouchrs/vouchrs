#!/bin/bash
set -e

# Vouchrs Release Script
# This script helps create a new release with automatic version updates

echo "🚀 Vouchrs Release Creator"
echo "=========================="

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -f "cliff.toml" ]; then
    echo "❌ This script must be run from the project root directory"
    exit 1
fi

# Check if git-cliff is installed
if ! command -v git-cliff &> /dev/null; then
    echo "❌ git-cliff is not installed. Install it with: cargo install git-cliff"
    exit 1
fi

# Check if cargo-edit is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ cargo is not installed"
    exit 1
fi

# Get current version
current_version=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo "📦 Current version: $current_version"

# Get new version
echo ""
read -p "Enter new version (e.g., 1.0.0): " new_version

# Validate version format
if [[ ! "$new_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
    echo "❌ Invalid version format. Use semantic versioning (e.g., 1.0.0, 1.0.0-beta.1)"
    exit 1
fi

# Check if tag already exists
if git rev-parse "v$new_version" >/dev/null 2>&1; then
    echo "❌ Tag v$new_version already exists"
    exit 1
fi

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ You have uncommitted changes. Please commit or stash them first."
    git status --short
    exit 1
fi

echo ""
echo "🔄 Updating version from $current_version to $new_version..."

# Install cargo-edit if not available
if ! cargo set-version --help &> /dev/null; then
    echo "📦 Installing cargo-edit..."
    cargo install cargo-edit
fi

# Update Cargo.toml version
cargo set-version "$new_version"
echo "✅ Updated Cargo.toml version"

# Update Cargo.lock
cargo check > /dev/null 2>&1
echo "✅ Updated Cargo.lock"

# Generate changelog
echo "📝 Generating changelog..."
git cliff --tag "v$new_version" --output CHANGELOG.md
echo "✅ Generated changelog"

# Show what changed
echo ""
echo "📋 Changes to be committed:"
git diff --name-only

# Preview the release notes
echo ""
echo "📖 Release notes preview:"
echo "========================="
if [ -f CHANGELOG.md ]; then
    # Extract the section for this version
    awk -v version="$new_version" '
        /^## \[/ {
            if (found) exit
            if ($0 ~ "\\[" version "\\]") {
                found=1
                next
            }
        }
        found && /^## \[/ { exit }
        found { print }
    ' CHANGELOG.md | head -20
else
    echo "Release v$new_version"
fi
echo "========================="

# Confirm
echo ""
read -p "Create release v$new_version? (Y/n): " confirm

if [ "$confirm" = "n" ] || [ "$confirm" = "N" ]; then
    echo "❌ Release cancelled. Reverting changes..."
    git checkout -- Cargo.toml Cargo.lock CHANGELOG.md
    exit 0
fi

# Commit changes
echo ""
echo "💾 Committing changes..."
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): prepare for v$new_version"
echo "✅ Committed version bump and changelog"

# Create a release branch
echo "🌿 Creating release branch..."
RELEASE_BRANCH="release/v$new_version"
git checkout -b "$RELEASE_BRANCH"
echo "✅ Created branch $RELEASE_BRANCH"

# Ask about pushing
echo ""
read -p "Push branch to origin and create a PR? (Y/n): " push_confirm

if [ "$push_confirm" != "n" ] && [ "$push_confirm" != "N" ]; then
    echo "⬆️  Pushing to origin..."
    git push origin $RELEASE_BRANCH
    echo "✅ Pushed release branch"

    echo ""
    echo "🎉 Release branch for v$new_version created successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Go to GitHub and create a PR from $RELEASE_BRANCH to main"
    echo "2. OR use the 'Create Release' GitHub Action workflow instead (recommended)"
    echo "3. After the PR is merged, main-release workflow will automatically:"
    echo "   - Create the version tag"
    echo "   - Create the GitHub release with changelog"
    echo "   - Build and push Docker images"
else
    echo "ℹ️  Changes committed locally but not pushed."
    echo "   Push manually with: git push origin $(git branch --show-current) && git push origin v$new_version"
fi

echo ""
echo "✨ Done!"
