# Conventional Commits Guide for Vouchrs

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automatic changelog generation.

## Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

## Types

- `feat`: New features (🚀 Features)
- `fix`: Bug fixes (🐛 Bug Fixes)
- `docs`: Documentation changes (📚 Documentation)
- `style`: Code style changes (🎨 Styling)
- `refactor`: Code refactoring (🚜 Refactor)
- `perf`: Performance improvements (⚡ Performance)
- `test`: Adding or modifying tests (🧪 Testing)
- `chore`: Maintenance tasks (⚙️ Miscellaneous Tasks)
- `ci`: CI/CD changes (⚙️ Miscellaneous Tasks)
- `deps`: Dependency updates (⬆️ Dependencies)

## Examples

### Basic commits:
```bash
feat: add JWT token validation
fix: resolve memory leak in session handler
docs: update API documentation
test: add OAuth flow integration tests
chore: update dependencies
```

### With scope (recommended for larger features):
```bash
feat(auth): implement Apple Sign-In support
fix(oauth): handle token refresh edge cases
docs(api): add endpoint documentation
test(session): add validation unit tests
refactor(proxy): extract upstream handling logic
```

### Breaking changes:
```bash
feat!: change session storage format
feat(auth)!: require API key for all endpoints

# Or with footer:
feat(auth): add new authentication method

BREAKING CHANGE: Sessions now require user context
```

## Benefits

- Automatic changelog generation
- Clear commit history
- Easier code review
- Semantic versioning support
- Better collaboration

## Automation

- Changelog is automatically generated on releases
- Only conventional commits appear in the changelog
- Non-conventional commits are ignored
- Release notes are automatically updated

## Manual Testing

Test your commit format locally:

```bash
# Generate changelog for unreleased changes
git cliff --unreleased

# Generate full changelog
git cliff
```
