# Vouchrs Development Guide

A concise guide to understanding and contributing to the Vouchrs authentication proxy codebase.

## Architecture Overview

Vouchrs is a stateless, high-performance authentication proxy built with Rust and Actix-web. The core principle is **encrypted HTTP-only cookies for session state**, eliminating server-side session storage.

### Key Architectural Principles

- **Stateless Authentication**: All session data stored in encrypted cookies
- **Separation of Concerns**: Clear module boundaries with focused responsibilities
- **Security-First**: AES-256-GCM encryption, CSRF protection, session hijacking prevention
- **Builder Patterns**: Fluent APIs for responses, requests, and test objects

## Module Organization

```
src/
├── handlers/         # HTTP request handlers (thin layer)
├── session/          # Encrypted session management
├── oauth/            # OAuth provider integration
├── passkey/          # WebAuthn/passkey authentication
├── utils/
│   ├── responses.rs  # Unified HTTP response builders
│   ├── headers.rs    # Header processing and forwarding
│   └── crypto.rs     # Encryption utilities
├── validation/       # Input validation and security checks
└── testing/          # Test utilities and builders
```

### Module Responsibilities

- **Handlers**: Thin HTTP adapters, delegate to services
- **Session**: Stateless session management with encrypted cookies
- **OAuth/Passkey**: Authentication method implementations
- **Utils**: Shared utilities (responses, headers, crypto)
- **Validation**: Security-focused input validation
- **Testing**: Comprehensive test builders and assertions

## Response System (`utils/responses.rs`)

The unified response system provides consistent HTTP responses across the application.

### Basic Usage

```rust
use crate::utils::responses::ResponseBuilder;

// Error responses
let response = ResponseBuilder::bad_request()
    .with_error_code("invalid_field")
    .with_message("Missing required field: email")
    .build();

// Success with redirect
let response = ResponseBuilder::redirect("https://app.example.com")
    .with_cookie(session_cookie)
    .build();

// JSON responses
let response = ResponseBuilder::ok()
    .json(&user_data);
```

### Key Features

- **Cached Responses**: Pre-serialized common errors for performance
- **Fluent Interface**: Method chaining for complex responses
- **Cookie Integration**: Built-in session cookie handling
- **Error Consistency**: Standardized error format across endpoints

## Header Processing (`utils/headers.rs`)

Handles HTTP header forwarding and processing for the proxy functionality.

### Usage

```rust
use crate::utils::headers::{forward_request_headers, is_browser_request};

// Forward headers to upstream (filters auth/session cookies)
let request_builder = forward_request_headers(&req, request_builder);

// Detect request type
if is_browser_request(&req) {
    // Handle browser redirect
} else {
    // Return JSON error
}
```

### Features

- **Security Filtering**: Removes hop-by-hop headers and auth cookies
- **Platform Detection**: User-agent analysis for client optimization
- **Request Classification**: Browser vs API client detection

## Session Management (`session/`)

Stateless encrypted session handling without server-side storage.

### Core Concept

```rust
// Sessions are encrypted into HTTP-only cookies
let session_cookie = session_manager.create_session_cookie(&session)?;
let user_cookie = session_manager.create_user_cookie(&user_data)?;

// Session data is split across two cookies:
// - vouchrs_session: tokens, credentials, expiry
// - vouchrs_user: profile data, client context
```

### Security Features

- **Client Context Validation**: Prevents session hijacking
- **IP/User-Agent Binding**: Detects context changes
- **Automatic Refresh**: Token refresh without re-authentication
- **CSRF Protection**: Secure state parameter handling

## Testing Framework (`testing/`)

Comprehensive testing utilities for all components.

### Test Builders

```rust
use crate::testing::{TestFixtures, TestSessionBuilder, RequestBuilder};

// Create test sessions
let session = TestSessionBuilder::new()
    .with_provider("github")
    .expires_in_hours(2)
    .build();

// Create test requests
let req = RequestBuilder::new()
    .browser_headers()
    .with_session_cookie(session_value)
    .build();

// Use fixtures for common objects
let session_manager = TestFixtures::session_manager();
let user_data = TestFixtures::user_data();
```

### Assertions

```rust
use crate::testing::assertions::*;

assert_valid_session(&session);
assert_header_present(&response, "Location");
assert_oauth_session(&session);
```

## Development Workflow

### Code Quality Tools

The project enforces strict code quality:

```bash
# Formatting (always use)
cargo fmt

# Linting (pedantic mode)
cargo clippy

# All warnings treated as errors
# See .cargo/config.toml for configuration
```

### Testing

```bash
# Run all tests
cargo test

# Integration tests
cargo test --test integration_test

# Feature-specific tests
cargo test --features passkeys
```

### Build & Run

```bash
# Development
cargo run

# Production build
cargo build --release

# Check without building
cargo check
```

## Key Development Patterns

### Response Building

Always use `ResponseBuilder` for consistency:

```rust
// ✅ Good - unified response
ResponseBuilder::authentication_failed("Invalid credentials")

// ❌ Avoid - direct HttpResponse
HttpResponse::Unauthorized().json(...)
```

### Error Handling

Use the standardized error patterns:

```rust
// ✅ Good - descriptive errors
ResponseBuilder::invalid_field("email", "must be valid format")

// ✅ Good - use cached responses for performance
ResponseBuilder::invalid_token()
```

### Session Handling

Always validate sessions appropriately:

```rust
// For proxy requests (basic validation)
let session = session_manager.decrypt_and_validate_session(cookie_value)?;

// For sensitive operations (with hijacking protection)
session_manager.validate_session_security(&user_data, &req)?;
```

### Testing

Use builders for consistent test objects:

```rust
// ✅ Good - use builders
let session = TestSessionBuilder::passkey()
    .with_credentials("cred_id", "user_handle")
    .build();

// ✅ Good - use fixtures for common objects
let manager = TestFixtures::session_manager();
```

## Security Considerations

### Session Security

- All session data encrypted with AES-256-GCM
- Client context validation prevents session hijacking
- Automatic session refresh with configurable timeouts
- HTTP-only, secure, SameSite cookies

### Input Validation

- Use `validation/` module for all user inputs
- Sanitize redirect URLs to prevent open redirects
- Validate OAuth state parameters to prevent CSRF
- Check Content-Type headers for API endpoints

### Header Processing

- Remove authorization headers when forwarding
- Filter out session cookies from upstream requests
- Validate hop-by-hop headers per RFC specifications

## Common Patterns

### Authentication Flow

1. Create encrypted state parameter
2. Redirect to OAuth provider
3. Validate callback state and exchange tokens
4. Create encrypted session cookies
5. Redirect to application with cookies

### Request Handling

1. Extract and validate session
2. Check authentication status
3. Forward request to upstream (with header filtering)
4. Return response (potentially refreshing session)

### Testing Flow

1. Create test fixtures with builders
2. Set up request context
3. Execute handler or service method
4. Assert response and side effects

## CI/CD Integration

The project uses automated workflows:

- **Conventional Commits**: For automatic changelog generation
- **Cargo fmt/clippy**: Enforced in CI (pedantic mode)
- **Security Audits**: Automated dependency scanning
- **Multi-platform Builds**: Docker images for ARM64/AMD64

Follow conventional commit format:
```bash
git commit -m "feat(auth): add Apple Sign-In support"
git commit -m "fix(session): resolve memory leak in validation"
```

This ensures automatic version bumping and changelog generation.
