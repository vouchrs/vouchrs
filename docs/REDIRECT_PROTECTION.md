# Redirect Protection in Vouchrs

## Overview

Vouchrs implements focused redirect protection that targets user-facing post-authentication redirects.

### Why This Matters

1. **User-Controlled Post-Auth Redirects**: These come from OAuth state/redirect parameters and can be manipulated by attackers - require comprehensive protection

## Protection Scope

### Protected: Post-Authentication Redirects

- ✅ User-controlled redirect URLs from OAuth state
- ✅ Post-login redirect destinations  
- ✅ Callback redirect parameters
- ✅ User-specified return URLs

## Implementation Architecture

### 1. Layered Security Architecture

We employ a multi-layered defense:

1. **Fast Path Validation**: Quickly validates common legitimate patterns (`/api/`, `/static/`, `/health`)
2. **Critical Pattern Check**: Simple, high-confidence attack detection
3. **URL Decode & Re-check**: Catches encoded attack attempts
4. **String-based Protocol Detection**: Simple substring matching for dangerous protocols
5. **URL Construction with Rust's URL Parser**: Proper normalization and canonicalization
6. **Final Validation**: Multiple security checks on the constructed URL

### 2. Separate Focused Regex Patterns

**OAuth2 Proxy Approach**: An efficient regex with allowlists:
```go
// Used to check final redirects are not susceptible to open redirects.
// Matches //, /\ and both of these with whitespace in between (eg / / or / \).
invalidRedirectRegex = regexp.MustCompile(`[/\\](?:[\s\v]*|\.{1,2})[/\\]`)
```

Their approach is focused on:
1. Checking if a redirect is relative and doesn't start with `//`
2. Using a simple regex to detect path traversal with whitespace
3. For absolute URLs, validating against an allowlist of domains
4. No protection against encoded attacks, Unicode spoofing, or other bypass techniques

**Our Approach**: Three simple, focused patterns:
```rust
// Core path traversal pattern
static PATH_TRAVERSAL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\.\.").unwrap()
});

// Protocol injection for absolute URLs
static PROTOCOL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(?:[a-z][a-z0-9+.-]*:)|(?:/{2,})").unwrap()
});

// Critical control characters and suspicious path starters
static SUSPICIOUS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)[\x00-\x1F\x7F-\x9F]|%(?:00|0[aAdD]|09|5c|26%23)|^[.@〱〵ゝーｰ]|\\|[\u{200E}\u{200F}\u{2060}-\u{2064}\u{2000}-\u{200A}]").unwrap()
});
```

This approach results in:
- **Improved Performance**: Simpler patterns compile and execute faster
- **Better Maintainability**: Easier to understand, review, and update
- **Enhanced Security**: Targeted patterns with layered validation

### 3. Extended Test Coverage

We maintain a comprehensive test suite of malicious URLs:

1. **Updated Test File**: Our `tests/openredirects.txt` contains 692 attack vectors, using oauth2-proxy's test data as a starting point and expanding it
2. **Custom Test Cases**: Added implementation-specific test vectors targeting:
   - Unicode spoofing attacks
   - Unicode control character injection
   - Multi-encoding bypass attempts
   - Domain confusion attacks with multiple `@` symbols
   - SSRF attack vectors with IP addresses

### 4. Performance Optimizations

- **Early Returns**: Stop processing as soon as an attack is detected
- **Fast Path**: Quick validation for common legitimate patterns
- **Pre-allocated Collections**: `Vec::with_capacity()` for decoded variants
- **Simple String Matching**: For protocol detection instead of complex regex

## Security Considerations

### Comprehensive Protection Against

1. **Path Traversal**: (`../`, encoded variants) - Blocks attempts to access unauthorized files
2. **Protocol Injection**: (`javascript:`, `data:`, `//evil.com`) - Prevents arbitrary URL schemes
3. **Domain Confusion**: (double `@` symbols, Unicode spoofing) - Avoids URL authority confusion
4. **Control Characters**: (null bytes, newlines, etc.) - Prevents header injection attacks
5. **Unicode Spoofing**: (lookalike characters) - Blocks homograph attacks
6. **SSRF Protection**: (IP address blocking) - Prevents server-side request forgery

### Validation Architecture

![Validation Flow](https://vouchrs.com/docs/images/redirect-protection.svg)

1. **Pattern Validation**: Fast pattern matching for known attacks
2. **Decoding Layer**: Handles URL encoding, double encoding
3. **URL Construction**: Proper parsing and normalization
4. **Host Validation**: SSRF protection, IP blocking
5. **Scheme Validation**: Restricts to safe protocols

## Integration and Usage

The redirect protection is integrated into post-authentication workflows through the `ResponseBuilder::validate_post_auth_redirect` method:

```rust
// In callback.rs - Post-authentication redirect handling
let validated_redirect = match ResponseBuilder::validate_post_auth_redirect(&redirect_to) {
    Ok(url) => url,
    Err(e) => {
        warn!("Invalid post-auth redirect URL '{}': {}", redirect_to, e);
        "/".to_string() // Safe fallback to home page
    }
};
```

### Key Integration Points

1. **OAuth Callback Handler**: Validates redirect URLs from OAuth state parameters
2. **Session Finalization**: Ensures post-login redirects are safe
3. **User-Controlled URLs**: Any redirect that comes from user input or external parameters

### Simplified Upstream URL Building

For admin-controlled upstream URLs, we use a simplified approach without redirect protection:

```rust
pub fn build_upstream_url(base_url: &str, request_path: &str) -> Result<String, HttpResponse> {
    // Simple URL construction for admin-controlled upstream URLs
    let base = url::Url::parse(base_url)
        .map_err(|_| HttpResponse::InternalServerError().body("Invalid base URL"))?;
    
    let clean_path = request_path.trim_start_matches('/');
    let final_url = base.join(clean_path)
        .map_err(|_| HttpResponse::InternalServerError().body("Invalid URL path"))?;
    
    Ok(final_url.to_string())
}
```

## Conclusion

Our redirect protection implementation focuses on where open redirect vulnerabilities actually matter - user-controlled post-authentication redirects. By combining:

1. **Focused Protection Scope**: Target user-controlled redirects while simplifying admin-controlled URL handling
2. **Layered Validation**: Multi-stage security checks for maximum protection
3. **Comprehensive Attack Coverage**: Protection against 692+ known attack vectors
4. **Performance Optimization**: Fast pattern matching with early returns
5. **Modern Security Principles**: Clear separation between trusted and untrusted inputs

This approach ensures robust security against actual open redirect attack vectors while maintaining high performance and code clarity. The security policy change from protecting all URLs to focusing on user-controlled post-authentication redirects provides better security with improved maintainability.
