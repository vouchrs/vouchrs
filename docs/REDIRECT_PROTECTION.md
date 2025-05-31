# Redirect Protection in Vouchrs

## Overview

Vouchrs implements a robust, layered approach to redirect protection that builds upon the open-source OAuth2 Proxy implementation. Our approach combines efficient pattern matching with comprehensive URL validation to prevent open redirect vulnerabilities while maintaining high performance.

## Enhancements Over OAuth2 Proxy

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

The redirect protection is integrated into the `ResponseBuilder::build_upstream_url` method, which ensures all redirects are properly validated before being returned to clients:

```rust
pub fn build_upstream_url(base_url: &str, request_path: &str) -> Result<String, HttpResponse> {
    debug!("Building upstream URL - base: {}, path: {}", base_url, request_path);
    
    // Layer 1: Fast pattern validation with early returns
    Self::validate_suspicious_patterns(request_path)?;
    
    // Layer 2: URL construction with normalization
    let final_url = Self::construct_normalized_url(base_url, request_path)?;
    
    // Layer 3: Final URL validation (scheme, host, port)
    Self::validate_final_url(base_url, &final_url)?;
    
    debug!("Successfully validated URL: {}", final_url);
    Ok(final_url)
}
```

## Conclusion

Our redirect protection implementation builds upon the oauth2-proxy approach by combining:

1. Separate focused regex patterns
2. Multi-layered validation
3. Comprehensive test coverage
4. Performance optimizations
5. Modern URL parsing techniques

This approach tries to ensure robust security while maintaining high performance and code maintainability, providing effective protection against open redirect vulnerabilities.
