use actix_web::HttpResponse;
use regex::Regex;
use once_cell::sync::Lazy;
use log::{debug, warn};
use url;

// Simplified security patterns - rely on layered validation rather than complex regex
// Focus on high-confidence attack patterns that URL parsing won't catch

// Core path traversal pattern - the most common and critical attack
static PATH_TRAVERSAL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\.\.").unwrap()
});

// Protocol injection for absolute URLs that could bypass URL parsing
static PROTOCOL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(?:[a-z][a-z0-9+.-]*:)|(?:/{2,})").unwrap()
});

// Critical control characters and suspicious path starters
static SUSPICIOUS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)[\x00-\x1F\x7F-\x9F]|%(?:00|0[aAdD]|09|5c|26%23)|^[.@〱〵ゝーｰ]|\\|[\u{200E}\u{200F}\u{2060}-\u{2064}\u{2000}-\u{200A}]").unwrap()
});

// Allowed schemes for the final URL
const ALLOWED_SCHEMES: &[&str] = &["http", "https", "ws", "wss"];

/// Validate post-authentication redirect URLs to prevent open redirect attacks
/// This protects user-facing redirects where open redirect vulnerabilities matter
pub fn validate_post_auth_redirect(redirect_url: &str) -> Result<String, HttpResponse> {
    debug!("Validating post-authentication redirect URL: {}", redirect_url);
    
    // Layer 1: Fast pattern validation with early returns
    validate_suspicious_patterns(redirect_url)?;
    
    // Layer 2: Check for relative URLs (most common legitimate case)
    if is_relative_url(redirect_url) {
        // For relative URLs, just normalize and validate patterns
        let normalized = normalize_relative_url(redirect_url)?;
        debug!("Validated relative redirect URL: {}", normalized);
        return Ok(normalized);
    }
    
    // Layer 3: For absolute URLs, perform full validation
    let final_url = validate_absolute_redirect_url(redirect_url)?;
    
    debug!("Successfully validated redirect URL: {}", final_url);
    Ok(final_url)
}

/// Check if URL is relative (starts with /, not //, and has no scheme)
fn is_relative_url(url: &str) -> bool {
    url.starts_with('/') && !url.starts_with("//") && !url.contains(':')
}

/// Normalize relative URLs and validate against attacks
fn normalize_relative_url(url: &str) -> Result<String, HttpResponse> {
    // Basic length check
    if url.len() > 2048 {
        warn!("Excessively long redirect URL: {} characters", url.len());
        return Err(invalid_redirect_error());
    }
    
    // Check decoded variants for attacks
    validate_encoded_patterns(url)?;
    
    Ok(url.to_string())
}

/// Validate absolute redirect URLs with comprehensive checks
fn validate_absolute_redirect_url(redirect_url: &str) -> Result<String, HttpResponse> {
    // Parse the URL
    let parsed = url::Url::parse(redirect_url)
        .map_err(|e| {
            warn!("Failed to parse redirect URL '{}': {}", redirect_url, e);
            invalid_redirect_error()
        })?;

    // Validate scheme is in allowed list
    if !ALLOWED_SCHEMES.contains(&parsed.scheme()) {
        warn!("Invalid scheme '{}' in redirect URL: {}", parsed.scheme(), redirect_url);
        return Err(invalid_redirect_error());
    }

    // Check for suspicious hosts (SSRF protection)
    if let Some(host) = parsed.host_str() {
        if is_suspicious_host(host) {
            warn!("Suspicious host detected in redirect: {}", host);
            return Err(invalid_redirect_error());
        }
    }

    Ok(redirect_url.to_string())
}

/// Return standardized error for invalid redirect URLs
fn invalid_redirect_error() -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({
        "error": "bad_request",
        "message": "Invalid redirect URL"
    }))
}

/// Validate against malicious patterns using simplified, high-confidence patterns
/// Used for post-authentication redirect validation
fn validate_suspicious_patterns(request_path: &str) -> Result<(), HttpResponse> {
    // Fast path: check for common legitimate patterns first
    if request_path.starts_with("/api/") || 
       request_path.starts_with("/static/") ||
       request_path.starts_with("/health") {
        // Still need to check for critical attacks in legitimate-looking paths
        return validate_critical_patterns(request_path);
    }
    
    // Check for path traversal (most critical and common)
    if PATH_TRAVERSAL_PATTERN.is_match(request_path) {
        warn!("Path traversal attempt detected: {}", request_path);
        return Err(invalid_redirect_error());
    }
    
    // Check for protocol injection (absolute URLs)
    if PROTOCOL_PATTERN.is_match(request_path) {
        warn!("Protocol injection attempt detected: {}", request_path);
        return Err(invalid_redirect_error());
    }
    
    // Check for control characters (should never be in legitimate paths)
    if SUSPICIOUS_PATTERN.is_match(request_path) {
        warn!("Suspicious pattern detected: {}", request_path);
        return Err(invalid_redirect_error());
    }
    
    // Check decoded variants for encoded attacks
    validate_encoded_patterns(request_path)
}

/// Validate critical patterns that should be checked even in legitimate-looking paths
fn validate_critical_patterns(request_path: &str) -> Result<(), HttpResponse> {
    // Only check the most critical patterns for performance
    if PATH_TRAVERSAL_PATTERN.is_match(request_path) ||
       SUSPICIOUS_PATTERN.is_match(request_path) {
        warn!("Critical attack pattern in legitimate path: {}", request_path);
        return Err(invalid_redirect_error());
    }
    
    // Check for double-encoded path traversal
    if let Ok(decoded) = urlencoding::decode(request_path) {
        if PATH_TRAVERSAL_PATTERN.is_match(&decoded) {
            warn!("Encoded path traversal detected: {} -> {}", request_path, decoded);
            return Err(invalid_redirect_error());
        }
    }
    
    Ok(())
}

/// Validate URL-decoded patterns for encoded attack attempts
/// Used for post-authentication redirect validation
fn validate_encoded_patterns(request_path: &str) -> Result<(), HttpResponse> {
    // Get decoded variants to check for encoded attacks
    let decoded_variants = get_decoded_variants(request_path);
    
    for decoded in decoded_variants {
        // Check critical patterns on decoded content
        if PATH_TRAVERSAL_PATTERN.is_match(&decoded) {
            warn!("Encoded path traversal detected: {} -> {}", request_path, decoded);
            return Err(invalid_redirect_error());
        }
        
        if PROTOCOL_PATTERN.is_match(&decoded) {
            warn!("Encoded protocol injection detected: {} -> {}", request_path, decoded);
            return Err(invalid_redirect_error());
        }
        
        if SUSPICIOUS_PATTERN.is_match(&decoded) {
            warn!("Encoded suspicious pattern detected: {} -> {}", request_path, decoded);
            return Err(invalid_redirect_error());
        }
        
        // Simple string-based checks for dangerous protocols (more reliable than complex regex)
        let decoded_lower = decoded.to_lowercase();
        if contains_dangerous_protocol(&decoded_lower) {
            warn!("Dangerous protocol detected: {}", decoded_lower);
            return Err(invalid_redirect_error());
        }
        
        // Check for double @ patterns (domain confusion)
        if decoded.matches('@').count() > 1 {
            warn!("Multiple @ symbols detected (domain confusion): {}", decoded);
            return Err(invalid_redirect_error());
        }
    }
    
    Ok(())
}

/// Get decoded variants of the input path
fn get_decoded_variants(request_path: &str) -> Vec<String> {
    let mut variants = Vec::with_capacity(3); // Pre-allocate for performance
    
    // Original path
    variants.push(request_path.to_string());
    
    // Single URL decoding (catches most attacks)
    if let Ok(decoded) = urlencoding::decode(request_path) {
        let decoded_string = decoded.into_owned();
        if decoded_string != request_path {
            variants.push(decoded_string.clone());
            
            // Double URL decoding only if first decode changed something
            if let Ok(double_decoded) = urlencoding::decode(&decoded_string) {
                let double_decoded_string = double_decoded.into_owned();
                if double_decoded_string != decoded_string {
                    variants.push(double_decoded_string);
                }
            }
        }
    }
    
    variants
}

/// Check for dangerous protocols in lowercase text
fn contains_dangerous_protocol(text: &str) -> bool {
    // Focus on the most common dangerous protocols
    const DANGEROUS_PROTOCOLS: &[&str] = &[
        "javascript:",
        "vbscript:",
        "data:",
        "file:",
        "ftp:",
    ];
    
    DANGEROUS_PROTOCOLS.iter().any(|protocol| text.contains(protocol))
}

/// Check if a host is suspicious (simplified - focus on critical cases)
fn is_suspicious_host(host: &str) -> bool {
    // Check for IPv4 addresses (potential SSRF)
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    
    // Check for IPv6 addresses
    if host.starts_with('[') && host.ends_with(']') {
        return true;
    }
    
    // Check for localhost variants
    let host_lower = host.to_lowercase();
    matches!(host_lower.as_str(), 
        "localhost" | "127.0.0.1" | "::1" | "0.0.0.0")
}

#[cfg(test)]
mod tests {
    use super::validate_post_auth_redirect;

    /// Test that legitimate post-auth redirect URLs are allowed
    #[test]
    fn test_legitimate_post_auth_redirects() {
        let legitimate_redirects = vec![
            "/dashboard",
            "/api/v1/users",
            "/users/123", 
            "/app/data",
            "/static/css/style.css",
            "/images/photo.jpg",
            "/search?q=test",
            "/app/profile?tab=settings",
            "/reports/2024/summary.pdf",
            "/"
        ];

        for redirect in legitimate_redirects {
            let result = validate_post_auth_redirect(redirect);
            assert!(result.is_ok(), "Legitimate redirect should be allowed: {}", redirect);
        }
    }

    /// Test that post-auth redirect validation blocks path traversal attacks
    #[test]
    fn test_post_auth_path_traversal_blocked() {
        let malicious_redirects = vec![
            "../etc/passwd",
            "../../etc/shadow",
            "..\\windows\\system32",
            "/api/../../../etc/passwd",
            "....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
        ];

        for redirect in malicious_redirects {
            let result = validate_post_auth_redirect(redirect);
            assert!(result.is_err(), "Path traversal redirect should be blocked: {}", redirect);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that post-auth redirect validation blocks dangerous protocols
    #[test]
    fn test_post_auth_dangerous_protocols_blocked() {
        let malicious_redirects = vec![
            "javascript:alert(1)",
            "Javascript:alert(1)", 
            "JAVASCRIPT:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "Data:text/html,<script>alert(1)</script>",
            "DATA:text/html,<script>alert(1)</script>", 
            "vbscript:msgbox(1)",
            "Vbscript:msgbox(1)",
            "VBSCRIPT:msgbox(1)",
            "file://etc/passwd",
            "ftp://evil.com",
        ];

        for redirect in malicious_redirects {
            let result = validate_post_auth_redirect(redirect);
            assert!(result.is_err(), "Dangerous protocol redirect should be blocked: {}", redirect);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that post-auth redirect validation blocks open redirect attacks
    #[test] 
    fn test_post_auth_open_redirects_blocked() {
        let malicious_redirects = vec![
            "//evil.com",
            "///evil.com",
            "////evil.com",
            "http://evil.com",
            "https://malicious.site.com",
            "http:/evil.com", 
            "https:/evil.com",
        ];

        for redirect in malicious_redirects {
            let result = validate_post_auth_redirect(redirect);
            assert!(result.is_err(), "Open redirect should be blocked: {}", redirect);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that comprehensive attack vectors from test file are blocked
    #[test]
    fn test_comprehensive_post_auth_redirect_attacks() {
        // Read malicious payloads from external test file
        let test_file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("openredirects.txt");
            
        let file_content = std::fs::read_to_string(&test_file_path)
            .expect("Failed to read openredirects.txt test file");
            
        let malicious_payloads: Vec<&str> = file_content
            .lines()
            .filter(|line| !line.trim().is_empty()) // Skip empty lines
            .filter(|line| !line.trim().starts_with('#')) // Skip comments
            .collect();

        println!("Testing {} malicious post-auth redirect payloads", malicious_payloads.len());

        let mut failed_payloads = Vec::new();
        
        for payload in malicious_payloads {
            let result = validate_post_auth_redirect(payload);
            if result.is_ok() {
                failed_payloads.push(payload);
            }
        }
        
        if !failed_payloads.is_empty() {
            println!("Failed to block {} post-auth redirect payloads:", failed_payloads.len());
            for (i, payload) in failed_payloads.iter().enumerate() {
                println!("  {}: {}", i + 1, payload);
                if i >= 19 { // Limit output to first 20 failed payloads
                    println!("  ... and {} more", failed_payloads.len() - 20);
                    break;
                }
            }
            panic!("Some malicious post-auth redirect payloads were not blocked");
        }
    }

    /// Test that encoded attacks in post-auth redirects are blocked  
    #[test]
    fn test_post_auth_encoded_attacks_blocked() {
        let encoded_attacks = vec![
            "/path%00/to/file",     // Null byte
            "/path%0a/to/file",     // Newline (lowercase)
            "/path%0A/to/file",     // Newline (uppercase)
            "/path%0d/to/file",     // Carriage return (lowercase)
            "/path%0D/to/file",     // Carriage return (uppercase)
            "/%00etc/passwd",
            "/api%0Aheader-injection",
            "/test%0Dresponse-splitting",
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd", // Double encoded ../../../etc/passwd
            "javas%2563ript%253aalert%25281%2529", // Double encoded javascript:alert(1)
        ];

        for redirect in encoded_attacks {
            let result = validate_post_auth_redirect(redirect);
            assert!(result.is_err(), "Encoded attack redirect should be blocked: {}", redirect);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that double-@ domain confusion attacks are blocked
    #[test]
    fn test_post_auth_domain_confusion_blocked() {
        let domain_confusion_attacks = vec![
            "admin@example.com@google.com",
            "test@localdomain.pw@trusted.com", 
            "user@legitimate.com@evil.com",
            "support@company.com@attacker.site",
        ];

        for redirect in domain_confusion_attacks {
            let result = validate_post_auth_redirect(redirect);
            assert!(result.is_err(), "Domain confusion redirect should be blocked: {}", redirect);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that Unicode attacks in post-auth redirects are blocked
    #[test]
    fn test_post_auth_unicode_attacks_blocked() {
        let unicode_attacks = vec![
            "/api/users/\u{200E}evil.com\u{200F}/data",  // LTR/RTL override
            "/path\u{2060}with\u{2061}invisible\u{2062}separators", // Invisible separators
            "/api\u{2000}spaced\u{2001}attack",  // En/em spaces
            "〱malicious.com/path",  // Kana repeat marks
            "〵evil.site.com/api",
            "ゝattacker.com/data", 
            "ーbad.domain.com/endpoint",
        ];

        for redirect in unicode_attacks {
            let result = validate_post_auth_redirect(redirect);
            assert!(result.is_err(), "Unicode attack redirect should be blocked: {}", redirect);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that excessively long post-auth redirects are blocked
    #[test]
    fn test_post_auth_long_redirect_blocked() {
        // Create a redirect longer than 2048 characters
        let long_redirect = format!("/api/{}", "a".repeat(2048));
        
        let result = validate_post_auth_redirect(&long_redirect);
        assert!(result.is_err(), "Excessively long redirect should be blocked");
        
        if let Err(response) = result {
            assert_eq!(response.status(), 400);
        }
    }

    /// Test that absolute redirect URLs with suspicious hosts are blocked
    #[test]
    fn test_post_auth_suspicious_hosts_blocked() {
        let suspicious_redirects = vec![
            "http://127.0.0.1/admin",
            "http://192.168.1.1/config", 
            "http://10.0.0.1/internal",
            "http://172.16.0.1/private",
            "http://[::1]/localhost",
            "http://[::ffff:127.0.0.1]/loopback",
            "https://0.0.0.0/any",
            "http://localhost/admin",
        ];

        for redirect in suspicious_redirects {
            let result = validate_post_auth_redirect(redirect);
            assert!(result.is_err(), "Suspicious host redirect should be blocked: {}", redirect);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that external absolute redirect URLs are blocked by default
    /// (This is our security policy - block external redirects to prevent open redirect attacks)
    #[test]
    fn test_post_auth_external_redirects_policy() {
        let external_redirects = vec![
            "https://example.com/dashboard",
            "https://trusted-domain.com/app",
            "https://api.partner.com/callback",
        ];

        for redirect in external_redirects {
            let result = validate_post_auth_redirect(redirect);
            // Current security policy: block external redirects to prevent open redirect attacks
            // If you need to allow specific external domains, modify the validation logic
            assert!(result.is_err(), "External redirect should be blocked by default: {}", redirect);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }
}
