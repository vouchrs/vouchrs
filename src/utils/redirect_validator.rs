use actix_web::HttpResponse;
use log::{debug, warn};

/// Validate post-authentication redirect URLs to prevent open redirect attacks
/// Balanced approach between security and simplicity
pub fn validate_post_auth_redirect(redirect_url: &str) -> Result<String, HttpResponse> {
    debug!("Validating post-authentication redirect URL: {}", redirect_url);
    
    // Empty redirects are invalid
    if redirect_url.is_empty() {
        return Err(invalid_redirect_error());
    }
    
    // Length limit to prevent DoS
    if redirect_url.len() > 2048 {
        warn!("Redirect URL too long: {} characters", redirect_url.len());
        return Err(invalid_redirect_error());
    }
    
    // Must start with a single slash (relative URL only)
    if !redirect_url.starts_with('/') || redirect_url.starts_with("//") {
        warn!("Invalid redirect URL format: {}", redirect_url);
        return Err(invalid_redirect_error());
    }
    
    // Check for control characters and other dangerous characters
    if contains_dangerous_characters(redirect_url) {
        warn!("Dangerous characters in redirect URL: {}", redirect_url);
        return Err(invalid_redirect_error());
    }
    
    // Simple path traversal check (including encoded variants)
    if contains_path_traversal(redirect_url) {
        warn!("Path traversal attempt in redirect: {}", redirect_url);
        return Err(invalid_redirect_error());
    }
    
    // Check for encoded slashes that could create // 
    if contains_encoded_double_slash(redirect_url) {
        warn!("Encoded double slash in redirect: {}", redirect_url);
        return Err(invalid_redirect_error());
    }
    
    // Basic protocol injection check (including mixed case)
    if contains_protocol_injection(redirect_url) {
        warn!("Protocol injection attempt in redirect: {}", redirect_url);
        return Err(invalid_redirect_error());
    }
    
    // Check for suspicious query parameters that could be open redirects
    if contains_redirect_in_query(redirect_url) {
        warn!("Redirect parameter in query string: {}", redirect_url);
        return Err(invalid_redirect_error());
    }
    
    Ok(redirect_url.to_string())
}

/// Check for dangerous characters including control chars and Unicode tricks
fn contains_dangerous_characters(url: &str) -> bool {
    // Check for null bytes
    if url.contains('\0') || url.contains("%00") {
        return true;
    }
    
    // Check for control characters (both raw and encoded)
    let control_patterns = [
        "\n", "\r", "\t", // Raw control chars
        "%0a", "%0A", "%0d", "%0D", "%09", // Encoded newline, carriage return, tab
        "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", // Other control chars
        "%0b", "%0B", "%0c", "%0C", "%0e", "%0E", "%0f", "%0F",
    ];
    
    let url_lower = url.to_lowercase();
    for pattern in &control_patterns {
        if url.contains(pattern) || url_lower.contains(pattern) {
            return true;
        }
    }
    
    // Check for Unicode direction override characters and various spaces
    if url.chars().any(|c| matches!(c, 
        '\u{202A}'..='\u{202E}' | // LTR/RTL override
        '\u{2060}'..='\u{2069}' | // Word joiner and invisible separators
        '\u{200B}'..='\u{200F}' | // Zero-width space and marks
        '\u{FEFF}' |              // Zero-width no-break space
        '\u{2000}'..='\u{200A}' | // Various Unicode spaces (en space, em space, etc.)
        '\u{00A0}' |              // Non-breaking space
        '\u{1680}' |              // Ogham space mark
        '\u{180E}' |              // Mongolian vowel separator
        '\u{2028}' |              // Line separator
        '\u{2029}' |              // Paragraph separator
        '\u{205F}' |              // Medium mathematical space
        '\u{3000}'                // Ideographic space
    )) {
        return true;
    }
    
    false
}

/// Check for path traversal patterns including encoded variants
fn contains_path_traversal(url: &str) -> bool {
    // Direct check
    if url.contains("..") || url.contains("\\") {
        return true;
    }
    
    // Check URL-encoded variants
    let encoded_patterns = [
        "%2e%2e", "%2e.", ".%2e", // encoded ..
        "%5c", "%2f%2e%2e", // encoded \ and /..
        "%252e%252e", // double-encoded ..
    ];
    
    let url_lower = url.to_lowercase();
    for pattern in &encoded_patterns {
        if url_lower.contains(pattern) {
            return true;
        }
    }
    
    false
}

/// Check for encoded slashes that could create //
fn contains_encoded_double_slash(url: &str) -> bool {
    let patterns = [
        "%2f%2f", "%2F%2F", // URL-encoded //
        "%252f%252f", "%252F%252F", // Double-encoded //
        "/%2f", "/%2F", // / followed by encoded /
    ];
    
    let url_lower = url.to_lowercase();
    for pattern in &patterns {
        if url_lower.contains(pattern) {
            return true;
        }
    }
    
    // Check for /<>// pattern
    if url.contains("<>//") {
        return true;
    }
    
    false
}

/// Check for protocol injection attempts
fn contains_protocol_injection(url: &str) -> bool {
    // Check if URL contains a colon in the path part (before query string)
    let path_part = url.split('?').next().unwrap_or(url);
    
    // Skip the first character (the required /)
    let check_part = &path_part[1..];
    
    // Check for common protocol patterns (case-insensitive)
    let lower = check_part.to_lowercase();
    let protocols = [
        "http:", "https:", "javascript:", "data:", "vbscript:", 
        "file:", "ftp:", "mailto:", "tel:", "ssh:", "ldap:"
    ];
    
    for protocol in &protocols {
        if lower.contains(protocol) {
            return true;
        }
    }
    
    // Check for encoded protocol patterns
    if lower.contains("%68%74%74%70") || // http encoded
       lower.contains("%6a%61%76%61%73%63%72%69%70%74") { // javascript encoded
        return true;
    }
    
    // Check for any remaining colons in the path (not in query string)
    if check_part.contains(':') {
        return true;
    }
    
    false
}

/// Check for redirect parameters in query string that could be open redirects
fn contains_redirect_in_query(url: &str) -> bool {
    // Only check the query string part
    if let Some(query_start) = url.find('?') {
        let query_part = &url[query_start + 1..];
        let query_lower = query_part.to_lowercase();
        
        // Common redirect parameter names
        let redirect_params = [
            "url=", "redirect=", "redir=", "next=", "return=", 
            "returnto=", "redirect_uri=", "redirect_url=", "rurl=",
            "destination=", "dest=", "target=", "continue=",
            "desiredlocationurl=", "successurl=", "return_to=",
            "callback=", "goto=", "link=", "location="
        ];
        
        for param in &redirect_params {
            if query_lower.contains(param) {
                // Check if the value after the param contains a URL pattern
                if let Some(param_pos) = query_lower.find(param) {
                    let value_start = param_pos + param.len();
                    let value_part = &query_lower[value_start..];
                    
                    // Check for protocol patterns in the parameter value
                    if value_part.starts_with("//") || 
                       value_part.starts_with("http") || 
                       value_part.starts_with("%2f%2f") ||
                       value_part.contains("://") {
                        return true;
                    }
                }
            }
        }
    }
    
    false
}

fn invalid_redirect_error() -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({
        "error": "bad_request",
        "message": "Invalid redirect URL"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_redirects() {
        let valid = vec![
            "/dashboard",
            "/api/v1/users",
            "/search?q=test",
            "/path?time=10:30:00", // Safe colon in query
        ];
        
        for url in valid {
            assert!(validate_post_auth_redirect(url).is_ok(), "Should allow: {}", url);
        }
    }

    #[test]
    fn test_invalid_redirects() {
        let invalid = vec![
            "", // Empty
            "//evil.com", // Protocol-relative
            "/path/../etc/passwd", // Path traversal
            "/path\\..\\etc", // Backslash
            "/path%2e%2e/etc", // Encoded traversal
            "/path%00/null", // Null byte
            "javascript:alert(1)", // No leading slash
            "http://evil.com", // Absolute URL
            "/path:with:colons", // Colons in path
        ];
        
        for url in invalid {
            assert!(validate_post_auth_redirect(url).is_err(), "Should block: {}", url);
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
