use actix_web::HttpResponse;
use log::{debug, warn};

// Pre-serialized JSON error responses for performance
const INVALID_REDIRECT_JSON: &str = r#"{"error":"invalid_redirect","error_description":"The redirect URL is invalid or potentially unsafe"}"#;

/// Validate post-authentication redirect URLs to prevent open redirect attacks
/// Balanced approach between security and simplicity
/// 
/// # Errors
/// 
/// Returns an `HttpResponse` error in the following cases:
/// - Empty redirect URL
/// - URL exceeds 2048 characters
/// - URL doesn't start with a single forward slash
/// - URL contains dangerous characters (control chars, Unicode tricks)
/// - URL contains path traversal patterns
/// - URL contains encoded double slashes
/// - URL contains protocol injection attempts
/// - URL contains suspicious redirect parameters in query string
pub fn validate_post_auth_redirect(redirect_url: &str) -> Result<String, HttpResponse> {
    debug!("Validating post-authentication redirect URL: {redirect_url}");
    
    // Empty redirects are invalid
    if redirect_url.is_empty() {
        return Err(HttpResponse::BadRequest()
            .content_type("application/json")
            .body(INVALID_REDIRECT_JSON));
    }
    
    // Length limit to prevent DoS
    if redirect_url.len() > 2048 {
        warn!("Redirect URL too long: {} characters", redirect_url.len());
        return Err(HttpResponse::BadRequest()
            .content_type("application/json")
            .body(INVALID_REDIRECT_JSON));
    }
    
    // Must start with a single slash (relative URL only)
    if !redirect_url.starts_with('/') || redirect_url.starts_with("//") {
        warn!("Invalid redirect URL format: {redirect_url}");
        return Err(HttpResponse::BadRequest()
            .content_type("application/json")
            .body(INVALID_REDIRECT_JSON));
    }
    
    // Check for control characters and other dangerous characters
    if contains_dangerous_characters(redirect_url) {
        warn!("Dangerous characters in redirect URL: {redirect_url}");
        return Err(HttpResponse::BadRequest()
            .content_type("application/json")
            .body(INVALID_REDIRECT_JSON));
    }
    
    // Simple path traversal check (including encoded variants)
    if contains_path_traversal(redirect_url) {
        warn!("Path traversal attempt in redirect: {redirect_url}");
        return Err(HttpResponse::BadRequest()
            .content_type("application/json")
            .body(INVALID_REDIRECT_JSON));
    }
    
    // Check for encoded slashes that could create // 
    if contains_encoded_double_slash(redirect_url) {
        warn!("Encoded double slash in redirect: {redirect_url}");
        return Err(HttpResponse::BadRequest()
            .content_type("application/json")
            .body(INVALID_REDIRECT_JSON));
    }
    
    // Basic protocol injection check (including mixed case)
    if contains_protocol_injection(redirect_url) {
        warn!("Protocol injection attempt in redirect: {redirect_url}");
        return Err(HttpResponse::BadRequest()
            .content_type("application/json")
            .body(INVALID_REDIRECT_JSON));
    }
    
    // Check for suspicious query parameters that could be open redirects
    if contains_redirect_in_query(redirect_url) {
        warn!("Redirect parameter in query string: {redirect_url}");
        return Err(HttpResponse::BadRequest()
            .content_type("application/json")
            .body(INVALID_REDIRECT_JSON));
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
    // Raw control chars (case-sensitive)
    if url.contains('\n') || url.contains('\r') || url.contains('\t') {
        return true;
    }
    
    // Encoded control chars - check both cases without allocation
    let encoded_patterns = [
        ("%0a", "%0A"), ("%0d", "%0D"), ("%09", "%09"), // newline, carriage return, tab
        ("%01", "%01"), ("%02", "%02"), ("%03", "%03"), ("%04", "%04"), // Other control chars
        ("%05", "%05"), ("%06", "%06"), ("%07", "%07"), ("%08", "%08"),
        ("%0b", "%0B"), ("%0c", "%0C"), ("%0e", "%0E"), ("%0f", "%0F"),
    ];
    
    for (lower_pattern, upper_pattern) in &encoded_patterns {
        if url.contains(lower_pattern) || url.contains(upper_pattern) {
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
    if url.contains("..") || url.contains('\\') {
        return true;
    }
    
    // Check URL-encoded variants - check both cases without allocation
    let encoded_patterns = [
        ("%2e%2e", "%2E%2E"), // ..
        ("%2e%2e%2f", "%2E%2E%2F"), // ../
        ("%2e%2e%5c", "%2E%2E%5C"), // ..\
        ("%252e%252e", "%252E%252E"), // Double-encoded ..
        ("%c0%ae", "%c0%ae"), ("%c1%9c", "%c1%9c"), // Unicode encoding tricks (case-sensitive)
        ("%5c", "%5C"), // \
        ("%252f", "%252F"), // Double-encoded /
        ("%255c", "%255C"), // Double-encoded \
    ];
    
    for (lower_pattern, upper_pattern) in &encoded_patterns {
        if url.contains(lower_pattern) || url.contains(upper_pattern) {
            return true;
        }
    }
    
    false
}

/// Check for encoded slashes that could create //
fn contains_encoded_double_slash(url: &str) -> bool {
    let patterns = [
        ("%2f%2f", "%2F%2F"), // //
        ("%252f%252f", "%252F%252F"), // Double-encoded //
        ("%2f%252f", "%252f%2f"), // Mixed encoding (case-sensitive for mixed)
        ("/%2f", "/%2F"), // Leading to //
        ("%5c%5c", "%5C%5C"), // \\
    ];
    
    for (lower_pattern, upper_pattern) in &patterns {
        if url.contains(lower_pattern) || url.contains(upper_pattern) {
            return true;
        }
    }
    
    // Check for patterns that would result in // after decoding
    if url.contains("/%2f") || url.contains("/%2F") ||
       url.contains("/%252f") || url.contains("/%252F") {
        return true;
    }
    
    false
}

/// Check for protocol injection attempts
fn contains_protocol_injection(url: &str) -> bool {
    let protocols = [
        "javascript:", "data:", "vbscript:", "file:", "about:",
        "chrome:", "chrome-extension:", "ms-browser-extension:",
        "opera:", "brave:", "edge:",
    ];
    
    // Single allocation for case-insensitive comparison
    let url_lower = url.to_ascii_lowercase();
    
    // Direct protocol check
    for protocol in &protocols {
        if url_lower.contains(protocol) {
            return true;
        }
    }
    
    // Check for encoded protocols (these are case-sensitive)
    let encoded_protocols = [
        "%6a%61%76%61%73%63%72%69%70%74%3a", // javascript:
        "%64%61%74%61%3a", // data:
        "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;", // HTML entity encoded javascript:
        "\\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74\\x3A", // Hex escaped javascript:
    ];
    
    for encoded_protocol in &encoded_protocols {
        if url_lower.contains(encoded_protocol) {
            return true;
        }
    }
    
    false
}

/// Check for redirect parameters in query string
fn contains_redirect_in_query(url: &str) -> bool {
    // Common redirect parameter names
    let redirect_params = [
        "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
        "return_url", "returnto", "return_to", "next", "goto", "target",
        "destination", "dest", "continue", "url", "link", "ref",
        "callback", "callback_url", "success_url", "failure_url",
    ];
    
    // Check if URL has query string
    if let Some(query_start) = url.find('?') {
        let query_part = &url[query_start + 1..];
        let query_lower = query_part.to_ascii_lowercase();
        
        for param in &redirect_params {
            // Check for parameter=value pattern
            let patterns = [
                format!("{param}="),
                format!("{param}&"),
                format!("{param}%3d"), // URL encoded =
            ];
            
            for pattern in &patterns {
                if query_lower.contains(pattern) {
                    return true;
                }
            }
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_redirects() {
        // Valid paths should pass
        assert!(validate_post_auth_redirect("/home").is_ok());
        assert!(validate_post_auth_redirect("/app/dashboard").is_ok());
        assert!(validate_post_auth_redirect("/").is_ok());
        assert!(validate_post_auth_redirect("/page?param=value").is_ok());
        assert!(validate_post_auth_redirect("/path#anchor").is_ok());
    }

    #[test]
    fn test_empty_redirect() {
        assert!(validate_post_auth_redirect("").is_err());
    }

    #[test]
    fn test_protocol_injection() {
        // Direct protocol injection
        assert!(validate_post_auth_redirect("/javascript:alert(1)").is_err());
        assert!(validate_post_auth_redirect("/data:text/html,<script>alert(1)</script>").is_err());
        
        // Case variations
        assert!(validate_post_auth_redirect("/JavaScript:alert(1)").is_err());
        assert!(validate_post_auth_redirect("/JAVASCRIPT:alert(1)").is_err());
        
        // URL encoded
        assert!(validate_post_auth_redirect("/%6a%61%76%61%73%63%72%69%70%74%3aalert(1)").is_err());
    }

    #[test]
    fn test_double_slash() {
        // Direct double slash
        assert!(validate_post_auth_redirect("//evil.com").is_err());
        assert!(validate_post_auth_redirect("//evil.com/path").is_err());
        
        // Encoded slashes
        assert!(validate_post_auth_redirect("/%2f%2fevil.com").is_err());
        assert!(validate_post_auth_redirect("/%2F%2Fevil.com").is_err());
        assert!(validate_post_auth_redirect("/%252f%252fevil.com").is_err());
    }

    #[test]
    fn test_path_traversal() {
        // Direct traversal
        assert!(validate_post_auth_redirect("/../etc/passwd").is_err());
        assert!(validate_post_auth_redirect("/../../etc/passwd").is_err());
        assert!(validate_post_auth_redirect("/path/../../../etc/passwd").is_err());
        
        // Backslashes
        assert!(validate_post_auth_redirect("/..\\etc\\passwd").is_err());
        assert!(validate_post_auth_redirect("\\..\\etc\\passwd").is_err());
        
        // URL encoded
        assert!(validate_post_auth_redirect("/%2e%2e/etc/passwd").is_err());
        assert!(validate_post_auth_redirect("/%2e%2e%2f%2e%2e%2fetc/passwd").is_err());
        assert!(validate_post_auth_redirect("/%252e%252e/etc/passwd").is_err());
    }

    #[test]
    fn test_control_characters() {
        // Raw control characters
        assert!(validate_post_auth_redirect("/path\nHeader: Value").is_err());
        assert!(validate_post_auth_redirect("/path\rHeader: Value").is_err());
        assert!(validate_post_auth_redirect("/path\0null").is_err());
        
        // URL encoded control characters
        assert!(validate_post_auth_redirect("/path%0aHeader:%20Value").is_err());
        assert!(validate_post_auth_redirect("/path%0dHeader:%20Value").is_err());
        assert!(validate_post_auth_redirect("/path%00null").is_err());
    }

    #[test]
    fn test_unicode_tricks() {
        // Unicode direction override
        assert!(validate_post_auth_redirect("/path\u{202E}reversed").is_err());
        
        // Zero-width characters
        assert!(validate_post_auth_redirect("/path\u{200B}invisible").is_err());
        assert!(validate_post_auth_redirect("/path\u{FEFF}bom").is_err());
        
        // Various Unicode spaces
        assert!(validate_post_auth_redirect("/path\u{2000}space").is_err());
        assert!(validate_post_auth_redirect("/path\u{3000}ideographic").is_err());
    }

    #[test]
    fn test_query_string_redirects() {
        // Common redirect parameters
        assert!(validate_post_auth_redirect("/page?redirect=http://evil.com").is_err());
        assert!(validate_post_auth_redirect("/page?redirect_uri=http://evil.com").is_err());
        assert!(validate_post_auth_redirect("/page?return_url=http://evil.com").is_err());
        assert!(validate_post_auth_redirect("/page?next=http://evil.com").is_err());
        assert!(validate_post_auth_redirect("/page?goto=http://evil.com").is_err());
        
        // Multiple parameters
        assert!(validate_post_auth_redirect("/page?safe=true&redirect=http://evil.com").is_err());
        
        // URL encoded equals
        assert!(validate_post_auth_redirect("/page?redirect%3dhttp://evil.com").is_err());
        assert!(validate_post_auth_redirect("/page?redirect%3Dhttp://evil.com").is_err());
    }

    #[test]
    fn test_length_limit() {
        let long_path = "/".to_string() + &"a".repeat(2048);
        assert!(validate_post_auth_redirect(&long_path).is_err());
        
        let max_path = "/".to_string() + &"a".repeat(2047);
        assert!(validate_post_auth_redirect(&max_path).is_ok());
    }

    #[test]
    fn test_complex_valid_paths() {
        // Valid complex paths that should pass
        assert!(validate_post_auth_redirect("/app/user/profile/123").is_ok());
        assert!(validate_post_auth_redirect("/search?q=rust+programming&page=2").is_ok());
        assert!(validate_post_auth_redirect("/docs/api/v2#authentication").is_ok());
        assert!(validate_post_auth_redirect("/files/document.pdf").is_ok());
        assert!(validate_post_auth_redirect("/user@example/profile").is_ok());
    }

    #[test]
    fn test_edge_cases() {
        // Must start with /
        assert!(validate_post_auth_redirect("home").is_err());
        assert!(validate_post_auth_redirect("./home").is_err());
        assert!(validate_post_auth_redirect("~/home").is_err());
        
        // Various invalid patterns
        assert!(validate_post_auth_redirect("/\0").is_err());
        assert!(validate_post_auth_redirect("/\n").is_err());
        assert!(validate_post_auth_redirect("/\r").is_err());
        
        // Just a slash is valid
        assert!(validate_post_auth_redirect("/").is_ok());
    }
}
