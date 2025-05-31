// filepath: /workspaces/vouchrs/src/utils/response_builder.rs
use actix_web::{cookie::Cookie, web, HttpRequest, HttpResponse};
use reqwest;
use std::collections::HashMap;
use url;
use regex::Regex;
use once_cell::sync::Lazy;
use log::{debug, warn};

use crate::utils::cookie_utils::filter_vouchrs_cookies;

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

pub struct ResponseBuilder;

// Helper function to check for hop-by-hop headers
pub fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

impl ResponseBuilder {
    /// Create a redirect response with optional cookies
    pub fn redirect(location: &str, cookies: Option<Vec<Cookie>>) -> HttpResponse {
        let mut builder = HttpResponse::Found();

        if let Some(cookies_vec) = cookies {
            for cookie in cookies_vec {
                builder.cookie(cookie);
            }
        }

        builder.append_header(("Location", location)).finish()
    }

    /// Create a redirect response with a single cookie
    pub fn redirect_with_cookie(location: &str, cookie: Option<Cookie>) -> HttpResponse {
        let cookies = cookie.map(|c| vec![c]);
        Self::redirect(location, cookies)
    }

    /// Create an error redirect response
    pub fn error_redirect(location: &str, error_param: &str) -> HttpResponse {
        let redirect_url = if location.contains('?') {
            format!("{location}&error={error_param}")
        } else {
            format!("{location}?error={error_param}")
        };

        Self::redirect(&redirect_url, None)
    }

    /// Create a success redirect response with cookie
    pub fn success_redirect_with_cookie(location: &str, cookie: Cookie) -> HttpResponse {
        Self::redirect(location, Some(vec![cookie]))
    }

    /// Create a success redirect response with multiple cookies
    pub fn success_redirect_with_cookies(location: &str, cookies: Vec<Cookie>) -> HttpResponse {
        Self::redirect(location, Some(cookies))
    }

    /// Convert Actix HTTP method to reqwest method
    pub fn convert_http_method(
        method: &actix_web::http::Method,
    ) -> Result<reqwest::Method, HttpResponse> {
        match method.as_str() {
            "GET" => Ok(reqwest::Method::GET),
            "POST" => Ok(reqwest::Method::POST),
            "PUT" => Ok(reqwest::Method::PUT),
            "DELETE" => Ok(reqwest::Method::DELETE),
            "PATCH" => Ok(reqwest::Method::PATCH),
            "HEAD" => Ok(reqwest::Method::HEAD),
            "OPTIONS" => Ok(reqwest::Method::OPTIONS),
            method_str => Err(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "bad_request",
                "message": format!("HTTP method '{}' is not supported", method_str)
            }))),
        }
    }

    /// Forward request headers (excluding Authorization, Cookie with vouchrs_session, and hop-by-hop headers)
    pub fn forward_request_headers(
        mut request_builder: reqwest::RequestBuilder,
        req: &HttpRequest,
    ) -> reqwest::RequestBuilder {
        for (name, value) in req.headers() {
            let name_str = name.as_str().to_lowercase();

            // Skip authorization and hop-by-hop headers
            if name_str == "authorization" || is_hop_by_hop_header(&name_str) {
                continue;
            }

            // Special handling for cookies
            if name_str == "cookie" {
                if let Ok(cookie_str) = value.to_str() {
                    if let Some(filtered_cookie) = filter_vouchrs_cookies(cookie_str) {
                        request_builder = request_builder.header(name.as_str(), filtered_cookie);
                    }
                }
                continue;
            }

            // Add other headers
            if let Ok(value_str) = value.to_str() {
                request_builder = request_builder.header(name.as_str(), value_str);
            }
        }
        request_builder
    }

    /// Forward query parameters
    pub fn forward_query_parameters(
        mut request_builder: reqwest::RequestBuilder,
        query_params: &web::Query<HashMap<String, String>>,
    ) -> reqwest::RequestBuilder {
        if !query_params.is_empty() {
            for (key, value) in query_params.iter() {
                request_builder = request_builder.query(&[(key, value)]);
            }
        }
        request_builder
    }

    /// Forward request body if present
    pub fn forward_request_body(
        mut request_builder: reqwest::RequestBuilder,
        body: &web::Bytes,
    ) -> reqwest::RequestBuilder {
        if !body.is_empty() {
            request_builder = request_builder.body(body.to_vec());
        }
        request_builder
    }

    /// Build the upstream URL by combining base URL with request path
    /// Ensures that the request only goes to the configured upstream URL
    /// and protects against path traversal attempts
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

    /// Validate against malicious patterns using simplified, high-confidence patterns
    /// Relies on URL parsing and final validation for comprehensive protection
    fn validate_suspicious_patterns(request_path: &str) -> Result<(), HttpResponse> {
        // Fast path: check for common legitimate patterns first
        if request_path.starts_with("/api/") || 
           request_path.starts_with("/static/") ||
           request_path.starts_with("/health") {
            // Still need to check for critical attacks in legitimate-looking paths
            return Self::validate_critical_patterns(request_path);
        }
        
        // Check for path traversal (most critical and common)
        if PATH_TRAVERSAL_PATTERN.is_match(request_path) {
            warn!("Path traversal attempt detected: {}", request_path);
            return Err(Self::invalid_path_error());
        }
        
        // Check for protocol injection (absolute URLs)
        if PROTOCOL_PATTERN.is_match(request_path) {
            warn!("Protocol injection attempt detected: {}", request_path);
            return Err(Self::invalid_path_error());
        }
        
        // Check for control characters (should never be in legitimate paths)
        if SUSPICIOUS_PATTERN.is_match(request_path) {
            warn!("Suspicious pattern detected: {}", request_path);
            return Err(Self::invalid_path_error());
        }
        
        // Check decoded variants for encoded attacks
        Self::validate_encoded_patterns(request_path)
    }
    
    /// Validate critical patterns that should be checked even in legitimate-looking paths
    fn validate_critical_patterns(request_path: &str) -> Result<(), HttpResponse> {
        // Only check the most critical patterns for performance
        if PATH_TRAVERSAL_PATTERN.is_match(request_path) ||
           SUSPICIOUS_PATTERN.is_match(request_path) {
            warn!("Critical attack pattern in legitimate path: {}", request_path);
            return Err(Self::invalid_path_error());
        }
        
        // Check for double-encoded path traversal
        if let Ok(decoded) = urlencoding::decode(request_path) {
            if PATH_TRAVERSAL_PATTERN.is_match(&decoded) {
                warn!("Encoded path traversal detected: {} -> {}", request_path, decoded);
                return Err(Self::invalid_path_error());
            }
        }
        
        Ok(())
    }
    
    /// Validate URL-decoded patterns for encoded attack attempts
    /// Simplified to focus on the most critical encoded attacks
    fn validate_encoded_patterns(request_path: &str) -> Result<(), HttpResponse> {
        // Get decoded variants to check for encoded attacks
        let decoded_variants = Self::get_decoded_variants(request_path);
        
        for decoded in decoded_variants {
            // Check critical patterns on decoded content
            if PATH_TRAVERSAL_PATTERN.is_match(&decoded) {
                warn!("Encoded path traversal detected: {} -> {}", request_path, decoded);
                return Err(Self::invalid_path_error());
            }
            
            if PROTOCOL_PATTERN.is_match(&decoded) {
                warn!("Encoded protocol injection detected: {} -> {}", request_path, decoded);
                return Err(Self::invalid_path_error());
            }
            
            if SUSPICIOUS_PATTERN.is_match(&decoded) {
                warn!("Encoded suspicious pattern detected: {} -> {}", request_path, decoded);
                return Err(Self::invalid_path_error());
            }
            
            // Simple string-based checks for dangerous protocols (more reliable than complex regex)
            let decoded_lower = decoded.to_lowercase();
            if Self::contains_dangerous_protocol(&decoded_lower) {
                warn!("Dangerous protocol detected: {}", decoded_lower);
                return Err(Self::invalid_path_error());
            }
            
            // Check for double @ patterns (domain confusion)
            if decoded.matches('@').count() > 1 {
                warn!("Multiple @ symbols detected (domain confusion): {}", decoded);
                return Err(Self::invalid_path_error());
            }
        }
        
        Ok(())
    }
    
    /// Get decoded variants of the input path (simplified approach)
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
    
    /// Check for dangerous protocols in lowercase text (simplified list)
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

    /// Construct normalized URL with proper path joining and additional security checks
    fn construct_normalized_url(base_url: &str, request_path: &str) -> Result<String, HttpResponse> {
        // Parse base URL
        let base = url::Url::parse(base_url)
            .map_err(|e| {
                warn!("Failed to parse base URL '{}': {}", base_url, e);
                Self::invalid_path_error()
            })?;

        // Normalize the request path
        let clean_path = Self::normalize_request_path(request_path)?;
        
        // Join the path with the base URL
        let joined = base.join(&clean_path)
            .map_err(|e| {
                warn!("Failed to join URL '{}' + '{}': {}", base_url, clean_path, e);
                Self::invalid_path_error()
            })?;
            
        // Additional security check: ensure the path didn't escape via URL parsing
        if let Some(host) = joined.host_str() {
            if host != base.host_str().unwrap_or("") {
                warn!("Host mismatch after URL join: expected '{}', got '{}'", 
                      base.host_str().unwrap_or(""), host);
                return Err(Self::invalid_path_error());
            }
        }

        Ok(joined.to_string())
    }
    
    /// Normalize request path to prevent bypass attempts (simplified)
    fn normalize_request_path(request_path: &str) -> Result<String, HttpResponse> {
        // Start with trimming leading slashes
        let path = request_path.trim_start_matches('/').trim();
        
        // Basic length check to prevent extremely long paths
        if path.len() > 2048 {
            warn!("Excessively long path detected: {} characters", path.len());
            return Err(Self::invalid_path_error());
        }
        
        Ok(path.to_string())
    }

    /// Validate the final constructed URL against security constraints
    fn validate_final_url(base_url: &str, final_url: &str) -> Result<(), HttpResponse> {
        let base = url::Url::parse(base_url)
            .map_err(|_| Self::invalid_path_error())?;
        let final_parsed = url::Url::parse(final_url)
            .map_err(|_| Self::invalid_path_error())?;

        // Validate scheme is in allowed list
        if !ALLOWED_SCHEMES.contains(&final_parsed.scheme()) {
            warn!("Invalid scheme '{}' in final URL: {}", final_parsed.scheme(), final_url);
            return Err(Self::invalid_path_error());
        }

        // Ensure the final URL stays within the same host as the base
        if final_parsed.host_str() != base.host_str() {
            warn!("Host mismatch: base '{}', final '{}'", 
                  base.host_str().unwrap_or(""), 
                  final_parsed.host_str().unwrap_or(""));
            return Err(Self::invalid_path_error());
        }

        // Ensure the port hasn't changed (if originally specified)
        if final_parsed.port() != base.port() {
            warn!("Port mismatch: base {:?}, final {:?}", base.port(), final_parsed.port());
            return Err(Self::invalid_path_error());
        }
        
        // Additional check: ensure path doesn't go above the base path
        let base_path = base.path();
        let final_path = final_parsed.path();
        
        // If base has a path, final path must start with it
        if !base_path.is_empty() && base_path != "/" && !final_path.starts_with(base_path) {
            warn!("Path escape attempt: base path '{}', final path '{}'", base_path, final_path);
            return Err(Self::invalid_path_error());
        }
        
        // Check for IP addresses in the host (potential SSRF)
        if let Some(host) = final_parsed.host_str() {
            if Self::is_suspicious_host(host) {
                warn!("Suspicious host detected: {}", host);
                return Err(Self::invalid_path_error());
            }
        }

        Ok(())
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

    /// Return standardized error for invalid paths
    fn invalid_path_error() -> HttpResponse {
        HttpResponse::BadRequest().json(serde_json::json!({
            "error": "bad_request",
            "message": "Invalid request path"
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::ResponseBuilder;

    /// Test that legitimate URLs are allowed
    #[test]
    fn test_legitimate_urls() {
        let base_url = "https://api.example.com";
        
        let legitimate_paths = vec![
            "/api/v1/users",
            "/users/123",
            "/api/data.json",
            "/path/to/resource",
            "/search?q=test",
            "/uploads/file.pdf",
            "/api/v2/endpoint",
            "/static/css/style.css",
            "/images/photo.jpg",
            "/docs/api.html",
        ];

        for path in legitimate_paths {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_ok(), "Legitimate path should be allowed: {}", path);
            let url = result.unwrap();
            assert!(url.starts_with(base_url), "URL should start with base URL: {}", url);
        }
    }

    /// Test that path traversal attempts are blocked
    #[test]
    fn test_path_traversal_blocked() {
        let base_url = "https://api.example.com";
        
        let malicious_paths = vec![
            "../etc/passwd",
            "../../etc/shadow",
            "..\\windows\\system32",
            "/api/../../../etc/passwd",
            "....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
        ];

        for path in malicious_paths {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_err(), "Path traversal should be blocked: {}", path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that protocol injection attempts are blocked
    #[test]
    fn test_protocol_injection_blocked() {
        let base_url = "https://api.example.com";
        
        let malicious_paths = vec![
            "http://evil.com",
            "https://malicious.site.com",
            "//evil.com",
            "///evil.com",
            "////evil.com",
            "http:/evil.com",
            "https:/evil.com",
            "ftp://evil.com",
            "file://etc/passwd",
        ];

        for path in malicious_paths {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_err(), "Protocol injection should be blocked: {}", path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that dangerous protocols are blocked
    #[test]
    fn test_dangerous_protocols_blocked() {
        let base_url = "https://api.example.com";
        
        let malicious_paths = vec![
            "javascript:alert(1)",
            "Javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "Data:text/html,<script>alert(1)</script>",
            "DATA:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "Vbscript:msgbox(1)",
            "VBSCRIPT:msgbox(1)",
        ];

        for path in malicious_paths {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_err(), "Dangerous protocol should be blocked: {}", path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that suspicious URL encodings are blocked
    #[test]
    fn test_suspicious_encodings_blocked() {
        let base_url = "https://api.example.com";
        
        let malicious_paths = vec![
            "/path%00/to/file",     // Null byte
            "/path%0a/to/file",     // Newline (lowercase)
            "/path%0A/to/file",     // Newline (uppercase)
            "/path%0d/to/file",     // Carriage return (lowercase)
            "/path%0D/to/file",     // Carriage return (uppercase)
            "/%00etc/passwd",
            "/api%0Aheader-injection",
            "/test%0Dresponse-splitting",
        ];

        for path in malicious_paths {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_err(), "Suspicious encoding should be blocked: {}", path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test comprehensive malicious payloads from external test file
    #[test]
    fn test_comprehensive_malicious_payloads() {
        let base_url = "https://api.example.com";
        
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

        println!("Testing {} malicious payloads from external file", malicious_payloads.len());

        let mut failed_payloads = Vec::new();
        
        for payload in malicious_payloads {
            let result = ResponseBuilder::build_upstream_url(base_url, payload);
            if result.is_ok() {
                failed_payloads.push(payload);
            }
        }
        
        if !failed_payloads.is_empty() {
            println!("Failed to block {} payloads:", failed_payloads.len());
            for (i, payload) in failed_payloads.iter().enumerate() {
                println!("  {}: {}", i + 1, payload);
                if i >= 19 { // Limit output to first 20 failed payloads
                    println!("  ... and {} more", failed_payloads.len() - 20);
                    break;
                }
            }
            panic!("Some malicious payloads were not blocked");
        }
    }

    /// Test that the final URL stays within the same host
    #[test]
    fn test_host_validation() {
        let base_url = "https://api.example.com";
        
        // These should work - same host
        let valid_paths = vec![
            "/api/users",
            "/some/path",
        ];

        for path in valid_paths {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_ok(), "Same host path should be allowed: {}", path);
        }
    }

    /// Test that legitimate URLs with email addresses are allowed
    #[test]
    fn test_legitimate_email_urls() {
        let base_url = "https://api.example.com";
        
        let legitimate_email_paths = vec![
            "/users/user@example.com",
            "/api/contact/admin@company.com", 
            "/reset-password/test.user@domain.org",
            "/invite/john.doe@example.co.uk",
            "/profile/user123@test-domain.com",
            "/notifications/support@example.com/settings",
            "/api/v1/users/email@sub.domain.com/profile",
        ];

        for path in legitimate_email_paths {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_ok(), "Legitimate email URL should be allowed: {}", path);
            let url = result.unwrap();
            assert!(url.starts_with(base_url), "URL should start with base URL: {}", url);
        }
    }

    /// Test that malicious double-@ redirect patterns are blocked
    #[test]
    fn test_malicious_double_at_blocked() {
        let base_url = "https://api.example.com";
        
        let malicious_double_at_patterns = vec![
            "admin@example.com@google.com",
            "test@localdomain.pw@trusted.com", 
            "user@legitimate.com@evil.com",
            "support@company.com@attacker.site",
        ];

        for path in malicious_double_at_patterns {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_err(), "Double-@ redirect should be blocked: {}", path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that Unicode spoofing attempts are blocked
    #[test]
    fn test_unicode_spoofing_blocked() {
        let base_url = "https://api.example.com";
        
        let unicode_attacks = vec![
            "/api/users/\u{200E}evil.com\u{200F}/data",  // LTR/RTL override
            "/path\u{2060}with\u{2061}invisible\u{2062}separators", // Invisible separators
            "/api\u{2000}spaced\u{2001}attack",  // En/em spaces
            "〱malicious.com/path",  // Kana repeat marks
            "〵evil.site.com/api",
            "ゝattacker.com/data",
            "ーbad.domain.com/endpoint",
        ];

        for path in unicode_attacks {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_err(), "Unicode spoofing should be blocked: {}", path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that control character injection is blocked
    #[test]
    fn test_control_character_injection_blocked() {
        let base_url = "https://api.example.com";
        
        let control_char_attacks = vec![
            "/api\x00null-byte/users",
            "/path\x01with\x02control\x03chars",
            "/endpoint\x0Bvertical-tab/data",
            "/api\x0Cform-feed/endpoint",
            "/data\x0Eshift-out/file",
            "/test\x0Fshift-in/path",
            "/api\x7Fdelete-char/users",
            "/path\u{0080}high-control/data",
        ];

        for path in control_char_attacks {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_err(), "Control character injection should be blocked: {:?}", path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that excessively long paths are blocked
    #[test]
    fn test_long_path_blocked() {
        let base_url = "https://api.example.com";
        
        // Create a path longer than 2048 characters
        let long_path = format!("/api/{}", "a".repeat(2048));
        
        let result = ResponseBuilder::build_upstream_url(base_url, &long_path);
        assert!(result.is_err(), "Excessively long path should be blocked");
        
        if let Err(response) = result {
            assert_eq!(response.status(), 400);
        }
    }

    /// Test that IP address hosts are blocked (SSRF protection)
    #[test]
    fn test_ip_address_hosts_blocked() {
        let ip_bases = vec![
            "http://127.0.0.1",
            "http://192.168.1.1", 
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://[::1]",
            "http://[::ffff:127.0.0.1]",
            "https://0.0.0.0",
        ];

        for base_url in ip_bases {
            let result = ResponseBuilder::build_upstream_url(base_url, "/api/test");
            assert!(result.is_err(), "IP address host should be blocked: {}", base_url);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test additional dangerous protocols are blocked
    #[test]
    fn test_additional_dangerous_protocols_blocked() {
        let base_url = "https://api.example.com";
        
        let additional_protocols = vec![
            "chrome://settings",
            "chrome-extension://abcd/popup.html",
            "moz-extension://1234/content.js",
            "ms-appx://app/page.html",
            "ms-appx-web://app/content.html", 
            "res://evil.dll/content",
            "resource://evil/file",
            "x-javascript:alert(1)",
            "livescript:alert(1)",
            "mocha:eval('alert(1)')",
        ];

        for protocol_path in additional_protocols {
            let result = ResponseBuilder::build_upstream_url(base_url, protocol_path);
            assert!(result.is_err(), "Additional dangerous protocol should be blocked: {}", protocol_path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that double URL decoding attacks are caught
    #[test]
    fn test_double_url_encoding_blocked() {
        let base_url = "https://api.example.com";
        
        let double_encoded_attacks = vec![
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd", // Double encoded ../../../etc/passwd
            "%252f%252f%252f%252fexample.com", // Double encoded ////example.com
            "javas%2563ript%253aalert%25281%2529", // Double encoded javascript:alert(1)
            "%2568%2574%2574%2570%253a%252f%252f%2565%2578%2561%256d%2570%256c%2565%252e%2563%256f%256d", // Triple encoded http://example.com
        ];

        for path in double_encoded_attacks {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_err(), "Double URL encoding attack should be blocked: {}", path);
            
            if let Err(response) = result {
                assert_eq!(response.status(), 400);
            }
        }
    }

    /// Test that performance optimizations work for legitimate fast-path requests
    #[test]
    fn test_fast_path_performance() {
        let base_url = "https://api.example.com";
        
        let fast_path_urls = vec![
            "/api/users",
            "/api/v1/data", 
            "/api/health",
            "/static/css/style.css",
            "/static/js/app.js",
            "/health",
            "/health/status",
        ];

        for path in fast_path_urls {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_ok(), "Fast path URL should be allowed: {}", path);
            
            if let Ok(url) = result {
                assert!(url.starts_with(base_url), "URL should start with base URL: {}", url);
            }
        }
    }

    /// Test base path enforcement
    #[test]
    fn test_base_path_enforcement() {
        let base_url = "https://api.example.com/v1/";
        
        let valid_paths = vec![
            "/users",
            "/data/123",
            "/endpoint",
        ];
        
        for path in valid_paths {
            let result = ResponseBuilder::build_upstream_url(base_url, path);
            assert!(result.is_ok(), "Valid path under base should be allowed: {}", path);
            
            if let Ok(url) = result {
                assert!(url.starts_with("https://api.example.com/v1/"), "URL should respect base path: {}", url);
            }
        }
    }
}
