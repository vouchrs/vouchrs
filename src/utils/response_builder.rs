// filepath: /workspaces/vouchrs/src/utils/response_builder.rs
use actix_web::{cookie::Cookie, web, HttpRequest, HttpResponse};
use reqwest;
use std::collections::HashMap;
use url;
use regex::Regex;
use once_cell::sync::Lazy;

use crate::utils::cookie_utils::filter_vouchrs_cookies;

// Optimized regex pattern for detecting malicious URL patterns  
// Consolidates redundant patterns while maintaining full coverage
static SUSPICIOUS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:\.\.)|(?:/{2,})|(?:https?:/[^/])|(?:[/\\](?:[\s\v]*|\.{1,2})[/\\])|(?:(?:javascript|data|vbscript):)|(?:%(?:00|0[aAdD]|09|2[ef]|5c|68%74%74%70%3a|6a%61%76%61%73%63%72%69%70%74%3a|64%61%74%61%3a))|(?:[\x00-\x08\x0B-\x1F\x7F-\x9F])|(?:^[\.@〱〵ゝーｰ][\w.-]+\.[\w]+)|(?:(?:%[0-9a-fA-F]{2}){6,})|(?:/\\/)|(?:[@\w.-]+@[\w.-]+@)|(?:javas?%26%23)|(?:(?:%26%23\d+;?){2,})|(?:\\[0-7]{3}\\[0-7]{3})|(?:\\[a-z]\\[a-z]\\[a-z])|(?:(?:\\[a-z]){4,})|(?:\\[ux][0-9a-fA-F]{2,4}\\[ux][0-9a-fA-F]{2,4})|(?:^https?:[^/])|(?:/%0[0-9a-fA-F])|(?:ja\\[ntr]va\\[tr]script)|(?:[\r\n\t]+:)").unwrap()
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
            format!("{}&error={}", location, error_param)
        } else {
            format!("{}?error={}", location, error_param)
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
        // Layer 1: Pattern validation
        Self::validate_suspicious_patterns(request_path)?;
        
        // Layer 2: URL construction with normalization
        let final_url = Self::construct_normalized_url(base_url, request_path)?;
        
        // Layer 3: Final URL validation (scheme, host, port)
        Self::validate_final_url(base_url, &final_url)?;
        
        Ok(final_url)
    }

    /// Validate against only high-confidence malicious patterns
    /// These patterns are almost never legitimate in URL paths
    fn validate_suspicious_patterns(request_path: &str) -> Result<(), HttpResponse> {
        // Check original path
        if SUSPICIOUS_PATTERN.is_match(request_path) {
            return Err(Self::invalid_path_error());
        }
        
        // URL decode and check again to catch encoded attacks
        if let Ok(decoded) = url::Url::parse(&format!("http://dummy{}", request_path))
            .and_then(|url| Ok(url.path().to_string()))
            .or_else(|_| {
                // Fallback: manual URL decoding for partial paths
                urlencoding::decode(request_path).map(|s| s.into_owned())
            }) 
        {
            if SUSPICIOUS_PATTERN.is_match(&decoded) {
                return Err(Self::invalid_path_error());
            }
            
            // Check for suspicious patterns after lowercasing
            let decoded_lower = decoded.to_lowercase();
            if decoded_lower.contains("javascript:") || 
               decoded_lower.contains("vbscript:") || 
               decoded_lower.contains("data:") ||
               decoded_lower.contains("file:") ||
               decoded_lower.contains("ftp:") {
                return Err(Self::invalid_path_error());
            }
        }
        
        Ok(())
    }

    /// Construct normalized URL with proper path joining
    fn construct_normalized_url(base_url: &str, request_path: &str) -> Result<String, HttpResponse> {
        // Parse base URL
        let base = url::Url::parse(base_url)
            .map_err(|_| Self::invalid_path_error())?;

        // Clean and normalize the request path
        let clean_path = request_path.trim_start_matches('/');
        
        // Join the path with the base URL
        if let Ok(joined) = base.join(clean_path) {
            Ok(joined.to_string())
        } else {
            Err(Self::invalid_path_error())
        }
    }

    /// Validate the final constructed URL against security constraints
    fn validate_final_url(base_url: &str, final_url: &str) -> Result<(), HttpResponse> {
        let base = url::Url::parse(base_url)
            .map_err(|_| Self::invalid_path_error())?;
        let final_parsed = url::Url::parse(final_url)
            .map_err(|_| Self::invalid_path_error())?;

        // Validate scheme is in allowed list
        if !ALLOWED_SCHEMES.contains(&final_parsed.scheme()) {
            return Err(Self::invalid_path_error());
        }

        // Ensure the final URL stays within the same host as the base
        if final_parsed.host_str() != base.host_str() {
            return Err(Self::invalid_path_error());
        }

        // Ensure the port hasn't changed (if originally specified)
        if final_parsed.port() != base.port() {
            return Err(Self::invalid_path_error());
        }

        Ok(())
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
}
