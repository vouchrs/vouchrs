//! HTTP Header Processing and User Agent Utilities
//!
//! This module consolidates all HTTP header processing logic and user agent
//! detection utilities used throughout the application.

use std::collections::HashMap;
use std::sync::LazyLock;

use actix_web::{HttpRequest, HttpResponseBuilder};
use reqwest::RequestBuilder;

use crate::session::cookie::filter_vouchrs_cookies;

// Cache for common user-agent platform mappings to avoid repeated parsing
static PLATFORM_CACHE: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut cache = HashMap::new();

    // Pre-populate with common user agents for faster lookup
    cache.insert("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows");
    cache.insert("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macOS");
    cache.insert("Mozilla/5.0 (X11; Linux x86_64)", "Linux");
    cache.insert(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
        "iOS",
    );
    cache.insert("Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X)", "iOS");
    cache.insert("Mozilla/5.0 (Linux; Android 11; SM-G991B)", "Android");
    cache.insert("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)", "Chrome OS");

    cache
});

// ===============================
// USER AGENT UTILITIES
// ===============================

/// User agent information extracted from HTTP headers
#[derive(Debug, Clone)]
pub struct UserAgentInfo {
    pub user_agent: Option<String>,
    pub platform: Option<String>,
    pub lang: Option<String>,
    pub mobile: u8, // 0 or 1
}

/// Extract user agent information from HTTP request headers
/// Uses modern client hints headers first, with fallback to traditional User-Agent header
#[must_use]
pub fn extract_user_agent_info(req: &HttpRequest) -> UserAgentInfo {
    let headers = req.headers();

    // Try to get user agent from modern client hints or fallback to User-Agent header
    let user_agent = headers
        .get("sec-ch-ua")
        .and_then(|h| h.to_str().ok())
        .map(ToString::to_string)
        .or_else(|| {
            headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(ToString::to_string)
        });

    // Try to get platform from client hints or derive from User-Agent
    let platform = headers
        .get("sec-ch-ua-platform")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim_matches('"').to_string())
        .or_else(|| {
            user_agent.as_ref().map_or_else(
                || Some("Unknown".to_string()),
                |ua| Some(derive_platform_from_user_agent(ua)),
            )
        });

    // Extract language preference from Accept-Language header
    let lang = headers
        .get("accept-language")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty());

    // Detect mobile from client hints
    let mobile = headers
        .get("sec-ch-ua-mobile")
        .and_then(|h| h.to_str().ok())
        .map_or(0, |s| u8::from(s.contains('1')));

    UserAgentInfo {
        user_agent,
        platform,
        lang,
        mobile,
    }
}

/// Derive platform from User-Agent string with caching for performance
/// Detects common platforms like Windows, macOS, Linux, Android, iOS, Chrome OS
#[must_use]
pub fn derive_platform_from_user_agent(user_agent: &str) -> String {
    // Check cache first for exact matches (most common case)
    if let Some(&cached) = PLATFORM_CACHE.get(user_agent) {
        return cached.to_string();
    }

    // Fallback to pattern matching for non-cached user agents
    let ua_lower = user_agent.to_lowercase();

    if ua_lower.contains("android") {
        "Android".to_string()
    } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") || ua_lower.contains("ios") {
        "iOS".to_string()
    } else if ua_lower.contains("chrome os") || ua_lower.contains("cros") {
        "Chrome OS".to_string()
    } else if ua_lower.contains("windows") {
        "Windows".to_string()
    } else if ua_lower.contains("macintosh") || ua_lower.contains("mac os") {
        "macOS".to_string()
    } else if ua_lower.contains("linux") {
        "Linux".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// Determine if a request came from a browser vs an API client
/// Browsers typically send Accept headers that include text/html
#[must_use]
pub fn is_browser_request(req: &HttpRequest) -> bool {
    if let Some(accept_header) = req.headers().get("accept") {
        if let Ok(accept_str) = accept_header.to_str() {
            // Browser requests typically accept text/html
            return accept_str.contains("text/html")
                || accept_str.contains("application/xhtml+xml");
        }
    }

    // Fallback: check User-Agent for common browser patterns
    if let Some(user_agent) = req.headers().get("user-agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            let ua_lower = ua_str.to_lowercase();
            return ua_lower.contains("mozilla")
                || ua_lower.contains("chrome")
                || ua_lower.contains("safari")
                || ua_lower.contains("firefox")
                || ua_lower.contains("edge");
        }
    }

    false
}

// ===============================
// HOP-BY-HOP HEADER DETECTION
// ===============================

/// Check if a header is a hop-by-hop header that should not be forwarded
///
/// Hop-by-hop headers are meant for a single transport-level connection only
/// and should not be forwarded by proxies or stored by caches.
///
/// Based on RFC 2616 Section 13.5.1
#[must_use]
pub fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
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

// ===============================
// REQUEST HEADER FORWARDING
// ===============================

/// Header Processing Strategy for request forwarding
#[derive(Debug, Clone)]
pub struct RequestHeaderProcessor {
    /// Whether to filter the authorization header
    pub skip_authorization: bool,
    /// Whether to filter hop-by-hop headers
    pub skip_hop_by_hop: bool,
    /// Whether to filter vouchrs session cookies
    pub filter_session_cookies: bool,
}

impl Default for RequestHeaderProcessor {
    fn default() -> Self {
        Self {
            skip_authorization: true,
            skip_hop_by_hop: true,
            filter_session_cookies: true,
        }
    }
}

impl RequestHeaderProcessor {
    /// Create a new processor with default settings for proxy requests
    #[must_use]
    pub fn for_proxy() -> Self {
        Self::default()
    }

    /// Forward headers from an Actix `HttpRequest` to a reqwest `RequestBuilder`
    ///
    /// This function handles:
    /// - Skipping authorization headers (when enabled)
    /// - Skipping hop-by-hop headers (when enabled)
    /// - Filtering vouchrs session cookies (when enabled)
    /// - Converting header values to strings safely
    pub fn forward_request_headers(
        &self,
        req: &HttpRequest,
        mut request_builder: RequestBuilder,
    ) -> RequestBuilder {
        for (name, value) in req.headers() {
            let name_str = name.as_str().to_lowercase();

            // Check if this header should be skipped
            if self.should_skip_header(&name_str) {
                continue;
            }

            // Special handling for cookies
            if name_str == "cookie" {
                request_builder = self.process_cookie_header(value, request_builder, name.as_str());
                continue;
            }

            // Add other headers
            if let Ok(value_str) = value.to_str() {
                request_builder = request_builder.header(name.as_str(), value_str);
            }
        }

        request_builder
    }

    /// Check if a header should be skipped based on processor configuration
    fn should_skip_header(&self, name_str: &str) -> bool {
        if self.skip_authorization && name_str == "authorization" {
            return true;
        }

        if self.skip_hop_by_hop && is_hop_by_hop_header(name_str) {
            return true;
        }

        false
    }

    /// Process cookie headers with optional session cookie filtering
    fn process_cookie_header(
        &self,
        value: &actix_web::http::header::HeaderValue,
        mut request_builder: RequestBuilder,
        header_name: &str,
    ) -> RequestBuilder {
        if let Ok(cookie_str) = value.to_str() {
            if self.filter_session_cookies {
                if let Some(filtered_cookie) = filter_vouchrs_cookies(cookie_str) {
                    request_builder = request_builder.header(header_name, filtered_cookie);
                }
            } else {
                request_builder = request_builder.header(header_name, cookie_str);
            }
        }
        request_builder
    }
}

// ===============================
// RESPONSE HEADER FORWARDING
// ===============================

/// Header Processing Strategy for response forwarding
#[derive(Debug, Clone)]
pub struct ResponseHeaderProcessor {
    /// Whether to filter hop-by-hop headers
    pub skip_hop_by_hop: bool,
}

impl Default for ResponseHeaderProcessor {
    fn default() -> Self {
        Self {
            skip_hop_by_hop: true,
        }
    }
}

impl ResponseHeaderProcessor {
    /// Create a new processor with default settings for proxy responses
    #[must_use]
    pub fn for_proxy() -> Self {
        Self::default()
    }

    /// Forward headers from a reqwest Response to an Actix `HttpResponseBuilder`
    ///
    /// Filters out hop-by-hop headers that should not be forwarded to clients
    pub fn forward_response_headers(
        &self,
        upstream_response: &reqwest::Response,
        response_builder: &mut HttpResponseBuilder,
    ) {
        for (name, value) in upstream_response.headers() {
            let name_str = name.as_str().to_lowercase();

            // Skip hop-by-hop headers if filtering is enabled
            if self.skip_hop_by_hop && is_hop_by_hop_header(&name_str) {
                continue;
            }

            if let Ok(value_str) = value.to_str() {
                response_builder.insert_header((name.as_str(), value_str));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::RequestBuilder;
    use reqwest::Client;

    // ===============================
    // USER AGENT TESTS
    // ===============================

    #[test]
    fn test_user_agent_extraction() {
        // Test with modern client hints headers
        let req = RequestBuilder::client_hints_request();

        let user_agent_info = extract_user_agent_info(&req);

        assert_eq!(
            user_agent_info.user_agent,
            Some("\"Google Chrome\";v=\"91\", \"Chromium\";v=\"91\"".to_string())
        );
        assert_eq!(user_agent_info.platform, Some("Windows".to_string()));
        assert_eq!(user_agent_info.lang, Some("en-US".to_string()));
        assert_eq!(user_agent_info.mobile, 0);

        // Test with fallback to User-Agent header
        let req = RequestBuilder::macos_french_request();

        let user_agent_info = extract_user_agent_info(&req);

        assert_eq!(
            user_agent_info.user_agent,
            Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string())
        );
        assert_eq!(user_agent_info.platform, Some("macOS".to_string())); // Derived from User-Agent
        assert_eq!(user_agent_info.lang, Some("fr-FR".to_string()));
        assert_eq!(user_agent_info.mobile, 0); // Default when not specified
    }

    #[test]
    fn test_platform_derivation_from_user_agent() {
        // Test Windows detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            "Windows"
        );

        // Test macOS detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
            "macOS"
        );

        // Test Linux detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (X11; Linux x86_64)"),
            "Linux"
        );

        // Test Android detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (Linux; Android 11; SM-G991B)"),
            "Android"
        );

        // Test iOS detection
        assert_eq!(
            derive_platform_from_user_agent(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"
            ),
            "iOS"
        );

        // Test Chrome OS detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)"),
            "Chrome OS"
        );

        // Test unknown platform - now returns "Unknown" instead of None
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (Unknown Platform)"),
            "Unknown"
        );
    }

    #[test]
    fn test_is_browser_request() {
        // Test browser detection with Accept: text/html
        let browser_req = RequestBuilder::browser_request();
        assert!(is_browser_request(&browser_req));

        // Test API client detection with Accept: application/json
        let api_req = RequestBuilder::api_request();
        assert!(!is_browser_request(&api_req));

        // Test with a user agent only request
        let browser_ua_req = RequestBuilder::user_agent_request(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        );
        assert!(is_browser_request(&browser_ua_req));

        // Test API client via User-Agent
        let api_ua_req = RequestBuilder::user_agent_request("curl/7.68.0");
        assert!(!is_browser_request(&api_ua_req));

        // Test unknown client (no Accept or User-Agent)
        let unknown_req = RequestBuilder::empty_request();
        assert!(!is_browser_request(&unknown_req));
    }

    // ===============================
    // HEADER PROCESSING TESTS
    // ===============================

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("Connection")); // Case insensitive
        assert!(is_hop_by_hop_header("TRANSFER-ENCODING")); // Case insensitive
        assert!(is_hop_by_hop_header("keep-alive"));
        assert!(is_hop_by_hop_header("proxy-authenticate"));
        assert!(is_hop_by_hop_header("proxy-authorization"));
        assert!(is_hop_by_hop_header("te"));
        assert!(is_hop_by_hop_header("trailers"));
        assert!(is_hop_by_hop_header("transfer-encoding"));
        assert!(is_hop_by_hop_header("upgrade"));

        // These should NOT be hop-by-hop headers
        assert!(!is_hop_by_hop_header("content-type"));
        assert!(!is_hop_by_hop_header("authorization"));
        assert!(!is_hop_by_hop_header("user-agent"));
        assert!(!is_hop_by_hop_header("accept"));
        assert!(!is_hop_by_hop_header("cookie"));
    }

    #[tokio::test]
    async fn test_cookie_filtering() {
        // Create a mock HTTP request with cookies including vouchrs session
        let cookies =
            "vouchrs_session=test_session_value; another_cookie=value; third_cookie=value3";
        let req = RequestBuilder::with_cookies(cookies);

        // Create a reqwest RequestBuilder and apply header forwarding
        let client = Client::new();
        let request_builder = client.get("http://example.com");

        let processor = RequestHeaderProcessor::for_proxy();
        let modified_builder = processor.forward_request_headers(&req, request_builder);

        // Convert to request and check headers
        let request = modified_builder.build().expect("Failed to build request");
        let headers = request.headers();

        // Verify cookie filtering worked
        if let Some(cookie_header) = headers.get(reqwest::header::COOKIE) {
            let cookie_str = cookie_header
                .to_str()
                .expect("Failed to convert cookie header to string");

            assert!(
                !cookie_str.contains("vouchrs_session="),
                "Cookie header should not contain vouchrs_session"
            );
            assert!(
                cookie_str.contains("another_cookie=value"),
                "Cookie header should contain other cookies"
            );
            assert!(
                cookie_str.contains("third_cookie=value3"),
                "Cookie header should contain other cookies"
            );
        } else {
            panic!("Cookie header is missing");
        }
    }

    #[tokio::test]
    async fn test_authorization_header_filtering() {
        // Create a request with authorization header using actix test framework
        let req = actix_web::test::TestRequest::default()
            .insert_header(("authorization", "Bearer test-token"))
            .insert_header(("content-type", "application/json"))
            .insert_header(("user-agent", "test-agent"))
            .to_http_request();

        let client = Client::new();
        let request_builder = client.get("http://example.com");

        let processor = RequestHeaderProcessor::for_proxy();
        let modified_builder = processor.forward_request_headers(&req, request_builder);

        let request = modified_builder.build().expect("Failed to build request");
        let headers = request.headers();

        // Authorization should be filtered out
        assert!(headers.get("authorization").is_none());

        // Other headers should be preserved
        assert!(headers.get("content-type").is_some());
        assert!(headers.get("user-agent").is_some());
    }

    #[tokio::test]
    async fn test_hop_by_hop_header_filtering() {
        // Create a request with hop-by-hop headers using actix test framework
        let req = actix_web::test::TestRequest::default()
            .insert_header(("connection", "keep-alive"))
            .insert_header(("transfer-encoding", "chunked"))
            .insert_header(("content-type", "application/json"))
            .to_http_request();

        let client = Client::new();
        let request_builder = client.get("http://example.com");

        let processor = RequestHeaderProcessor::for_proxy();
        let modified_builder = processor.forward_request_headers(&req, request_builder);

        let request = modified_builder.build().expect("Failed to build request");
        let headers = request.headers();

        // Hop-by-hop headers should be filtered out
        assert!(headers.get("connection").is_none());
        assert!(headers.get("transfer-encoding").is_none());

        // Normal headers should be preserved
        assert!(headers.get("content-type").is_some());
    }

    #[test]
    fn test_processor_configuration() {
        let mut processor = RequestHeaderProcessor::default();

        // Test default configuration
        assert!(processor.skip_authorization);
        assert!(processor.skip_hop_by_hop);
        assert!(processor.filter_session_cookies);

        // Test that we can disable filtering
        processor.skip_authorization = false;
        processor.filter_session_cookies = false;

        assert!(!processor.should_skip_header("authorization"));
        assert!(processor.should_skip_header("connection")); // hop-by-hop still filtered
    }
}
