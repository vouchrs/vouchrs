//! Header Processing Utilities
//!
//! This module consolidates all HTTP header processing logic used throughout
//! the application, eliminating duplication between production and test code.

use actix_web::{HttpRequest, HttpResponseBuilder};
use reqwest::RequestBuilder;

use crate::session::cookie::filter_vouchrs_cookies;

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

    /// Create a new processor for testing that allows more control
    #[must_use]
    pub fn for_testing() -> Self {
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

// ===============================
// CONVENIENCE FUNCTIONS
// ===============================

/// Convenience function for basic request header forwarding (most common use case)
pub fn forward_request_headers(
    req: &HttpRequest,
    request_builder: RequestBuilder,
) -> RequestBuilder {
    RequestHeaderProcessor::for_proxy().forward_request_headers(req, request_builder)
}

/// Convenience function for basic response header forwarding (most common use case)
pub fn forward_response_headers(
    upstream_response: &reqwest::Response,
    response_builder: &mut HttpResponseBuilder,
) {
    ResponseHeaderProcessor::for_proxy()
        .forward_response_headers(upstream_response, response_builder);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::RequestBuilder;
    use reqwest::Client;

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
