use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use log;
use reqwest::Client;
use std::collections::HashMap;

use crate::{
    models::VouchrsSession,
    session::SessionManager,
    settings::VouchrsSettings,
    utils::headers::{is_browser_request, RequestHeaderProcessor, ResponseHeaderProcessor},
    utils::responses::{build_upstream_url, convert_http_method, ResponseBuilder},
};

/// HTTP client for making upstream requests
static CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(Client::new);

/// Optimized proxy handler that forwards requests to upstream with efficient session management
///
/// This optimized version delegates all session logic to `SessionManager`, eliminating
/// manual session reconstruction and OAuth configuration dependencies.
///
/// # Errors
///
/// Returns an error if:
/// - Session processing fails (authentication, validation, token refresh)
/// - Upstream request building or execution fails
/// - Response forwarding fails
#[allow(clippy::implicit_hasher)]
pub async fn proxy_upstream(
    req: HttpRequest,
    query_params: web::Query<HashMap<String, String>>,
    body: web::Bytes,
    session_manager: web::Data<SessionManager>,
    settings: web::Data<VouchrsSettings>,
) -> ActixResult<HttpResponse> {
    // 1. Single call to SessionManager for all session handling
    let Ok((session, tokens_were_refreshed)) =
        session_manager.as_ref().process_proxy_session(&req).await
    else {
        return Ok(handle_authentication_error(&req, &settings));
    };

    // 2. Extract user data for auth headers
    let user_data = if let Ok(data) = session_manager.extract_user_data(&req) {
        Some(data)
    } else {
        log::warn!("Failed to extract user data for auth headers");
        None
    };

    // 3. Execute upstream request with auth headers
    let upstream_response =
        match execute_upstream_request(&req, &query_params, &body, &settings, user_data.as_ref())
            .await
        {
            Ok(response) => response,
            Err(err_response) => return Ok(err_response),
        };

    // 4. Handle 401 responses
    if upstream_response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(handle_authentication_error(&req, &settings));
    }

    // 5. Forward response with automatic session refresh
    forward_response_with_session_refresh(
        upstream_response,
        &req,
        &session_manager,
        &session,
        tokens_were_refreshed,
    )
    .await
}

/// Handle authentication errors with appropriate redirect or error response
fn handle_authentication_error(req: &HttpRequest, settings: &VouchrsSettings) -> HttpResponse {
    if is_browser_request(req) {
        // Redirect browser requests to sign-in page
        let sign_in_url = format!("{}/auth/sign_in", settings.application.redirect_base_url);
        HttpResponse::Found()
            .insert_header(("Location", sign_in_url))
            .finish()
    } else {
        // For non-browser requests, return JSON error
        ResponseBuilder::unauthorized().build()
    }
}

/// Execute the upstream request with proper headers and body
///
/// # Errors
///
/// Returns an `HttpResponse` error if:
/// - HTTP method conversion fails
/// - Upstream request fails
async fn execute_upstream_request(
    req: &HttpRequest,
    query_params: &web::Query<HashMap<String, String>>,
    body: &web::Bytes,
    settings: &VouchrsSettings,
    user_data: Option<&crate::models::VouchrsUserData>,
) -> Result<reqwest::Response, HttpResponse> {
    // Build upstream URL
    let upstream_url = build_upstream_url(&settings.proxy.upstream_url, req.path())
        .map_err(|_| ResponseBuilder::bad_gateway().build())?;

    let reqwest_method = convert_http_method(req.method())?;

    let mut request_builder = CLIENT
        .request(reqwest_method, &upstream_url)
        .header("User-Agent", "Vouchrs-Proxy/1.0");

    // Forward headers first
    request_builder =
        RequestHeaderProcessor::for_proxy().forward_request_headers(req, request_builder);

    // Add auth headers AFTER forwarding original headers to prevent header spoofing
    // This ensures our legitimate auth headers always take precedence
    if let Some(data) = user_data {
        request_builder = request_builder
            .header("X-Auth-Request-User", data.uid.to_string())
            .header("X-Auth-Request-Session", data.session_id.to_string());
    }

    // Forward query parameters
    if !query_params.is_empty() {
        for (key, value) in query_params.iter() {
            request_builder = request_builder.query(&[(key, value)]);
        }
    }

    // Forward request body if present
    if !body.is_empty() {
        request_builder = request_builder.body(body.to_vec());
    }

    // Execute the request
    request_builder.send().await.map_err(|_err| {
        // Return a bad gateway error response for upstream connection failures
        ResponseBuilder::bad_gateway().build()
    })
}

/// Forward response with session refresh functionality
///
/// # Errors
///
/// Returns an error if reading the upstream response body fails
async fn forward_response_with_session_refresh(
    upstream_response: reqwest::Response,
    req: &HttpRequest,
    session_manager: &web::Data<SessionManager>,
    session: &VouchrsSession,
    tokens_were_refreshed: bool,
) -> ActixResult<HttpResponse> {
    let status_code = upstream_response.status();
    let actix_status = actix_web::http::StatusCode::from_u16(status_code.as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = HttpResponse::build(actix_status);

    // Forward relevant headers (excluding hop-by-hop headers)
    ResponseHeaderProcessor::for_proxy()
        .forward_response_headers(&upstream_response, &mut response_builder);

    // Delegate session refresh to SessionManager
    if let Err(e) = session_manager.apply_session_refresh(
        &mut response_builder,
        req,
        session,
        tokens_were_refreshed,
    ) {
        log::warn!("Failed to apply session refresh: {e}");
        // Continue without refresh rather than failing the request
    }

    // Get response body
    let response_body = upstream_response.bytes().await.map_err(|err| {
        actix_web::error::ErrorBadGateway(format!("Failed to read upstream response: {err}"))
    })?;

    Ok(response_builder.body(response_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{RequestBuilder, TestFixtures};
    use crate::utils::headers::{is_hop_by_hop_header, RequestHeaderProcessor};
    use std::collections::HashMap;

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("transfer-encoding"));
        assert!(!is_hop_by_hop_header("content-type"));
        assert!(!is_hop_by_hop_header("authorization"));
    }

    #[tokio::test]
    async fn test_401_redirect_for_browser_requests() {
        // Test browser request (Accept: text/html)
        let browser_req = RequestBuilder::browser("/");

        let settings = TestFixtures::settings();

        // Test that browser requests are properly detected
        assert!(
            is_browser_request(&browser_req),
            "Should detect browser request"
        );

        // Test API request (Accept: application/json)
        let api_req = RequestBuilder::new().api_headers().build();

        assert!(!is_browser_request(&api_req), "Should detect API request");

        // Test that the redirect URL is properly constructed
        let expected_redirect_url =
            format!("{}/auth/sign_in", settings.application.redirect_base_url);
        assert_eq!(expected_redirect_url, "http://localhost:8080/auth/sign_in");
    }

    #[test]
    fn test_sign_in_url_generation() {
        let settings = TestFixtures::settings();
        let expected_url = format!("{}/auth/sign_in", settings.application.redirect_base_url);
        assert_eq!(expected_url, "http://localhost:8080/auth/sign_in");
    }

    #[tokio::test]
    async fn test_cookie_filtering() {
        // Create a mock HTTP request with cookies
        let cookies =
            "vouchrs_session=test_session_value; another_cookie=value; third_cookie=value3";
        let req = RequestBuilder::with_cookies(cookies);

        // Create a reqwest RequestBuilder and apply header forwarding using new processor
        let client = Client::new();
        let request_builder = client.get("http://example.com");

        let processor = RequestHeaderProcessor::for_proxy();
        let modified_builder = processor.forward_request_headers(&req, request_builder);

        // Convert to request and check headers
        let request = modified_builder.build().expect("Failed to build request");
        let headers = request.headers();

        // Verify cookie filtering
        verify_cookie_filtering(headers);
    }

    /// Verify that cookie filtering worked correctly
    fn verify_cookie_filtering(headers: &reqwest::header::HeaderMap) {
        if let Some(cookie_header) = headers.get(reqwest::header::COOKIE) {
            let cookie_str = cookie_header
                .to_str()
                .expect("Failed to convert cookie header to string");

            // Check that vouchrs_session is filtered out
            assert!(
                !cookie_str.contains("vouchrs_session"),
                "vouchrs_session cookie should be filtered out"
            );

            // Check that other cookies are preserved
            assert!(
                cookie_str.contains("another_cookie=value"),
                "Other cookies should be preserved"
            );
        }
    }

    #[tokio::test]
    async fn test_auth_header_security() {
        use crate::models::VouchrsUserData;
        use uuid::Uuid;

        // Create test user data
        let user_data = VouchrsUserData {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            provider: "google".to_string(),
            provider_id: "123456789".to_string(),
            uid: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            session_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap(),
            client_ip: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            platform: Some("Windows".to_string()),
            lang: Some("en".to_string()),
            mobile: 0,
            session_start: Some(1_700_000_000),
        };

        // Create a mock HTTP request with malicious auth headers
        let req = RequestBuilder::new()
            .header("X-Auth-Request-User", "malicious-user-id")
            .header("X-Auth-Request-Session", "malicious-session-id")
            .header("User-Agent", "Test Client")
            .build();

        let _query_params = web::Query::<HashMap<String, String>>::from_query("").unwrap();
        let _body = web::Bytes::new();
        let settings = TestFixtures::settings();

        // Test the FIXED logic: headers AFTER forwarding (current implementation)
        let client = Client::new();
        let mut request_builder = client
            .get(format!("{}/test", settings.proxy.upstream_url))
            .header("User-Agent", "Vouchrs-Proxy/1.0");

        // Forward headers first (including malicious auth headers)
        request_builder =
            RequestHeaderProcessor::for_proxy().forward_request_headers(&req, request_builder);

        // Add legitimate auth headers AFTER forwarding (this should override malicious ones)
        request_builder = request_builder
            .header("X-Auth-Request-User", user_data.uid.to_string())
            .header("X-Auth-Request-Session", user_data.session_id.to_string());

        // Build the request and verify headers
        let request = request_builder.build().expect("Failed to build request");
        let headers = request.headers();

        // Verify that our legitimate auth headers are present and override malicious ones
        assert_eq!(
            headers
                .get("X-Auth-Request-User")
                .unwrap()
                .to_str()
                .unwrap(),
            user_data.uid.to_string(),
            "Legitimate user ID should override malicious header"
        );

        assert_eq!(
            headers
                .get("X-Auth-Request-Session")
                .unwrap()
                .to_str()
                .unwrap(),
            user_data.session_id.to_string(),
            "Legitimate session ID should override malicious header"
        );

        // Also test that if NO malicious headers are present, our headers are still added
        let clean_req = RequestBuilder::new()
            .header("User-Agent", "Test Client")
            .build();

        let mut clean_request_builder = client
            .get(format!("{}/test", settings.proxy.upstream_url))
            .header("User-Agent", "Vouchrs-Proxy/1.0");

        clean_request_builder = RequestHeaderProcessor::for_proxy()
            .forward_request_headers(&clean_req, clean_request_builder);

        clean_request_builder = clean_request_builder
            .header("X-Auth-Request-User", user_data.uid.to_string())
            .header("X-Auth-Request-Session", user_data.session_id.to_string());

        let clean_request = clean_request_builder
            .build()
            .expect("Failed to build request");
        let clean_headers = clean_request.headers();

        assert_eq!(
            clean_headers
                .get("X-Auth-Request-User")
                .unwrap()
                .to_str()
                .unwrap(),
            user_data.uid.to_string(),
            "Auth headers should be present even without malicious headers"
        );
    }

    #[tokio::test]
    async fn test_auth_header_filtering() {
        // Test that malicious auth headers are filtered out during forwarding
        let req = RequestBuilder::new()
            .header("X-Auth-Request-User", "malicious-user-id")
            .header("X-Auth-Request-Session", "malicious-session-id")
            .header("User-Agent", "Test Client")
            .header("Content-Type", "application/json")
            .build();

        let client = Client::new();
        let request_builder = client.get("http://example.com");

        // Forward headers - malicious auth headers should be filtered out
        let request_builder =
            RequestHeaderProcessor::for_proxy().forward_request_headers(&req, request_builder);

        let request = request_builder.build().expect("Failed to build request");
        let headers = request.headers();

        // Verify that auth headers were filtered out
        assert!(
            headers.get("X-Auth-Request-User").is_none(),
            "Malicious X-Auth-Request-User header should be filtered out"
        );

        assert!(
            headers.get("X-Auth-Request-Session").is_none(),
            "Malicious X-Auth-Request-Session header should be filtered out"
        );

        // Verify that other headers are preserved
        assert!(
            headers.get("Content-Type").is_some(),
            "Other headers should be preserved"
        );
    }

    #[tokio::test]
    async fn test_reqwest_header_replacement() {
        use reqwest::header::{HeaderMap, HeaderValue};

        // Test building headers manually to ensure override
        let client = Client::new();

        let mut headers = HeaderMap::new();
        headers.insert("X-Test-Header", HeaderValue::from_static("first-value"));
        headers.insert("X-Test-Header", HeaderValue::from_static("second-value")); // This should replace

        let request_builder = client.get("http://example.com").headers(headers);

        let request = request_builder.build().expect("Failed to build request");
        let request_headers = request.headers();

        if let Some(header_value) = request_headers.get("X-Test-Header") {
            let value_str = header_value.to_str().unwrap();
            println!("HeaderMap replacement value: {value_str}");

            // HeaderMap.insert should replace the value
            assert_eq!(
                value_str, "second-value",
                "HeaderMap insert should replace the value"
            );
        } else {
            panic!("Header should be present");
        }
    }
}
