use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use reqwest::Client;
use std::collections::HashMap;

use crate::{
    models::VouchrsSession,
    oauth::{check_and_refresh_tokens, OAuthConfig},
    session::SessionManager,
    settings::VouchrsSettings,
    utils::response_builder::{is_hop_by_hop_header, ResponseBuilder},
    utils::user_agent::is_browser_request,
};

/// HTTP client for making upstream requests
static CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(Client::new);

/// Generic catch-all proxy handler that forwards requests as-is to upstream
/// Proxy requests with authentication
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Authentication fails (missing or invalid session)
/// - Request building fails
/// - Upstream server is unreachable
#[allow(clippy::implicit_hasher)]
pub async fn proxy_upstream(
    req: HttpRequest,
    query_params: web::Query<HashMap<String, String>>,
    body: web::Bytes,
    session_manager: web::Data<SessionManager>,
    settings: web::Data<VouchrsSettings>,
    oauth_config: web::Data<OAuthConfig>,
) -> ActixResult<HttpResponse> {
    // Extract and validate session from encrypted cookie
    let session = match extract_session_from_request(&req, &session_manager) {
        Ok(session) => session,
        Err(response) => return Ok(response),
    };

    // Check and refresh tokens if necessary
    let _tokens =
        match check_and_refresh_tokens(session.clone(), &oauth_config, &session.provider).await {
            Ok(tokens) => tokens,
            Err(response) => return Ok(response),
        };

    // Build and execute upstream request
    let upstream_url =
        match ResponseBuilder::build_upstream_url(&settings.proxy.upstream_url, req.path()) {
            Ok(url) => url,
            Err(response) => return Ok(response),
        };

    let upstream_response =
        match execute_upstream_request(&req, &query_params, &body, &upstream_url).await {
            Ok(response) => response,
            Err(response) => return Ok(response),
        };

    // Forward upstream response back to client
    forward_upstream_response(upstream_response, &req, &settings).await
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
    upstream_url: &str,
) -> Result<reqwest::Response, HttpResponse> {
    let reqwest_method = ResponseBuilder::convert_http_method(req.method())?;

    let mut request_builder = CLIENT
        .request(reqwest_method, upstream_url)
        .header("User-Agent", "Vouchrs-Proxy/1.0");

    // Forward headers, query params, and body
    request_builder = ResponseBuilder::forward_request_headers(request_builder, req);
    request_builder = ResponseBuilder::forward_query_parameters(request_builder, query_params);
    request_builder = ResponseBuilder::forward_request_body(request_builder, body);

    // Execute the request
    request_builder.send().await.map_err(|err| {
        // Return a simple error response
        HttpResponse::BadGateway().json(serde_json::json!({
            "error": "upstream_error",
            "message": format!("Failed to reach upstream service: {err}")
        }))
    })
}

// Functions have been moved to ResponseBuilder

/// Forward upstream response back to client, handling 401/403 redirects for browsers
/// 
/// # Errors
/// 
/// Returns an error if reading the upstream response body fails
async fn forward_upstream_response(
    upstream_response: reqwest::Response,
    req: &HttpRequest,
    settings: &VouchrsSettings,
) -> ActixResult<HttpResponse> {
    let status_code = upstream_response.status();

    // Check if this is a 401 Unauthorized response
    if status_code == reqwest::StatusCode::UNAUTHORIZED {
        // Determine if this is a browser request 
        if is_browser_request(req) {
            // Redirect browser requests to sign-in page
            let sign_in_url = format!("{}/oauth2/sign_in", settings.application.redirect_base_url);
            return Ok(HttpResponse::Found()
                .insert_header(("Location", sign_in_url.clone()))
                .json(serde_json::json!({
                    "error": "authentication_required",
                    "message": "Authentication required. Redirecting to sign-in page.",
                    "redirect_url": sign_in_url
                })));
        }
        // For non-browser requests, return 401 with JSON error
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "unauthorized",
            "message": "Authentication required. Please obtain a valid session cookie or bearer token."
        })));
    }

    // For all other status codes, forward the response as-is
    let actix_status = actix_web::http::StatusCode::from_u16(status_code.as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = HttpResponse::build(actix_status);

    // Forward relevant headers (excluding hop-by-hop headers)
    for (name, value) in upstream_response.headers() {
        let name_str = name.as_str().to_lowercase();
        if !is_hop_by_hop_header(&name_str) {
            if let Ok(value_str) = value.to_str() {
                response_builder.insert_header((name.as_str(), value_str));
            }
        }
    }

    // Get response body
    let response_body = upstream_response.bytes().await.map_err(|err| {
        actix_web::error::ErrorBadGateway(format!("Failed to read upstream response: {err}"))
    })?;

    Ok(response_builder.body(response_body))
}

/// Extract and validate session from encrypted cookie
/// 
/// # Errors
/// 
/// Returns an `HttpResponse` error if:
/// - No session cookie is found
/// - Session is invalid or expired
fn extract_session_from_request(
    req: &HttpRequest,
    session_manager: &SessionManager,
) -> Result<VouchrsSession, HttpResponse> {
    // Helper function to handle authentication errors
    let handle_auth_error = |message: &str| {
        if is_browser_request(req) {
            // For browser requests, redirect to sign-in page
            let sign_in_url = "/oauth2/sign_in";
            HttpResponse::Found()
                .insert_header(("Location", sign_in_url))
                .finish()
        } else {
            // For non-browser requests, return JSON error
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "unauthorized",
                "message": message
            }))
        }
    };

    // Extract session cookie
    let cookie = req
        .cookie("vouchrs_session")
        .ok_or_else(|| handle_auth_error("No session cookie found. Please authenticate first."))?;

    // Decrypt and validate session
    session_manager.decrypt_and_validate_session(cookie.value()).map_or_else(|_| Err(handle_auth_error(
        "Session is invalid or expired. Please authenticate again.",
    )), Ok)
}

// is_hop_by_hop_header function has been moved to utils::response_builder

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::create_test_settings;
    use crate::utils::test_request_builder::TestRequestBuilder;
    use crate::utils::user_agent::{derive_platform_from_user_agent, extract_user_agent_info};

    #[test]
    fn test_hop_by_hop_headers() {
        use crate::utils::response_builder::is_hop_by_hop_header;
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("transfer-encoding"));
        assert!(!is_hop_by_hop_header("content-type"));
        assert!(!is_hop_by_hop_header("authorization"));
    }

    #[test]
    fn test_user_agent_extraction() {
        // Test with modern client hints headers
        let req = TestRequestBuilder::client_hints_request();

        let user_agent_info = extract_user_agent_info(&req);

        assert_eq!(
            user_agent_info.user_agent,
            Some("\"Google Chrome\";v=\"91\", \"Chromium\";v=\"91\"".to_string())
        );
        assert_eq!(user_agent_info.platform, Some("Windows".to_string()));
        assert_eq!(user_agent_info.lang, Some("en-US".to_string()));
        assert_eq!(user_agent_info.mobile, 0);

        // Test with fallback to User-Agent header
        let req = TestRequestBuilder::macos_french_request();

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
            "Windows".to_string()
        );

        // Test macOS detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
            "macOS".to_string()
        );

        // Test Linux detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (X11; Linux x86_64)"),
            "Linux".to_string()
        );

        // Test Android detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (Linux; Android 11; SM-G991B)"),
            "Android".to_string()
        );

        // Test iOS detection
        assert_eq!(
            derive_platform_from_user_agent(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"
            ),
            "iOS".to_string()
        );

        // Test Chrome OS detection
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)"),
            "Chrome OS".to_string()
        );

        // Test unknown platform - now returns "Unknown" instead of None
        assert_eq!(
            derive_platform_from_user_agent("Mozilla/5.0 (Unknown Platform)"),
            "Unknown".to_string()
        );
    }

    #[tokio::test]
    async fn test_401_redirect_for_browser_requests() {
        // Test browser request (Accept: text/html)
        let browser_req = TestRequestBuilder::browser_request();

        let settings = create_test_settings();

        // Test that browser requests are properly detected
        assert!(
            is_browser_request(&browser_req),
            "Should detect browser request"
        );

        // Test API request (Accept: application/json)
        let api_req = TestRequestBuilder::api_request();

        assert!(!is_browser_request(&api_req), "Should detect API request");

        // Test that the redirect URL is properly constructed
        let expected_redirect_url =
            format!("{}/oauth2/sign_in", settings.application.redirect_base_url);
        assert_eq!(
            expected_redirect_url,
            "http://localhost:8080/oauth2/sign_in"
        );
    }

    #[test]
    fn test_browser_detection() {
        // Test browser detection with Accept: text/html
        let browser_req = TestRequestBuilder::browser_request();
        assert!(is_browser_request(&browser_req));

        // Test API client detection with Accept: application/json
        let api_req = TestRequestBuilder::api_request();
        assert!(!is_browser_request(&api_req));

        // Test browser detection via User-Agent fallback
        let browser_ua_req = TestRequestBuilder::user_agent_request(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        );
        assert!(is_browser_request(&browser_ua_req));

        // Test API client via User-Agent
        let api_ua_req = TestRequestBuilder::user_agent_request("curl/7.68.0");
        assert!(!is_browser_request(&api_ua_req));

        // Test unknown client (no Accept or User-Agent)
        let unknown_req = TestRequestBuilder::empty_request();
        assert!(!is_browser_request(&unknown_req));
    }

    #[test]
    fn test_sign_in_url_generation() {
        let settings = create_test_settings();
        let expected_url = format!("{}/oauth2/sign_in", settings.application.redirect_base_url);
        assert_eq!(expected_url, "http://localhost:8080/oauth2/sign_in");
    }

    #[tokio::test]
    async fn test_cookie_filtering() {
        // Create a mock HTTP request with cookies
        let cookies =
            "vouchrs_session=test_session_value; another_cookie=value; third_cookie=value3";
        let req = TestRequestBuilder::with_cookies(cookies);

        // Create a reqwest RequestBuilder
        let client = Client::new();
        let request_builder = client.get("http://example.com");

        // Apply header forwarding
        let modified_builder = ResponseBuilder::forward_request_headers(request_builder, &req);

        // Since we can't inspect the actual headers directly in the builder,
        // we need to convert it to a request and check the headers
        let request = modified_builder.build().expect("Failed to build request");
        let headers = request.headers();

        // Check that the Cookie header exists but doesn't contain vouchrs_session
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
}
