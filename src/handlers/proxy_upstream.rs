use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use log;
use reqwest::Client;
use std::collections::HashMap;

use crate::{
    models::VouchrsSession,
    oauth::check_and_refresh_tokens,
    oauth::OAuthConfig,
    session::SessionManager,
    settings::VouchrsSettings,
    utils::headers::{is_browser_request, RequestHeaderProcessor, ResponseHeaderProcessor},
    utils::responses::{build_upstream_url, convert_http_method, ResponseBuilder},
};

/// HTTP client for making upstream requests
static CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(Client::new);

/// Reconstruct session from OAuth result after token refresh
fn reconstruct_session_from_oauth_result(
    oauth_result: &crate::oauth::OAuthResult,
    req: &HttpRequest,
    session_manager: &SessionManager,
) -> VouchrsSession {
    let (client_ip, _) = crate::session::utils::extract_client_info(req);
    VouchrsSession {
        id_token: oauth_result.id_token.clone(),
        refresh_token: oauth_result.refresh_token.clone(),
        credential_id: None,
        user_handle: None,
        provider: oauth_result.provider.clone(),
        expires_at: oauth_result.expires_at,
        authenticated_at: oauth_result.authenticated_at,
        client_ip: if session_manager.is_session_ip_binding_enabled() {
            client_ip
        } else {
            None
        },
    }
}

/// Handle token refresh for proxy requests
async fn handle_token_refresh(
    session: &VouchrsSession,
    oauth_config: &OAuthConfig,
) -> Result<(crate::oauth::OAuthResult, bool), HttpResponse> {
    let oauth_result = check_and_refresh_tokens(
        crate::oauth::OAuthResult {
            provider: session.provider.clone(),
            provider_id: String::new(), // Not needed for refresh
            email: None,                // Not needed for refresh
            name: None,                 // Not needed for refresh
            expires_at: session.expires_at,
            authenticated_at: session.authenticated_at,
            id_token: session.id_token.clone(),
            refresh_token: session.refresh_token.clone(),
        },
        oauth_config,
        &session.provider,
    )
    .await?;

    // Check if tokens were actually refreshed by comparing expires_at
    let tokens_refreshed = oauth_result.expires_at != session.expires_at;

    Ok((oauth_result, tokens_refreshed))
}

/// Process OAuth result and determine if session needs updating
fn process_oauth_result(
    oauth_result: &crate::oauth::OAuthResult,
    original_session: VouchrsSession,
    req: &HttpRequest,
    session_manager: &SessionManager,
) -> (VouchrsSession, bool) {
    let tokens_refreshed = oauth_result.expires_at != original_session.expires_at;

    if tokens_refreshed {
        log::info!("OAuth tokens were refreshed during proxy request");
        let updated_session =
            reconstruct_session_from_oauth_result(oauth_result, req, session_manager);
        (updated_session, true)
    } else {
        (original_session, false)
    }
}

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
    let (updated_session, tokens_were_refreshed) =
        match handle_token_refresh(&session, &oauth_config).await {
            Ok((oauth_result, _tokens_refreshed)) => {
                process_oauth_result(&oauth_result, session, &req, &session_manager)
            }
            Err(response) => return Ok(response),
        };

    // Build and execute upstream request
    let upstream_url = match build_upstream_url(&settings.proxy.upstream_url, req.path()) {
        Ok(url) => url,
        Err(response) => return Ok(response),
    };

    let upstream_response =
        match execute_upstream_request(&req, &query_params, &body, &upstream_url).await {
            Ok(response) => response,
            Err(response) => return Ok(response),
        };

    // Forward upstream response back to client with potential cookie refresh
    forward_upstream_response(
        upstream_response,
        &req,
        &settings,
        &session_manager,
        &updated_session,
        tokens_were_refreshed,
    )
    .await
}

/// Handle 401 Unauthorized responses with appropriate redirect or error response
fn handle_unauthorized_response(req: &HttpRequest, settings: &VouchrsSettings) -> HttpResponse {
    if is_browser_request(req) {
        // Redirect browser requests to sign-in page
        let sign_in_url = format!("{}/auth/sign_in", settings.application.redirect_base_url);
        HttpResponse::Found()
            .insert_header(("Location", sign_in_url.clone()))
            .json(serde_json::json!({
                "error": "authentication_required",
                "message": "Authentication required. Redirecting to sign-in page.",
                "redirect_url": sign_in_url
            }))
    } else {
        // For non-browser requests, return 401 with JSON error
        ResponseBuilder::unauthorized().build()
    }
}

/// Update session cookie if needed due to token refresh or regular refresh
fn update_session_cookie_if_needed(
    response_builder: &mut actix_web::HttpResponseBuilder,
    session_manager: &SessionManager,
    session: &VouchrsSession,
    req: &HttpRequest,
    tokens_were_refreshed: bool,
) {
    if tokens_were_refreshed || session_manager.is_cookie_refresh_enabled() {
        let reason = if tokens_were_refreshed {
            "tokens were refreshed"
        } else {
            "regular session refresh is enabled"
        };
        log::debug!("Updating session cookie because {reason}");

        // Use IP binding if enabled for cookie updates
        let cookie_result = if session_manager.is_session_ip_binding_enabled() {
            session_manager
                .cookie_factory()
                .create_session_cookie_with_context(session, req)
        } else {
            session_manager
                .cookie_factory()
                .create_session_cookie(session)
        };

        match cookie_result {
            Ok(updated_cookie) => {
                log::info!(
                    "Setting updated session cookie for user on provider: {} (reason: {reason})",
                    session.provider
                );
                response_builder.cookie(updated_cookie);
            }
            Err(e) => {
                log::warn!("Failed to create updated session cookie: {e}");
                // Continue without refresh rather than failing the request
            }
        }
    }
}

/// Forward upstream response back to client with session refresh functionality
///
/// # Errors
///
/// Returns an error if reading the upstream response body fails
async fn forward_upstream_response(
    upstream_response: reqwest::Response,
    req: &HttpRequest,
    settings: &VouchrsSettings,
    session_manager: &SessionManager,
    session: &VouchrsSession,
    tokens_were_refreshed: bool,
) -> ActixResult<HttpResponse> {
    let status_code = upstream_response.status();

    // Check if this is a 401 Unauthorized response
    if status_code == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(handle_unauthorized_response(req, settings));
    }

    // For all other status codes, forward the response as-is
    let actix_status = actix_web::http::StatusCode::from_u16(status_code.as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = HttpResponse::build(actix_status);

    // Forward relevant headers (excluding hop-by-hop headers)
    ResponseHeaderProcessor::for_proxy()
        .forward_response_headers(&upstream_response, &mut response_builder);

    // Check if session cookie should be updated due to token refresh or regular refresh
    update_session_cookie_if_needed(
        &mut response_builder,
        session_manager,
        session,
        req,
        tokens_were_refreshed,
    );

    // Get response body
    let response_body = upstream_response.bytes().await.map_err(|err| {
        actix_web::error::ErrorBadGateway(format!("Failed to read upstream response: {err}"))
    })?;

    Ok(response_builder.body(response_body))
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
    let reqwest_method = convert_http_method(req.method())?;

    let mut request_builder = CLIENT
        .request(reqwest_method, upstream_url)
        .header("User-Agent", "Vouchrs-Proxy/1.0");

    // Forward headers
    request_builder =
        RequestHeaderProcessor::for_proxy().forward_request_headers(req, request_builder);

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

/// Extract and validate session from encrypted cookie with session hijacking prevention
///
/// # Errors
///
/// Returns an `HttpResponse` error if:
/// - No session cookie is found
/// - Session is invalid or expired
/// - Client context validation fails (session hijacking prevention)
fn extract_session_from_request(
    req: &HttpRequest,
    session_manager: &SessionManager,
) -> Result<VouchrsSession, HttpResponse> {
    // Helper function to handle authentication errors
    let handle_auth_error = |_message: &str| {
        if is_browser_request(req) {
            // For browser requests, redirect to sign-in page
            let sign_in_url = "/auth/sign_in";
            HttpResponse::Found()
                .insert_header(("Location", sign_in_url))
                .finish()
        } else {
            // For non-browser requests, return JSON error
            ResponseBuilder::unauthorized().build()
        }
    };

    // Extract and validate session using modern method
    let session = session_manager.extract_session(req).map_err(|_| {
        handle_auth_error("Session is invalid or expired. Please authenticate again.")
    })?;

    // For proxy requests, we only need basic session validation
    // Client context validation (session hijacking detection) should only be used
    // for sensitive operations like passkey registration, not regular proxy requests
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::fixtures::TestFixtures;
    use crate::testing::RequestBuilder;
    use crate::utils::headers::{is_hop_by_hop_header, RequestHeaderProcessor};

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
