use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use crate::{
    jwt_session::JwtSessionManager,
    models::{VouchrsSession},
    oauth::OAuthConfig,
    settings::VouchrsSettings,
    utils::response_builder::ResponseBuilder,
};

/// HTTP client for making upstream API requests
static CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(|| {
    Client::new()
});

/// Generic catch-all proxy handler that forwards requests as-is to upstream with JWT token injection
pub async fn proxy_generic_api(
    req: HttpRequest,
    query_params: web::Query<HashMap<String, String>>,
    body: web::Bytes,
    jwt_manager: web::Data<JwtSessionManager>,
    settings: web::Data<VouchrsSettings>,
    oauth_config: web::Data<OAuthConfig>,
) -> ActixResult<HttpResponse> {
    // Extract and validate session from encrypted cookie
    let session = match extract_session_from_request(&req, &jwt_manager).await {
        Ok(session) => session,
        Err(response) => return Ok(response),
    };

    // Check and refresh tokens if necessary
    let _tokens = match check_and_refresh_tokens(session.clone(), &oauth_config, &session.provider).await {
        Ok(tokens) => tokens,
        Err(response) => return Ok(response),
    };

    // Build and execute upstream request
    let upstream_url = build_upstream_url(&settings.proxy.upstream_url, req.path());
    let upstream_response = match execute_upstream_request(&req, &query_params, &body, &upstream_url).await {
        Ok(response) => response,
        Err(response) => return Ok(response),
    };

    // Forward upstream response back to client
    forward_upstream_response(upstream_response, &req, &settings).await
}

/// Build the upstream URL by combining base URL with request path
fn build_upstream_url(base_url: &str, request_path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), request_path)
}

/// Execute the upstream request with proper headers and body
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
    
    // Note: Access token functionality removed - requests are forwarded without custom Authorization header

    // Forward headers, query params, and body
    request_builder = forward_request_headers(request_builder, req);
    request_builder = forward_query_parameters(request_builder, query_params);
    request_builder = forward_request_body(request_builder, body);

    // Execute the request
    request_builder.send().await.map_err(|err| {
        ResponseBuilder::json_error(
            actix_web::http::StatusCode::BAD_GATEWAY, 
            "upstream_request_failed", 
            &format!("Failed to reach upstream service: {}", err)
        )
    })
}

/// Convert Actix HTTP method to reqwest method
fn convert_http_method(method: &actix_web::http::Method) -> Result<reqwest::Method, HttpResponse> {
    match method.as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "DELETE" => Ok(reqwest::Method::DELETE),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "HEAD" => Ok(reqwest::Method::HEAD),
        "OPTIONS" => Ok(reqwest::Method::OPTIONS),
        method_str => Err(ResponseBuilder::bad_request_json(&format!("HTTP method '{}' is not supported", method_str))),
    }
}

/// Forward request headers (excluding Authorization and hop-by-hop headers)
fn forward_request_headers(
    mut request_builder: reqwest::RequestBuilder,
    req: &HttpRequest,
) -> reqwest::RequestBuilder {
    for (name, value) in req.headers() {
        let name_str = name.as_str().to_lowercase();
        if name_str != "authorization" && !is_hop_by_hop_header(&name_str) {
            if let Ok(value_str) = value.to_str() {
                request_builder = request_builder.header(name.as_str(), value_str);
            }
        }
    }
    request_builder
}

/// Forward query parameters
fn forward_query_parameters(
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
fn forward_request_body(
    mut request_builder: reqwest::RequestBuilder,
    body: &web::Bytes,
) -> reqwest::RequestBuilder {
    if !body.is_empty() {
        request_builder = request_builder.body(body.to_vec());
    }
    request_builder
}

/// Forward upstream response back to client, handling 401/403 redirects for browsers
async fn forward_upstream_response(upstream_response: reqwest::Response, req: &HttpRequest, settings: &VouchrsSettings) -> ActixResult<HttpResponse> {
    let status_code = upstream_response.status();
    
    // Check if this is a 401 Unauthorized response
    if status_code == reqwest::StatusCode::UNAUTHORIZED {
        // Determine if this is a browser request vs API request
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
        // For API requests, return 401 with JSON error
        else {
            return Ok(ResponseBuilder::unauthorized_json(
                "Authentication required. Please obtain a valid session cookie or bearer token."
            ));
        }
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
        actix_web::error::ErrorBadGateway(format!("Failed to read upstream response: {}", err))
    })?;

    Ok(response_builder.body(response_body))
}

/// Determine if a request came from a browser vs an API client
/// Browsers typically send Accept headers that include text/html
fn is_browser_request(req: &HttpRequest) -> bool {
    if let Some(accept_header) = req.headers().get("accept") {
        if let Ok(accept_str) = accept_header.to_str() {
            // Browser requests typically accept text/html
            return accept_str.contains("text/html") || accept_str.contains("application/xhtml+xml");
        }
    }
    
    // Fallback: check User-Agent for common browser patterns
    if let Some(user_agent) = req.headers().get("user-agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            let ua_lower = ua_str.to_lowercase();
            return ua_lower.contains("mozilla") || 
                   ua_lower.contains("chrome") || 
                   ua_lower.contains("safari") || 
                   ua_lower.contains("firefox") || 
                   ua_lower.contains("edge");
        }
    }
    
    false
}

/// Extract and validate session from encrypted cookie
async fn extract_session_from_request(
    req: &HttpRequest,
    jwt_manager: &JwtSessionManager,
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
            // For API requests, return JSON error
            ResponseBuilder::unauthorized_json(message)
        }
    };

    // Extract session cookie
    let cookie = req.cookie("vouchrs_session")
        .ok_or_else(|| {
            handle_auth_error("No session cookie found. Please authenticate first.")
        })?;

    // Decrypt and validate session
    match jwt_manager.decrypt_and_validate_session(cookie.value()) {
        Ok(session) => Ok(session),
        Err(_) => Err(handle_auth_error("Session is invalid or expired. Please authenticate again.")),
    }
}

/// Check if tokens need refresh and refresh them if necessary
async fn check_and_refresh_tokens(
    mut session: VouchrsSession,
    oauth_config: &OAuthConfig,
    provider: &str,
) -> Result<VouchrsSession, HttpResponse> {
    // Check if tokens need refresh (within 5 minutes of expiry)
    let now = chrono::Utc::now();
    let buffer_time = chrono::Duration::minutes(5);
    if session.expires_at > now + buffer_time {
        return Ok(session);
    }

    // Attempt to refresh tokens
    let refresh_token = session.refresh_token.as_ref().ok_or_else(|| {
        ResponseBuilder::unauthorized_json("OAuth tokens expired and no refresh token available. Please re-authenticate.")
    })?;

    // Call refresh_oauth_tokens and update session fields
    match refresh_oauth_tokens(refresh_token, oauth_config, provider).await {
        Ok((new_id_token, new_refresh_token, new_expires_at)) => {
            session.id_token = new_id_token;
            session.refresh_token = new_refresh_token;
            session.expires_at = new_expires_at;
            Ok(session)
        }
        Err(err) => Err(ResponseBuilder::unauthorized_json(&format!("Failed to refresh OAuth tokens: {}", err))),
    }
}

/// Refresh OAuth tokens using the refresh token
async fn refresh_oauth_tokens(
    refresh_token: &str,
    oauth_config: &OAuthConfig,
    provider: &str,
) -> Result<(Option<String>, Option<String>, chrono::DateTime<chrono::Utc>), String> {
    // Get provider configuration
    let runtime_provider = oauth_config.providers.get(provider)
        .ok_or_else(|| format!("Provider {} not configured", provider))?;

    let client_id = runtime_provider.client_id.as_ref()
        .ok_or_else(|| format!("Client ID not configured for provider {}", provider))?;

    // Handle client credentials based on provider configuration
    let client_secret = if let Some(ref secret) = runtime_provider.client_secret {
        secret.clone()
    } else if let Some(ref jwt_config) = runtime_provider.settings.jwt_signing {
        // Generate JWT client secret for Apple
        generate_apple_client_secret_for_refresh(jwt_config, &runtime_provider.settings)
            .map_err(|e| format!("Failed to generate client secret: {}", e))?
    } else {
        return Err(format!("No client secret or JWT signing configuration for provider {}", provider));
    };

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
    ];

    let response = CLIENT
        .post(&runtime_provider.token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Token refresh failed with status {}: {}", status, error_text));
    }

    // Parse token response as before, but extract id_token, refresh_token, expires_at
    let token_response: Value = response.json().await
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    let expires_in = token_response["expires_in"]
        .as_u64()
        .unwrap_or(3600); // Default to 1 hour

    let new_refresh_token = token_response["refresh_token"]
        .as_str()
        .map(|s| s.to_string());

    let new_id_token = token_response["id_token"]
        .as_str()
        .map(|s| s.to_string());

    let new_expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64);

    Ok((new_id_token, new_refresh_token, new_expires_at))
}

/// Extract Apple client secret generation to a separate function
fn generate_apple_client_secret_for_refresh(jwt_config: &crate::settings::JwtSigningConfig, provider_settings: &crate::settings::ProviderSettings) -> Result<String, String> {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use p256::pkcs8::DecodePrivateKey;
    use base64::{Engine as _, engine::general_purpose};
    use chrono::{Utc, Duration};
    use serde::{Serialize, Deserialize};
    
    #[derive(Debug, Serialize, Deserialize)]
    struct AppleJwtClaims {
        iss: String,    // Team ID
        iat: i64,       // Issued at time
        exp: i64,       // Expiration time
        aud: String,    // Audience (always "https://appleid.apple.com")
        sub: String,    // Client ID
    }

    // Get required values using the new getter methods
    let team_id = jwt_config.get_team_id()
        .ok_or_else(|| "Team ID not configured for Apple provider".to_string())?;
    let client_id = provider_settings.get_client_id()
        .ok_or_else(|| "Client ID not configured for Apple provider".to_string())?;
    let key_id = jwt_config.get_key_id()
        .ok_or_else(|| "Key ID not configured for Apple provider".to_string())?;
    let private_key_path = jwt_config.get_private_key_path()
        .ok_or_else(|| "Private key path not configured for Apple provider".to_string())?;

    // Read the private key file
    let private_key_pem = std::fs::read_to_string(&private_key_path)
        .map_err(|e| format!("Failed to read Apple private key file {}: {}", private_key_path, e))?;

    // Parse the private key
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|e| format!("Failed to parse Apple private key: {}", e))?;

    // Create JWT header
    let header = serde_json::json!({
        "alg": "ES256",
        "kid": key_id,
        "typ": "JWT"
    });

    // Create JWT claims
    let now = Utc::now();
    let exp = now + Duration::minutes(5); // Apple recommends 5 minutes max
    
    let claims = AppleJwtClaims {
        iss: team_id,
        iat: now.timestamp(),
        exp: exp.timestamp(),
        aud: "https://appleid.apple.com".to_string(),
        sub: client_id,
    };

    // Encode header and payload as base64url
    let header_json = serde_json::to_string(&header)
        .map_err(|e| format!("Failed to serialize header: {}", e))?;
    let claims_json = serde_json::to_string(&claims)
        .map_err(|e| format!("Failed to serialize claims: {}", e))?;

    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
    
    // Create the message to sign (header.payload)
    let message = format!("{}.{}", header_b64, payload_b64);

    // Sign with ES256 (ECDSA using P-256 and SHA-256)
    let signature: Signature = signing_key.sign(message.as_bytes());
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());

    // Combine into final JWT
    let jwt = format!("{}.{}", message, signature_b64);

    log::debug!("Generated Apple client secret JWT for token refresh");
    Ok(jwt)
}

// Place is_hop_by_hop_header above the tests module and make it pub(crate) so both main code and tests can use it
pub(crate) fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(name, 
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" |
        "te" | "trailers" | "transfer-encoding" | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::create_test_settings;
    use crate::utils::test_request_builder::TestRequestBuilder;
    use crate::utils::user_agent::{extract_user_agent_info, derive_platform_from_user_agent};
    // Import is_hop_by_hop_header for tests
    use super::is_hop_by_hop_header;

    #[test]
    fn test_hop_by_hop_headers() {
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
        
        assert_eq!(user_agent_info.user_agent, Some("\"Google Chrome\";v=\"91\", \"Chromium\";v=\"91\"".to_string()));
        assert_eq!(user_agent_info.platform, Some("Windows".to_string()));
        assert_eq!(user_agent_info.lang, Some("en-US".to_string()));
        assert_eq!(user_agent_info.mobile, 0);
        
        // Test with fallback to User-Agent header
        let req = TestRequestBuilder::macos_french_request();
        
        let user_agent_info = extract_user_agent_info(&req);
        
        assert_eq!(user_agent_info.user_agent, Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string()));
        assert_eq!(user_agent_info.platform, Some("macOS".to_string())); // Derived from User-Agent
        assert_eq!(user_agent_info.lang, Some("fr-FR".to_string()));
        assert_eq!(user_agent_info.mobile, 0); // Default when not specified
    }

    #[test]
    fn test_platform_derivation_from_user_agent() {
        // Test Windows detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "Windows".to_string());
        
        // Test macOS detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"), "macOS".to_string());
        
        // Test Linux detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (X11; Linux x86_64)"), "Linux".to_string());
        
        // Test Android detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (Linux; Android 11; SM-G991B)"), "Android".to_string());
        
        // Test iOS detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"), "iOS".to_string());
        
        // Test Chrome OS detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)"), "Chrome OS".to_string());
        
        // Test unknown platform - now returns "Unknown" instead of None
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (Unknown Platform)"), "Unknown".to_string());
    }

    #[tokio::test]
    async fn test_401_redirect_for_browser_requests() {
        // Test browser request (Accept: text/html)
        let browser_req = TestRequestBuilder::browser_request();
        
        let settings = create_test_settings();
        
        // Test that browser requests are properly detected
        assert!(is_browser_request(&browser_req), "Should detect browser request");
        
        // Test API request (Accept: application/json)
        let api_req = TestRequestBuilder::api_request();
        
        assert!(!is_browser_request(&api_req), "Should detect API request");
        
        // Test that the redirect URL is properly constructed
        let expected_redirect_url = format!("{}/oauth2/sign_in", settings.application.redirect_base_url);
        assert_eq!(expected_redirect_url, "http://localhost:8080/oauth2/sign_in");
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
        let browser_ua_req = TestRequestBuilder::user_agent_request("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
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
}
