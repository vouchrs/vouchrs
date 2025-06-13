//! HTTP response handling system
//!
//! This module provides a unified interface for creating HTTP responses across the application,
//! offering consistent patterns for errors, redirects, and JSON responses while maintaining
//! performance optimizations through cached common responses.

use actix_web::{cookie::Cookie, http::header, HttpResponse};
use serde_json::{json, Value};

// ===============================
// CACHED RESPONSES FOR PERFORMANCE
// ===============================

/// Global instance of pre-serialized common responses for performance
static CACHED_RESPONSES: std::sync::LazyLock<CachedResponses> =
    std::sync::LazyLock::new(CachedResponses::new);

/// Container for pre-serialized common HTTP response bodies
/// These JSON strings are computed once at startup and reused for better performance
struct CachedResponses {
    invalid_redirect: String,
    invalid_token: String,
    unauthorized: String,
    missing_parameters: String,
    server_error: String,
    bad_gateway: String,
    rate_limited: String,
    invalid_request: String,
}

impl CachedResponses {
    /// Create a new instance with all pre-serialized responses
    fn new() -> Self {
        Self {
            invalid_redirect: Self::create_json(
                "invalid_redirect",
                "The redirect URL is invalid or potentially unsafe",
            ),
            invalid_token: Self::create_json(
                "invalid_token",
                "The provided token is invalid or has expired",
            ),
            unauthorized: Self::create_json(
                "unauthorized",
                "Authentication is required to access this resource",
            ),
            missing_parameters: Self::create_json(
                "invalid_request",
                "Required parameters are missing from the request",
            ),
            server_error: Self::create_json("server_error", "An internal server error occurred"),
            bad_gateway: Self::create_json("bad_gateway", "Failed to connect to upstream server"),
            rate_limited: Self::create_json(
                "rate_limited",
                "Too many requests. Please try again later.",
            ),
            invalid_request: Self::create_json(
                "invalid_request",
                "The request is malformed or invalid",
            ),
        }
    }

    /// Helper to create JSON strings
    fn create_json(error: &str, description: &str) -> String {
        let json = json!({
            "error": error,
            "error_description": description
        });
        serde_json::to_string(&json).expect("Failed to serialize JSON")
    }

    /// Create invalid redirect response
    fn invalid_redirect(&self) -> HttpResponse {
        HttpResponse::BadRequest()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.invalid_redirect.clone())
    }

    /// Create invalid token response
    fn invalid_token(&self) -> HttpResponse {
        HttpResponse::Unauthorized()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.invalid_token.clone())
    }

    /// Create unauthorized response
    fn unauthorized(&self) -> HttpResponse {
        HttpResponse::Unauthorized()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.unauthorized.clone())
    }

    /// Create missing parameters response
    fn missing_parameters(&self) -> HttpResponse {
        HttpResponse::BadRequest()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.missing_parameters.clone())
    }

    /// Create server error response
    fn server_error(&self) -> HttpResponse {
        HttpResponse::InternalServerError()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.server_error.clone())
    }

    /// Create bad gateway response
    fn bad_gateway(&self) -> HttpResponse {
        HttpResponse::BadGateway()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.bad_gateway.clone())
    }

    /// Create rate limited response
    fn rate_limited(&self) -> HttpResponse {
        HttpResponse::TooManyRequests()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.rate_limited.clone())
    }

    /// Create invalid request response
    fn invalid_request(&self) -> HttpResponse {
        HttpResponse::BadRequest()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.invalid_request.clone())
    }
}

/// Unified response builder that handles all types of HTTP responses
pub struct ResponseBuilder;

impl ResponseBuilder {
    // ===============================
    // ERROR RESPONSE METHODS
    // ===============================

    /// Create a `BadRequest` (400) error response with optional customization
    #[must_use]
    pub fn bad_request() -> ErrorResponseBuilder {
        ErrorResponseBuilder::new(ErrorType::BadRequest)
    }

    /// Create an `Unauthorized` (401) error response with optional customization
    #[must_use]
    pub fn unauthorized() -> ErrorResponseBuilder {
        ErrorResponseBuilder::new(ErrorType::Unauthorized)
    }

    /// Create an `InternalServerError` (500) error response with optional customization
    #[must_use]
    pub fn internal_server_error() -> ErrorResponseBuilder {
        ErrorResponseBuilder::new(ErrorType::InternalServerError)
    }

    /// Create a `ServiceUnavailable` (503) error response with optional customization
    #[must_use]
    pub fn service_unavailable() -> ErrorResponseBuilder {
        ErrorResponseBuilder::new(ErrorType::ServiceUnavailable)
    }

    /// Create a `BadGateway` (502) error response with optional customization
    #[must_use]
    pub fn bad_gateway() -> ErrorResponseBuilder {
        ErrorResponseBuilder::new(ErrorType::BadGateway)
    }

    /// Create a `TooManyRequests` (429) error response with optional customization
    #[must_use]
    pub fn too_many_requests() -> ErrorResponseBuilder {
        ErrorResponseBuilder::new(ErrorType::TooManyRequests)
    }

    // ===============================
    // SUCCESS RESPONSE METHODS
    // ===============================

    /// Create a redirect response (302 Found) with optional cookies
    #[must_use]
    pub fn redirect(location: &str) -> RedirectBuilder {
        RedirectBuilder::new(location)
    }

    /// Create a redirect response with multiple cookies (avoids lifetime issues)
    /// This method takes owned cookies and creates the response directly
    #[must_use]
    pub fn redirect_with_cookies(location: &str, cookies: Vec<Cookie<'static>>) -> HttpResponse {
        let mut builder = HttpResponse::Found();

        // Add cookies
        for cookie in cookies {
            builder.cookie(cookie);
        }

        builder
            .append_header(("Location", location.to_string()))
            .finish()
    }

    /// Helper function to create a redirect with cookies, avoiding lifetime issues
    /// by separating cookie creation from redirect creation
    #[must_use]
    pub fn create_redirect_with_session_cookies(
        location: &str,
        session_cookie: Cookie<'static>,
        user_cookie: Cookie<'static>,
    ) -> HttpResponse {
        let mut builder = HttpResponse::Found();
        builder.cookie(session_cookie);
        builder.cookie(user_cookie);
        builder
            .append_header(("Location", location.to_string()))
            .finish()
    }

    /// Create an OK response (200) with JSON content
    #[must_use]
    pub fn ok() -> JsonResponseBuilder {
        JsonResponseBuilder::new(200)
    }

    /// Create a Created response (201) with JSON content
    #[must_use]
    pub fn created() -> JsonResponseBuilder {
        JsonResponseBuilder::new(201)
    }

    // ===============================
    // CACHED ERROR SHORTCUTS
    // ===============================

    /// Use cached invalid redirect response for performance
    #[must_use]
    pub fn invalid_redirect() -> HttpResponse {
        CACHED_RESPONSES.invalid_redirect()
    }

    /// Use cached invalid token response for performance
    #[must_use]
    pub fn invalid_token() -> HttpResponse {
        CACHED_RESPONSES.invalid_token()
    }

    /// Use cached missing parameters response for performance
    #[must_use]
    pub fn missing_parameters() -> HttpResponse {
        CACHED_RESPONSES.missing_parameters()
    }

    // ===============================
    // CONVENIENCE METHODS
    // ===============================

    /// Common validation error: missing field
    #[must_use]
    pub fn missing_field(field_name: &str) -> HttpResponse {
        Self::bad_request()
            .with_error_code("missing_field")
            .with_message(&format!("Missing required field: {field_name}"))
            .build()
    }

    /// Common validation error: invalid field
    #[must_use]
    pub fn invalid_field(field_name: &str, reason: &str) -> HttpResponse {
        Self::bad_request()
            .with_error_code("invalid_field")
            .with_message(&format!("Invalid {field_name}: {reason}"))
            .build()
    }

    /// Authentication failure
    #[must_use]
    pub fn authentication_failed(reason: &str) -> HttpResponse {
        Self::unauthorized()
            .with_error_code("authentication_failed")
            .with_message(reason)
            .build()
    }

    /// Service unavailable with specific service name
    #[must_use]
    pub fn service_unavailable_with_details(service: &str) -> HttpResponse {
        Self::service_unavailable()
            .with_error_code("service_unavailable")
            .with_message(&format!("{service} is currently unavailable"))
            .build()
    }

    /// Encoding/serialization error
    #[must_use]
    pub fn encoding_failed(operation: &str) -> HttpResponse {
        Self::internal_server_error()
            .with_error_code("encoding_failed")
            .with_message(&format!("Failed to encode {operation}"))
            .build()
    }

    /// Decoding/parsing error
    #[must_use]
    pub fn decoding_failed(operation: &str) -> HttpResponse {
        Self::bad_request()
            .with_error_code("decoding_failed")
            .with_message(&format!("Failed to decode {operation}"))
            .build()
    }

    // Passkey-specific convenience methods
    #[must_use]
    pub fn missing_credential() -> HttpResponse {
        Self::bad_request()
            .with_error_code("missing_credential")
            .with_message("Missing credential in request")
            .build()
    }

    #[must_use]
    pub fn invalid_credential(reason: &str) -> HttpResponse {
        Self::bad_request()
            .with_error_code("invalid_credential")
            .with_message(&format!("Invalid credential: {reason}"))
            .build()
    }

    #[must_use]
    pub fn missing_state() -> HttpResponse {
        Self::bad_request()
            .with_error_code("missing_state")
            .with_message("Missing authentication state")
            .build()
    }

    #[must_use]
    pub fn invalid_state(reason: &str) -> HttpResponse {
        Self::bad_request()
            .with_error_code("invalid_state")
            .with_message(&format!("Invalid state: {reason}"))
            .build()
    }

    #[must_use]
    pub fn missing_user_data() -> HttpResponse {
        Self::bad_request()
            .with_error_code("missing_user_data")
            .with_message("User data is required")
            .build()
    }

    #[must_use]
    pub fn invalid_user_data(reason: &str) -> HttpResponse {
        Self::bad_request()
            .with_error_code("invalid_user_data")
            .with_message(&format!("Invalid user data: {reason}"))
            .build()
    }

    #[must_use]
    pub fn registration_failed(reason: &str) -> HttpResponse {
        Self::bad_request()
            .with_error_code("registration_failed")
            .with_message(reason)
            .build()
    }
}

// ===============================
// BUILDER TYPES
// ===============================

/// Builder for error responses with fluent interface
pub struct ErrorResponseBuilder {
    error_type: ErrorType,
    error_code: Option<String>,
    message: Option<String>,
    additional_fields: Option<Value>,
}

/// Builder for redirect responses
pub struct RedirectBuilder {
    location: String,
    cookies: Vec<Cookie<'static>>,
    status_code: u16,
}

/// Builder for JSON responses
pub struct JsonResponseBuilder {
    status_code: u16,
    headers: Vec<(String, String)>,
}

/// Supported HTTP error response types
#[derive(Clone)]
enum ErrorType {
    BadRequest,
    Unauthorized,
    InternalServerError,
    ServiceUnavailable,
    BadGateway,
    TooManyRequests,
}

// ===============================
// ERROR RESPONSE BUILDER IMPL
// ===============================

impl ErrorResponseBuilder {
    fn new(error_type: ErrorType) -> Self {
        Self {
            error_type,
            error_code: None,
            message: None,
            additional_fields: None,
        }
    }

    /// Set a custom error code (e.g., "`invalid_request`", "`missing_credential`")
    #[must_use]
    pub fn with_error_code(mut self, code: &str) -> Self {
        self.error_code = Some(code.to_string());
        self
    }

    /// Set a custom error message
    #[must_use]
    pub fn with_message(mut self, message: &str) -> Self {
        self.message = Some(message.to_string());
        self
    }

    /// Add additional JSON fields to the response
    #[must_use]
    pub fn with_additional_fields(mut self, fields: Value) -> Self {
        self.additional_fields = Some(fields);
        self
    }

    /// Build the final `HttpResponse`
    #[must_use]
    pub fn build(self) -> HttpResponse {
        // If no customization is needed, try to use cached responses for performance
        if self.error_code.is_none() && self.message.is_none() && self.additional_fields.is_none() {
            return self.build_cached_response();
        }

        // Build custom response with specified fields
        self.build_custom_response()
    }

    /// Try to use cached responses for common error patterns
    fn build_cached_response(&self) -> HttpResponse {
        match self.error_type {
            ErrorType::BadRequest => CACHED_RESPONSES.invalid_request(),
            ErrorType::Unauthorized => CACHED_RESPONSES.unauthorized(),
            ErrorType::InternalServerError => CACHED_RESPONSES.server_error(),
            ErrorType::ServiceUnavailable => {
                // No cached equivalent, build custom
                let error_type = self.error_type.clone();
                ErrorResponseBuilder::new(error_type).build_custom_response()
            }
            ErrorType::BadGateway => CACHED_RESPONSES.bad_gateway(),
            ErrorType::TooManyRequests => CACHED_RESPONSES.rate_limited(),
        }
    }

    /// Build a custom response with the specified fields
    fn build_custom_response(self) -> HttpResponse {
        let mut json_body = json!({});

        // Set error code
        let error_code = self
            .error_code
            .clone()
            .unwrap_or_else(|| self.default_error_code());
        json_body["error"] = Value::String(error_code);

        // Set message (use provided message or default description)
        let message = self
            .message
            .clone()
            .unwrap_or_else(|| self.default_message());
        json_body["message"] = Value::String(message);

        // Add any additional fields
        if let Some(Value::Object(map)) = self.additional_fields {
            for (key, value) in map {
                json_body[key] = value;
            }
        }

        // Build the HTTP response with appropriate status code
        let mut response = match self.error_type {
            ErrorType::BadRequest => HttpResponse::BadRequest(),
            ErrorType::Unauthorized => HttpResponse::Unauthorized(),
            ErrorType::InternalServerError => HttpResponse::InternalServerError(),
            ErrorType::ServiceUnavailable => HttpResponse::ServiceUnavailable(),
            ErrorType::BadGateway => HttpResponse::BadGateway(),
            ErrorType::TooManyRequests => HttpResponse::TooManyRequests(),
        };

        response
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .json(json_body)
    }

    /// Get the default error code for this error type
    fn default_error_code(&self) -> String {
        match self.error_type {
            ErrorType::BadRequest => "invalid_request",
            ErrorType::Unauthorized => "unauthorized",
            ErrorType::InternalServerError => "server_error",
            ErrorType::ServiceUnavailable => "service_unavailable",
            ErrorType::BadGateway => "bad_gateway",
            ErrorType::TooManyRequests => "rate_limited",
        }
        .to_string()
    }

    /// Get the default error message for this error type
    fn default_message(&self) -> String {
        match self.error_type {
            ErrorType::BadRequest => "The request is malformed or invalid",
            ErrorType::Unauthorized => "Authentication is required to access this resource",
            ErrorType::InternalServerError => "An internal server error occurred",
            ErrorType::ServiceUnavailable => "The service is temporarily unavailable",
            ErrorType::BadGateway => "Failed to connect to upstream server",
            ErrorType::TooManyRequests => "Too many requests. Please try again later.",
        }
        .to_string()
    }
}

// ===============================
// REDIRECT BUILDER IMPL
// ===============================

impl RedirectBuilder {
    fn new(location: &str) -> Self {
        Self {
            location: location.to_string(),
            cookies: Vec::new(),
            status_code: 302, // Found
        }
    }

    /// Add a cookie to the redirect response
    #[must_use]
    pub fn with_cookie(mut self, cookie: Cookie<'static>) -> Self {
        self.cookies.push(cookie);
        self
    }

    /// Add multiple cookies to the redirect response
    #[must_use]
    pub fn with_cookies(mut self, mut cookies: Vec<Cookie<'static>>) -> Self {
        self.cookies.append(&mut cookies);
        self
    }

    /// Add an error parameter to the redirect URL
    #[must_use]
    pub fn with_error(mut self, error_param: &str) -> Self {
        self.location = if self.location.contains('?') {
            format!("{}&error={error_param}", self.location)
        } else {
            format!("{}?error={error_param}", self.location)
        };
        self
    }

    /// Use 301 Moved Permanently instead of 302 Found
    #[must_use]
    pub fn permanent(mut self) -> Self {
        self.status_code = 301;
        self
    }

    /// Build the final redirect response
    #[must_use]
    pub fn build(self) -> HttpResponse {
        let mut builder = match self.status_code {
            301 => HttpResponse::MovedPermanently(),
            _ => HttpResponse::Found(),
        };

        // Add cookies
        for cookie in self.cookies {
            builder.cookie(cookie);
        }

        builder.append_header(("Location", self.location)).finish()
    }
}

// ===============================
// JSON RESPONSE BUILDER IMPL
// ===============================

impl JsonResponseBuilder {
    fn new(status_code: u16) -> Self {
        Self {
            status_code,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        }
    }

    /// Add a custom header
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Build the response with JSON content
    #[must_use]
    pub fn json<T: serde::Serialize>(self, data: &T) -> HttpResponse {
        let mut builder = match self.status_code {
            200 => HttpResponse::Ok(),
            201 => HttpResponse::Created(),
            _ => HttpResponse::build(
                actix_web::http::StatusCode::from_u16(self.status_code)
                    .unwrap_or(actix_web::http::StatusCode::OK),
            ),
        };

        // Add headers
        for (name, value) in self.headers {
            builder.insert_header((name, value));
        }

        builder.json(data)
    }
}

// ===============================
// UTILITY FUNCTIONS (from original response_builder.rs)
// ===============================

/// Helper function to check for hop-by-hop headers
#[must_use]
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

/// Convert Actix HTTP method to reqwest method
///
/// # Errors
///
/// Returns an `HttpResponse` error if the HTTP method is not supported
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
        _method_str => Err(ResponseBuilder::bad_request()
            .with_error_code("unsupported_method")
            .with_message("HTTP method not supported")
            .build()),
    }
}

/// Build the upstream URL by combining base URL with request path
/// Simple URL construction for admin-controlled upstream URLs
/// No redirect protection needed since upstream URLs are controlled by admins
///
/// # Errors
///
/// Returns an `HttpResponse` error if:
/// - The base URL cannot be parsed
/// - The path cannot be joined with the base URL
pub fn build_upstream_url(base_url: &str, request_path: &str) -> Result<String, HttpResponse> {
    use log::{debug, warn};
    use url::Url;

    debug!("Building upstream URL - base: {base_url}, path: {request_path}");

    // Parse base URL
    let base = Url::parse(base_url).map_err(|e| {
        warn!("Failed to parse base URL '{base_url}': {e}");
        ResponseBuilder::bad_request()
            .with_error_code("invalid_base_url")
            .with_message("Failed to parse base URL")
            .build()
    })?;

    // Normalize the request path by removing leading slashes
    let clean_path = request_path.trim_start_matches('/');

    // Join the path with the base URL
    let final_url = base.join(clean_path).map_err(|e| {
        warn!("Failed to join URL '{base_url}' + '{clean_path}': {e}");
        ResponseBuilder::bad_request()
            .with_error_code("invalid_url_join")
            .with_message("Failed to construct upstream URL")
            .build()
    })?;

    debug!("Successfully built upstream URL: {final_url}");
    Ok(final_url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[test]
    fn test_unified_error_responses() {
        let response = ResponseBuilder::bad_request().build();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = ResponseBuilder::unauthorized().build();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = ResponseBuilder::internal_server_error().build();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_custom_error_responses() {
        let response = ResponseBuilder::bad_request()
            .with_error_code("custom_error")
            .with_message("Custom error message")
            .build();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_redirect_builder() {
        let response = ResponseBuilder::redirect("https://example.com")
            .with_error("invalid_token")
            .build();

        assert_eq!(response.status(), StatusCode::FOUND);
    }

    #[test]
    fn test_redirect_with_cookies_direct() {
        use actix_web::cookie::Cookie;

        let session_cookie = Cookie::new("session", "value1");
        let user_cookie = Cookie::new("user", "value2");
        let cookies = vec![session_cookie, user_cookie];

        let response = ResponseBuilder::redirect_with_cookies("https://example.com", cookies);
        assert_eq!(response.status(), StatusCode::FOUND);
    }

    #[test]
    fn test_convenience_functions() {
        let response = ResponseBuilder::missing_field("email");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = ResponseBuilder::authentication_failed("Invalid credentials");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = ResponseBuilder::missing_credential();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_cached_response_shortcuts() {
        let response = ResponseBuilder::invalid_redirect();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = ResponseBuilder::invalid_token();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_json_response_builder() {
        let data = serde_json::json!({"message": "success"});
        let response = ResponseBuilder::ok().json(&data);
        assert_eq!(response.status(), StatusCode::OK);

        let response = ResponseBuilder::created().json(&data);
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[test]
    fn test_utility_functions() {
        assert!(is_hop_by_hop_header("connection"));
        assert!(!is_hop_by_hop_header("authorization"));

        let method = actix_web::http::Method::GET;
        let result = convert_http_method(&method);
        assert!(result.is_ok());
    }

    #[test]
    fn test_upstream_url_building() {
        let base_url = "https://api.example.com";
        let path = "/api/v1/users";

        let result = build_upstream_url(base_url, path);
        assert!(result.is_ok());

        let url = result.unwrap();
        assert_eq!(url, "https://api.example.com/api/v1/users");
    }
}
