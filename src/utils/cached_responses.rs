// Pre-serialized HTTP responses for common errors to improve performance
use actix_web::{http::header, HttpResponse};

/// Global instance of pre-serialized common responses
pub static RESPONSES: std::sync::LazyLock<CommonResponses> = std::sync::LazyLock::new(CommonResponses::new);

/// Container for pre-serialized common HTTP response bodies
/// These JSON strings are computed once at startup and reused for better performance
pub struct CommonResponses {
    pub invalid_redirect_json: String,
    pub invalid_token_json: String,
    pub unauthorized_json: String,
    pub missing_parameters_json: String,
    pub server_error_json: String,
    pub rate_limited_json: String,
    pub invalid_request_json: String,
    pub oauth_config_error_json: String,
    pub state_encryption_failed_json: String,
    pub unsupported_provider_json: String,
}

impl CommonResponses {
    /// Create a new instance with all pre-serialized responses
    #[must_use]
    pub fn new() -> Self {
        Self {
            invalid_redirect_json: Self::create_invalid_redirect_json(),
            invalid_token_json: Self::create_invalid_token_json(),
            unauthorized_json: Self::create_unauthorized_json(),
            missing_parameters_json: Self::create_missing_parameters_json(),
            server_error_json: Self::create_server_error_json(),
            rate_limited_json: Self::create_rate_limited_json(),
            invalid_request_json: Self::create_invalid_request_json(),
            oauth_config_error_json: Self::create_oauth_config_error_json(),
            state_encryption_failed_json: Self::create_state_encryption_failed_json(),
            unsupported_provider_json: Self::create_unsupported_provider_json(),
        }
    }

    /// Create invalid redirect response
    #[must_use]
    pub fn invalid_redirect(&self) -> HttpResponse {
        HttpResponse::BadRequest()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.invalid_redirect_json.clone())
    }

    /// Create invalid token response
    #[must_use]
    pub fn invalid_token(&self) -> HttpResponse {
        HttpResponse::Unauthorized()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.invalid_token_json.clone())
    }

    /// Create unauthorized response
    #[must_use]
    pub fn unauthorized(&self) -> HttpResponse {
        HttpResponse::Unauthorized()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.unauthorized_json.clone())
    }

    /// Create missing parameters response
    #[must_use]
    pub fn missing_parameters(&self) -> HttpResponse {
        HttpResponse::BadRequest()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.missing_parameters_json.clone())
    }

    /// Create server error response
    #[must_use]
    pub fn server_error(&self) -> HttpResponse {
        HttpResponse::InternalServerError()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.server_error_json.clone())
    }

    /// Create rate limited response
    #[must_use]
    pub fn rate_limited(&self) -> HttpResponse {
        HttpResponse::TooManyRequests()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.rate_limited_json.clone())
    }

    /// Create invalid request response
    #[must_use]
    pub fn invalid_request(&self) -> HttpResponse {
        HttpResponse::BadRequest()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.invalid_request_json.clone())
    }

    /// Create OAuth configuration error response
    #[must_use]
    pub fn oauth_config_error(&self) -> HttpResponse {
        HttpResponse::InternalServerError()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.oauth_config_error_json.clone())
    }

    /// Create state encryption failed response
    #[must_use]
    pub fn state_encryption_failed(&self) -> HttpResponse {
        HttpResponse::InternalServerError()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.state_encryption_failed_json.clone())
    }

    /// Create unsupported provider response
    #[must_use]
    pub fn unsupported_provider(&self) -> HttpResponse {
        HttpResponse::BadRequest()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(self.unsupported_provider_json.clone())
    }

    /// Create invalid redirect JSON string
    fn create_invalid_redirect_json() -> String {
        let json = serde_json::json!({
            "error": "invalid_redirect",
            "error_description": "The redirect URL is invalid or potentially unsafe"
        });
        serde_json::to_string(&json).expect("Failed to serialize invalid_redirect JSON")
    }

    /// Create invalid token JSON string
    fn create_invalid_token_json() -> String {
        let json = serde_json::json!({
            "error": "invalid_token",
            "error_description": "The provided token is invalid or has expired"
        });
        serde_json::to_string(&json).expect("Failed to serialize invalid_token JSON")
    }

    /// Create unauthorized JSON string
    fn create_unauthorized_json() -> String {
        let json = serde_json::json!({
            "error": "unauthorized",
            "error_description": "Authentication is required to access this resource"
        });
        serde_json::to_string(&json).expect("Failed to serialize unauthorized JSON")
    }

    /// Create missing parameters JSON string
    fn create_missing_parameters_json() -> String {
        let json = serde_json::json!({
            "error": "invalid_request",
            "error_description": "Required parameters are missing from the request"
        });
        serde_json::to_string(&json).expect("Failed to serialize missing_parameters JSON")
    }

    /// Create server error JSON string
    fn create_server_error_json() -> String {
        let json = serde_json::json!({
            "error": "server_error",
            "error_description": "An internal server error occurred"
        });
        serde_json::to_string(&json).expect("Failed to serialize server_error JSON")
    }

    /// Create rate limited JSON string
    fn create_rate_limited_json() -> String {
        let json = serde_json::json!({
            "error": "rate_limited",
            "error_description": "Too many requests. Please try again later."
        });
        serde_json::to_string(&json).expect("Failed to serialize rate_limited JSON")
    }

    /// Create invalid request JSON string
    fn create_invalid_request_json() -> String {
        let json = serde_json::json!({
            "error": "invalid_request",
            "error_description": "The request is malformed or invalid"
        });
        serde_json::to_string(&json).expect("Failed to serialize invalid_request JSON")
    }

    /// Create OAuth configuration error JSON string
    fn create_oauth_config_error_json() -> String {
        let json = serde_json::json!({
            "error": "configuration_error",
            "error_description": "OAuth provider configuration is invalid"
        });
        serde_json::to_string(&json).expect("Failed to serialize oauth_config_error JSON")
    }

    /// Create state encryption failed JSON string
    fn create_state_encryption_failed_json() -> String {
        let json = serde_json::json!({
            "error": "encryption_error",
            "error_description": "Failed to encrypt OAuth state parameter"
        });
        serde_json::to_string(&json).expect("Failed to serialize state_encryption_failed JSON")
    }

    /// Create unsupported provider JSON string
    fn create_unsupported_provider_json() -> String {
        let json = serde_json::json!({
            "error": "unsupported_provider",
            "error_description": "The specified OAuth provider is not supported or not configured"
        });
        serde_json::to_string(&json).expect("Failed to serialize unsupported_provider JSON")
    }
}

impl Default for CommonResponses {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[test]
    fn test_cached_responses_creation() {
        let responses = CommonResponses::new();

        // Test that all JSON strings are not empty
        assert!(!responses.invalid_redirect_json.is_empty());
        assert!(!responses.invalid_token_json.is_empty());
        assert!(!responses.unauthorized_json.is_empty());
        assert!(!responses.missing_parameters_json.is_empty());
        assert!(!responses.server_error_json.is_empty());
        assert!(!responses.rate_limited_json.is_empty());
        assert!(!responses.invalid_request_json.is_empty());
        assert!(!responses.oauth_config_error_json.is_empty());
        assert!(!responses.state_encryption_failed_json.is_empty());
        assert!(!responses.unsupported_provider_json.is_empty());
    }

    #[test]
    fn test_response_methods() {
        let responses = CommonResponses::new();

        // Test that all response methods create proper HttpResponse objects
        assert_eq!(
            responses.invalid_redirect().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(responses.invalid_token().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(responses.unauthorized().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            responses.missing_parameters().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            responses.server_error().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            responses.rate_limited().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            responses.invalid_request().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            responses.oauth_config_error().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            responses.state_encryption_failed().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            responses.unsupported_provider().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn test_global_responses_access() {
        // Test that global responses can be accessed without panicking
        let _response = RESPONSES.invalid_redirect();
        let _json = &RESPONSES.invalid_token_json;
    }
}
