//! OAuth callback validation module
//!
//! This module breaks down the complex OAuth callback validation logic into
//! focused, testable components for better maintainability and error handling.

use actix_web::{HttpRequest, HttpResponse};
use log::{debug, error};

use crate::oauth::{OAuthCallback, OAuthState};
use crate::session::{get_state_from_callback, SessionManager};
use crate::utils::responses::ResponseBuilder;

/// OAuth callback validator with structured validation steps
pub struct CallbackValidator;

/// Callback validation result containing extracted and validated data
#[derive(Debug)]
pub struct ValidatedCallback {
    pub code: String,
    pub oauth_state: OAuthState,
}

impl CallbackValidator {
    /// Main validation entry point for OAuth callbacks
    ///
    /// This replaces the large inline validation logic in `oauth_callback` handlers
    /// with a structured approach that separates concerns.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - OAuth provider returned an error code
    /// - Authorization code is missing or empty
    /// - State parameter is missing or empty
    /// - OAuth state validation fails
    pub fn validate_and_extract(
        callback_data: &OAuthCallback,
        session_manager: &SessionManager,
        req: &HttpRequest,
    ) -> Result<ValidatedCallback, HttpResponse> {
        debug!("Starting OAuth callback validation");

        // Step 1: Check for OAuth errors
        Self::validate_oauth_error(callback_data, session_manager)?;

        // Step 2: Extract and validate authorization code
        let code = Self::extract_authorization_code(callback_data, session_manager)?;

        // Step 3: Extract and validate state parameter
        let state_param = Self::extract_state_parameter(callback_data, session_manager)?;

        // Step 4: Parse and verify OAuth state
        let oauth_state = Self::verify_oauth_state(&state_param, session_manager, req)?;

        debug!(
            "OAuth callback validation successful for provider: {}",
            oauth_state.provider
        );

        Ok(ValidatedCallback { code, oauth_state })
    }

    /// Check for OAuth errors in the callback
    ///
    /// OAuth providers may return error codes instead of authorization codes
    /// when authentication fails or is cancelled.
    fn validate_oauth_error(
        callback_data: &OAuthCallback,
        session_manager: &SessionManager,
    ) -> Result<(), HttpResponse> {
        if let Some(error) = &callback_data.error {
            error!("OAuth error received: {error}");
            let clear_cookie = session_manager.cookie_factory().create_expired_cookie();
            return Err(ResponseBuilder::redirect("/auth/sign_in?error=auth_failed")
                .with_cookie(clear_cookie)
                .build());
        }

        Ok(())
    }

    /// Extract and validate the authorization code
    ///
    /// The authorization code is required for the token exchange and must be present
    /// in successful OAuth callbacks.
    fn extract_authorization_code(
        callback_data: &OAuthCallback,
        session_manager: &SessionManager,
    ) -> Result<String, HttpResponse> {
        if let Some(code) = &callback_data.code {
            if code.trim().is_empty() {
                error!("Empty authorization code received");
                let clear_cookie = session_manager.cookie_factory().create_expired_cookie();
                return Err(ResponseBuilder::redirect("/auth/sign_in?error=auth_failed")
                    .with_cookie(clear_cookie)
                    .build());
            }
            Ok(code.clone())
        } else {
            error!("No authorization code received in OAuth callback");
            let clear_cookie = session_manager.cookie_factory().create_expired_cookie();
            Err(ResponseBuilder::redirect("/auth/sign_in?error=auth_failed")
                .with_cookie(clear_cookie)
                .build())
        }
    }

    /// Extract and validate the state parameter
    ///
    /// The state parameter is used for CSRF protection and must be present
    /// to verify the callback authenticity.
    fn extract_state_parameter(
        callback_data: &OAuthCallback,
        session_manager: &SessionManager,
    ) -> Result<String, HttpResponse> {
        if let Some(state) = &callback_data.state {
            if state.trim().is_empty() {
                error!("Empty state parameter received");
                let clear_cookie = session_manager.cookie_factory().create_expired_cookie();
                return Err(
                    ResponseBuilder::redirect("/auth/sign_in?error=oauth_state_error")
                        .with_cookie(clear_cookie)
                        .build(),
                );
            }
            Ok(state.clone())
        } else {
            error!("No state parameter received in OAuth callback");
            let clear_cookie = session_manager.cookie_factory().create_expired_cookie();
            Err(
                ResponseBuilder::redirect("/auth/sign_in?error=oauth_state_error")
                    .with_cookie(clear_cookie)
                    .build(),
            )
        }
    }

    /// Parse and verify the OAuth state
    ///
    /// This validates that the state parameter corresponds to a valid OAuth session
    /// and hasn't been tampered with.
    fn verify_oauth_state(
        received_state: &str,
        session_manager: &SessionManager,
        req: &HttpRequest,
    ) -> Result<OAuthState, HttpResponse> {
        match get_state_from_callback(received_state, session_manager, req) {
            Ok(state) => {
                debug!("OAuth state verified for provider: {}", state.provider);
                Ok(state)
            }
            Err(e) => {
                error!("Failed to parse OAuth state: {e}");
                let clear_cookie = session_manager.cookie_factory().create_expired_cookie();
                Err(
                    ResponseBuilder::redirect("/auth/sign_in?error=oauth_state_error")
                        .with_cookie(clear_cookie)
                        .build(),
                )
            }
        }
    }
}

/// Callback data extraction utilities
pub struct CallbackDataExtractor;

impl CallbackDataExtractor {
    /// Extract callback data from either query parameters or form submission
    ///
    /// Some OAuth providers send callback data via POST form, others via GET query params.
    /// This function handles both cases with proper precedence.
    #[must_use]
    pub fn extract_callback_data(
        query: actix_web::web::Query<OAuthCallback>,
        form: Option<actix_web::web::Form<OAuthCallback>>,
    ) -> OAuthCallback {
        if let Some(form_data) = form {
            debug!("Using OAuth callback data from form submission");
            form_data.into_inner()
        } else {
            debug!("Using OAuth callback data from query parameters");
            query.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::OAuthCallback;
    use crate::testing::TestFixtures;

    fn create_test_callback(
        code: Option<String>,
        state: Option<String>,
        error: Option<String>,
    ) -> OAuthCallback {
        OAuthCallback {
            code,
            state,
            error,
            user: None,
        }
    }

    fn create_test_session_manager() -> SessionManager {
        TestFixtures::session_manager()
    }

    #[test]
    fn test_oauth_error_validation() {
        let session_manager = create_test_session_manager();

        // Test with OAuth error
        let callback_with_error =
            create_test_callback(None, None, Some("access_denied".to_string()));
        let result =
            CallbackValidator::validate_oauth_error(&callback_with_error, &session_manager);
        assert!(result.is_err());

        // Test without OAuth error
        let callback_without_error = create_test_callback(
            Some("test_code".to_string()),
            Some("test_state".to_string()),
            None,
        );
        let result =
            CallbackValidator::validate_oauth_error(&callback_without_error, &session_manager);
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorization_code_extraction() {
        let session_manager = create_test_session_manager();

        // Test with valid code
        let callback_with_code = create_test_callback(
            Some("valid_auth_code".to_string()),
            Some("test_state".to_string()),
            None,
        );
        let result =
            CallbackValidator::extract_authorization_code(&callback_with_code, &session_manager);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "valid_auth_code");

        // Test with missing code
        let callback_without_code =
            create_test_callback(None, Some("test_state".to_string()), None);
        let result =
            CallbackValidator::extract_authorization_code(&callback_without_code, &session_manager);
        assert!(result.is_err());

        // Test with empty code
        let callback_with_empty_code = create_test_callback(
            Some("   ".to_string()),
            Some("test_state".to_string()),
            None,
        );
        let result = CallbackValidator::extract_authorization_code(
            &callback_with_empty_code,
            &session_manager,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_state_parameter_extraction() {
        let session_manager = create_test_session_manager();

        // Test with valid state
        let callback_with_state = create_test_callback(
            Some("test_code".to_string()),
            Some("valid_state_param".to_string()),
            None,
        );
        let result =
            CallbackValidator::extract_state_parameter(&callback_with_state, &session_manager);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "valid_state_param");

        // Test with missing state
        let callback_without_state =
            create_test_callback(Some("test_code".to_string()), None, None);
        let result =
            CallbackValidator::extract_state_parameter(&callback_without_state, &session_manager);
        assert!(result.is_err());

        // Test with empty state
        let callback_with_empty_state =
            create_test_callback(Some("test_code".to_string()), Some("  ".to_string()), None);
        let result = CallbackValidator::extract_state_parameter(
            &callback_with_empty_state,
            &session_manager,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_callback_data_extraction() {
        // Test form data precedence
        let query_data = OAuthCallback {
            code: Some("query_code".to_string()),
            state: Some("query_state".to_string()),
            error: None,
            user: None,
        };

        let form_data = OAuthCallback {
            code: Some("form_code".to_string()),
            state: Some("form_state".to_string()),
            error: None,
            user: None,
        };

        // When both form and query data are present, form should take precedence
        let query = actix_web::web::Query(query_data);
        let form = Some(actix_web::web::Form(form_data));

        let result = CallbackDataExtractor::extract_callback_data(query, form);
        assert_eq!(result.code, Some("form_code".to_string()));

        // When only query data is present
        let query_data_only = OAuthCallback {
            code: Some("query_code".to_string()),
            state: Some("query_state".to_string()),
            error: None,
            user: None,
        };
        let query = actix_web::web::Query(query_data_only);
        let result = CallbackDataExtractor::extract_callback_data(query, None);
        assert_eq!(result.code, Some("query_code".to_string()));
    }

    #[test]
    fn test_validation_step_independence() {
        let session_manager = create_test_session_manager();

        // Each validation step should be independently testable

        // Valid callback data
        let valid_callback = create_test_callback(
            Some("test_code".to_string()),
            Some("test_state".to_string()),
            None,
        );

        // Test each step independently
        assert!(CallbackValidator::validate_oauth_error(&valid_callback, &session_manager).is_ok());
        assert!(
            CallbackValidator::extract_authorization_code(&valid_callback, &session_manager)
                .is_ok()
        );
        assert!(
            CallbackValidator::extract_state_parameter(&valid_callback, &session_manager).is_ok()
        );

        // Test error cases for each step
        let error_callback = create_test_callback(None, None, Some("access_denied".to_string()));
        assert!(
            CallbackValidator::validate_oauth_error(&error_callback, &session_manager).is_err()
        );

        let no_code_callback = create_test_callback(None, Some("test_state".to_string()), None);
        assert!(
            CallbackValidator::extract_authorization_code(&no_code_callback, &session_manager)
                .is_err()
        );

        let no_state_callback = create_test_callback(Some("test_code".to_string()), None, None);
        assert!(
            CallbackValidator::extract_state_parameter(&no_state_callback, &session_manager)
                .is_err()
        );
    }
}
