// Authentication handlers: sign-in and sign-out
use crate::oauth::OAuthConfig;
use crate::oauth::OAuthState;
use crate::session::cookie::{create_expired_cookie, COOKIE_NAME, USER_COOKIE_NAME};
use crate::session::SessionManager;
use crate::settings::VouchrsSettings;
use crate::utils::crypto::{encrypt_data, generate_csrf_token};
use crate::utils::response_builder::{redirect_with_cookie, success_redirect_with_cookies};
use actix_web::{web, HttpRequest, HttpResponse, Result};
use log::{debug, error, info};

use super::static_files::get_sign_in_page;
use serde::Deserialize;
#[derive(Deserialize)]
pub struct SignInQuery {
    pub provider: Option<String>,
    pub rd: Option<String>,
}

/// OAuth sign in handler
///
/// # Errors
/// Returns an error if provider is not found, authentication fails,
/// or redirect URL generation fails
pub async fn oauth_sign_in(
    query: web::Query<SignInQuery>,
    _req: HttpRequest,
    oauth_config: web::Data<OAuthConfig>,
    settings: web::Data<VouchrsSettings>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    // Clear any existing session by setting an expired cookie
    let clear_cookie = create_expired_cookie(COOKIE_NAME, session_manager.cookie_secure());

    match &query.provider {
        Some(provider) if oauth_config.get_client_configured(provider) => {
            // Generate state for CSRF protection using high-entropy crypto-secure token
            let csrf_state = generate_csrf_token();

            // Create OAuth state object
            let oauth_state = OAuthState {
                state: csrf_state,
                provider: provider.clone(),
                redirect_url: query.rd.clone(),
            };

            // 🔒 SECURITY: Use encrypted state parameter to prevent tampering
            // This prevents attackers from modifying the provider name or redirect URL
            let actual_state = match encrypt_data(&oauth_state, session_manager.encryption_key()) {
                Ok(encrypted_state) => {
                    info!("Using encrypted state parameter for {provider} OAuth (tamper-proof)");
                    encrypted_state
                }
                Err(e) => {
                    error!("Failed to encrypt OAuth state: {e}");
                    let clear_cookie =
                        create_expired_cookie(COOKIE_NAME, session_manager.cookie_secure());
                    return Ok(HttpResponse::Found()
                        .cookie(clear_cookie)
                        .append_header((
                            "Location",
                            "/oauth2/sign_in?error=state_encryption_failed",
                        ))
                        .finish());
                }
            };
            let mut response_builder = HttpResponse::Found();
            response_builder.cookie(clear_cookie);

            debug!(
                "Generated encrypted OAuth state for provider {provider}: length = {} chars",
                actual_state.len()
            );
            debug!(
                "Stored OAuth state for provider: {provider}, using encrypted state parameter (tamper-proof)"
            );

            // Get authorization URL
            match oauth_config.get_auth_url(provider, &actual_state) {
                Ok(auth_url) => {
                    info!("Redirecting to {provider} OAuth: {auth_url}");
                    Ok(response_builder
                        .append_header(("Location", auth_url))
                        .finish())
                }
                Err(e) => {
                    error!("Failed to get auth URL for {provider}: {e}");
                    let error_clear_cookie =
                        create_expired_cookie(COOKIE_NAME, session_manager.cookie_secure());
                    Ok(redirect_with_cookie(
                        "/oauth2/sign_in?error=oauth_config",
                        Some(error_clear_cookie),
                    ))
                }
            }
        }
        Some(provider) => {
            let clear_cookie = create_expired_cookie(COOKIE_NAME, session_manager.cookie_secure());
            let error_url =
                format!("/oauth2/sign_in?error=unsupported_provider&provider={provider}");
            Ok(redirect_with_cookie(&error_url, Some(clear_cookie)))
        }
        None => {
            // Return login page HTML
            let clear_cookie = create_expired_cookie(COOKIE_NAME, session_manager.cookie_secure());
            Ok(HttpResponse::Ok()
                .cookie(clear_cookie)
                .content_type("text/html")
                .body(get_sign_in_page(&settings)))
        }
    }
}

/// OAuth sign out handler
///
/// # Errors
/// Returns an error if session validation fails or cookie clearing fails
pub async fn oauth_sign_out(
    req: HttpRequest,
    oauth_config: web::Data<OAuthConfig>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    // Get the user's provider before clearing the session
    let provider = match session_manager.get_session_from_request(&req) {
        Ok(Some(session)) => Some(session.provider),
        _ => None,
    };

    // Create expired cookies to clear both session and user data
    let clear_session_cookie = session_manager.create_expired_cookie();
    let clear_user_cookie =
        create_expired_cookie(USER_COOKIE_NAME, session_manager.cookie_secure());
    info!("User signed out and both session and user data cleared");

    // If we have a provider, check if it supports sign-out URL
    if let Some(provider_name) = provider {
        if let Some(signout_url) = oauth_config.get_signout_url(&provider_name) {
            info!("Redirecting to {provider_name} sign-out: {signout_url}");
            return Ok(success_redirect_with_cookies(
                &signout_url,
                vec![clear_session_cookie, clear_user_cookie],
            ));
        }
        debug!("Provider {provider_name} does not support automatic sign-out");
    }

    // Default: redirect to login page
    Ok(success_redirect_with_cookies(
        "/oauth2/sign_in",
        vec![clear_session_cookie, clear_user_cookie],
    ))
}
