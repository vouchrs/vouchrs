// Authentication handlers: sign-in and sign-out
use crate::jwt_session::JwtSessionManager;
use crate::models::OAuthState;
use crate::oauth::OAuthConfig;
use crate::settings::VouchrsSettings;
use crate::utils::response_builder::ResponseBuilder;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::Engine as _;
use log::{debug, error, info};
use uuid::Uuid;

use super::types::SignInQuery;
use super::helpers::get_sign_in_page;

pub async fn jwt_oauth_sign_in(
    query: web::Query<SignInQuery>,
    _req: HttpRequest,
    oauth_config: web::Data<OAuthConfig>,
    settings: web::Data<VouchrsSettings>,
    jwt_manager: web::Data<JwtSessionManager>,
) -> Result<HttpResponse> {
    // Clear any existing JWT session by setting an expired cookie
    let clear_cookie = jwt_manager.create_expired_cookie();

    match &query.provider {
        Some(provider) if oauth_config.get_client_configured(provider) => {
            // Generate state for CSRF protection
            let csrf_state = Uuid::new_v4().to_string();

            // Create OAuth state object
            let oauth_state = OAuthState {
                state: csrf_state.clone(),
                provider: provider.clone(),
                redirect_url: query.redirect_url.clone(),
            };

            // Use direct state parameter for OAuth providers (no cookies needed)
            // Format: csrf_state|provider|encoded_redirect_url
            let state_with_redirect = if let Some(ref redirect) = oauth_state.redirect_url {
                format!(
                    "{}|{}|{}",
                    csrf_state,
                    provider,
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(redirect)
                )
            } else {
                format!("{}|{}", csrf_state, provider)
            };

            info!(
                "Using direct state parameter for {} OAuth (stateless, no cookies needed)",
                provider
            );
            let mut response_builder = HttpResponse::Found();
            response_builder.cookie(clear_cookie);
            let actual_state = state_with_redirect;

            debug!(
                "Generated OAuth state for provider {}: '{}'", 
                provider, 
                actual_state
            );
            debug!(
                "Stored OAuth state for provider: {}, using direct state parameter (no cookies)",
                provider
            );

            // Get authorization URL
            match oauth_config.get_auth_url(provider, &actual_state).await {
                Ok(auth_url) => {
                    info!("Redirecting to {} OAuth: {}", provider, auth_url);
                    Ok(response_builder
                        .append_header(("Location", auth_url))
                        .finish())
                }
                Err(e) => {
                    error!("Failed to get auth URL for {}: {}", provider, e);
                    let error_clear_cookie = jwt_manager.create_expired_cookie();
                    Ok(ResponseBuilder::redirect_with_cookie(
                        "/oauth2/sign_in?error=oauth_config",
                        Some(error_clear_cookie)
                    ))
                }
            }
        }
        Some(provider) => {
            let clear_cookie = jwt_manager.create_expired_cookie();
            let error_url = format!("/oauth2/sign_in?error=unsupported_provider&provider={}", provider);
            Ok(ResponseBuilder::redirect_with_cookie(
                &error_url,
                Some(clear_cookie)
            ))
        }
        None => {
            // Return login page HTML
            let clear_cookie = jwt_manager.create_expired_cookie();
            Ok(HttpResponse::Ok()
                .cookie(clear_cookie)
                .content_type("text/html")
                .body(get_sign_in_page(&settings)))
        }
    }
}

pub async fn jwt_oauth_sign_out(
    req: HttpRequest,
    oauth_config: web::Data<OAuthConfig>,
    jwt_manager: web::Data<JwtSessionManager>,
) -> Result<HttpResponse> {
    // Get the user's provider before clearing the session
    let provider = match jwt_manager.get_session_from_request(&req) {
        Ok(Some(session)) => Some(session.provider),
        _ => None,
    };

    // Create expired cookies to clear both session and user data
    let clear_session_cookie = jwt_manager.create_expired_cookie();
    let clear_user_cookie = jwt_manager.create_expired_user_cookie();
    info!("User signed out and both JWT session and user data cleared");

    // If we have a provider, check if it supports sign-out URL
    if let Some(provider_name) = provider {
        if let Some(signout_url) = oauth_config.get_signout_url(&provider_name) {
            info!("Redirecting to {} sign-out: {}", provider_name, signout_url);
            return Ok(ResponseBuilder::success_redirect_with_cookies(&signout_url, vec![
                clear_session_cookie,
                clear_user_cookie,
            ]));
        } else {
            debug!(
                "Provider {} does not support automatic sign-out",
                provider_name
            );
        }
    }

    // Default: redirect to login page
    Ok(ResponseBuilder::success_redirect_with_cookies("/oauth2/sign_in", vec![
        clear_session_cookie,
        clear_user_cookie,
    ]))
}
