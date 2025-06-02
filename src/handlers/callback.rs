// OAuth callback handler
use crate::oauth::{OAuthCallback, OAuthConfig, OAuthState, get_state_from_callback};
use crate::session::SessionManager;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use log::{debug, error, info, warn};

use crate::session_builder::{AuthenticationData, SessionBuilder};
use crate::utils::apple::process_apple_callback;

// SessionFinalizeParams struct removed - parameters passed directly to simplify code

/// OAuth callback handler
/// 
/// # Errors
/// 
/// Returns an error if:
/// - OAuth state validation fails
/// - Authorization code exchange fails
/// - Session building fails
/// - Cookie creation fails
pub async fn oauth_callback(
    query: web::Query<OAuthCallback>,
    form: Option<web::Form<OAuthCallback>>,
    req: HttpRequest,
    oauth_config: web::Data<OAuthConfig>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    // Extract callback data from either query params or form
    let callback_data = extract_callback_data(query, form);
    debug!(
        "OAuth callback received via {}: {callback_data:?}",
        req.method()
    );
    debug!("Callback request headers: {:?}", req.headers());
    debug!(
        "Callback request connection info: {:?}",
        req.connection_info()
    );

    // Validate callback and extract required data
    let (code, oauth_state) = match validate_callback(&callback_data, &session_manager, &req) {
        Ok(data) => data,
        Err(response) => return Ok(response),
    };

    // Exchange code for OAuth tokens
    let token_result = oauth_config
        .exchange_code_for_tokens(&oauth_state.provider, &code)
        .await;

    let (id_token, refresh_token, expires_at, apple_user_info) = match token_result {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to exchange code for user info: {e}");
            let clear_cookie = session_manager.create_expired_cookie();
            return Ok(HttpResponse::Found()
                .cookie(clear_cookie)
                .append_header(("Location", "/oauth2/sign_in?error=auth_failed"))
                .finish());
        }
    };

    info!("=== OAuth Token Exchange Success for {} ===", oauth_state.provider);
    // Expires at, refresh token, and id token are now on VouchrSession or passed separately.
    if oauth_state.provider == "apple" {
        info!("=== Apple User Info Analysis ===");
        info!("Apple user info present: {}", apple_user_info.is_some());

        if let Some(user_info) = apple_user_info.as_ref() {
            info!("Apple user info email: {:?}", user_info.email);
            info!("Apple user info name: \"{} {}\"", 
                user_info.name.first_name.as_deref().unwrap_or(""),
                user_info.name.last_name.as_deref().unwrap_or(""));
            info!("Apple user info first_name: {:?}", user_info.name.first_name);
            info!("Apple user info last_name: {:?}", user_info.name.last_name);

            // Log raw JSON serialization for complete debugging
            if let Ok(user_info_json) = serde_json::to_string_pretty(user_info) {
                info!("Apple user info JSON:\n{user_info_json}");
            }
        } else {
            warn!("Apple OAuth completed but no user info was returned in the token response");
            warn!("This may happen on subsequent logins or if user info was not requested");
        }
    }
    info!("=== End OAuth Token Analysis ===");

    // Process additional Apple user info if available
    let processed_apple_info = process_apple_callback(&callback_data, apple_user_info);

    // Build and complete the session using the SessionBuilder
    // Create authentication data object
    let auth_data = AuthenticationData::new(
        &oauth_state.provider,
        id_token,
        refresh_token,
        expires_at
    ).with_apple_info(processed_apple_info);
    
    let result = SessionBuilder::finalize_session(
        &req,
        &session_manager,
        &auth_data,
        oauth_state.redirect_url,
    );

    Ok(result)
}

/// Extract callback data from either query parameters or form submission
fn extract_callback_data(
    query: web::Query<OAuthCallback>,
    form: Option<web::Form<OAuthCallback>>,
) -> OAuthCallback {
    form.map_or_else(|| {
        debug!("OAuth callback received via query: {query:?}");
        query.into_inner()
    }, |form_data| {
        debug!("OAuth callback received via form_post: {form_data:?}");
        form_data.into_inner()
    })
}

/// Validate the callback data and extract the required code and OAuth state
fn validate_callback(
    callback_data: &OAuthCallback,
    session_manager: &SessionManager,
    req: &HttpRequest,
) -> Result<(String, OAuthState), HttpResponse> {
    // Check for OAuth errors
    if let Some(_error) = &callback_data.error {
        let clear_cookie = session_manager.create_expired_cookie();
        return Err(HttpResponse::Found()
            .cookie(clear_cookie)
            .append_header(("Location", "/oauth2/sign_in?error=auth_failed"))
            .finish());
    }

    // Get authorization code
    let code = if let Some(code) = &callback_data.code {
        code.clone()
    } else {
        error!("No authorization code received");
        let clear_cookie = session_manager.create_expired_cookie();
        return Err(HttpResponse::Found()
            .cookie(clear_cookie)
            .append_header(("Location", "/oauth2/sign_in?error=auth_failed"))
            .finish());
    };

    // Get state parameter
    let received_state = if let Some(state) = &callback_data.state {
        state.clone()
    } else {
        error!("No state parameter received");
        let clear_cookie = session_manager.create_expired_cookie();
        return Err(HttpResponse::Found()
            .cookie(clear_cookie)
            .append_header(("Location", "/oauth2/sign_in?error=oauth_state_error"))
            .finish());
    };

    // Parse and validate OAuth state
    match get_state_from_callback(&received_state, session_manager, req) {
        Ok(state) => {
            debug!("OAuth state verified for provider: {}", state.provider);
            Ok((code, state))
        }
        Err(e) => {
            error!("Failed to parse OAuth state: {e}");
            let clear_cookie = session_manager.create_expired_cookie();
            Err(HttpResponse::Found()
                .cookie(clear_cookie)
                .append_header(("Location", "/oauth2/sign_in?error=oauth_state_error"))
                .finish())
        }
    }
}

// Note: Session finalization logic has been moved to SessionBuilder::finalize_session
