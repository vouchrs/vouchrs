// OAuth callback handler
use crate::oauth::OAuthConfig;
use crate::oauth::{OAuthCallback, OAuthState};
use crate::session::{get_state_from_callback, SessionManager};
use actix_web::{web, HttpRequest, HttpResponse, Result};
use log::{debug, error, info};

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
    _oauth_config: web::Data<OAuthConfig>,
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

    info!(
        "=== OAuth Callback Processing for {} ===",
        oauth_state.provider
    );

    // Process additional Apple user info if available from the callback form
    let processed_apple_info = process_apple_callback(&callback_data, None);

    // Delegate to SessionManager for unified authentication handling
    // The OAuth service will handle token exchange and Apple user info extraction
    match session_manager
        .handle_oauth_callback(
            &req,
            &oauth_state.provider,
            &code,
            &oauth_state,
            processed_apple_info,
        )
        .await
    {
        Ok(response) => {
            info!(
                "OAuth callback processing successful for {}",
                oauth_state.provider
            );
            Ok(response)
        }
        Err(error_response) => {
            error!(
                "OAuth callback processing failed for {}",
                oauth_state.provider
            );
            Ok(error_response)
        }
    }
}

/// Extract callback data from either query parameters or form submission
fn extract_callback_data(
    query: web::Query<OAuthCallback>,
    form: Option<web::Form<OAuthCallback>>,
) -> OAuthCallback {
    form.map_or_else(
        || {
            debug!("OAuth callback received via query: {query:?}");
            query.into_inner()
        },
        |form_data| {
            debug!("OAuth callback received via form_post: {form_data:?}");
            form_data.into_inner()
        },
    )
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
            .append_header(("Location", "/sign_in?error=auth_failed"))
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
            .append_header(("Location", "/sign_in?error=auth_failed"))
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
            .append_header(("Location", "/sign_in?error=oauth_state_error"))
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
                .append_header(("Location", "/sign_in?error=oauth_state_error"))
                .finish())
        }
    }
}
