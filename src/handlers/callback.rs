// OAuth callback handler
use crate::session::SessionManager;
use crate::oauth::{OAuthConfig, OAuthCallback, OAuthState};
use actix_web::{web, HttpRequest, HttpResponse, Result};
use chrono::{DateTime, Utc};
use log::{debug, error};

use super::session_builder::SessionBuilder;
use crate::utils::response_builder::ResponseBuilder;
use crate::utils::logging::LoggingHelper;
use crate::utils::apple_utils::{process_apple_callback, AppleUserInfo};
use crate::utils::oauth_utils::get_oauth_state_from_callback;
use crate::utils::user_agent::extract_user_agent_info;

/// Parameters for session finalization
struct SessionFinalizeParams {
    provider: String,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: DateTime<Utc>,
    apple_user_info: Option<AppleUserInfo>,
    redirect_url: Option<String>,
}

pub async fn jwt_oauth_callback(
    query: web::Query<OAuthCallback>,
    form: Option<web::Form<OAuthCallback>>,
    req: HttpRequest,
    oauth_config: web::Data<OAuthConfig>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    // Extract callback data from either query params or form
    let callback_data = extract_callback_data(query, form);
    LoggingHelper::log_callback_debug(&req, &callback_data);

    // Validate callback and extract required data
    let (code, oauth_state) = match validate_callback(&callback_data, &session_manager, &req) {
        Ok(data) => data,
        Err(response) => return Ok(response),
    };

    // Exchange code for OAuth tokens
    let token_result = oauth_config
        .exchange_code_for_session_data(&oauth_state.provider, &code)
        .await;

    let (id_token, refresh_token, expires_at, apple_user_info) = match token_result {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to exchange code for user info: {}", e);
            let clear_cookie = session_manager.create_expired_cookie();
            return Ok(HttpResponse::Found()
                .cookie(clear_cookie)
                .append_header(("Location", "/oauth2/sign_in?error=auth_failed"))
                .finish());
        }
    };
    
    LoggingHelper::log_oauth_token_response(&oauth_state.provider, apple_user_info.as_ref());
    
    // Process additional Apple user info if available
    let processed_apple_info = process_apple_callback(&callback_data, apple_user_info);
    
    // Build and complete the session
    let result = build_and_finalize_session(
        &req, 
        &session_manager, 
        SessionFinalizeParams {
            provider: oauth_state.provider, 
            id_token, 
            refresh_token, 
            expires_at, 
            apple_user_info: processed_apple_info,
            redirect_url: oauth_state.redirect_url,
        }
    );
    
    Ok(result)
}

/// Extract callback data from either query parameters or form submission
fn extract_callback_data(
    query: web::Query<OAuthCallback>, 
    form: Option<web::Form<OAuthCallback>>
) -> OAuthCallback {
    if let Some(form_data) = form {
        debug!("OAuth callback received via form_post: {:?}", form_data);
        form_data.into_inner()
    } else {
        debug!("OAuth callback received via query: {:?}", query);
        query.into_inner()
    }
}

/// Validate the callback data and extract the required code and OAuth state
fn validate_callback(
    callback_data: &OAuthCallback, 
    session_manager: &SessionManager, 
    req: &HttpRequest
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
    let code = match &callback_data.code {
        Some(code) => code.clone(),
        None => {
            error!("No authorization code received");
            let clear_cookie = session_manager.create_expired_cookie();
            return Err(HttpResponse::Found()
                .cookie(clear_cookie)
                .append_header(("Location", "/oauth2/sign_in?error=auth_failed"))
                .finish());
        }
    };

    // Get state parameter
    let received_state = match &callback_data.state {
        Some(state) => state.clone(),
        None => {
            error!("No state parameter received");
            let clear_cookie = session_manager.create_expired_cookie();
            return Err(HttpResponse::Found()
                .cookie(clear_cookie)
                .append_header(("Location", "/oauth2/sign_in?error=oauth_state_error"))
                .finish());
        }
    };

    // Parse and validate OAuth state
    match get_oauth_state_from_callback(&received_state, session_manager, req) {
        Ok(state) => {
            debug!("OAuth state verified for provider: {}", state.provider);
            Ok((code, state))
        },
        Err(e) => {
            error!("Failed to parse OAuth state: {}", e);
            let clear_cookie = session_manager.create_expired_cookie();
            Err(HttpResponse::Found()
                .cookie(clear_cookie)
                .append_header(("Location", "/oauth2/sign_in?error=oauth_state_error"))
                .finish())
        }
    }
}

// Function moved to utils/apple_utils.rs

/// Build session and finalize the authentication process
fn build_and_finalize_session(
    req: &HttpRequest,
    session_manager: &SessionManager,
    params: SessionFinalizeParams,
) -> HttpResponse {
    // Extract client info
    let client_ip = req.connection_info().realip_remote_addr()
        .map(|s| s.to_string());
    let user_agent_info = extract_user_agent_info(req);
    
    // Build the session (without access token)
    let session_result = SessionBuilder::build_session_with_apple_info(
        params.provider.clone(),
        params.id_token,
        params.refresh_token,
        params.expires_at,
        params.apple_user_info,
    );
    
    match session_result {
        Ok(complete_session) => {
            LoggingHelper::log_session_created(&complete_session.user_email, &params.provider);
            
            // Split complete session into token data and user data
            let session = complete_session.to_session();
            let user_data = complete_session.to_user_data(
                client_ip.as_deref(),
                Some(&user_agent_info),
            );
            
            // Create both session and user cookies
            let session_cookie = match session_manager.create_session_cookie(&session) {
                Ok(cookie) => cookie,
                Err(e) => {
                    error!("Failed to create session cookie: {}", e);
                    let clear_cookie = session_manager.create_expired_cookie();
                    return HttpResponse::Found()
                        .cookie(clear_cookie)
                        .append_header(("Location", "/oauth2/sign_in?error=session_build_error"))
                        .finish();
                }
            };
            
            let user_cookie = match session_manager.create_user_cookie(&user_data) {
                Ok(cookie) => cookie,
                Err(e) => {
                    error!("Failed to create user cookie: {}", e);
                    let clear_cookie = session_manager.create_expired_cookie();
                    return HttpResponse::Found()
                        .cookie(clear_cookie)
                        .append_header(("Location", "/oauth2/sign_in?error=session_build_error"))
                        .finish();
                }
            };
            
            let clear_temp_cookie = session_manager.create_expired_temp_state_cookie();
            let redirect_to = params.redirect_url.unwrap_or_else(|| "/".to_string());
            
            // Create response with multiple cookies
            ResponseBuilder::success_redirect_with_cookies(&redirect_to, vec![
                session_cookie,
                user_cookie,
                clear_temp_cookie,
            ])
        },
        Err(e) => {
            error!("Failed to build session from ID token: {}", e);
            let clear_cookie = session_manager.create_expired_cookie();
            HttpResponse::Found()
                .cookie(clear_cookie)
                .append_header(("Location", "/oauth2/sign_in?error=session_build_error"))
                .finish()
        }
    }
}


