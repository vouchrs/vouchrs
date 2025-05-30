use actix_web::HttpResponse;
use crate::jwt_session::JwtSessionManager;

pub struct ErrorHandler;

impl ErrorHandler {
    /// Handle OAuth error with cookie clearing and redirect
    pub fn handle_oauth_error(
        jwt_manager: &JwtSessionManager,
        error_type: &str,
        redirect_url: Option<&str>
    ) -> HttpResponse {
        let clear_cookie = jwt_manager.create_expired_cookie();
        let location = redirect_url.unwrap_or("/oauth2/sign_in");
        
        let redirect_url = if location.contains('?') {
            format!("{}&error={}", location, error_type)
        } else {
            format!("{}?error={}", location, error_type)
        };
        
        HttpResponse::Found()
            .cookie(clear_cookie)
            .append_header(("Location", redirect_url))
            .finish()
    }

    /// Handle authentication failure
    pub fn auth_failed(jwt_manager: &JwtSessionManager) -> HttpResponse {
        Self::handle_oauth_error(jwt_manager, "auth_failed", None)
    }

    /// Handle OAuth state error
    pub fn oauth_state_error(jwt_manager: &JwtSessionManager) -> HttpResponse {
        Self::handle_oauth_error(jwt_manager, "oauth_state_error", None)
    }

    /// Handle session build error
    pub fn session_build_error(jwt_manager: &JwtSessionManager) -> HttpResponse {
        Self::handle_oauth_error(jwt_manager, "session_error", None)
    }
}