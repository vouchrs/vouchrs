use actix_web::HttpResponse;
use crate::jwt_session::JwtSessionManager;

pub struct ErrorHandler;

impl ErrorHandler {
    /// Create an OAuth error redirect with cookie clearing
    pub fn oauth_error_redirect(
        session_manager: &JwtSessionManager,
        error_type: &str,
        redirect_url: Option<&str>
    ) -> HttpResponse {
        let clear_cookie = session_manager.create_expired_cookie();
        let location = redirect_url.unwrap_or("/oauth2/sign_in");
        
        let final_url = if location.contains('?') {
            format!("{location}&error={error_type}")
        } else {
            format!("{location}?error={error_type}")
        };
        
        HttpResponse::Found()
            .cookie(clear_cookie)
            .append_header(("Location", final_url))
            .finish()
    }
}