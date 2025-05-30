use actix_web::{HttpResponse, cookie::Cookie};

pub struct ResponseBuilder;

impl ResponseBuilder {
    /// Create a redirect response with optional cookie
    pub fn redirect_with_cookie(location: &str, cookie: Option<Cookie>) -> HttpResponse {
        let mut builder = HttpResponse::Found();
        
        if let Some(cookie) = cookie {
            builder.cookie(cookie);
        }
        
        builder
            .append_header(("Location", location))
            .finish()
    }

    /// Create an error redirect response
    pub fn error_redirect(location: &str, error_param: &str) -> HttpResponse {
        let redirect_url = if location.contains('?') {
            format!("{}&error={}", location, error_param)
        } else {
            format!("{}?error={}", location, error_param)
        };
        
        HttpResponse::Found()
            .append_header(("Location", redirect_url))
            .finish()
    }

    /// Create a success redirect response with cookie
    pub fn success_redirect_with_cookie(location: &str, cookie: Cookie) -> HttpResponse {
        HttpResponse::Found()
            .cookie(cookie)
            .append_header(("Location", location))
            .finish()
    }

    /// Create a success redirect response with multiple cookies
    pub fn success_redirect_with_cookies(location: &str, cookies: Vec<Cookie>) -> HttpResponse {
        let mut builder = HttpResponse::Found();
        
        for cookie in cookies {
            builder.cookie(cookie);
        }
        
        builder
            .append_header(("Location", location))
            .finish()
    }

    /// Create a JSON error response
    pub fn json_error(status: actix_web::http::StatusCode, error_type: &str, message: &str) -> HttpResponse {
        HttpResponse::build(status).json(serde_json::json!({
            "error": error_type,
            "message": message
        }))
    }

    /// Create an unauthorized JSON response
    pub fn unauthorized_json(message: &str) -> HttpResponse {
        Self::json_error(actix_web::http::StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    /// Create a bad request JSON response
    pub fn bad_request_json(message: &str) -> HttpResponse {
        Self::json_error(actix_web::http::StatusCode::BAD_REQUEST, "bad_request", message)
    }

    /// Create an internal server error JSON response
    pub fn internal_error_json(message: &str) -> HttpResponse {
        Self::json_error(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }

    /// Create a forbidden JSON response
    pub fn forbidden_json(message: &str) -> HttpResponse {
        Self::json_error(actix_web::http::StatusCode::FORBIDDEN, "forbidden", message)
    }

    /// Create a not found JSON response
    pub fn not_found_json(message: &str) -> HttpResponse {
        Self::json_error(actix_web::http::StatusCode::NOT_FOUND, "not_found", message)
    }

    /// Create a JSON response with custom status and data
    pub fn json_response<T: serde::Serialize>(status: actix_web::http::StatusCode, data: T) -> HttpResponse {
        HttpResponse::build(status).json(data)
    }
}