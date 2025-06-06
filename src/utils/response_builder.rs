// HTTP response building utilities
use crate::utils::cached_responses::RESPONSES;
use actix_web::{cookie::Cookie, HttpResponse};
use log::{debug, warn};
use reqwest;
use url;

// Helper function to check for hop-by-hop headers
#[must_use]
pub fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Create a redirect response with optional cookies
#[must_use]
pub fn redirect(location: &str, cookies: Option<Vec<Cookie>>) -> HttpResponse {
    let mut builder = HttpResponse::Found();

    if let Some(cookies_vec) = cookies {
        for cookie in cookies_vec {
            builder.cookie(cookie);
        }
    }

    builder.append_header(("Location", location)).finish()
}

/// Create a redirect response with a single cookie
#[must_use]
pub fn redirect_with_cookie(location: &str, cookie: Option<Cookie>) -> HttpResponse {
    let cookies = cookie.map(|c| vec![c]);
    redirect(location, cookies)
}

/// Create an error redirect response
#[must_use]
pub fn error_redirect(location: &str, error_param: &str) -> HttpResponse {
    let redirect_url = if location.contains('?') {
        format!("{location}&error={error_param}")
    } else {
        format!("{location}?error={error_param}")
    };

    redirect(&redirect_url, None)
}

/// Create a success redirect response with multiple cookies
#[must_use]
pub fn success_redirect_with_cookies(location: &str, cookies: Vec<Cookie>) -> HttpResponse {
    redirect(location, Some(cookies))
}

/// Convert Actix HTTP method to reqwest method
///
/// # Errors
///
/// Returns an `HttpResponse` error if the HTTP method is not supported
pub fn convert_http_method(
    method: &actix_web::http::Method,
) -> Result<reqwest::Method, HttpResponse> {
    match method.as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "DELETE" => Ok(reqwest::Method::DELETE),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "HEAD" => Ok(reqwest::Method::HEAD),
        "OPTIONS" => Ok(reqwest::Method::OPTIONS),
        _method_str => Err(RESPONSES.invalid_request()),
    }
}

/// Build the upstream URL by combining base URL with request path
/// Simple URL construction for admin-controlled upstream URLs
/// No redirect protection needed since upstream URLs are controlled by admins
///
/// # Errors
///
/// Returns an `HttpResponse` error if:
/// - The base URL cannot be parsed
/// - The path cannot be joined with the base URL
pub fn build_upstream_url(base_url: &str, request_path: &str) -> Result<String, HttpResponse> {
    debug!("Building upstream URL - base: {base_url}, path: {request_path}");

    // Parse base URL
    let base = url::Url::parse(base_url).map_err(|e| {
        warn!("Failed to parse base URL '{base_url}': {e}");
        RESPONSES.invalid_request()
    })?;

    // Normalize the request path by removing leading slashes
    let clean_path = request_path.trim_start_matches('/');

    // Join the path with the base URL
    let final_url = base.join(clean_path).map_err(|e| {
        warn!("Failed to join URL '{base_url}' + '{clean_path}': {e}");
        RESPONSES.invalid_request()
    })?;

    debug!("Successfully built upstream URL: {final_url}");
    Ok(final_url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that legitimate upstream URLs still work with simplified `build_upstream_url`
    #[test]
    fn test_upstream_url_building() {
        let base_url = "https://api.example.com";

        let legitimate_paths = vec![
            "/api/v1/users",
            "/users/123",
            "/api/data.json",
            "/path/to/resource",
            "/search?q=test",
            "/uploads/file.pdf",
        ];

        for path in legitimate_paths {
            let result = build_upstream_url(base_url, path);
            assert!(
                result.is_ok(),
                "Legitimate upstream path should work: {path}"
            );
            let url = result.unwrap();
            assert!(
                url.starts_with(base_url),
                "URL should start with base URL: {url}"
            );
        }
    }
}
