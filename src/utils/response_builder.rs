// filepath: /workspaces/vouchrs/src/utils/response_builder.rs
use actix_web::{web, HttpRequest, HttpResponse, cookie::Cookie};
use reqwest;
use std::collections::HashMap;
use url;

use crate::utils::cookie_utils::filter_vouchrs_cookies;

pub struct ResponseBuilder;

// Helper function to check for hop-by-hop headers
pub fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(name, 
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" |
        "te" | "trailers" | "transfer-encoding" | "upgrade"
    )
}

impl ResponseBuilder {
    /// Create a redirect response with optional cookies
    pub fn redirect(location: &str, cookies: Option<Vec<Cookie>>) -> HttpResponse {
        let mut builder = HttpResponse::Found();
        
        if let Some(cookies_vec) = cookies {
            for cookie in cookies_vec {
                builder.cookie(cookie);
            }
        }
        
        builder
            .append_header(("Location", location))
            .finish()
    }
    
    /// Create a redirect response with a single cookie
    pub fn redirect_with_cookie(location: &str, cookie: Option<Cookie>) -> HttpResponse {
        let cookies = cookie.map(|c| vec![c]);
        Self::redirect(location, cookies)
    }

    /// Create an error redirect response
    pub fn error_redirect(location: &str, error_param: &str) -> HttpResponse {
        let redirect_url = if location.contains('?') {
            format!("{}&error={}", location, error_param)
        } else {
            format!("{}?error={}", location, error_param)
        };
        
        Self::redirect(&redirect_url, None)
    }

    /// Create a success redirect response with cookie
    pub fn success_redirect_with_cookie(location: &str, cookie: Cookie) -> HttpResponse {
        Self::redirect(location, Some(vec![cookie]))
    }

    /// Create a success redirect response with multiple cookies
    pub fn success_redirect_with_cookies(location: &str, cookies: Vec<Cookie>) -> HttpResponse {
        Self::redirect(location, Some(cookies))
    }
    
    /// Convert Actix HTTP method to reqwest method
    pub fn convert_http_method(method: &actix_web::http::Method) -> Result<reqwest::Method, HttpResponse> {
        match method.as_str() {
            "GET" => Ok(reqwest::Method::GET),
            "POST" => Ok(reqwest::Method::POST),
            "PUT" => Ok(reqwest::Method::PUT),
            "DELETE" => Ok(reqwest::Method::DELETE),
            "PATCH" => Ok(reqwest::Method::PATCH),
            "HEAD" => Ok(reqwest::Method::HEAD),
            "OPTIONS" => Ok(reqwest::Method::OPTIONS),
            method_str => Err(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "bad_request",
                "message": format!("HTTP method '{}' is not supported", method_str)
            }))),
        }
    }

    /// Forward request headers (excluding Authorization, Cookie with vouchrs_session, and hop-by-hop headers)
    pub fn forward_request_headers(
        mut request_builder: reqwest::RequestBuilder,
        req: &HttpRequest,
    ) -> reqwest::RequestBuilder {
        for (name, value) in req.headers() {
            let name_str = name.as_str().to_lowercase();
            
            // Skip authorization and hop-by-hop headers
            if name_str == "authorization" || is_hop_by_hop_header(&name_str) {
                continue;
            }
            
            // Special handling for cookies
            if name_str == "cookie" {
                if let Ok(cookie_str) = value.to_str() {
                    if let Some(filtered_cookie) = filter_vouchrs_cookies(cookie_str) {
                        request_builder = request_builder.header(name.as_str(), filtered_cookie);
                    }
                }
                continue;
            }
            
            // Add other headers
            if let Ok(value_str) = value.to_str() {
                request_builder = request_builder.header(name.as_str(), value_str);
            }
        }
        request_builder
    }

    /// Forward query parameters
    pub fn forward_query_parameters(
        mut request_builder: reqwest::RequestBuilder,
        query_params: &web::Query<HashMap<String, String>>,
    ) -> reqwest::RequestBuilder {
        if !query_params.is_empty() {
            for (key, value) in query_params.iter() {
                request_builder = request_builder.query(&[(key, value)]);
            }
        }
        request_builder
    }

    /// Forward request body if present
    pub fn forward_request_body(
        mut request_builder: reqwest::RequestBuilder,
        body: &web::Bytes,
    ) -> reqwest::RequestBuilder {
        if !body.is_empty() {
            request_builder = request_builder.body(body.to_vec());
        }
        request_builder
    }

    /// Build the upstream URL by combining base URL with request path
    /// Ensures that the request only goes to the configured upstream URL
    /// and protects against path traversal attempts
    pub fn build_upstream_url(base_url: &str, request_path: &str) -> Result<String, HttpResponse> {
        // Validate that the request path doesn't contain suspicious patterns
        if request_path.contains("..") || request_path.contains("://") {
            return Err(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "bad_request",
                "message": "Invalid request path. Path traversal or URL protocol specifications are not allowed."
            })));
        }

        // Normalize the path to prevent path traversal attempts
        let normalized_path = request_path
            .split('/')
            .filter(|&segment| !segment.is_empty() && segment != "." && segment != "..")
            .collect::<Vec<&str>>()
            .join("/");

        // Construct the final URL
        let final_url = format!("{}/{}", base_url.trim_end_matches('/'), normalized_path.trim_start_matches('/'));
        
        // For extra security, validate the final URL is under the base_url domain
        if let (Ok(base_uri), Ok(final_uri)) = (url::Url::parse(base_url), url::Url::parse(&final_url)) {
            if base_uri.host_str() != final_uri.host_str() {
                return Err(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "bad_request",
                    "message": "Request URL doesn't match configured upstream host"
                })));
            }
        } else {
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "internal_error",
                "message": "Failed to parse URL for security validation"
            })));
        }

        Ok(final_url)
    }
}
