//! HTTP request builders for testing handlers
//!
//! This module provides fluent builders for creating HTTP requests with common
//! patterns used in testing, such as browser requests, API calls, and mobile requests.

use actix_web::cookie::Cookie;
use actix_web::http::Method;
use actix_web::{test, HttpRequest};
use serde_json::{json, Value};

use super::constants::TEST_USER_AGENT;

/// Builder for creating HTTP requests for testing
pub struct RequestBuilder {
    method: Method,
    uri: String,
    headers: Vec<(String, String)>,
    cookies: Vec<Cookie<'static>>,
    body: Option<Value>,
}

impl Default for RequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestBuilder {
    /// Create a new request builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            method: Method::GET,
            uri: "/".to_string(),
            headers: Vec::new(),
            cookies: Vec::new(),
            body: None,
        }
    }

    /// Set the HTTP method
    #[must_use]
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Set the request URI
    #[must_use]
    pub fn uri(mut self, uri: &str) -> Self {
        self.uri = uri.to_string();
        self
    }

    /// Add a header
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Set the User-Agent header
    #[must_use]
    pub fn user_agent(self, user_agent: &str) -> Self {
        self.header("User-Agent", user_agent)
    }

    /// Set common browser headers
    #[must_use]
    pub fn browser_headers(self) -> Self {
        self.user_agent(TEST_USER_AGENT)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("Accept-Language", "en-US,en;q=0.5")
            .header("Accept-Encoding", "gzip, deflate")
    }

    /// Set common API headers
    #[must_use]
    pub fn api_headers(self) -> Self {
        self.user_agent("VouchrsAPI/1.0")
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
    }

    /// Set common mobile headers
    #[must_use]
    pub fn mobile_headers(self) -> Self {
        self.user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)")
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("Accept-Language", "en-US,en;q=0.5")
    }

    /// Add a cookie to the request
    #[must_use]
    pub fn with_cookie(mut self, cookie: Cookie<'static>) -> Self {
        self.cookies.push(cookie);
        self
    }

    /// Add a session cookie using the provided session value
    #[must_use]
    pub fn with_session_cookie(self, session_value: String) -> Self {
        let cookie = Cookie::build("vouchrs_session", session_value)
            .domain("localhost")
            .path("/")
            .finish();
        self.with_cookie(cookie)
    }

    /// Add a user cookie using the provided user value
    #[must_use]
    pub fn with_user_cookie(self, user_value: String) -> Self {
        let cookie = Cookie::build("vouchrs_user", user_value)
            .domain("localhost")
            .path("/")
            .finish();
        self.with_cookie(cookie)
    }

    /// Add cookies from a cookie header string
    #[must_use]
    pub fn with_cookie_header(self, cookies: &str) -> Self {
        self.header("Cookie", cookies)
    }

    /// Set JSON body
    #[must_use]
    pub fn json_body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    /// Set client IP for testing purposes
    /// This adds the necessary headers that would be used to extract client IP
    #[must_use]
    pub fn with_client_ip(self, ip: &str) -> Self {
        self.header("X-Forwarded-For", ip).header("X-Real-IP", ip)
    }

    /// Build the final `HttpRequest`
    #[must_use]
    pub fn build(self) -> HttpRequest {
        let mut req = test::TestRequest::default()
            .method(self.method)
            .uri(&self.uri);

        // Add headers
        for (name, value) in self.headers {
            req = req.insert_header((name, value));
        }

        // Add cookies
        for cookie in self.cookies {
            req = req.cookie(cookie);
        }

        // Add body if present
        if let Some(body) = self.body {
            req = req.set_json(body);
        }

        req.to_http_request()
    }
}

/// Quick builder functions for common request types
impl RequestBuilder {
    /// Create a browser-like GET request
    #[must_use]
    pub fn browser(uri: &str) -> HttpRequest {
        Self::new()
            .method(Method::GET)
            .uri(uri)
            .browser_headers()
            .build()
    }

    /// Create an API POST request
    #[must_use]
    pub fn api_post(uri: &str, body: Value) -> HttpRequest {
        Self::new()
            .method(Method::POST)
            .uri(uri)
            .api_headers()
            .json_body(body)
            .build()
    }

    /// Create a mobile GET request
    #[must_use]
    pub fn mobile(uri: &str) -> HttpRequest {
        Self::new()
            .method(Method::GET)
            .uri(uri)
            .mobile_headers()
            .build()
    }

    /// Create an authenticated browser request
    #[must_use]
    pub fn authenticated_browser(uri: &str, session_value: &str) -> HttpRequest {
        Self::new()
            .method(Method::GET)
            .uri(uri)
            .browser_headers()
            .with_session_cookie(session_value.to_string())
            .build()
    }

    /// Create a request with cookies from a cookie header string
    #[must_use]
    pub fn with_cookies(cookies: &str) -> HttpRequest {
        Self::new().with_cookie_header(cookies).build()
    }

    /// Create an empty request with no headers
    #[must_use]
    pub fn empty_request() -> HttpRequest {
        Self::new().build()
    }

    /// Create a request with specific User-Agent
    #[must_use]
    pub fn user_agent_request(user_agent: &str) -> HttpRequest {
        Self::new().user_agent(user_agent).build()
    }

    /// Create a request with client hints headers
    #[must_use]
    pub fn client_hints_request() -> HttpRequest {
        Self::new()
            .header(
                "sec-ch-ua",
                "\"Google Chrome\";v=\"91\", \"Chromium\";v=\"91\"",
            )
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("accept-language", "en-US,en;q=0.9,es;q=0.8")
            .build()
    }

    /// Create a macOS request with French locale
    #[must_use]
    pub fn macos_french_request() -> HttpRequest {
        Self::new()
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
            .header("accept-language", "fr-FR,fr;q=0.9")
            .build()
    }

    /// Create a browser request (shorthand)
    #[must_use]
    pub fn browser_request() -> HttpRequest {
        Self::browser("/")
    }

    /// Create an API request (shorthand)
    #[must_use]
    pub fn api_request() -> HttpRequest {
        Self::new().api_headers().build()
    }
}

/// Specialized request builders for OAuth flows
pub struct OAuthRequestBuilder;

impl OAuthRequestBuilder {
    /// Create an OAuth authorization request
    #[must_use]
    pub fn authorization(provider: &str, redirect_uri: &str) -> HttpRequest {
        let uri = format!("/oauth/{provider}/authorize?redirect_uri={redirect_uri}");
        RequestBuilder::browser(&uri)
    }

    /// Create an OAuth callback request
    #[must_use]
    pub fn callback(provider: &str, code: &str, state: &str) -> HttpRequest {
        let uri = format!("/oauth/{provider}/callback?code={code}&state={state}");
        RequestBuilder::browser(&uri)
    }

    /// Create an OAuth token exchange request
    #[must_use]
    pub fn token_exchange(provider: &str, code: &str) -> HttpRequest {
        let body = json!({
            "code": code,
            "grant_type": "authorization_code"
        });
        RequestBuilder::api_post(&format!("/oauth/{provider}/token"), body)
    }
}

/// Specialized request builders for passkey flows
pub struct PasskeyRequestBuilder;

impl PasskeyRequestBuilder {
    /// Create a passkey registration initiation request
    #[must_use]
    pub fn register_init() -> HttpRequest {
        RequestBuilder::api_post("/passkey/register/begin", json!({}))
    }

    /// Create a passkey registration completion request
    #[must_use]
    pub fn register_complete(credential: Value) -> HttpRequest {
        RequestBuilder::api_post("/passkey/register/finish", credential)
    }

    /// Create a passkey authentication initiation request
    #[must_use]
    pub fn auth_init() -> HttpRequest {
        RequestBuilder::api_post("/passkey/authenticate/begin", json!({}))
    }

    /// Create a passkey authentication completion request
    #[must_use]
    pub fn auth_complete(assertion: Value) -> HttpRequest {
        RequestBuilder::api_post("/passkey/authenticate/finish", assertion)
    }
}

// Legacy function aliases for backward compatibility
#[must_use]
pub fn create_test_request() -> HttpRequest {
    RequestBuilder::browser("/")
}

#[must_use]
pub fn create_browser_request(uri: &str) -> HttpRequest {
    RequestBuilder::browser(uri)
}

#[must_use]
pub fn create_api_request(uri: &str) -> HttpRequest {
    RequestBuilder::new().uri(uri).api_headers().build()
}

#[must_use]
pub fn create_mobile_request(uri: &str) -> HttpRequest {
    RequestBuilder::mobile(uri)
}

#[must_use]
pub fn oauth_callback(_code: &str, _state: &str) -> HttpRequest {
    // Simplified version for backward compatibility
    RequestBuilder::browser("/oauth/callback")
}
