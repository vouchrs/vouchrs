// Test request builders for common test patterns
use actix_web::http::header;
use actix_web::{test, HttpRequest};

pub struct TestRequestBuilder;

impl TestRequestBuilder {
    /// Create a browser request with typical browser headers
    pub fn browser_request() -> HttpRequest {
        test::TestRequest::default()
            .insert_header((
                header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ))
            .insert_header((
                header::USER_AGENT,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ))
            .to_http_request()
    }

    /// Create an API request with typical API client headers
    pub fn api_request() -> HttpRequest {
        test::TestRequest::default()
            .insert_header((header::ACCEPT, "application/json"))
            .insert_header((header::USER_AGENT, "MyApp/1.0"))
            .to_http_request()
    }

    /// Create a request with client hints headers
    pub fn client_hints_request() -> HttpRequest {
        test::TestRequest::default()
            .insert_header((
                "sec-ch-ua",
                "\"Google Chrome\";v=\"91\", \"Chromium\";v=\"91\"",
            ))
            .insert_header(("sec-ch-ua-platform", "\"Windows\""))
            .insert_header(("sec-ch-ua-mobile", "?0"))
            .insert_header(("accept-language", "en-US,en;q=0.9,es;q=0.8"))
            .to_http_request()
    }

    /// Create a mobile browser request
    pub fn mobile_browser_request() -> HttpRequest {
        test::TestRequest::default()
            .insert_header((
                header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ))
            .insert_header((
                header::USER_AGENT,
                "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15",
            ))
            .insert_header(("sec-ch-ua-mobile", "?1"))
            .to_http_request()
    }

    /// Create a request with specific User-Agent for platform testing
    pub fn user_agent_request(user_agent: &str) -> HttpRequest {
        test::TestRequest::default()
            .insert_header((header::USER_AGENT, user_agent))
            .to_http_request()
    }

    /// Create an empty request with no headers
    pub fn empty_request() -> HttpRequest {
        test::TestRequest::default().to_http_request()
    }

    /// Create a request with macOS User-Agent and French language
    pub fn macos_french_request() -> HttpRequest {
        test::TestRequest::default()
            .insert_header((
                header::USER_AGENT,
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            ))
            .insert_header(("accept-language", "fr-FR,fr;q=0.9"))
            .to_http_request()
    }

    /// Create a request with specific cookie header
    pub fn with_cookies(cookies: &str) -> HttpRequest {
        test::TestRequest::default()
            .insert_header((header::COOKIE, cookies))
            .to_http_request()
    }
}
