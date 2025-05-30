// User agent extraction and platform detection utilities
use actix_web::HttpRequest;

/// User agent information extracted from HTTP headers
#[derive(Debug, Clone)]
pub struct UserAgentInfo {
    pub user_agent: Option<String>,
    pub platform: Option<String>,
    pub lang: Option<String>,
    pub mobile: u8, // 0 or 1
}

/// Extract user agent information from HTTP request headers
/// Uses modern client hints headers first, with fallback to traditional User-Agent header
pub fn extract_user_agent_info(req: &HttpRequest) -> UserAgentInfo {
    let headers = req.headers();
    
    // Try to get user agent from modern client hints or fallback to User-Agent header
    let user_agent = headers.get("sec-ch-ua")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            headers.get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        });
    
    // Try to get platform from client hints or derive from User-Agent
    let platform = headers.get("sec-ch-ua-platform")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim_matches('"').to_string())
        .or_else(|| {
            if let Some(ref ua) = user_agent {
                Some(derive_platform_from_user_agent(ua))
            } else {
                Some("Unknown".to_string())
            }
        });
    
    // Extract language preference from Accept-Language header
    let lang = headers.get("accept-language")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty());
    
    // Detect mobile from client hints
    let mobile = headers.get("sec-ch-ua-mobile")
        .and_then(|h| h.to_str().ok())
        .map(|s| if s.contains("1") { 1 } else { 0 })
        .unwrap_or(0);
    
    UserAgentInfo {
        user_agent,
        platform,
        lang,
        mobile,
    }
}

/// Derive platform from User-Agent string
/// Detects common platforms like Windows, macOS, Linux, Android, iOS, Chrome OS
pub fn derive_platform_from_user_agent(user_agent: &str) -> String {
    let ua_lower = user_agent.to_lowercase();
    
    if ua_lower.contains("android") {
        "Android".to_string()
    } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") || ua_lower.contains("ios") {
        "iOS".to_string()
    } else if ua_lower.contains("chrome os") || ua_lower.contains("cros") {
        "Chrome OS".to_string()
    } else if ua_lower.contains("windows") {
        "Windows".to_string()
    } else if ua_lower.contains("macintosh") || ua_lower.contains("mac os") {
        "macOS".to_string()
    } else if ua_lower.contains("linux") {
        "Linux".to_string()
    } else {
        "Unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_request_builder::TestRequestBuilder;

    #[test]
    fn test_user_agent_extraction() {
        // Test with modern client hints headers
        let req = TestRequestBuilder::client_hints_request();
        
        let user_agent_info = extract_user_agent_info(&req);
        
        assert_eq!(user_agent_info.user_agent, Some("\"Google Chrome\";v=\"91\", \"Chromium\";v=\"91\"".to_string()));
        assert_eq!(user_agent_info.platform, Some("Windows".to_string()));
        assert_eq!(user_agent_info.lang, Some("en-US".to_string()));
        assert_eq!(user_agent_info.mobile, 0);
        
        // Test with fallback to User-Agent header
        let req = TestRequestBuilder::macos_french_request();
        
        let user_agent_info = extract_user_agent_info(&req);
        
        assert_eq!(user_agent_info.user_agent, Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string()));
        assert_eq!(user_agent_info.platform, Some("macOS".to_string())); // Derived from User-Agent
        assert_eq!(user_agent_info.lang, Some("fr-FR".to_string()));
        assert_eq!(user_agent_info.mobile, 0); // Default when not specified
    }

    #[test]
    fn test_platform_derivation_from_user_agent() {
        // Test Windows detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "Windows".to_string());
        
        // Test macOS detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"), "macOS".to_string());
        
        // Test Linux detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (X11; Linux x86_64)"), "Linux".to_string());
        
        // Test Android detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (Linux; Android 11; SM-G991B)"), "Android".to_string());
        
        // Test iOS detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"), "iOS".to_string());
        
        // Test Chrome OS detection
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)"), "Chrome OS".to_string());
        
        // Test unknown platform - now returns "Unknown" instead of None
        assert_eq!(derive_platform_from_user_agent("Mozilla/5.0 (Unknown Platform)"), "Unknown".to_string());
    }
}
