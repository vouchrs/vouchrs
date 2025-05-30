// OAuth callback utility functions
use base64::Engine as _;
use log::debug;

/// Parse OAuth state from received state parameter and retrieve stored state from cookie
/// This eliminates provider-specific branching logic by using the stored OAuth state
pub fn get_oauth_state_from_callback(
    received_state: &str, 
    jwt_manager: &crate::session::SessionManager,
    req: &actix_web::HttpRequest
) -> Result<crate::oauth::OAuthState, String> {
    debug!("Received OAuth state parameter: '{}'", received_state);
    debug!("Received state length: {} characters", received_state.len());
    
    // First, try to get the stored OAuth state from temporary cookie
    match jwt_manager.get_temporary_state_from_request(req) {
        Ok(Some(stored_state)) => {
            // Verify the received state matches the stored CSRF token
            if stored_state.state == received_state {
                debug!("OAuth state verified: stored state matches received state for provider {}", stored_state.provider);
                Ok(stored_state)
            } else {
                Err("OAuth state mismatch: received state does not match stored CSRF token".to_string())
            }
        }
        Ok(None) => {
            // Fallback: Parse state parameter directly (for stateless providers like Apple)
            // In this case, we need to extract provider info from the received state
            parse_stateless_oauth_state(received_state)
        }
        Err(e) => {
            debug!("Failed to retrieve stored OAuth state: {}", e);
            // Fallback to parsing state parameter directly
            parse_stateless_oauth_state(received_state)
        }
    }
}

/// Parse OAuth state when no stored state is available (stateless mode)
/// This handles cases where the provider info needs to be extracted from the state parameter itself
fn parse_stateless_oauth_state(received_state: &str) -> Result<crate::oauth::OAuthState, String> {
    debug!("Attempting to parse stateless OAuth state: '{}'", received_state);
    debug!("Contains pipe character: {}", received_state.contains('|'));
    
    if received_state.contains('|') {
        // New format: "csrf_token|provider|optional_redirect"
        let parts: Vec<&str> = received_state.split('|').collect();
        
        if parts.len() < 2 {
            return Err("Stateless OAuth state missing provider information".to_string());
        }
        
        let csrf_state = parts[0].to_string();
        let provider = parts[1].to_string();
        
        let redirect_url = if parts.len() > 2 {
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]) {
                Ok(decoded_bytes) => String::from_utf8(decoded_bytes).ok(),
                Err(_) => None,
            }
        } else {
            None
        };
        
        debug!("Successfully parsed stateless OAuth state for provider: {}", provider);
        
        Ok(crate::oauth::OAuthState {
            state: csrf_state,
            provider,
            redirect_url,
        })
    } else {
        // Simple CSRF token without provider or redirect URL
        Err("Cannot determine provider from simple CSRF token in stateless mode".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stateless_oauth_state_simple() {
        let result = parse_stateless_oauth_state("simple_csrf_token");
        
        // Should fail because we can't determine provider in stateless mode
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot determine provider"));
    }

    #[test]  
    fn test_parse_stateless_oauth_state_with_provider_and_redirect() {
        let redirect_url = "/dashboard";
        let encoded_redirect = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(redirect_url.as_bytes());
        let state = format!("csrf_token|google|{}", encoded_redirect);
        
        let result = parse_stateless_oauth_state(&state);
        
        // Should succeed with the new format
        assert!(result.is_ok());
        let oauth_state = result.unwrap();
        assert_eq!(oauth_state.state, "csrf_token");
        assert_eq!(oauth_state.provider, "google");
        assert_eq!(oauth_state.redirect_url, Some(redirect_url.to_string()));
    }
    
    #[test]  
    fn test_parse_stateless_oauth_state_with_provider_without_redirect() {
        let state = "csrf_token|google";
        
        let result = parse_stateless_oauth_state(&state);
        
        // Should succeed with the new format
        assert!(result.is_ok());
        let oauth_state = result.unwrap();
        assert_eq!(oauth_state.state, "csrf_token");
        assert_eq!(oauth_state.provider, "google");
        assert_eq!(oauth_state.redirect_url, None);
    }

    #[test]
    fn test_parse_stateless_oauth_state_invalid_base64() {
        let state = "csrf_token|google|invalid_base64!@#";
        
        let result = parse_stateless_oauth_state(state);
        
        // Should succeed but ignore invalid base64 redirect URL
        assert!(result.is_ok());
        let oauth_state = result.unwrap();
        assert_eq!(oauth_state.state, "csrf_token");
        assert_eq!(oauth_state.provider, "google");
        assert_eq!(oauth_state.redirect_url, None);
    }
}
