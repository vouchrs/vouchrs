// Centralized logging utilities to reduce verbose logging patterns
use log::{info, warn, debug};
use crate::models::{AppleUserInfo};

pub struct LoggingHelper;

impl LoggingHelper {
    /// Log OAuth token response in a standardized format
    pub fn log_oauth_token_response(provider: &str, apple_user_info: Option<&AppleUserInfo>) {
        info!("=== OAuth Token Exchange Success for {} ===", provider);
        // Expires at, refresh token, and id token are now on VouchrSession or passed separately.
        if provider == "apple" {
            Self::log_apple_user_info(apple_user_info);
        }
        info!("=== End OAuth Token Analysis ===");
    }

    /// Log Apple user info in a standardized format
    fn log_apple_user_info(apple_user_info: Option<&AppleUserInfo>) {
        info!("=== Apple User Info Analysis ===");
        info!("Apple user info present: {}", apple_user_info.is_some());

        if let Some(user_info) = apple_user_info {
            info!("Apple user info email: {:?}", user_info.email);
            info!("Apple user info name: {:?}", user_info.name.full_name());
            info!("Apple user info first_name: {:?}", user_info.name.first_name);
            info!("Apple user info last_name: {:?}", user_info.name.last_name);

            // Log raw JSON serialization for complete debugging
            if let Ok(user_info_json) = serde_json::to_string_pretty(user_info) {
                info!("Apple user info JSON:\n{}", user_info_json);
            }
        } else {
            warn!("Apple OAuth completed but no user info was returned in the token response");
            warn!("This may happen on subsequent logins or if user info was not requested");
        }
    }

    /// Log provider initialization status
    pub fn log_provider_init(provider_name: &str, display_name: Option<&str>, configured: bool) {
        let name = display_name.unwrap_or(provider_name);
        if configured {
            info!("✅ {} OAuth2 configured ({})", name, provider_name);
        } else {
            info!("❌ {} OAuth2 not configured - missing environment variables", name);
        }
    }

    /// Log OAuth provider initialization start
    pub fn log_oauth_provider_initialization() {
        info!("🔧 Initializing OAuth providers from configuration...");
    }

    /// Log that a provider is disabled
    pub fn log_oauth_provider_disabled(provider_name: &str) {
        info!("⏭️  Provider {} is disabled, skipping", provider_name);
    }

    /// Log that a provider is configured
    pub fn log_oauth_provider_configured(display_name: &str, provider_name: &str) {
        info!("✅ {} OAuth2 configured ({})", display_name, provider_name);
    }

    /// Log that a provider is not configured
    pub fn log_oauth_provider_not_configured(display_name: &str) {
        info!("❌ {} OAuth2 not configured - missing environment variables", display_name);
    }

    /// Log summary of configured OAuth providers
    pub fn log_oauth_providers_summary(provider_names: &[&String]) {
        info!("🎯 Configured OAuth providers: {:?}", provider_names);
    }

    /// Log OAuth URL building
    pub fn log_oauth_url_built(provider: &str, scopes: &str, extra_params: &std::collections::HashMap<String, String>) {
        info!("🔍 Built {} OAuth URL with scopes: {} and extra params: {:?}", 
            provider, scopes, extra_params);
    }

    /// Log token exchange start
    pub fn log_token_exchange_start(provider: &str) {
        info!("🔄 Exchanging authorization code for tokens with {}", provider);
    }

    /// Log raw Apple token response for debugging
    pub fn log_apple_token_response_raw(response_text: &str) {
        info!("=== Raw Apple Token Response ===");
        info!("Response text: {}", response_text);
        info!("=== End Raw Apple Token Response ===");
    }

    /// Log raw token response for other providers
    pub fn log_token_response_raw(provider: &str, response_text: &str) {
        debug!("Raw {} token response: {}", provider, response_text);
    }

    /// Log token exchange summary
    pub fn log_token_exchange_summary(
        provider: &str,
        refresh_token: Option<&String>,
        id_token: Option<&String>,
        token_type: &str,
        scope: Option<&String>,
        user_info_present: bool
    ) {
        info!("🔍 Token exchange summary for {}: refresh_token={}, id_token={}, token_type={}, scope={:?}, user_info={}", 
            provider,
            refresh_token.map(|_| "present").unwrap_or("missing"),
            id_token.map(|_| "present").unwrap_or("missing"),
            token_type,
            scope,
            if user_info_present { "present" } else { "missing" }
        );
    }

    /// Log session creation success
    pub fn log_session_created(user_email: &str, provider: &str) {
        info!("Successfully built session for user: {} (provider: {})", user_email, provider);
    }

    /// Log OAuth callback details in development mode
    pub fn log_callback_debug(req: &actix_web::HttpRequest, callback_data: &crate::oauth::OAuthCallback) {
        debug!("OAuth callback received via {}: {:?}", req.method(), callback_data);
        debug!("Callback request headers: {:?}", req.headers());
        debug!("Callback request connection info: {:?}", req.connection_info());
    }
}
