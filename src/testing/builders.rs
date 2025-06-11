//! Fluent builders for creating customizable test objects
//!
//! This module provides builder patterns for creating test objects with custom
//! configurations while maintaining sensible defaults.

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::session::SessionManager;
use crate::settings::{ApplicationSettings, ProxySettings, SessionSettings, VouchrsSettings};
use crate::utils::headers::UserAgentInfo;
use chrono::{Duration, Utc};

use super::constants::{
    TEST_CLIENT_IP, TEST_EMAIL, TEST_JWT_KEY, TEST_LANGUAGE, TEST_PLATFORM, TEST_PROVIDER_ID,
    TEST_USER_AGENT, TEST_USER_NAME,
};
use super::fixtures::TestFixtures;

/// Builder for creating customized test sessions
pub struct TestSessionBuilder {
    provider: String,
    id_token: Option<String>,
    refresh_token: Option<String>,
    credential_id: Option<String>,
    user_handle: Option<String>,
    expires_in_hours: i64,
    authenticated_ago_minutes: i64,
}

impl TestSessionBuilder {
    /// Create a new session builder with OAuth defaults
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider: "google".to_string(),
            id_token: Some("test_id_token".to_string()),
            refresh_token: Some("test_refresh_token".to_string()),
            credential_id: None,
            user_handle: None,
            expires_in_hours: 1,
            authenticated_ago_minutes: 0,
        }
    }

    /// Create a passkey session builder
    #[must_use]
    pub fn passkey() -> Self {
        Self {
            provider: "passkey".to_string(),
            id_token: None,
            refresh_token: None,
            credential_id: Some("test_credential_123".to_string()),
            user_handle: Some("test_user_handle_456".to_string()),
            expires_in_hours: 168, // 7 days
            authenticated_ago_minutes: 0,
        }
    }

    /// Set the provider
    #[must_use]
    pub fn with_provider(mut self, provider: &str) -> Self {
        self.provider = provider.to_string();
        self
    }

    /// Set custom tokens (converts to OAuth session)
    #[must_use]
    pub fn with_tokens(mut self, id_token: Option<&str>, refresh_token: Option<&str>) -> Self {
        self.id_token = id_token.map(ToString::to_string);
        self.refresh_token = refresh_token.map(ToString::to_string);
        self.credential_id = None;
        self.user_handle = None;
        self
    }

    /// Set passkey credentials (converts to passkey session)
    #[must_use]
    pub fn with_credentials(mut self, credential_id: &str, user_handle: &str) -> Self {
        self.credential_id = Some(credential_id.to_string());
        self.user_handle = Some(user_handle.to_string());
        self.id_token = None;
        self.refresh_token = None;
        self
    }

    /// Set expiry time (in hours from now)
    #[must_use]
    pub fn expires_in_hours(mut self, hours: i64) -> Self {
        self.expires_in_hours = hours;
        self
    }

    /// Set authenticated time (minutes ago)
    #[must_use]
    pub fn authenticated_ago_minutes(mut self, minutes: i64) -> Self {
        self.authenticated_ago_minutes = minutes;
        self
    }

    /// Create an expired session
    #[must_use]
    pub fn expired(mut self) -> Self {
        self.expires_in_hours = -1;
        self
    }

    /// Build the session
    #[must_use]
    pub fn build(self) -> VouchrsSession {
        VouchrsSession {
            id_token: self.id_token,
            refresh_token: self.refresh_token,
            credential_id: self.credential_id,
            user_handle: self.user_handle,
            provider: self.provider,
            expires_at: Utc::now() + Duration::hours(self.expires_in_hours),
            authenticated_at: Utc::now() - Duration::minutes(self.authenticated_ago_minutes),
        }
    }
}

impl Default for TestSessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating customized user data
pub struct TestUserDataBuilder {
    email: String,
    name: Option<String>,
    provider: String,
    provider_id: String,
    client_ip: Option<String>,
    user_agent: Option<String>,
    platform: Option<String>,
    lang: Option<String>,
    mobile: i32,
    session_start: Option<i64>,
}

impl TestUserDataBuilder {
    /// Create a new user data builder with defaults
    #[must_use]
    pub fn new() -> Self {
        Self {
            email: TEST_EMAIL.to_string(),
            name: Some(TEST_USER_NAME.to_string()),
            provider: "google".to_string(),
            provider_id: TEST_PROVIDER_ID.to_string(),
            client_ip: Some(TEST_CLIENT_IP.to_string()),
            user_agent: Some(TEST_USER_AGENT.to_string()),
            platform: Some(TEST_PLATFORM.to_string()),
            lang: Some(TEST_LANGUAGE.to_string()),
            mobile: 0,
            session_start: Some(Utc::now().timestamp()),
        }
    }

    /// Create a minimal user data builder (no optional fields)
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            email: TEST_EMAIL.to_string(),
            name: None,
            provider: "google".to_string(),
            provider_id: TEST_PROVIDER_ID.to_string(),
            client_ip: None,
            user_agent: None,
            platform: None,
            lang: None,
            mobile: 0,
            session_start: None,
        }
    }

    /// Set email
    #[must_use]
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = email.to_string();
        self
    }

    /// Set name
    #[must_use]
    pub fn with_name(mut self, name: Option<&str>) -> Self {
        self.name = name.map(ToString::to_string);
        self
    }

    /// Set provider
    #[must_use]
    pub fn with_provider(mut self, provider: &str) -> Self {
        self.provider = provider.to_string();
        self
    }

    /// Set provider ID
    #[must_use]
    pub fn with_provider_id(mut self, provider_id: &str) -> Self {
        self.provider_id = provider_id.to_string();
        self
    }

    /// Set client context
    #[must_use]
    pub fn with_client_context(mut self, ip: Option<&str>, user_agent: Option<&str>) -> Self {
        self.client_ip = ip.map(ToString::to_string);
        self.user_agent = user_agent.map(ToString::to_string);
        self
    }

    /// Set mobile flag
    #[must_use]
    pub fn mobile(mut self, is_mobile: bool) -> Self {
        self.mobile = i32::from(is_mobile);
        self
    }

    /// Set from user agent info
    #[must_use]
    pub fn with_user_agent_info(mut self, info: &UserAgentInfo) -> Self {
        self.user_agent.clone_from(&info.user_agent);
        self.platform.clone_from(&info.platform);
        self.lang.clone_from(&info.lang);
        self.mobile = i32::from(info.mobile);
        self
    }

    /// Build the user data
    #[must_use]
    pub fn build(self) -> VouchrsUserData {
        VouchrsUserData {
            email: self.email,
            name: self.name,
            provider: self.provider,
            provider_id: self.provider_id,
            client_ip: self.client_ip,
            user_agent: self.user_agent,
            platform: self.platform,
            lang: self.lang,
            mobile: self.mobile,
            session_start: self.session_start,
        }
    }
}

impl Default for TestUserDataBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating customized session managers
pub struct TestSessionManagerBuilder {
    secret: Vec<u8>,
    cookie_secure: bool,
    session_duration_hours: u64,
    session_expiration_hours: u64,
    session_refresh_hours: u64,
}

impl TestSessionManagerBuilder {
    /// Create a new session manager builder with defaults
    #[must_use]
    pub fn new() -> Self {
        Self {
            secret: TEST_JWT_KEY.to_vec(),
            cookie_secure: false,
            session_duration_hours: 24,
            session_expiration_hours: 1,
            session_refresh_hours: 0,
        }
    }

    /// Set custom secret
    #[must_use]
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = secret.to_vec();
        self
    }

    /// Set cookie security
    #[must_use]
    pub fn with_cookie_secure(mut self, secure: bool) -> Self {
        self.cookie_secure = secure;
        self
    }

    /// Set session duration
    #[must_use]
    pub fn with_session_duration_hours(mut self, hours: u64) -> Self {
        self.session_duration_hours = hours;
        self
    }

    /// Set session expiration
    #[must_use]
    pub fn with_session_expiration_hours(mut self, hours: u64) -> Self {
        self.session_expiration_hours = hours;
        self
    }

    /// Set refresh configuration
    #[must_use]
    pub fn with_refresh_hours(mut self, hours: u64) -> Self {
        self.session_refresh_hours = hours;
        self
    }

    /// Enable refresh (2 hour default)
    #[must_use]
    pub fn with_refresh_enabled(mut self) -> Self {
        self.session_refresh_hours = 2;
        self
    }

    /// Build the session manager
    #[must_use]
    pub fn build(self) -> SessionManager {
        SessionManager::new(
            &self.secret,
            self.cookie_secure,
            self.session_duration_hours,
            self.session_expiration_hours,
            self.session_refresh_hours,
        )
    }
}

impl Default for TestSessionManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating customized test settings
pub struct TestSettingsBuilder {
    host: String,
    port: u16,
    redirect_base_url: String,
    cors_origins: String,
    upstream_url: String,
    session_duration_hours: u64,
    session_secret: String,
    session_expiration_hours: u64,
    session_refresh_hours: u64,
    cookie_secure: bool,
}

impl TestSettingsBuilder {
    /// Create a new settings builder with defaults
    #[must_use]
    pub fn new() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            redirect_base_url: "http://localhost:8080".to_string(),
            cors_origins: "http://localhost:3000".to_string(),
            upstream_url: "http://localhost:3000".to_string(),
            session_duration_hours: 24,
            session_secret: TestFixtures::consistent_test_secret().to_string(),
            session_expiration_hours: 1,
            session_refresh_hours: 0,
            cookie_secure: false,
        }
    }

    /// Set application configuration
    #[must_use]
    pub fn with_app_config(mut self, host: &str, port: u16, base_url: &str) -> Self {
        self.host = host.to_string();
        self.port = port;
        self.redirect_base_url = base_url.to_string();
        self
    }

    /// Set proxy upstream URL
    #[must_use]
    pub fn with_upstream_url(mut self, url: &str) -> Self {
        self.upstream_url = url.to_string();
        self
    }

    /// Set session configuration
    #[must_use]
    pub fn with_session_config(
        mut self,
        duration_hours: u64,
        expiration_hours: u64,
        refresh_hours: u64,
    ) -> Self {
        self.session_duration_hours = duration_hours;
        self.session_expiration_hours = expiration_hours;
        self.session_refresh_hours = refresh_hours;
        self
    }

    /// Set cookie security
    #[must_use]
    pub fn with_secure_cookies(mut self, secure: bool) -> Self {
        self.cookie_secure = secure;
        self
    }

    /// Build the settings
    #[must_use]
    pub fn build(self) -> VouchrsSettings {
        VouchrsSettings {
            application: ApplicationSettings {
                host: self.host,
                port: self.port,
                redirect_base_url: self.redirect_base_url,
                cors_origins: self.cors_origins,
            },
            proxy: ProxySettings {
                upstream_url: self.upstream_url,
            },
            session: SessionSettings {
                session_duration_hours: self.session_duration_hours,
                session_secret: self.session_secret,
                session_expiration_hours: self.session_expiration_hours,
                session_refresh_hours: self.session_refresh_hours,
            },
            cookies: crate::settings::CookieSettings {
                secure: self.cookie_secure,
            },
            ..Default::default()
        }
    }
}

impl Default for TestSettingsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_builder_oauth() {
        let session = TestSessionBuilder::new()
            .with_provider("github")
            .expires_in_hours(2)
            .build();

        assert_eq!(session.provider, "github");
        assert!(session.is_oauth_session());
        assert!(session.expires_at > Utc::now() + Duration::minutes(110)); // ~2 hours
    }

    #[test]
    fn test_session_builder_passkey() {
        let session = TestSessionBuilder::passkey()
            .with_credentials("custom_cred", "custom_handle")
            .build();

        assert_eq!(session.provider, "passkey");
        assert!(session.is_passkey_session());
        assert_eq!(session.credential_id, Some("custom_cred".to_string()));
        assert_eq!(session.user_handle, Some("custom_handle".to_string()));
    }

    #[test]
    fn test_session_builder_expired() {
        let session = TestSessionBuilder::new().expired().build();
        assert!(session.expires_at < Utc::now());
    }

    #[test]
    fn test_user_data_builder() {
        let user_data = TestUserDataBuilder::new()
            .with_email("custom@test.com")
            .with_provider("github")
            .mobile(true)
            .build();

        assert_eq!(user_data.email, "custom@test.com");
        assert_eq!(user_data.provider, "github");
        assert_eq!(user_data.mobile, 1);
    }

    #[test]
    fn test_user_data_builder_minimal() {
        let user_data = TestUserDataBuilder::minimal().build();
        assert!(user_data.name.is_none());
        assert!(user_data.client_ip.is_none());
        assert!(user_data.platform.is_none());
    }

    #[test]
    fn test_session_manager_builder() {
        let manager = TestSessionManagerBuilder::new()
            .with_refresh_enabled()
            .with_session_duration_hours(48)
            .build();

        assert!(manager.is_cookie_refresh_enabled());
    }

    #[test]
    fn test_settings_builder() {
        let settings = TestSettingsBuilder::new()
            .with_app_config("127.0.0.1", 9090, "http://localhost:9090")
            .with_secure_cookies(true)
            .build();

        assert_eq!(settings.application.host, "127.0.0.1");
        assert_eq!(settings.application.port, 9090);
        assert!(settings.cookies.secure);
    }
}
