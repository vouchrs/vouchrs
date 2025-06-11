//! Test fixtures providing pre-built test objects
//!
//! This module provides commonly used test data and configurations as static fixtures,
//! eliminating the need to recreate the same test objects in multiple test files.

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::session::SessionManager;
use crate::settings::{ApplicationSettings, ProxySettings, SessionSettings, VouchrsSettings};
use crate::utils::headers::UserAgentInfo;
use actix_web::cookie::Cookie;
use actix_web::{test, HttpRequest};
use chrono::{Duration, Utc};
use std::sync::OnceLock;

use super::constants::{
    TEST_CLIENT_IP, TEST_EMAIL, TEST_JWT_KEY, TEST_LANGUAGE, TEST_PLATFORM, TEST_PROVIDER_ID,
    TEST_USER_AGENT, TEST_USER_NAME,
};

/// Central fixture provider for all test data
pub struct TestFixtures;

impl TestFixtures {
    /// Create a standard OAuth session for testing
    #[must_use]
    pub fn oauth_session() -> VouchrsSession {
        VouchrsSession {
            id_token: Some("test_id_token".to_string()),
            refresh_token: Some("test_refresh_token".to_string()),
            credential_id: None,
            user_handle: None,
            provider: "google".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            client_ip: None, // Test sessions don't have IP binding by default
        }
    }

    /// Create a standard passkey session for testing
    #[must_use]
    pub fn passkey_session() -> VouchrsSession {
        VouchrsSession {
            id_token: None,
            refresh_token: None,
            credential_id: Some("test_credential_123".to_string()),
            user_handle: Some("test_user_handle_456".to_string()),
            provider: "passkey".to_string(),
            expires_at: Utc::now() + Duration::hours(168), // 7 days
            authenticated_at: Utc::now(),
            client_ip: None, // Test sessions don't have IP binding by default
        }
    }

    /// Create a session for a specific provider
    #[must_use]
    pub fn session_for_provider(provider: &str) -> VouchrsSession {
        if provider == "passkey" {
            Self::passkey_session()
        } else {
            let mut session = Self::oauth_session();
            session.provider = provider.to_string();
            session
        }
    }

    /// Create an expired session for testing expiration logic
    #[must_use]
    pub fn expired_session() -> VouchrsSession {
        let mut session = Self::oauth_session();
        session.expires_at = Utc::now() - Duration::hours(1);
        session
    }

    /// Create a session manager with default test configuration
    #[must_use]
    pub fn session_manager() -> SessionManager {
        let secret = Self::generate_test_secret();
        SessionManager::new(secret.as_bytes(), false, false, 24, 1, 0)
    }

    /// Create a session manager with custom refresh hours
    #[must_use]
    pub fn session_manager_with_refresh(refresh_hours: u64) -> SessionManager {
        let secret = Self::generate_test_secret();
        SessionManager::new(secret.as_bytes(), false, false, 24, 1, refresh_hours)
    }

    /// Create a session manager from provided settings
    #[must_use]
    pub fn session_manager_from_settings(settings: &VouchrsSettings) -> SessionManager {
        SessionManager::new(
            settings.session.session_secret.as_bytes(),
            false,
            false, // Default to disabled for tests
            settings.session.session_duration_hours,
            settings.session.session_expiration_hours,
            0,
        )
    }

    /// Create standard test settings
    #[must_use]
    pub fn settings() -> VouchrsSettings {
        VouchrsSettings {
            application: ApplicationSettings {
                host: "0.0.0.0".to_string(),
                port: 8080,
                redirect_base_url: "http://localhost:8080".to_string(),
                cors_origins: "http://localhost:3000".to_string(),
            },
            proxy: ProxySettings {
                upstream_url: "http://localhost:3000".to_string(),
            },
            session: SessionSettings {
                session_duration_hours: 24,
                session_secret: Self::generate_test_secret(),
                session_expiration_hours: 1,
                session_refresh_hours: 0,
            },
            cookies: crate::settings::CookieSettings {
                secure: false,             // Set to false for testing
                bind_session_to_ip: false, // Default to disabled for tests
            },
            ..Default::default()
        }
    }

    /// Create test user data with all fields populated
    #[must_use]
    pub fn user_data() -> VouchrsUserData {
        Self::user_data_with_context(Some(TEST_CLIENT_IP), Some(&Self::user_agent_info()))
    }

    /// Create test user data with minimal information
    #[must_use]
    pub fn minimal_user_data() -> VouchrsUserData {
        Self::user_data_with_context(None, None)
    }

    /// Create test user data with optional context
    pub fn user_data_with_context(
        client_ip: Option<&str>,
        user_agent_info: Option<&UserAgentInfo>,
    ) -> VouchrsUserData {
        VouchrsUserData {
            email: TEST_EMAIL.to_string(),
            name: Some(TEST_USER_NAME.to_string()),
            provider: "google".to_string(),
            provider_id: TEST_PROVIDER_ID.to_string(),
            client_ip: client_ip.map(ToString::to_string),
            user_agent: user_agent_info.and_then(|ua| ua.user_agent.clone()),
            platform: user_agent_info.and_then(|ua| ua.platform.clone()),
            lang: user_agent_info.and_then(|ua| ua.lang.clone()),
            mobile: user_agent_info.map_or(0, |ua| i32::from(ua.mobile)),
            session_start: Some(Utc::now().timestamp()),
        }
    }

    /// Create test user agent information
    #[must_use]
    pub fn user_agent_info() -> UserAgentInfo {
        UserAgentInfo {
            user_agent: Some(TEST_USER_AGENT.to_string()),
            platform: Some(TEST_PLATFORM.to_string()),
            lang: Some(TEST_LANGUAGE.to_string()),
            mobile: 0,
        }
    }

    /// Create mobile user agent information
    #[must_use]
    pub fn mobile_user_agent_info() -> UserAgentInfo {
        UserAgentInfo {
            user_agent: Some("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)".to_string()),
            platform: Some("iOS".to_string()),
            lang: Some(TEST_LANGUAGE.to_string()),
            mobile: 1,
        }
    }

    /// Create an HTTP request with a cookie
    #[must_use]
    pub fn request_with_cookie(cookie: Cookie) -> HttpRequest {
        test::TestRequest::default()
            .cookie(cookie)
            .to_http_request()
    }

    /// Generate a secure test session secret
    fn generate_test_secret() -> String {
        use base64::{engine::general_purpose, Engine as _};
        use rand::RngCore;

        let mut secret = [0u8; 32]; // 256 bits for AES-256
        rand::rng().fill_bytes(&mut secret);
        general_purpose::STANDARD.encode(secret)
    }
}

/// Thread-safe static test secret for consistent testing
static TEST_SECRET: OnceLock<String> = OnceLock::new();

impl TestFixtures {
    /// Get a consistent test secret across all tests
    pub fn consistent_test_secret() -> &'static str {
        TEST_SECRET.get_or_init(|| {
            use base64::{engine::general_purpose, Engine as _};
            general_purpose::STANDARD.encode(TEST_JWT_KEY)
        })
    }

    /// Create a session manager with consistent secret for predictable testing
    #[must_use]
    pub fn consistent_session_manager() -> SessionManager {
        SessionManager::new(TEST_JWT_KEY, false, false, 24, 1, 0)
    }
}

// Current testing utilities are available through TestFixtures struct
