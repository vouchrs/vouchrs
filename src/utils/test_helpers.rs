// Test utilities shared across modules
use crate::models::VouchrsSession;
use crate::session::SessionManager;
use crate::settings::{ApplicationSettings, ProxySettings, SessionSettings, VouchrsSettings};
use actix_web::cookie::Cookie;
use actix_web::{test, HttpRequest};
use chrono::{Duration, Utc};

/// Create a test session for use in unit tests
#[must_use]
pub fn create_test_session() -> VouchrsSession {
    VouchrsSession {
        id_token: Some("test_id_token".to_string()),
        refresh_token: Some("test_refresh_token".to_string()),
        credential_id: None, // OAuth doesn't use credentials
        user_handle: None,   // OAuth doesn't use user handles
        provider: "google".to_string(),
        expires_at: Utc::now() + Duration::hours(1),
        authenticated_at: Utc::now(), // Updated field name
    }
}

/// Create a test `SessionManager` with a generated secure test key
#[must_use]
pub fn create_test_session_manager() -> SessionManager {
    // Use the existing secure random key generation from settings
    let test_secret = generate_test_session_secret();
    SessionManager::new(test_secret.as_bytes(), false, 24, 1, 0)
}

/// Generate a secure test session secret using the same method as the main app
fn generate_test_session_secret() -> String {
    use base64::{engine::general_purpose, Engine as _};
    use rand::RngCore;

    let mut secret = [0u8; 32]; // 256 bits for AES-256
    rand::rng().fill_bytes(&mut secret);
    general_purpose::STANDARD.encode(secret)
}

/// Create a test `SessionManager` from provided settings
#[must_use]
pub fn create_test_session_manager_from_settings(settings: &VouchrsSettings) -> SessionManager {
    SessionManager::new(
        settings.session.session_secret.as_bytes(),
        false,
        settings.session.session_duration_hours,
        settings.session.session_expiration_hours,
        0,
    )
}

/// Create a test `SessionManager` with custom refresh hours
#[must_use]
pub fn create_test_session_manager_with_refresh(session_refresh_hours: u64) -> SessionManager {
    let test_secret = generate_test_session_secret();
    SessionManager::new(test_secret.as_bytes(), false, 24, 1, session_refresh_hours)
}

/// Create a test HTTP request with a cookie
#[must_use]
pub fn create_request_with_cookie(cookie: Cookie) -> HttpRequest {
    test::TestRequest::default()
        .cookie(cookie)
        .to_http_request()
}

/// Create test settings for use in unit tests
#[must_use]
pub fn create_test_settings() -> VouchrsSettings {
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
            session_secret: "test-secret-key".to_string(),
            session_expiration_hours: 1,
            session_refresh_hours: 0,
        },
        ..Default::default()
    }
}

/// Create a test passkey session for use in unit tests
#[must_use]
pub fn create_test_passkey_session() -> VouchrsSession {
    VouchrsSession {
        id_token: None,      // Passkeys don't use OAuth tokens
        refresh_token: None, // Passkeys don't refresh
        credential_id: Some("test_credential_123".to_string()),
        user_handle: Some("test_user_handle_456".to_string()),
        provider: "passkey".to_string(),
        expires_at: Utc::now() + Duration::hours(168), // 7 days default
        authenticated_at: Utc::now(),
    }
}
