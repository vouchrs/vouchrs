// Test utilities shared across modules
use crate::models::VouchrsSession;
use crate::settings::{ApplicationSettings, ProxySettings, JwtSettings, VouchrsSettings};
use chrono::{Duration, Utc};

/// Create a test session for use in unit tests
pub fn create_test_session() -> VouchrsSession {
    VouchrsSession {
        user_email: "test@example.com".to_string(),
        user_name: Some("Test User".to_string()),
        provider: "google".to_string(),
        provider_id: "123456789".to_string(),
        id_token: Some("test_id_token".to_string()),
        refresh_token: Some("test_refresh_token".to_string()),
        expires_at: Utc::now() + Duration::hours(1),
        created_at: Utc::now(),
        access_token: None,
    }
}

/// Create test settings for use in unit tests
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
        jwt: JwtSettings {
            session_duration_hours: 24,
            session_secret: "test-secret-key".to_string(),
            issuer: "https://vouchrs.app".to_string(),
            audience: "http://localhost:3000".to_string(),
        },
        ..Default::default()
    }
}
