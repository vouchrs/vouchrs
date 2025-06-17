use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sha2::{Sha256, Digest};

pub mod auth;

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub message: String,
}

/// User data structure for the `vouchrs_user` cookie
/// Contains only essential user information
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VouchrsUserData {
    pub email: String,
    pub name: Option<String>,
    pub provider: String,
    pub provider_id: String,
    pub uid: Uuid,
    pub session_id: Uuid,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub platform: Option<String>,
    pub lang: Option<String>,
    pub mobile: i32,
    pub session_start: Option<i64>,
}

impl VouchrsUserData {
    /// Generate a `UUIDv5` based on provider and `provider_id`
    ///
    /// # Panics
    ///
    /// Panics if the hardcoded namespace UUID is invalid (should never happen)
    #[must_use]
    pub fn generate_uid(provider: &str, provider_id: &str) -> Uuid {
        let provider_string = format!("{provider}|{provider_id}");
        // Use a fixed namespace UUID for vouchrs
        let namespace = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        Uuid::new_v5(&namespace, provider_string.as_bytes())
    }

    /// Generate a `session_id` based on uid and session-related properties
    /// Uses SHA-256 hash for efficiency and deterministic generation
    #[must_use]
    pub fn generate_session_id(
        uid: &Uuid,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
        platform: Option<&str>,
        mobile: i32,
        session_start: Option<i64>,
    ) -> Uuid {
        let mut hasher = Sha256::new();

        // Add uid (always present)
        hasher.update(uid.as_bytes());

        // Add client_ip (use empty string if None)
        hasher.update(client_ip.unwrap_or("").as_bytes());

        // Add user_agent (use empty string if None)
        hasher.update(user_agent.unwrap_or("").as_bytes());

        // Add platform (use empty string if None)
        hasher.update(platform.unwrap_or("").as_bytes());

        // Add mobile flag
        hasher.update(mobile.to_le_bytes());

        // Add session_start (use current timestamp if None)
        let timestamp = session_start.unwrap_or_else(|| Utc::now().timestamp());
        hasher.update(timestamp.to_le_bytes());

        let hash_result = hasher.finalize();

        // Use more entropy by XORing first and second halves of the hash
        // This combines all 32 bytes into 16 bytes instead of discarding half
        let mut uuid_bytes = [0u8; 16];
        for i in 0..16 {
            uuid_bytes[i] = hash_result[i] ^ hash_result[i + 16];
        }

        // Set version to 4 and variant bits to make it a valid UUID
        uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40; // Version 4
        uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80; // Variant 10

        Uuid::from_bytes(uuid_bytes)
    }

    /// Create a new `VouchrsUserData` with auto-generated uid and `session_id`
    #[must_use]
    #[allow(clippy::too_many_arguments)] // Constructor needs all these parameters
    pub fn new(
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
    ) -> Self {
        let uid = Self::generate_uid(&provider, &provider_id);

        // Use current timestamp if session_start is None
        let actual_session_start = session_start.unwrap_or_else(|| Utc::now().timestamp());

        let session_id = Self::generate_session_id(
            &uid,
            client_ip.as_deref(),
            user_agent.as_deref(),
            platform.as_deref(),
            mobile,
            Some(actual_session_start),
        );

        Self {
            email,
            name,
            provider,
            provider_id,
            uid,
            session_id,
            client_ip,
            user_agent,
            platform,
            lang,
            mobile,
            session_start: Some(actual_session_start),
        }
    }
}

/// Session structure containing only essential token data for cookies
/// User data is stored separately in the `vouchrs_user` cookie
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VouchrsSession {
    // OAuth-specific fields (None for passkeys)
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,

    // Passkey-specific fields (None for OAuth)
    pub credential_id: Option<String>,
    pub user_handle: Option<String>,

    // Common fields (used by both authentication methods)
    pub provider: String,
    pub expires_at: DateTime<Utc>,
    pub authenticated_at: DateTime<Utc>, // Unified from session_created_at

    // Optional client IP binding for additional security
    pub client_ip: Option<String>,
}

impl VouchrsSession {
    /// Check if tokens need refresh (within 5 minutes of expiry)
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        let now = chrono::Utc::now();
        let buffer_minutes = chrono::Duration::minutes(5);
        self.expires_at <= now + buffer_minutes
    }

    /// Check if this is a passkey session
    #[must_use]
    pub fn is_passkey_session(&self) -> bool {
        self.credential_id.is_some() && self.user_handle.is_some()
    }

    /// Check if this is an OAuth session
    #[must_use]
    pub fn is_oauth_session(&self) -> bool {
        self.id_token.is_some() || self.refresh_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_vouchrs_session_type_detection() {
        // Test OAuth session detection
        let oauth_session = VouchrsSession {
            id_token: Some("oauth_token".to_string()),
            refresh_token: Some("refresh_token".to_string()),
            credential_id: None,
            user_handle: None,
            provider: "google".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            authenticated_at: Utc::now(),
            client_ip: None,
        };

        assert!(oauth_session.is_oauth_session());
        assert!(!oauth_session.is_passkey_session());

        // Test passkey session detection
        let passkey_session = VouchrsSession {
            id_token: None,
            refresh_token: None,
            credential_id: Some("credential_123".to_string()),
            user_handle: Some("user_handle_456".to_string()),
            provider: "passkey".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(168),
            authenticated_at: Utc::now(),
            client_ip: None,
        };

        assert!(passkey_session.is_passkey_session());
        assert!(!passkey_session.is_oauth_session());

        // Test session with only ID token (still OAuth)
        let id_only_session = VouchrsSession {
            id_token: Some("id_token".to_string()),
            refresh_token: None,
            credential_id: None,
            user_handle: None,
            provider: "github".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            authenticated_at: Utc::now(),
            client_ip: None,
        };

        assert!(id_only_session.is_oauth_session());
        assert!(!id_only_session.is_passkey_session());
    }

    #[test]
    fn test_vouchrs_user_data_uid_generation() {
        // Test that the same provider and provider_id always generate the same uid
        let uid1 = VouchrsUserData::generate_uid("google", "user123");
        let uid2 = VouchrsUserData::generate_uid("google", "user123");
        assert_eq!(uid1, uid2);

        // Test that different providers generate different uids
        let uid_google = VouchrsUserData::generate_uid("google", "user123");
        let uid_github = VouchrsUserData::generate_uid("github", "user123");
        assert_ne!(uid_google, uid_github);

        // Test that different provider_ids generate different uids
        let uid_user1 = VouchrsUserData::generate_uid("google", "user123");
        let uid_user2 = VouchrsUserData::generate_uid("google", "user456");
        assert_ne!(uid_user1, uid_user2);
    }

    #[test]
    fn test_vouchrs_user_data_session_id_generation() {
        let uid = VouchrsUserData::generate_uid("google", "user123");

        // Test that the same session properties always generate the same session_id
        let session_id1 = VouchrsUserData::generate_session_id(
            &uid,
            Some("192.168.1.1"),
            Some("Mozilla/5.0"),
            Some("macOS"),
            0,
            Some(1_234_567_890),
        );
        let session_id2 = VouchrsUserData::generate_session_id(
            &uid,
            Some("192.168.1.1"),
            Some("Mozilla/5.0"),
            Some("macOS"),
            0,
            Some(1_234_567_890),
        );
        assert_eq!(session_id1, session_id2);

        // Test that different session properties generate different session_ids
        let session_id_different_ip = VouchrsUserData::generate_session_id(
            &uid,
            Some("192.168.1.2"), // Different IP
            Some("Mozilla/5.0"),
            Some("macOS"),
            0,
            Some(1_234_567_890),
        );
        assert_ne!(session_id1, session_id_different_ip);

        let session_id_different_agent = VouchrsUserData::generate_session_id(
            &uid,
            Some("192.168.1.1"),
            Some("Chrome/90.0"), // Different user agent
            Some("macOS"),
            0,
            Some(1_234_567_890),
        );
        assert_ne!(session_id1, session_id_different_agent);

        let session_id_different_time = VouchrsUserData::generate_session_id(
            &uid,
            Some("192.168.1.1"),
            Some("Mozilla/5.0"),
            Some("macOS"),
            0,
            Some(1_234_567_999), // Different timestamp
        );
        assert_ne!(session_id1, session_id_different_time);

        // Test handling of None values - session_start=None will use current timestamp
        // so we need to test with a fixed timestamp
        let session_id_none_values = VouchrsUserData::generate_session_id(
            &uid,
            None, // No IP
            None, // No user agent
            None, // No platform
            1,    // Mobile
            Some(9_999_999_999), // Fixed timestamp for deterministic testing
        );
        assert_ne!(session_id1, session_id_none_values);

        // Test that None values are handled consistently with same fixed timestamp
        let session_id_none_values2 = VouchrsUserData::generate_session_id(
            &uid,
            None,
            None,
            None,
            1,
            Some(9_999_999_999), // Same fixed timestamp
        );
        assert_eq!(session_id_none_values, session_id_none_values2);
    }    #[test]
    fn test_vouchrs_user_data_new() {
        let user_data = VouchrsUserData::new(
            "test@example.com".to_string(),
            Some("Test User".to_string()),
            "google".to_string(),
            "user123".to_string(),
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string()),
            Some("web".to_string()),
            Some("en".to_string()),
            0,
            Some(1_234_567_890),
        );

        assert_eq!(user_data.email, "test@example.com");
        assert_eq!(user_data.provider, "google");
        assert_eq!(user_data.provider_id, "user123");

        // Test that uid is generated correctly
        let expected_uid = VouchrsUserData::generate_uid("google", "user123");
        assert_eq!(user_data.uid, expected_uid);

        // Test that session_id is generated correctly
        let expected_session_id = VouchrsUserData::generate_session_id(
            &expected_uid,
            Some("192.168.1.1"),
            Some("Mozilla/5.0"),
            Some("web"),
            0,
            Some(1_234_567_890),
        );
        assert_eq!(user_data.session_id, expected_session_id);

        // Test that creating another instance with same params gives same IDs
        let user_data2 = VouchrsUserData::new(
            "test@example.com".to_string(),
            Some("Test User".to_string()),
            "google".to_string(),
            "user123".to_string(),
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string()),
            Some("web".to_string()),
            Some("en".to_string()),
            0,
            Some(1_234_567_890),
        );

        assert_eq!(user_data.uid, user_data2.uid);
        assert_eq!(user_data.session_id, user_data2.session_id);
    }

    #[test]
    fn test_vouchrs_user_data_session_start_fallback() {
        // Test that when session_start is None, it falls back to current timestamp
        let user_data = VouchrsUserData::new(
            "test@example.com".to_string(),
            Some("Test User".to_string()),
            "google".to_string(),
            "user123".to_string(),
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string()),
            Some("web".to_string()),
            Some("en".to_string()),
            0,
            None, // No session_start provided
        );

        // session_start should be populated with current timestamp
        assert!(user_data.session_start.is_some());

        // The timestamp should be close to current time (within a few seconds)
        let now = Utc::now().timestamp();
        let session_start = user_data.session_start.unwrap();
        assert!((now - session_start).abs() < 5); // Within 5 seconds

        // Session ID should be generated with the fallback timestamp
        let expected_session_id = VouchrsUserData::generate_session_id(
            &user_data.uid,
            Some("192.168.1.1"),
            Some("Mozilla/5.0"),
            Some("web"),
            0,
            Some(session_start),
        );
        assert_eq!(user_data.session_id, expected_session_id);
    }
}
