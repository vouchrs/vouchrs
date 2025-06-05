use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub platform: Option<String>,
    pub lang: Option<String>,
    pub mobile: i32,
    pub session_start: Option<i64>,
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

/// Complete session data structure used during OAuth flow
/// Contains both user data and token data before splitting into separate cookies
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CompleteSessionData {
    pub user_email: String,
    pub user_name: Option<String>,
    pub provider: String,
    pub provider_id: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl CompleteSessionData {
    /// Extract token data as `VouchrsSession`
    #[must_use]
    pub fn to_session(&self) -> VouchrsSession {
        VouchrsSession {
            id_token: self.id_token.clone(),
            refresh_token: self.refresh_token.clone(),
            credential_id: None, // OAuth doesn't use credentials
            user_handle: None,   // OAuth doesn't use user handles
            provider: self.provider.clone(),
            expires_at: self.expires_at,
            authenticated_at: self.created_at, // Maps created_at to authenticated_at
        }
    }

    /// Extract user data as `VouchrsUserData` with additional context
    #[must_use]
    pub fn to_user_data(
        &self,
        client_ip: Option<&str>,
        user_agent_info: Option<&crate::utils::user_agent::UserAgentInfo>,
    ) -> VouchrsUserData {
        VouchrsUserData {
            email: self.user_email.clone(),
            name: self.user_name.clone(),
            provider: self.provider.clone(),
            provider_id: self.provider_id.clone(),
            client_ip: client_ip.map(std::string::ToString::to_string),
            user_agent: user_agent_info.and_then(|ua| ua.user_agent.clone()),
            platform: user_agent_info.and_then(|ua| ua.platform.clone()),
            lang: user_agent_info.and_then(|ua| ua.lang.clone()),
            mobile: user_agent_info.map_or(0, |ua| i32::from(ua.mobile)),
            session_start: Some(self.created_at.timestamp()), // Convert created_at to Unix timestamp
        }
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
        };

        assert!(id_only_session.is_oauth_session());
        assert!(!id_only_session.is_passkey_session());
    }
}
