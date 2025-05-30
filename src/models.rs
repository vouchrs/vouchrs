use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub message: String,
}

/// User data structure for the vouchrs_user cookie
/// Contains only essential user information (not JWT metadata)
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
/// User data is now stored separately in the vouchrs_user cookie
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VouchrsSession {
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub provider: String,
    pub expires_at: DateTime<Utc>,
}

impl VouchrsSession {
    /// Check if tokens need refresh (within 5 minutes of expiry)
    pub fn needs_refresh(&self) -> bool {
        let now = chrono::Utc::now();
        let buffer_minutes = chrono::Duration::minutes(5);
        self.expires_at <= now + buffer_minutes
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
    /// Extract token data as VouchrsSession
    pub fn to_session(&self) -> VouchrsSession {
        VouchrsSession {
            id_token: self.id_token.clone(),
            refresh_token: self.refresh_token.clone(),
            provider: self.provider.clone(),
            expires_at: self.expires_at,
        }
    }

    /// Extract user data as VouchrsUserData with additional context
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
            client_ip: client_ip.map(|ip| ip.to_string()),
            user_agent: user_agent_info.and_then(|ua| ua.user_agent.clone()),
            platform: user_agent_info.and_then(|ua| ua.platform.clone()),
            lang: user_agent_info.and_then(|ua| ua.lang.clone()),
            mobile: user_agent_info.map(|ua| ua.mobile as i32).unwrap_or(0),
            session_start: Some(self.created_at.timestamp()), // Convert created_at to Unix timestamp
        }
    }
}
