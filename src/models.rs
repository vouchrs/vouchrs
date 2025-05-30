use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OAuthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
}

// JWT Session Management Structures
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OAuthTokens {
    pub token_type: String,
    pub scope: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppleUserName {
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
}

impl AppleUserName {
    /// Get the full name by concatenating first and last name with a space
    pub fn full_name(&self) -> String {
        format!(
            "{} {}",
            self.first_name.as_deref().unwrap_or(""),
            self.last_name.as_deref().unwrap_or("")
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppleUserInfo {
    pub name: AppleUserName,
    pub email: Option<String>,
}

impl VouchrsSession {
    /// Check if tokens need refresh (within 5 minutes of expiry)
    pub fn needs_refresh(&self) -> bool {
        let now = chrono::Utc::now();
        let buffer_minutes = chrono::Duration::minutes(5);
        self.expires_at <= now + buffer_minutes
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VouchrsSession {
    pub user_email: String,
    pub user_name: Option<String>,
    pub provider: String,
    pub provider_id: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub access_token: Option<String>,
}