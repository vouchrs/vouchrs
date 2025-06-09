use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// Encrypted user data for storage during webauthn flows
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasskeyUserData {
    pub user_handle: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

impl PasskeyUserData {
    /// Create a new `PasskeyUserData`
    pub fn new(user_handle: &str, email: Option<&str>, name: Option<&str>) -> Self {
        Self {
            user_handle: user_handle.to_string(),
            email: email.map(ToString::to_string),
            name: name.map(ToString::to_string),
        }
    }

    /// Encode user data for transport
    ///
    /// # Errors
    /// Returns an error if:
    /// - JSON serialization fails
    /// - Base64 encoding fails
    pub fn encode(&self) -> Result<String, anyhow::Error> {
        let serialized = serde_json::to_string(self)?;
        // Base64 encode for transport safety
        Ok(URL_SAFE_NO_PAD.encode(serialized))
    }

    /// Decode user data from transport
    ///
    /// # Errors
    /// Returns an error if:
    /// - Base64 decoding fails
    /// - UTF-8 conversion fails
    /// - JSON deserialization fails
    pub fn decode(encoded: &str) -> Result<Self, anyhow::Error> {
        // Decode from Base64
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
        let serialized = String::from_utf8(decoded)?;
        let data: Self = serde_json::from_str(&serialized)?;
        Ok(data)
    }
}
