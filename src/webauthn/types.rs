//! `WebAuthn` core types
//!
//! This module defines core data structures for `WebAuthn` operations,
//! independent of application-specific logic.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// `WebAuthn` registration options sent to the client
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistrationOptions {
    pub challenge: String, // Base64URL-encoded random challenge
    pub rp: RelyingParty,  // Relying party information
    pub user: UserEntity,  // User information
    #[serde(rename = "pubKeyCredParams")]
    pub public_key_params: Vec<PublicKeyCredentialParameters>, // Allowed algorithms
    pub timeout: u32,      // Timeout in milliseconds
    pub attestation: String, // "none", "indirect", "direct"
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelectionCriteria,
}

/// `WebAuthn` authentication options sent to the client
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthenticationOptions {
    pub challenge: String, // Base64URL-encoded random challenge
    pub timeout: u32,      // Timeout in milliseconds
    #[serde(rename = "rpId")]
    pub rp_id: String, // Relying party ID
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>, // Optional allowed credentials
    #[serde(rename = "userVerification")]
    pub user_verification: String, // "required", "preferred", "discouraged"
}

/// `WebAuthn` relying party information
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelyingParty {
    pub id: String,   // Domain name (e.g., "example.com")
    pub name: String, // Display name
}

/// `WebAuthn` user entity
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserEntity {
    pub id: String,   // Base64URL-encoded user handle
    pub name: String, // Username (e.g., email)
    #[serde(rename = "displayName")]
    pub display_name: String, // Display name
}

/// Public key credential parameters
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub r#type: String, // Always "public-key"
    pub alg: i32, // Algorithm identifier (-7 for ES256, -257 for RS256)
}

/// Authenticator selection criteria
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>, // "platform", "cross-platform"
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: bool, // Whether resident key is required
    #[serde(rename = "userVerification")]
    pub user_verification: String, // "required", "preferred", "discouraged"
}

/// Public key credential descriptor
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub r#type: String, // Always "public-key"
    pub id: String, // Base64URL-encoded credential ID
}

/// Registration response from client
#[derive(Serialize, Deserialize, Debug)]
pub struct RegistrationResponse {
    pub id: String,     // Base64URL-encoded credential ID
    pub raw_id: String, // Base64URL-encoded raw credential ID
    pub response: AuthenticatorAttestationResponse,
    pub client_extension_results: Option<serde_json::Value>,
    pub r#type: String, // Always "public-key"
}

/// Authentication response from client
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticationResponse {
    pub id: String,     // Base64URL-encoded credential ID
    pub raw_id: String, // Base64URL-encoded raw credential ID
    pub response: AuthenticatorAssertionResponse,
    pub client_extension_results: Option<serde_json::Value>,
    pub r#type: String, // Always "public-key"
}

/// Authenticator attestation response during registration
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: String,   // Base64URL-encoded client data JSON
    pub attestation_object: String, // Base64URL-encoded attestation object
}

/// Authenticator assertion response during authentication
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: String,    // Base64URL-encoded client data JSON
    pub authenticator_data: String,  // Base64URL-encoded authenticator data
    pub signature: String,           // Base64URL-encoded signature
    pub user_handle: Option<String>, // Base64URL-encoded user handle
}

/// Registration state stored during registration process
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistrationState {
    pub user_handle: String,       // User handle (provider_id)
    pub user_name: String,         // User's name
    pub user_email: String,        // User's email
    pub challenge: String,         // Base64URL-encoded challenge
    pub created_at: DateTime<Utc>, // When registration started
}

/// Authentication state stored during authentication process
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthenticationState {
    pub challenge: String,         // Base64URL-encoded challenge
    pub created_at: DateTime<Utc>, // When authentication started
}

/// Credential data
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Credential {
    pub credential_id: String,            // Base64URL-encoded credential ID
    pub user_handle: String,              // User handle (provider_id)
    pub public_key: Vec<u8>,              // COSE-encoded public key
    pub counter: u32,                     // Signature counter
    pub created_at: DateTime<Utc>,        // When credential was created
    pub last_used: Option<DateTime<Utc>>, // When credential was last used
    pub name: Option<String>,             // User-friendly credential name
}

/// Authentication result
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthenticationResult {
    pub credential_id: String,           // Base64URL-encoded credential ID
    pub user_handle: String,             // User handle (provider_id)
    pub counter: u32,                    // Updated signature counter
    pub authenticated_at: DateTime<Utc>, // When authentication completed
}
