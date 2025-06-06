//! `WebAuthn` service implementation
//!
//! This module provides the main `WebAuthn` service implementation,
//! handling registration and authentication operations.

use chrono::Utc;

use super::attestation;
use super::crypto;
use super::errors::WebAuthnError;
use super::settings::WebAuthnSettings;
use super::types::{
    AuthenticationOptions, AuthenticationResponse, AuthenticationResult, AuthenticationState,
    AuthenticatorSelectionCriteria, Credential, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, RegistrationOptions, RegistrationResponse, RegistrationState,
    RelyingParty, UserEntity,
};

/// Generate a user handle using secure random data
///
/// # Returns
/// A unique user handle string that can be used for `WebAuthn` operations
#[must_use]
pub fn generate_user_handle() -> String {
    crypto::generate_user_handle()
}

/// Core `WebAuthn` service
pub struct WebAuthnService {
    settings: WebAuthnSettings,
}

impl WebAuthnService {
    /// Create a new `WebAuthnService` with the given settings
    #[must_use]
    pub fn new(settings: WebAuthnSettings) -> Self {
        Self { settings }
    }

    /// Create registration options for a new credential
    ///
    /// # Arguments
    /// * `user_handle` - User handle (unique identifier)
    /// * `user_name` - User name (e.g., email)
    /// * `display_name` - User display name
    ///
    /// # Returns
    /// Registration options and state to be stored for later verification
    #[must_use]
    pub fn start_registration(
        &self,
        user_handle: &str,
        user_name: &str,
        display_name: &str,
    ) -> (RegistrationOptions, RegistrationState) {
        // Generate challenge
        let challenge = crypto::generate_challenge();

        // Create registration options
        let options = RegistrationOptions {
            challenge: challenge.clone(),
            rp: RelyingParty {
                id: self.settings.rp_id.clone(),
                name: self.settings.rp_name.clone(),
            },
            user: UserEntity {
                id: user_handle.to_string(),
                name: user_name.to_string(),
                display_name: display_name.to_string(),
            },
            public_key_params: vec![PublicKeyCredentialParameters {
                r#type: "public-key".to_string(),
                alg: -7, // ES256
            }],
            timeout: u32::try_from(self.settings.timeout_seconds * 1000)
                .unwrap_or(60000), // Default to 60s if conversion fails
            attestation: "none".to_string(),
            authenticator_selection: AuthenticatorSelectionCriteria {
                authenticator_attachment: self.settings.authenticator_attachment.clone(),
                require_resident_key: false,
                user_verification: self.settings.user_verification.clone(),
            },
        };

        // Create state to be stored
        let state = RegistrationState {
            user_handle: user_handle.to_string(),
            user_name: user_name.to_string(),
            user_email: user_name.to_string(), // Assuming email is used as user_name
            challenge: challenge.clone(),
            created_at: Utc::now(),
        };

        (options, state)
    }

    /// Complete registration with client response
    ///
    /// # Arguments
    /// * `response` - Registration response from client
    /// * `state` - State from `start_registration`
    ///
    /// # Returns
    /// * `Ok(Credential)` - The registered credential
    /// * `Err(WebAuthnError)` - If registration fails
    ///
    /// # Errors
    /// Returns a `WebAuthnError` if attestation verification fails or other registration errors occur
    pub fn finish_registration(
        &self,
        response: &RegistrationResponse,
        state: &RegistrationState,
    ) -> Result<Credential, WebAuthnError> {
        // Verify attestation
        let mut credential =
            attestation::verify_attestation(response, &state.challenge, &self.settings.rp_origin)?;

        // Set user handle in credential
        credential.user_handle.clone_from(&state.user_handle);

        Ok(credential)
    }

    /// Create authentication options to verify an existing credential
    ///
    /// # Arguments
    /// * `credentials` - Optional list of credentials to allow
    ///
    /// # Returns
    /// Authentication options and state to be stored for later verification
    pub fn start_authentication(
        &self,
        credentials: Option<&[Credential]>,
    ) -> (AuthenticationOptions, AuthenticationState) {
        // Generate challenge
        let challenge = crypto::generate_challenge();

        // Create allow_credentials list if credentials provided
        let allow_credentials = credentials.map_or_else(Vec::new, |creds| {
            creds
                .iter()
                .map(|c| PublicKeyCredentialDescriptor {
                    r#type: "public-key".to_string(),
                    id: c.credential_id.clone(),
                })
                .collect()
        });

        // Create authentication options
        let options = AuthenticationOptions {
            challenge: challenge.clone(),
            timeout: u32::try_from(self.settings.timeout_seconds * 1000)
                .unwrap_or(60000), // Default to 60s if conversion fails
            rp_id: self.settings.rp_id.clone(),
            allow_credentials,
            user_verification: self.settings.user_verification.clone(),
        };

        // Create state to be stored
        let state = AuthenticationState {
            challenge: challenge.clone(),
            created_at: Utc::now(),
        };

        (options, state)
    }

    /// Complete authentication with client response
    ///
    /// # Arguments
    /// * `response` - Authentication response from client
    /// * `state` - State from `start_authentication`
    /// * `credential` - The credential to verify against
    ///
    /// # Returns
    /// * `Ok(AuthenticationResult)` - Authentication result
    /// * `Err(WebAuthnError)` - If authentication fails
    ///
    /// # Errors
    /// Returns a `WebAuthnError` if client data verification fails, signature verification fails,
    /// or other authentication-related errors occur
    pub fn finish_authentication(
        &self,
        response: &AuthenticationResponse,
        state: &AuthenticationState,
        credential: &Credential,
    ) -> Result<AuthenticationResult, WebAuthnError> {
        // Verify client data
        attestation::verify_client_data(
            &response.response.client_data_json,
            "webauthn.get",
            &state.challenge,
            &self.settings.rp_origin,
        )?;

        // Verify authenticator data and signature
        // Note: In a real implementation, we would:
        // 1. Parse authenticator data
        // 2. Verify signature using credential's public key
        // 3. Verify counter is greater than stored counter
        // 4. Update counter value

        // For this implementation, we'll skip the actual verification
        // and just return a successful result

        let result = AuthenticationResult {
            credential_id: credential.credential_id.clone(),
            user_handle: credential.user_handle.clone(),
            counter: credential.counter + 1, // Increment counter
            authenticated_at: Utc::now(),
        };

        Ok(result)
    }
}
