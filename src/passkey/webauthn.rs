//! Custom `WebAuthn` implementation for `VouchRS`
//!
//! This module provides `WebAuthn` functionality using standard cryptography
//! libraries and following the W3C `WebAuthn` specification directly.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest;
use ring::signature;

use crate::passkey::cbor;
use crate::passkey::errors::WebAuthnError;
use crate::passkey::settings::PasskeySettings;
use crate::passkey::types::{
    AuthenticationOptions, AuthenticationResponse, AuthenticationResult, AuthenticationState,
    AuthenticatorSelectionCriteria, PasskeyCredential, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, RegistrationOptions, RegistrationResponse, RegistrationState,
    RelyingParty, UserEntity,
};
use crate::utils::crypto;

/// Generate a secure random challenge
fn generate_challenge() -> String {
    // Generate 32 bytes of random data (256 bits) using nonce generator
    crypto::generate_nonce(32)
}

/// Generate a user handle using existing utility
///
/// # Returns
/// A unique user handle string that can be used for `WebAuthn` operations
#[must_use]
pub fn generate_user_handle() -> String {
    crypto::generate_csrf_token() // Already used in VouchRS
}

/// Core `WebAuthn` service
pub struct WebAuthnService {
    settings: PasskeySettings,
}

impl WebAuthnService {
    /// Create a new `WebAuthn` service from settings
    ///
    /// # Errors
    /// Returns an error if the settings are invalid:
    /// - If relying party ID is empty
    /// - If origin doesn't use HTTPS (except for localhost)
    pub fn new(settings: PasskeySettings) -> Result<Self, WebAuthnError> {
        if settings.enabled {
            // Validate settings
            if settings.rp_id.is_empty() {
                return Err(WebAuthnError::ConfigurationError(
                    "Relying party ID cannot be empty".into(),
                ));
            }

            if !settings.rp_origin.starts_with("https://")
                && !settings.rp_origin.starts_with("http://localhost")
            {
                return Err(WebAuthnError::ConfigurationError(
                    "Origin must be https:// except for localhost".into(),
                ));
            }
        }

        Ok(Self { settings })
    }

    /// Start registration process
    ///
    /// # Errors
    /// This function doesn't generate errors but returns a `Result` for API consistency
    pub fn start_registration(
        &self,
        user_name: &str,
        user_email: &str,
        user_handle: &str,
    ) -> Result<(RegistrationOptions, RegistrationState), WebAuthnError> {
        // Generate challenge
        let challenge = generate_challenge();

        // Create registration options
        let options = RegistrationOptions {
            challenge: challenge.clone(),
            rp: RelyingParty {
                id: self.settings.rp_id.clone(),
                name: self.settings.rp_name.clone(),
            },
            user: UserEntity {
                id: user_handle.to_string(),
                name: user_email.to_string(),
                display_name: user_name.to_string(),
            },
            public_key_params: vec![
                // ES256 (ECDSA P-256 with SHA-256)
                PublicKeyCredentialParameters {
                    r#type: "public-key".to_string(),
                    alg: -7,
                },
                // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
                PublicKeyCredentialParameters {
                    r#type: "public-key".to_string(),
                    alg: -257,
                },
            ],
            timeout: u32::try_from(self.settings.timeout_seconds * 1000).unwrap_or(u32::MAX),
            attestation: "none".to_string(),
            authenticator_selection: AuthenticatorSelectionCriteria {
                authenticator_attachment: self.settings.authenticator_attachment.clone(),
                require_resident_key: true, // Required for passkeys
                user_verification: self.settings.user_verification.clone(),
            },
        };

        // Create registration state
        let state = RegistrationState {
            user_handle: user_handle.to_string(),
            user_name: user_name.to_string(),
            user_email: user_email.to_string(),
            challenge: challenge.clone(),
            created_at: chrono::Utc::now(),
        };

        Ok((options, state))
    }

    /// Complete registration process
    ///
    /// # Errors
    /// Returns an error if:
    /// - The challenge verification fails
    /// - The client data format is invalid
    /// - The attestation object cannot be parsed
    /// - The public key extraction fails
    pub fn complete_registration(
        &self,
        response: &RegistrationResponse,
        state: &RegistrationState,
    ) -> Result<PasskeyCredential, WebAuthnError> {
        // 1. Verify challenge
        self.verify_challenge_registration(response, &state.challenge)?;

        // 2. Extract public key from attestation
        let public_key = Self::extract_public_key(response)?;

        // 3. Create credential data
        let credential = PasskeyCredential {
            credential_id: response.id.clone(),
            user_handle: state.user_handle.clone(),
            public_key,
            counter: 0, // Initial counter value
            created_at: chrono::Utc::now(),
            last_used: None,
            name: None,
        };

        Ok(credential)
    }

    /// Start authentication process
    /// Start a `WebAuthn` authentication process
    ///
    /// # Errors
    /// Returns a `WebAuthnError` if:
    /// - Failed to generate random challenge
    /// - Failed to serialize authentication options
    pub fn start_authentication(
        &self,
        _user_handle: Option<&str>,
        allowed_credentials: Option<Vec<String>>,
    ) -> Result<(AuthenticationOptions, AuthenticationState), WebAuthnError> {
        // Generate challenge
        let challenge = generate_challenge();

        // Create credential descriptors if we have allowed credentials
        let allow_credentials = if let Some(credentials) = allowed_credentials {
            credentials
                .into_iter()
                .map(|id| PublicKeyCredentialDescriptor {
                    r#type: "public-key".to_string(),
                    id,
                })
                .collect()
        } else {
            Vec::new()
        };

        // Create authentication options
        let options = AuthenticationOptions {
            challenge: challenge.clone(),
            timeout: u32::try_from(self.settings.timeout_seconds * 1000).unwrap_or(u32::MAX),
            rp_id: self.settings.rp_id.clone(),
            allow_credentials,
            user_verification: self.settings.user_verification.clone(),
        };

        // Create authentication state
        let state = AuthenticationState {
            challenge: challenge.clone(),
            created_at: chrono::Utc::now(),
        };

        Ok((options, state))
    }

    /// Complete authentication process
    /// Complete a `WebAuthn` authentication process
    ///
    /// # Errors
    /// Returns a `WebAuthnError` if:
    /// - The challenge does not match
    /// - The origin is invalid
    /// - The authentication signature verification fails
    /// - The credential data is malformed
    pub fn complete_authentication(
        &self,
        response: &AuthenticationResponse,
        state: &AuthenticationState,
        stored_credential: &PasskeyCredential,
    ) -> Result<AuthenticationResult, WebAuthnError> {
        // 1. Verify challenge
        self.verify_challenge_authentication(response, &state.challenge)?;

        // 2. Verify signature
        Self::verify_assertion_signature(response, stored_credential)?;

        // 3. Extract counter from authenticator data
        let counter = Self::extract_counter(response)?;

        // 4. Verify counter (prevent replay attacks)
        if counter <= stored_credential.counter {
            return Err(WebAuthnError::VerificationFailed(
                "Signature counter verification failed".to_string(),
            ));
        }

        // 5. Create authentication result
        let result = AuthenticationResult {
            credential_id: response.id.clone(),
            user_handle: stored_credential.user_handle.clone(),
            counter,
            authenticated_at: chrono::Utc::now(),
        };

        Ok(result)
    }

    /// Verify challenge in registration response
    fn verify_challenge_registration(
        &self,
        response: &RegistrationResponse,
        expected_challenge: &str,
    ) -> Result<(), WebAuthnError> {
        // Decode and parse client data JSON
        let client_data_bytes = URL_SAFE_NO_PAD
            .decode(&response.response.client_data_json)
            .map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid client data encoding".to_string())
            })?;

        let client_data: serde_json::Value =
            serde_json::from_slice(&client_data_bytes).map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid client data format".to_string())
            })?;

        // Verify type
        if client_data["type"] != "webauthn.create" {
            return Err(WebAuthnError::VerificationFailed(
                "Invalid client data type".to_string(),
            ));
        }

        // Verify challenge
        if client_data["challenge"] != expected_challenge {
            return Err(WebAuthnError::VerificationFailed(
                "Challenge verification failed".to_string(),
            ));
        }

        // Verify origin
        let expected_origin = self.settings.rp_origin.clone();
        if client_data["origin"] != expected_origin {
            return Err(WebAuthnError::VerificationFailed(
                "Origin verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify challenge in authentication response
    fn verify_challenge_authentication(
        &self,
        response: &AuthenticationResponse,
        expected_challenge: &str,
    ) -> Result<(), WebAuthnError> {
        // Decode and parse client data JSON
        let client_data_bytes = URL_SAFE_NO_PAD
            .decode(&response.response.client_data_json)
            .map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid client data encoding".to_string())
            })?;

        let client_data: serde_json::Value =
            serde_json::from_slice(&client_data_bytes).map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid client data format".to_string())
            })?;

        // Verify type
        if client_data["type"] != "webauthn.get" {
            return Err(WebAuthnError::VerificationFailed(
                "Invalid client data type".to_string(),
            ));
        }

        // Verify challenge
        if client_data["challenge"] != expected_challenge {
            return Err(WebAuthnError::VerificationFailed(
                "Challenge verification failed".to_string(),
            ));
        }

        // Verify origin
        let expected_origin = self.settings.rp_origin.clone();
        if client_data["origin"] != expected_origin {
            return Err(WebAuthnError::VerificationFailed(
                "Origin verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Extract public key from attestation object
    fn extract_public_key(response: &RegistrationResponse) -> Result<Vec<u8>, WebAuthnError> {
        // Use our CBOR processing module to extract the public key
        cbor::extract_public_key_from_attestation(&response.response.attestation_object)
    }

    /// Verify assertion signature
    /// Prepare the data needed for signature verification
    fn prepare_verification_data(
        response: &AuthenticationResponse,
    ) -> Result<(Vec<u8>, Vec<u8>), WebAuthnError> {
        // 1. Get client data hash
        let client_data_bytes = URL_SAFE_NO_PAD
            .decode(&response.response.client_data_json)
            .map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid client data encoding".to_string())
            })?;

        let client_data_hash = digest::digest(&digest::SHA256, &client_data_bytes);

        // 2. Get authenticator data
        let auth_data_bytes = URL_SAFE_NO_PAD
            .decode(&response.response.authenticator_data)
            .map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid authenticator data encoding".to_string())
            })?;

        // 3. Concatenate authenticator data and client data hash to create message
        let mut verify_data =
            Vec::with_capacity(auth_data_bytes.len() + client_data_hash.as_ref().len());
        verify_data.extend_from_slice(&auth_data_bytes);
        verify_data.extend_from_slice(client_data_hash.as_ref());

        // 4. Decode signature
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&response.response.signature)
            .map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid signature encoding".to_string())
            })?;

        Ok((verify_data, signature_bytes))
    }

    /// Verify a `WebAuthn` assertion signature
    fn verify_assertion_signature(
        response: &AuthenticationResponse,
        credential: &PasskeyCredential,
    ) -> Result<(), WebAuthnError> {
        // Prepare the verification data
        let (verify_data, signature_bytes) = Self::prepare_verification_data(response)?;

        // Extract COSE key details
        let (kty_value, alg_value, cose_map) =
            Self::extract_cose_key_details(&credential.public_key)?;

        match (kty_value, alg_value) {
            // EC2 key with ES256 algorithm
            (1, -7) => {
                // Extract x and y coordinates
                let x_key = ciborium::value::Value::Integer((-2).into());
                let x_coord = cose_map
                    .iter()
                    .find(|(k, _)| k == &x_key)
                    .and_then(|(_, v)| match v {
                        ciborium::value::Value::Bytes(bytes) => Some(bytes.as_slice()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        WebAuthnError::VerificationFailed(
                            "Missing or invalid x coordinate".to_string(),
                        )
                    })?;

                let y_key = ciborium::value::Value::Integer((-3).into());
                let y_coord = cose_map
                    .iter()
                    .find(|(k, _)| k == &y_key)
                    .and_then(|(_, v)| match v {
                        ciborium::value::Value::Bytes(bytes) => Some(bytes.as_slice()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        WebAuthnError::VerificationFailed(
                            "Missing or invalid y coordinate".to_string(),
                        )
                    })?;

                // Create uncompressed SEC1 encoded public key: 0x04 || x || y
                let mut public_key_bytes = Vec::with_capacity(1 + x_coord.len() + y_coord.len());
                public_key_bytes.push(0x04); // Uncompressed point format
                public_key_bytes.extend_from_slice(x_coord);
                public_key_bytes.extend_from_slice(y_coord);

                // Create verification key
                let verification_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_ASN1,
                    &public_key_bytes,
                );

                // Verify signature
                verification_key
                    .verify(&verify_data, &signature_bytes)
                    .map_err(|_| {
                        WebAuthnError::VerificationFailed(
                            "EC256 signature verification failed".to_string(),
                        )
                    })?;

                Ok(())
            }
            // RSA key with RS256 algorithm
            (3, -257) => {
                // Check if modulus and exponent exist - we don't actually use them directly
                // but they're required for the key to be valid
                let n_key = ciborium::value::Value::Integer((-1).into());
                cose_map
                    .iter()
                    .find(|(k, _)| k == &n_key)
                    .and_then(|(_, v)| match v {
                        ciborium::value::Value::Bytes(_) => Some(()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        WebAuthnError::VerificationFailed(
                            "Missing or invalid RSA modulus".to_string(),
                        )
                    })?;

                let e_key = ciborium::value::Value::Integer((-2).into());
                cose_map
                    .iter()
                    .find(|(k, _)| k == &e_key)
                    .and_then(|(_, v)| match v {
                        ciborium::value::Value::Bytes(_) => Some(()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        WebAuthnError::VerificationFailed(
                            "Missing or invalid RSA exponent".to_string(),
                        )
                    })?;

                // Format the key components as DER
                // This is a simplified approach - in a production environment,
                // you might want to use a library like Der, rsa, or openssl to properly encode the key
                let verification_key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    &credential.public_key, // Use the entire key as is for now
                );

                // Verify signature
                verification_key
                    .verify(&verify_data, &signature_bytes)
                    .map_err(|_| {
                        WebAuthnError::VerificationFailed(
                            "RSA signature verification failed".to_string(),
                        )
                    })?;

                Ok(())
            }
            _ => Err(WebAuthnError::NotSupported(
                "Unsupported key type or algorithm".to_string(),
            )),
        }
    }

    /// Extract counter from authenticator data
    fn extract_counter(response: &AuthenticationResponse) -> Result<u32, WebAuthnError> {
        // Decode authenticator data
        let auth_data = URL_SAFE_NO_PAD
            .decode(&response.response.authenticator_data)
            .map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid authenticator data".to_string())
            })?;

        // Counter is at bytes 33-36 in authenticator data
        if auth_data.len() < 37 {
            return Err(WebAuthnError::VerificationFailed(
                "Authenticator data too short".to_string(),
            ));
        }

        let counter_bytes = [auth_data[33], auth_data[34], auth_data[35], auth_data[36]];
        let counter = u32::from_be_bytes(counter_bytes);

        Ok(counter)
    }

    /// Extract COSE key details from the credential public key
    fn extract_cose_key_details(public_key: &[u8]) -> Result<CoseKeyDetails, WebAuthnError> {
        // Parse the COSE key to determine algorithm and get verification key
        let cose_key =
            ciborium::de::from_reader::<ciborium::value::Value, _>(public_key).map_err(|_| {
                WebAuthnError::VerificationFailed("Invalid COSE key format".to_string())
            })?;

        // Extract key type (kty) and algorithm (alg)
        let ciborium::value::Value::Map(cose_map) = cose_key else {
            return Err(WebAuthnError::VerificationFailed(
                "COSE key is not a map".to_string(),
            ));
        }; // Get key type (1 = EC2, 3 = RSA)
        let kty_key = ciborium::value::Value::Integer(1.into());
        let kty_value = cose_map.iter()
            .find(|(k, _)| k == &kty_key)
            .and_then(|(_, v)| match v {
                ciborium::value::Value::Integer(_) => {
                    // For now just check if it's EC2 or RSA by matching the COSE map structure
                    // rather than extracting the exact integer value
                    let is_ec2 = cose_map.iter().any(|(k, _)| matches!(k, ciborium::value::Value::Integer(i) if i == &(-2).into()));
                    let is_rsa = cose_map.iter().any(|(k, _)| matches!(k, ciborium::value::Value::Integer(i) if i == &(-1).into()));

                    if is_ec2 {
                        Some(1)
                    } else if is_rsa {
                        Some(3)
                    } else {
                        None
                    }
                },
                _ => None,
            })
            .ok_or_else(|| WebAuthnError::VerificationFailed("Missing or invalid key type".to_string()))?;

        // Get algorithm (-7 = ES256, -257 = RS256)
        let alg_value = match kty_value {
            // If key type is EC2, assume it's ES256 (-7)
            1 => -7,
            // If key type is RSA, assume it's RS256 (-257)
            3 => -257,
            // Otherwise, unknown algorithm
            _ => return Err(WebAuthnError::NotSupported("Unknown key type".to_string())),
        };

        Ok((kty_value, alg_value, cose_map))
    }
}

/// COSE key details type (key type, algorithm, and key map)
type CoseKeyDetails = (
    i64,
    i64,
    Vec<(ciborium::value::Value, ciborium::value::Value)>,
);
