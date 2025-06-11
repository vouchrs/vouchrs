// JWT validation module with JWKS discovery and caching
// Supports cryptographic signature verification and claims validation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// Cryptographic imports
use p256::{
    ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey},
    EncodedPoint,
};
use rsa::{pkcs1v15::VerifyingKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::settings::{JwtValidationConfig, ProviderSettings};

// Import HTTP functions from oauth module
use crate::oauth::{fetch_discovery_document, fetch_jwks};

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum JwtValidationError {
    KeyNotFound(String),
    SignatureInvalid,
    ClaimValidationFailed {
        claim: String,
        expected: String,
        actual: String,
    },
    JwksFetchFailed(String),
    UnsupportedAlgorithm(String),
    TokenExpired,
    TokenNotYetValid,
    InvalidToken(String),
    KeyDecodingFailed(String),
    CryptographicError(String),
}

impl std::fmt::Display for JwtValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotFound(kid) => write!(f, "Key not found: {kid}"),
            Self::SignatureInvalid => write!(f, "JWT signature verification failed"),
            Self::ClaimValidationFailed {
                claim,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Claim '{claim}' validation failed: expected '{expected}', got '{actual}'"
                )
            }
            Self::JwksFetchFailed(msg) => write!(f, "Failed to fetch JWKS: {msg}"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "Unsupported algorithm: {alg}"),
            Self::TokenExpired => write!(f, "Token has expired"),
            Self::TokenNotYetValid => write!(f, "Token is not yet valid"),
            Self::InvalidToken(msg) => write!(f, "Invalid token: {msg}"),
            Self::KeyDecodingFailed(msg) => write!(f, "Failed to decode key: {msg}"),
            Self::CryptographicError(msg) => write!(f, "Cryptographic error: {msg}"),
        }
    }
}

impl std::error::Error for JwtValidationError {}

// ============================================================================
// JWT Structures
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct JwtClaims {
    pub iss: Option<String>,            // Issuer
    pub aud: Option<serde_json::Value>, // Audience (can be string or array)
    pub exp: Option<i64>,               // Expiration time
    pub nbf: Option<i64>,               // Not before
    pub iat: Option<i64>,               // Issued at
    pub sub: Option<String>,            // Subject
}

// ============================================================================
// OIDC Discovery Document
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

// ============================================================================
// JWKS Structures
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonWebKey {
    pub kty: String,         // Key type (RSA, EC, etc.)
    pub kid: Option<String>, // Key ID
    pub alg: Option<String>, // Algorithm (RS256, ES256, etc.)
    #[serde(rename = "use")]
    pub key_use: Option<String>, // "sig" for signing

    // RSA keys
    pub n: Option<String>, // Modulus
    pub e: Option<String>, // Exponent

    // EC keys
    pub crv: Option<String>, // Curve
    pub x: Option<String>,   // X coordinate
    pub y: Option<String>,   // Y coordinate
}

// ============================================================================
// JWKS Cache
// ============================================================================

pub struct JwksCache {
    // Provider name -> Key ID -> JsonWebKey
    keys: HashMap<String, HashMap<String, JsonWebKey>>,

    // When each provider's keys were last fetched
    last_updated: HashMap<String, DateTime<Utc>>,

    // Failed fetch tracking for backoff
    failed_fetches: HashMap<String, DateTime<Utc>>,

    // Configuration
    cache_duration: Duration,
    retry_backoff: Duration,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksCache {
    /// Create a new JWKS cache with default settings
    ///
    /// # Panics
    /// Never panics as it only creates data structures
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            last_updated: HashMap::new(),
            failed_fetches: HashMap::new(),
            cache_duration: Duration::from_secs(3600), // 1 hour default
            retry_backoff: Duration::from_secs(300),   // 5 minutes default
        }
    }

    #[must_use]
    pub fn with_cache_duration(mut self, duration: Duration) -> Self {
        self.cache_duration = duration;
        self
    }

    /// Check if cached keys are still valid for a provider
    #[must_use]
    pub fn is_cache_valid(&self, provider: &str) -> bool {
        if let Some(last_updated) = self.last_updated.get(provider) {
            let elapsed = Utc::now().signed_duration_since(*last_updated);
            elapsed.to_std().unwrap_or(Duration::MAX) < self.cache_duration
        } else {
            false
        }
    }

    /// Check if we should retry a failed fetch
    #[must_use]
    pub fn should_retry_fetch(&self, provider: &str) -> bool {
        if let Some(last_failed) = self.failed_fetches.get(provider) {
            let elapsed = Utc::now().signed_duration_since(*last_failed);
            elapsed.to_std().unwrap_or(Duration::MAX) >= self.retry_backoff
        } else {
            true
        }
    }

    /// Get a key by provider and key ID
    #[must_use]
    pub fn get_key(&self, provider: &str, kid: &str) -> Option<&JsonWebKey> {
        self.keys.get(provider)?.get(kid)
    }

    /// Store keys for a provider
    pub fn store_keys(&mut self, provider: &str, keys: Vec<JsonWebKey>) {
        let mut provider_keys = HashMap::new();

        for key in keys {
            if let Some(kid) = &key.kid {
                provider_keys.insert(kid.clone(), key);
            } else {
                // Generate a fallback key ID based on key properties
                let fallback_kid = format!(
                    "{}_{}",
                    key.kty,
                    key.n
                        .as_deref()
                        .unwrap_or("unknown")
                        .chars()
                        .take(8)
                        .collect::<String>()
                );
                provider_keys.insert(fallback_kid, key);
            }
        }

        debug!(
            "💾 Cached {} keys for provider '{provider}'",
            provider_keys.len()
        );
        self.keys.insert(provider.to_string(), provider_keys);
        self.last_updated.insert(provider.to_string(), Utc::now());
        self.failed_fetches.remove(provider);
    }

    /// Record a failed fetch attempt
    pub fn record_fetch_failure(&mut self, provider: String) {
        self.failed_fetches.insert(provider, Utc::now());
    }
}

// ============================================================================
// JWT Validator
// ============================================================================

pub struct JwtValidator {
    cache: Arc<RwLock<JwksCache>>,
}

impl Clone for JwtValidator {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
        }
    }
}

impl JwtValidator {
    /// Create a new JWT validator with default settings
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(JwksCache::new())),
        }
    }

    /// Create a validator with custom cache settings
    #[must_use]
    pub fn with_cache_duration(cache_duration: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(
                JwksCache::new().with_cache_duration(cache_duration),
            )),
        }
    }

    /// Initialize from provider settings with discovery
    ///
    /// # Errors
    /// Returns error if discovery document cannot be fetched or JWKS cannot be cached
    pub async fn from_provider_settings(
        settings: &ProviderSettings,
        config: JwtValidationConfig,
    ) -> Result<Self, JwtValidationError> {
        let validator =
            Self::with_cache_duration(Duration::from_secs(config.cache_duration_seconds));

        // Pre-populate cache if discovery URL is available
        if let Some(discovery_url) = &settings.discovery_url {
            validator
                .discover_and_cache_keys(&settings.name, discovery_url)
                .await?;
        }

        Ok(validator)
    }

    /// Discover JWKS URI from OIDC discovery document and cache keys
    ///
    /// # Errors
    /// Returns error if discovery document or JWKS cannot be fetched
    pub async fn discover_and_cache_keys(
        &self,
        provider: &str,
        discovery_url: &str,
    ) -> Result<(), JwtValidationError> {
        info!("🔍 Discovering JWKS URI for provider '{provider}' from {discovery_url}");

        // Fetch discovery document
        let discovery_doc = self.fetch_discovery_document(discovery_url).await?;

        // Fetch and cache JWKS
        self.fetch_and_cache_jwks(provider, &discovery_doc.jwks_uri)
            .await
    }

    /// Fetch OIDC discovery document
    ///
    /// # Errors
    /// Returns error if discovery document cannot be fetched or parsed
    pub async fn fetch_discovery_document(
        &self,
        discovery_url: &str,
    ) -> Result<OidcDiscoveryDocument, JwtValidationError> {
        debug!("📄 Fetching OIDC discovery document from {discovery_url}");

        let discovery_doc_value = fetch_discovery_document(discovery_url)
            .await
            .map_err(JwtValidationError::JwksFetchFailed)?;

        let discovery_doc: OidcDiscoveryDocument = serde_json::from_value(discovery_doc_value)
            .map_err(|e| {
                JwtValidationError::JwksFetchFailed(format!(
                    "Failed to parse discovery document: {e}"
                ))
            })?;

        debug!(
            "✅ Discovery document fetched, JWKS URI: {}",
            discovery_doc.jwks_uri
        );
        Ok(discovery_doc)
    }

    /// Fetch JWKS from URI and cache the keys
    ///
    /// # Errors
    /// Returns error if JWKS cannot be fetched or parsed
    pub async fn fetch_and_cache_jwks(
        &self,
        provider: &str,
        jwks_uri: &str,
    ) -> Result<(), JwtValidationError> {
        let cache = self.cache.write().await;

        // Check if we should skip due to recent failure
        if !cache.should_retry_fetch(provider) {
            return Err(JwtValidationError::JwksFetchFailed(
                "Skipping fetch due to recent failure and backoff".to_string(),
            ));
        }

        debug!("🔑 Fetching JWKS for provider '{provider}' from {jwks_uri}");

        // Drop the write lock before making HTTP request
        drop(cache);

        let jwks_value = fetch_jwks(jwks_uri).await.map_err(|e| {
            // Record failure in cache
            tokio::spawn({
                let cache = Arc::clone(&self.cache);
                let provider = provider.to_string();
                async move {
                    let mut cache = cache.write().await;
                    cache.record_fetch_failure(provider);
                }
            });

            JwtValidationError::JwksFetchFailed(e)
        })?;

        let jwks: JsonWebKeySet = serde_json::from_value(jwks_value).map_err(|e| {
            JwtValidationError::JwksFetchFailed(format!("Failed to parse JWKS: {e}"))
        })?;
        // Re-acquire write lock to store keys
        let mut cache = self.cache.write().await;
        cache.store_keys(provider, jwks.keys);

        Ok(())
    }

    /// Get a public key for token verification
    ///
    /// # Errors
    /// Returns error if key cannot be found or JWKS cannot be fetched
    pub async fn get_public_key(
        &self,
        provider: &str,
        kid: &str,
        jwks_uri: Option<&str>,
    ) -> Result<JsonWebKey, JwtValidationError> {
        let cache = self.cache.read().await;

        // Check cache first
        if cache.is_cache_valid(provider) {
            if let Some(key) = cache.get_key(provider, kid) {
                debug!("🎯 Found cached key '{kid}' for provider '{provider}'");
                return Ok(key.clone());
            }
        }

        // Cache miss or expired - need to refresh
        drop(cache);

        if let Some(jwks_uri) = jwks_uri {
            // Fetch fresh keys
            self.fetch_and_cache_jwks(provider, jwks_uri).await?;

            // Try cache again
            let cache = self.cache.read().await;
            if let Some(key) = cache.get_key(provider, kid) {
                return Ok(key.clone());
            }
        }

        Err(JwtValidationError::KeyNotFound(kid.to_string()))
    }

    /// Validate an ID token with cryptographic signature verification
    ///
    /// # Errors
    /// Returns error if token is invalid, signature verification fails, or claims validation fails
    pub async fn validate_id_token(
        &self,
        token: &str,
        provider: &str,
        config: &JwtValidationConfig,
        discovery_doc: Option<&OidcDiscoveryDocument>,
    ) -> Result<(), JwtValidationError> {
        debug!("🔒 Starting JWT validation for provider '{provider}'");

        // Parse JWT structure
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtValidationError::InvalidToken(
                "Invalid JWT format".to_string(),
            ));
        }

        // Decode header
        let header = Self::decode_jwt_header(parts[0])?;
        debug!("📋 JWT header: alg={}, kid={:?}", header.alg, header.kid);

        // Verify algorithm is supported
        match header.alg.as_str() {
            "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" => {}
            alg => return Err(JwtValidationError::UnsupportedAlgorithm(alg.to_string())),
        }

        // Extract key ID
        let kid = header.kid.as_deref().unwrap_or("default");

        // Get public key for verification
        let jwks_uri = discovery_doc.map(|doc| doc.jwks_uri.as_str());
        let public_key = self.get_public_key(provider, kid, jwks_uri).await?;

        // Verify signature
        self.verify_signature(token, &header.alg, &public_key)?;
        debug!("✅ JWT signature verified successfully");

        // Validate claims if any validation is enabled
        if config.validate_audience || config.validate_issuer || config.validate_expiration {
            let claims = Self::decode_jwt_claims(parts[1])?;
            Self::validate_claims(self, &claims, config, discovery_doc)?;
            debug!("✅ JWT claims validated successfully");
        }

        info!("🎉 JWT validation completed successfully for provider '{provider}'");
        Ok(())
    }

    /// Decode JWT header from base64
    fn decode_jwt_header(header_b64: &str) -> Result<JwtHeader, JwtValidationError> {
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| {
                JwtValidationError::InvalidToken(format!("Invalid header encoding: {e}"))
            })?;

        serde_json::from_slice(&header_bytes)
            .map_err(|e| JwtValidationError::InvalidToken(format!("Invalid header JSON: {e}")))
    }

    /// Decode JWT claims from base64
    fn decode_jwt_claims(claims_b64: &str) -> Result<JwtClaims, JwtValidationError> {
        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|e| {
                JwtValidationError::InvalidToken(format!("Invalid claims encoding: {e}"))
            })?;

        serde_json::from_slice(&claims_bytes)
            .map_err(|e| JwtValidationError::InvalidToken(format!("Invalid claims JSON: {e}")))
    }

    /// Verify JWT signature cryptographically
    fn verify_signature(
        &self,
        token: &str,
        algorithm: &str,
        public_key: &JsonWebKey,
    ) -> Result<(), JwtValidationError> {
        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| {
                JwtValidationError::InvalidToken(format!("Invalid signature encoding: {e}"))
            })?;

        match algorithm {
            "RS256" | "RS384" | "RS512" => {
                Self::verify_rsa_signature(&signing_input, &signature_bytes, algorithm, public_key)
            }
            "ES256" | "ES384" | "ES512" => Self::verify_ecdsa_signature(
                self,
                &signing_input,
                &signature_bytes,
                algorithm,
                public_key,
            ),
            alg => Err(JwtValidationError::UnsupportedAlgorithm(alg.to_string())),
        }
    }

    /// Verify RSA signature (RS256, RS384, RS512)
    fn verify_rsa_signature(
        signing_input: &str,
        signature: &[u8],
        algorithm: &str,
        public_key: &JsonWebKey,
    ) -> Result<(), JwtValidationError> {
        // Extract RSA components
        let n = public_key.n.as_ref().ok_or_else(|| {
            JwtValidationError::KeyDecodingFailed("Missing RSA modulus (n)".to_string())
        })?;
        let e = public_key.e.as_ref().ok_or_else(|| {
            JwtValidationError::KeyDecodingFailed("Missing RSA exponent (e)".to_string())
        })?;

        // Decode base64url components
        let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(n)
            .map_err(|e| {
                JwtValidationError::KeyDecodingFailed(format!("Invalid modulus encoding: {e}"))
            })?;
        let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(e)
            .map_err(|e| {
                JwtValidationError::KeyDecodingFailed(format!("Invalid exponent encoding: {e}"))
            })?;

        // Create RSA public key
        let rsa_key = RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&n_bytes),
            rsa::BigUint::from_bytes_be(&e_bytes),
        )
        .map_err(|e| JwtValidationError::KeyDecodingFailed(format!("Invalid RSA key: {e}")))?;

        // Create verifying key based on algorithm
        match algorithm {
            "RS256" => {
                use rsa::signature::Verifier;
                let verifying_key = VerifyingKey::<Sha256>::new(rsa_key);
                verifying_key
                    .verify(
                        signing_input.as_bytes(),
                        &rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| {
                            JwtValidationError::CryptographicError(format!(
                                "Invalid signature format: {e}"
                            ))
                        })?,
                    )
                    .map_err(|_| JwtValidationError::SignatureInvalid)?;
            }
            _ => {
                return Err(JwtValidationError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                ))
            }
        }

        Ok(())
    }

    /// Verify ECDSA signature (ES256, ES384, ES512)
    fn verify_ecdsa_signature(
        _self: &Self,
        signing_input: &str,
        signature: &[u8],
        algorithm: &str,
        public_key: &JsonWebKey,
    ) -> Result<(), JwtValidationError> {
        use p256::ecdsa::signature::Verifier;
        match algorithm {
            "ES256" => {
                // Extract ECDSA P-256 components
                let x = public_key.x.as_ref().ok_or_else(|| {
                    JwtValidationError::KeyDecodingFailed("Missing ECDSA x coordinate".to_string())
                })?;
                let y = public_key.y.as_ref().ok_or_else(|| {
                    JwtValidationError::KeyDecodingFailed("Missing ECDSA y coordinate".to_string())
                })?;

                // Decode coordinates
                let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| {
                        JwtValidationError::KeyDecodingFailed(format!("Invalid x coordinate: {e}"))
                    })?;
                let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(y)
                    .map_err(|e| {
                        JwtValidationError::KeyDecodingFailed(format!("Invalid y coordinate: {e}"))
                    })?;

                // Create encoded point (uncompressed format: 0x04 + x + y)
                let mut point_bytes = vec![0x04];
                point_bytes.extend_from_slice(&x_bytes);
                point_bytes.extend_from_slice(&y_bytes);

                let encoded_point = EncodedPoint::from_bytes(&point_bytes).map_err(|e| {
                    JwtValidationError::KeyDecodingFailed(format!("Invalid EC point: {e}"))
                })?;

                // Create verifying key
                let verifying_key =
                    EcdsaVerifyingKey::from_encoded_point(&encoded_point).map_err(|e| {
                        JwtValidationError::KeyDecodingFailed(format!("Invalid ECDSA key: {e}"))
                    })?;

                // Parse signature (DER format)
                let signature = EcdsaSignature::from_der(signature).map_err(|e| {
                    JwtValidationError::CryptographicError(format!("Invalid signature format: {e}"))
                })?;

                // Hash the signing input with SHA256
                let mut hasher = Sha256::new();
                hasher.update(signing_input.as_bytes());
                let hash = hasher.finalize();

                // Verify signature
                verifying_key
                    .verify(&hash, &signature)
                    .map_err(|_| JwtValidationError::SignatureInvalid)?;
            }
            _ => {
                return Err(JwtValidationError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                ))
            }
        }

        Ok(())
    }

    /// Validate JWT claims
    fn validate_claims(
        _: &Self,
        claims: &JwtClaims,
        config: &JwtValidationConfig,
        discovery_doc: Option<&OidcDiscoveryDocument>,
    ) -> Result<(), JwtValidationError> {
        let now = chrono::Utc::now().timestamp();
        let clock_skew = i64::try_from(config.clock_skew_seconds).unwrap_or(300);

        // Early return pattern - validate each claim type separately
        if config.validate_expiration {
            Self::validate_expiration_claims(claims, now, clock_skew)?;
        }

        if config.validate_issuer {
            Self::validate_issuer_claim(claims, config, discovery_doc)?;
        }

        if config.validate_audience {
            Self::validate_audience_claim(claims, config)?;
        }

        Ok(())
    }

    /// Validate expiration and not-before claims
    fn validate_expiration_claims(
        claims: &JwtClaims,
        now: i64,
        clock_skew: i64,
    ) -> Result<(), JwtValidationError> {
        // Validate expiration time
        if let Some(exp) = claims.exp {
            if now > exp + clock_skew {
                return Err(JwtValidationError::TokenExpired);
            }
        }

        // Validate not-before time
        if let Some(nbf) = claims.nbf {
            if now < nbf - clock_skew {
                return Err(JwtValidationError::TokenNotYetValid);
            }
        }

        Ok(())
    }

    /// Validate issuer claim
    fn validate_issuer_claim(
        claims: &JwtClaims,
        config: &JwtValidationConfig,
        discovery_doc: Option<&OidcDiscoveryDocument>,
    ) -> Result<(), JwtValidationError> {
        let Some(discovery_doc) = discovery_doc else {
            return Ok(()); // No discovery doc available for validation
        };

        let Some(token_issuer) = &claims.iss else {
            return Ok(()); // No issuer claim to validate
        };

        let expected_issuer = config
            .expected_issuer
            .as_ref()
            .unwrap_or(&discovery_doc.issuer);

        if token_issuer != expected_issuer {
            return Err(JwtValidationError::ClaimValidationFailed {
                claim: "iss".to_string(),
                expected: expected_issuer.clone(),
                actual: token_issuer.clone(),
            });
        }

        Ok(())
    }

    /// Validate audience claim
    fn validate_audience_claim(
        claims: &JwtClaims,
        config: &JwtValidationConfig,
    ) -> Result<(), JwtValidationError> {
        let Some(expected_audience) = &config.expected_audience else {
            return Ok(()); // No expected audience configured
        };

        let token_audiences = Self::extract_audiences_from_claims(claims);

        if !token_audiences.iter().any(|aud| aud == expected_audience) {
            return Err(JwtValidationError::ClaimValidationFailed {
                claim: "aud".to_string(),
                expected: expected_audience.clone(),
                actual: format!("{token_audiences:?}"),
            });
        }

        Ok(())
    }

    /// Extract audience values from JWT claims
    fn extract_audiences_from_claims(claims: &JwtClaims) -> Vec<String> {
        match &claims.aud {
            Some(aud_value) => crate::validation::extract_audiences_from_claim(aud_value),
            _ => vec![],
        }
    }
}

impl Default for JwtValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Extract key ID from JWT header without full parsing
///
/// # Errors
///
/// Returns error if:
/// - The token format is invalid (not three parts separated by dots)
/// - The header part cannot be decoded from base64url
/// - The header is not valid JSON
pub fn extract_key_id_from_jwt(token: &str) -> Result<Option<String>, JwtValidationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtValidationError::InvalidToken(
            "Invalid JWT format".to_string(),
        ));
    }

    // Decode header (first part)
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| JwtValidationError::InvalidToken(format!("Invalid header encoding: {e}")))?;

    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwtValidationError::InvalidToken(format!("Invalid header JSON: {e}")))?;

    Ok(header["kid"].as_str().map(ToString::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwks_cache_operations() {
        let mut cache = JwksCache::new();

        // Test empty cache
        assert!(!cache.is_cache_valid("test-provider"));
        assert!(cache.should_retry_fetch("test-provider"));

        // Store some test keys
        let test_keys = vec![JsonWebKey {
            kty: "RSA".to_string(),
            kid: Some("key1".to_string()),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            n: Some("test-modulus".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        }];

        cache.store_keys("test-provider", test_keys);

        // Test cache validity
        assert!(cache.is_cache_valid("test-provider"));
        assert!(cache.get_key("test-provider", "key1").is_some());
        assert!(cache.get_key("test-provider", "nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_jwt_validator_creation() {
        let validator = JwtValidator::new();

        // Test that validator is created successfully
        assert!(validator.cache.read().await.keys.is_empty());
    }

    #[test]
    fn test_extract_key_id_from_jwt() {
        // Test invalid JWT format
        assert!(extract_key_id_from_jwt("invalid").is_err());
        assert!(extract_key_id_from_jwt("only.two.parts").is_err());

        // Test with valid JWT structure but invalid base64 (would need real JWT for full test)
        let result = extract_key_id_from_jwt("invalid.base64.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_header_parsing() {
        let _validator = JwtValidator::new();

        // Test invalid base64
        let result = JwtValidator::decode_jwt_header("invalid-base64");
        assert!(result.is_err());

        // Test valid base64 but invalid JSON
        let invalid_json_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-json");
        let result = JwtValidator::decode_jwt_header(&invalid_json_b64);
        assert!(result.is_err());

        // Test valid JWT header
        let header = r#"{"alg":"RS256","typ":"JWT","kid":"test-key"}"#;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.as_bytes());
        let result = JwtValidator::decode_jwt_header(&header_b64);
        assert!(result.is_ok());
        let parsed_header = result.unwrap();
        assert_eq!(parsed_header.alg, "RS256");
        assert_eq!(parsed_header.kid, Some("test-key".to_string()));
    }

    #[test]
    fn test_jwt_claims_parsing() {
        let _validator = JwtValidator::new();

        // Test valid JWT claims
        let now = chrono::Utc::now().timestamp(); // Use chrono's timestamp which is already i64
        let claims = format!(
            r#"{{"iss":"https://example.com","aud":"test-client","exp":{},"iat":{},"sub":"test-user"}}"#,
            now + 3600,
            now
        );
        let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let result = JwtValidator::decode_jwt_claims(&claims_b64);
        assert!(result.is_ok());
        let parsed_claims = result.unwrap();
        assert_eq!(parsed_claims.iss, Some("https://example.com".to_string()));
        assert_eq!(parsed_claims.sub, Some("test-user".to_string()));
    }

    #[test]
    fn test_jwt_validation_config() {
        // Test default configuration
        let config = JwtValidationConfig {
            enabled: Some(true),
            validate_audience: true,
            validate_issuer: true,
            validate_expiration: true,
            expected_audience: Some("test-client".to_string()),
            expected_issuer: None,
            clock_skew_seconds: 300,
            cache_duration_seconds: 3600,
        };

        assert!(config.validate_audience);
        assert!(config.validate_issuer);
        assert!(config.validate_expiration);
        assert_eq!(config.clock_skew_seconds, 300);
    }

    #[test]
    fn test_claims_validation_logic() {
        let validator = JwtValidator::new();
        let now = chrono::Utc::now().timestamp();

        // Test expired token
        let expired_claims = JwtClaims {
            iss: Some("https://example.com".to_string()),
            aud: Some(serde_json::Value::String("test-client".to_string())),
            exp: Some(now - 1000), // Expired 1000 seconds ago
            nbf: None,
            iat: Some(now - 3600),
            sub: Some("test-user".to_string()),
        };

        let config = JwtValidationConfig {
            enabled: Some(true),
            validate_audience: false,
            validate_issuer: false,
            validate_expiration: true,
            expected_audience: None,
            expected_issuer: None,
            clock_skew_seconds: 300,
            cache_duration_seconds: 3600,
        };

        let result = JwtValidator::validate_claims(&validator, &expired_claims, &config, None);
        assert!(result.is_err());
        matches!(result.unwrap_err(), JwtValidationError::TokenExpired);

        // Test not yet valid token
        let future_claims = JwtClaims {
            iss: Some("https://example.com".to_string()),
            aud: Some(serde_json::Value::String("test-client".to_string())),
            exp: Some(now + 3600),
            nbf: Some(now + 1000), // Not valid for another 1000 seconds
            iat: Some(now),
            sub: Some("test-user".to_string()),
        };

        let result = JwtValidator::validate_claims(&validator, &future_claims, &config, None);
        assert!(result.is_err());
        matches!(result.unwrap_err(), JwtValidationError::TokenNotYetValid);

        // Test valid token
        let valid_claims = JwtClaims {
            iss: Some("https://example.com".to_string()),
            aud: Some(serde_json::Value::String("test-client".to_string())),
            exp: Some(now + 3600),
            nbf: Some(now - 100),
            iat: Some(now - 100),
            sub: Some("test-user".to_string()),
        };

        let result = JwtValidator::validate_claims(&validator, &valid_claims, &config, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audience_validation() {
        let validator = JwtValidator::new();

        let config = JwtValidationConfig {
            enabled: Some(true),
            validate_audience: true,
            validate_issuer: false,
            validate_expiration: false,
            expected_audience: Some("expected-client".to_string()),
            expected_issuer: None,
            clock_skew_seconds: 300,
            cache_duration_seconds: 3600,
        };

        // Test single audience match
        let claims_single = JwtClaims {
            iss: None,
            aud: Some(serde_json::Value::String("expected-client".to_string())),
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_claims(&validator, &claims_single, &config, None);
        assert!(result.is_ok());

        // Test multiple audiences with match
        let claims_multiple = JwtClaims {
            iss: None,
            aud: Some(serde_json::Value::Array(vec![
                serde_json::Value::String("other-client".to_string()),
                serde_json::Value::String("expected-client".to_string()),
            ])),
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_claims(&validator, &claims_multiple, &config, None);
        assert!(result.is_ok());

        // Test audience mismatch
        let claims_mismatch = JwtClaims {
            iss: None,
            aud: Some(serde_json::Value::String("wrong-client".to_string())),
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_claims(&validator, &claims_mismatch, &config, None);
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            JwtValidationError::ClaimValidationFailed { .. }
        );
    }

    #[test]
    fn test_unsupported_algorithms() {
        let validator = JwtValidator::new();
        let dummy_key = JsonWebKey {
            kty: "RSA".to_string(),
            kid: Some("test".to_string()),
            alg: Some("HS256".to_string()),
            key_use: Some("sig".to_string()),
            n: Some("test".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let result = validator.verify_signature("header.payload.signature", "HS256", &dummy_key);
        assert!(result.is_err());
        matches!(
            result.unwrap_err(),
            JwtValidationError::UnsupportedAlgorithm(_)
        );
    }

    #[test]
    fn test_validate_expiration_claims_helper() {
        let now = chrono::Utc::now().timestamp();
        let clock_skew = 300;

        // Test expired token
        let expired_claims = JwtClaims {
            iss: None,
            aud: None,
            exp: Some(now - 1000), // Expired 1000 seconds ago
            nbf: None,
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_expiration_claims(&expired_claims, now, clock_skew);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            JwtValidationError::TokenExpired
        ));

        // Test not yet valid token
        let future_claims = JwtClaims {
            iss: None,
            aud: None,
            exp: Some(now + 3600),
            nbf: Some(now + 1000), // Not valid for another 1000 seconds
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_expiration_claims(&future_claims, now, clock_skew);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            JwtValidationError::TokenNotYetValid
        ));

        // Test valid token
        let valid_claims = JwtClaims {
            iss: None,
            aud: None,
            exp: Some(now + 3600),
            nbf: Some(now - 100),
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_expiration_claims(&valid_claims, now, clock_skew);
        assert!(result.is_ok());

        // Test token with no expiration claims (should pass)
        let no_exp_claims = JwtClaims {
            iss: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_expiration_claims(&no_exp_claims, now, clock_skew);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_issuer_claim_helper() {
        let config = JwtValidationConfig {
            enabled: Some(true),
            validate_audience: false,
            validate_issuer: true,
            validate_expiration: false,
            expected_audience: None,
            expected_issuer: Some("https://expected.com".to_string()),
            clock_skew_seconds: 300,
            cache_duration_seconds: 3600,
        };

        let discovery_doc = OidcDiscoveryDocument {
            issuer: "https://discovery.com".to_string(),
            authorization_endpoint: "https://discovery.com/auth".to_string(),
            token_endpoint: "https://discovery.com/token".to_string(),
            jwks_uri: "https://discovery.com/jwks".to_string(),
            userinfo_endpoint: None,
            end_session_endpoint: None,
            id_token_signing_alg_values_supported: vec![],
        };

        // Test valid issuer (uses expected_issuer from config)
        let valid_claims = JwtClaims {
            iss: Some("https://expected.com".to_string()),
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result =
            JwtValidator::validate_issuer_claim(&valid_claims, &config, Some(&discovery_doc));
        assert!(result.is_ok());

        // Test invalid issuer
        let invalid_claims = JwtClaims {
            iss: Some("https://malicious.com".to_string()),
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result =
            JwtValidator::validate_issuer_claim(&invalid_claims, &config, Some(&discovery_doc));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            JwtValidationError::ClaimValidationFailed { .. }
        ));

        // Test no discovery document (should pass)
        let result = JwtValidator::validate_issuer_claim(&valid_claims, &config, None);
        assert!(result.is_ok());

        // Test no issuer in claims (should pass)
        let no_issuer_claims = JwtClaims {
            iss: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result =
            JwtValidator::validate_issuer_claim(&no_issuer_claims, &config, Some(&discovery_doc));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_audience_claim_helper() {
        let config = JwtValidationConfig {
            enabled: Some(true),
            validate_audience: true,
            validate_issuer: false,
            validate_expiration: false,
            expected_audience: Some("expected-client".to_string()),
            expected_issuer: None,
            clock_skew_seconds: 300,
            cache_duration_seconds: 3600,
        };

        // Test single matching audience
        let single_aud_claims = JwtClaims {
            iss: None,
            aud: Some(serde_json::Value::String("expected-client".to_string())),
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_audience_claim(&single_aud_claims, &config);
        assert!(result.is_ok());

        // Test multiple audiences with match
        let multiple_aud_claims = JwtClaims {
            iss: None,
            aud: Some(serde_json::Value::Array(vec![
                serde_json::Value::String("other-client".to_string()),
                serde_json::Value::String("expected-client".to_string()),
            ])),
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_audience_claim(&multiple_aud_claims, &config);
        assert!(result.is_ok());

        // Test no matching audience
        let no_match_claims = JwtClaims {
            iss: None,
            aud: Some(serde_json::Value::String("different-client".to_string())),
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let result = JwtValidator::validate_audience_claim(&no_match_claims, &config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            JwtValidationError::ClaimValidationFailed { .. }
        ));

        // Test no expected audience configured (should pass)
        let config_no_aud = JwtValidationConfig {
            expected_audience: None,
            ..config
        };

        let result = JwtValidator::validate_audience_claim(&no_match_claims, &config_no_aud);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_audiences_from_claims() {
        // Test single string audience
        let single_claims = JwtClaims {
            iss: None,
            aud: Some(serde_json::Value::String("client1".to_string())),
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let audiences = JwtValidator::extract_audiences_from_claims(&single_claims);
        assert_eq!(audiences, vec!["client1"]);

        // Test multiple audiences
        let multiple_claims = JwtClaims {
            iss: None,
            aud: Some(serde_json::Value::Array(vec![
                serde_json::Value::String("client1".to_string()),
                serde_json::Value::String("client2".to_string()),
                serde_json::Value::Number(serde_json::Number::from(123)), // Non-string should be filtered
            ])),
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let audiences = JwtValidator::extract_audiences_from_claims(&multiple_claims);
        assert_eq!(audiences, vec!["client1", "client2"]);

        // Test no audience
        let no_aud_claims = JwtClaims {
            iss: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            sub: None,
        };

        let audiences = JwtValidator::extract_audiences_from_claims(&no_aud_claims);
        assert!(audiences.is_empty());
    }
}
