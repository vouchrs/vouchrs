use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

// Additional imports for environment and logging setup

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VouchrsSettings {
    pub application: ApplicationSettings,
    pub proxy: ProxySettings,
    pub static_files: StaticFilesSettings,
    pub session: SessionSettings,
    pub cookies: CookieSettings,
    pub logging: LoggingSettings,
    pub providers: Vec<ProviderSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationSettings {
    pub host: String,
    pub port: u16,
    pub redirect_base_url: String,
    pub cors_origins: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub upstream_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFilesSettings {
    pub assets_folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSettings {
    pub session_duration_hours: u64,
    pub session_secret: String,
    /// Session validity in hours (how long the actual session remains valid)
    /// This is separate from cookie lifetime and provides additional security
    pub session_expiration_hours: u64,
    /// Cookie refresh interval in hours. If 0, cookie refresh is disabled.
    /// When enabled, the session cookie's expiration will be extended by this
    /// amount each time the user makes a request, keeping active users logged in.
    pub session_refresh_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieSettings {
    pub secure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSettings {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSettings {
    pub name: String,
    pub display_name: Option<String>,
    pub discovery_url: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub signout_url: Option<String>,
    pub scopes: Vec<String>,

    // Direct values (can be overridden by environment variables)
    pub client_id: Option<String>,
    pub client_secret: Option<String>,

    // Environment variable names for overrides
    pub client_id_env: Option<String>,
    pub client_secret_env: Option<String>,

    pub enabled: bool,
    pub extra_auth_params: Option<HashMap<String, String>>,
    pub jwt_signing: Option<JwtSigningConfig>,

    /// JWT validation configuration (optional overrides, auto-enabled for providers with `discovery_url`)
    pub jwt_validation: Option<JwtValidationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSigningConfig {
    // Direct values (can be overridden by environment variables)
    pub team_id: Option<String>,
    pub key_id: Option<String>,
    pub private_key_path: Option<String>,

    // Environment variable names for overrides
    pub team_id_env: Option<String>,
    pub key_id_env: Option<String>,
    pub private_key_path_env: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtValidationConfig {
    /// Enable/disable JWT validation (auto-determined from `discovery_url` if not specified)
    pub enabled: Option<bool>,

    /// Validate the audience claim against `client_id` (default: true when enabled)
    #[serde(default = "default_true")]
    pub validate_audience: bool,

    /// Validate the issuer claim against discovered issuer (default: true when enabled)
    #[serde(default = "default_true")]
    pub validate_issuer: bool,

    /// Validate expiration and not-before claims (default: true when enabled)
    #[serde(default = "default_true")]
    pub validate_expiration: bool,

    /// Override expected audience (defaults to `client_id`)
    pub expected_audience: Option<String>,

    /// Override expected issuer (defaults to discovered issuer)
    pub expected_issuer: Option<String>,

    /// Clock skew tolerance in seconds (default: 300 = 5 minutes)
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,

    /// JWKS cache duration in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_cache_duration")]
    pub cache_duration_seconds: u64,
}

// Helper functions for serde defaults
fn default_true() -> bool { true }
fn default_clock_skew() -> u64 { 300 }
fn default_cache_duration() -> u64 { 3600 }

impl Default for JwtValidationConfig {
    fn default() -> Self {
        Self {
            enabled: None, // Auto-determined at runtime
            validate_audience: true,
            validate_issuer: true,
            validate_expiration: true,
            expected_audience: None,
            expected_issuer: None,
            clock_skew_seconds: 300,
            cache_duration_seconds: 3600,
        }
    }
}

impl Default for ApplicationSettings {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            redirect_base_url: "http://localhost:8080".to_string(),
            cors_origins: "http://localhost:3000,http://localhost:8080".to_string(),
        }
    }
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            upstream_url: "http://localhost:3000".to_string(),
        }
    }
}

impl Default for StaticFilesSettings {
    fn default() -> Self {
        Self {
            assets_folder: "src/static".to_string(),
        }
    }
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            session_duration_hours: 24,
            session_secret: String::new(), // Will be generated if empty
            session_expiration_hours: 1,   // Default to 1 hour for security
            session_refresh_hours: 0,      // Disabled by default
        }
    }
}

impl Default for CookieSettings {
    fn default() -> Self {
        Self {
            secure: true, // Default to secure cookies
        }
    }
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

impl Default for ProviderSettings {
    fn default() -> Self {
        Self {
            name: String::new(),
            display_name: None,
            discovery_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            signout_url: None,
            scopes: vec!["openid".to_string(), "email".to_string()],
            client_id: None,
            client_secret: None,
            client_id_env: None,
            client_secret_env: None,
            enabled: true,
            extra_auth_params: Some(HashMap::new()),
            jwt_signing: None,
            jwt_validation: None,
        }
    }
}

impl VouchrsSettings {
    /// Load settings from configuration files and environment variables
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Environment initialization fails
    /// - Settings file cannot be read or parsed
    /// - TOML parsing fails
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize environment and logging
        Self::initialize_environment()?;

        // Load base settings from TOML or defaults
        let mut settings = Self::load_base_settings()?;

        // Apply environment variable overrides
        Self::apply_env_overrides(&mut settings);

        Ok(settings)
    }

    /// Initialize environment variables and logging
    ///
    /// # Errors
    ///
    /// Initialize environment and logging
    ///
    /// # Errors
    ///
    /// Returns an error if logger initialization fails
    fn initialize_environment() -> Result<(), Box<dyn std::error::Error>> {
        Self::load_env_file();
        env_logger::try_init()?;
        Ok(())
    }

    /// Load base settings from TOML file(s) or use defaults
    /// Settings are loaded with the following priority (highest to lowest):
    /// 1. Environment variables (applied separately after loading base settings)
    /// 2. Settings.toml in `VOUCHRS_SECRETS_DIR` (if specified and exists)
    /// 3. Settings.toml in current directory (if exists)
    /// 4. Default settings
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Settings file cannot be read
    /// - TOML parsing fails
    fn load_base_settings() -> Result<Self, Box<dyn std::error::Error>> {
        // 1. Start with default settings
        let mut settings = Self::default();

        // 2. Try to load from Settings.toml in current directory (lower priority)
        let default_config_path = std::path::PathBuf::from("Settings.toml");
        if default_config_path.exists() {
            let toml_content = fs::read_to_string(&default_config_path)?;
            settings = basic_toml::from_str(&toml_content)?;
            println!(
                "✓ Loaded base settings from {}",
                default_config_path.display()
            );
        }

        // 3. If VOUCHRS_SECRETS_DIR is set and contains Settings.toml, override with those settings (higher priority)
        if let Ok(secrets_dir) = std::env::var("VOUCHRS_SECRETS_DIR") {
            let secrets_path = std::path::Path::new(&secrets_dir).join("Settings.toml");
            if secrets_path.exists() {
                let secrets_toml_content = fs::read_to_string(&secrets_path)?;
                let secrets_settings: Self = basic_toml::from_str(&secrets_toml_content)?;

                println!("✓ Overriding settings from {}", secrets_path.display());

                // Replace settings with those from secrets directory
                settings = secrets_settings;
            } else {
                println!(
                    "ℹ VOUCHRS_SECRETS_DIR set but no Settings.toml found at: {}",
                    secrets_path.display()
                );
            }
        }

        // Environment variables will be applied next, after this function returns

        Ok(settings)
    }

    /// Apply environment variable overrides to settings
    fn apply_env_overrides(settings: &mut Self) {
        Self::apply_application_env_overrides(&mut settings.application);
        Self::apply_proxy_env_overrides(&mut settings.proxy);
        Self::apply_static_files_env_overrides(&mut settings.static_files);
        Self::apply_session_env_overrides(&mut settings.session);
        Self::apply_cookie_env_overrides(&mut settings.cookies);
        Self::apply_logging_env_overrides(&mut settings.logging);
    }

    /// Apply environment overrides for application settings
    fn apply_application_env_overrides(app_settings: &mut ApplicationSettings) {
        if let Ok(host) = std::env::var("HOST") {
            app_settings.host = host;
        }
        if let Ok(port_str) = std::env::var("PORT") {
            if let Ok(port) = port_str.parse::<u16>() {
                app_settings.port = port;
            }
        }
        if let Ok(redirect_base_url) = std::env::var("REDIRECT_BASE_URL") {
            app_settings.redirect_base_url = redirect_base_url;
        }
        if let Ok(cors_origins) = std::env::var("CORS_ORIGINS") {
            app_settings.cors_origins = cors_origins;
        }
    }

    /// Apply environment overrides for proxy settings
    fn apply_proxy_env_overrides(proxy_settings: &mut ProxySettings) {
        if let Ok(upstream_url) = std::env::var("UPSTREAM_URL") {
            proxy_settings.upstream_url = upstream_url;
        }
    }

    /// Apply environment overrides for static files settings
    fn apply_static_files_env_overrides(static_settings: &mut StaticFilesSettings) {
        if let Ok(assets_folder) = std::env::var("STATIC_FOLDER_PATH") {
            static_settings.assets_folder = assets_folder;
        }
    }

    /// Apply environment overrides for session settings
    pub fn apply_session_env_overrides(session_settings: &mut SessionSettings) {
        // Apply numeric environment variable overrides
        Self::apply_numeric_env_override(
            "SESSION_DURATION_HOURS",
            &mut session_settings.session_duration_hours,
        );
        Self::apply_numeric_env_override(
            "SESSION_EXPIRATION_HOURS",
            &mut session_settings.session_expiration_hours,
        );
        Self::apply_numeric_env_override(
            "SESSION_REFRESH_HOURS",
            &mut session_settings.session_refresh_hours,
        );

        // Handle session secret with special logic
        Self::handle_session_secret_override(session_settings);
    }

    /// Helper function to apply numeric environment variable overrides
    fn apply_numeric_env_override(env_var: &str, target: &mut u64) {
        if let Ok(value_str) = std::env::var(env_var) {
            if let Ok(value) = value_str.parse::<u64>() {
                *target = value;
            }
        }
    }

    /// Helper function to handle session secret environment override and generation
    fn handle_session_secret_override(session_settings: &mut SessionSettings) {
        let env_secret_set = std::env::var("SESSION_SECRET").is_ok_and(|secret| {
            if secret.is_empty() {
                false
            } else {
                session_settings.session_secret = secret;
                true
            }
        });

        // Generate random session secret if no environment variable was set and current value is empty
        if !env_secret_set && session_settings.session_secret.is_empty() {
            session_settings.session_secret = Self::generate_random_session_secret();
            Self::warn_about_generated_secret(&session_settings.session_secret);
        }
    }

    /// Generate a cryptographically secure random session secret
    ///
    /// Uses the same secure random source as our crypto utilities
    /// Generates 32 bytes (256 bits) of entropy for AES-256 compatibility
    fn generate_random_session_secret() -> String {
        use rand::RngCore;
        let mut secret = [0u8; 32]; // 256 bits for AES-256
        rand::rng().fill_bytes(&mut secret);
        general_purpose::STANDARD.encode(secret)
    }

    /// Display warnings about using a generated session secret
    fn warn_about_generated_secret(secret: &str) {
        eprintln!("⚠️  WARNING: Using auto-generated session secret");
        eprintln!("📝 Generated secret: {secret}");
        eprintln!("🔒 For production use, set the SESSION_SECRET environment variable");
        eprintln!("   or configure session_secret in Settings.toml");
        eprintln!("💡 This secret will change on each restart unless explicitly configured");
    }

    /// Apply environment overrides for cookie settings
    fn apply_cookie_env_overrides(cookie_settings: &mut CookieSettings) {
        if let Ok(cookie_secure_str) = std::env::var("COOKIE_SECURE") {
            if let Ok(cookie_secure) = cookie_secure_str.parse::<bool>() {
                cookie_settings.secure = cookie_secure;
            }
        }
    }

    /// Apply environment overrides for logging settings
    fn apply_logging_env_overrides(logging_settings: &mut LoggingSettings) {
        if let Ok(log_level) = std::env::var("RUST_LOG") {
            logging_settings.level = log_level;
        }
    }

    /// Load environment variables from .env file
    fn load_env_file() {
        if let Ok(contents) = std::fs::read_to_string(".env") {
            for line in contents.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    std::env::set_var(key.trim(), value.trim());
                }
            }
        }
    }

    /// Get the bind address for the server
    #[must_use]
    pub fn get_bind_address(&self) -> String {
        format!("{}:{}", self.application.host, self.application.port)
    }

    /// Get CORS origins as a vector of strings
    #[must_use]
    pub fn get_cors_origins(&self) -> Vec<String> {
        self.application
            .cors_origins
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    }

    /// Get enabled providers
    #[must_use]
    pub fn get_enabled_providers(&self) -> Vec<&ProviderSettings> {
        self.providers.iter().filter(|p| p.enabled).collect()
    }

    /// Get provider by name
    #[must_use]
    pub fn get_provider(&self, name: &str) -> Option<&ProviderSettings> {
        self.providers.iter().find(|p| p.name == name)
    }
}

impl ProviderSettings {
    /// Get the client ID, checking environment variable first, then falling back to direct value
    #[must_use]
    pub fn get_client_id(&self) -> Option<String> {
        if let Some(env_var) = &self.client_id_env {
            if let Ok(value) = std::env::var(env_var) {
                return Some(value);
            }
        }
        self.client_id.clone()
    }

    /// Get the client secret, checking environment variable first, then falling back to direct value
    #[must_use]
    pub fn get_client_secret(&self) -> Option<String> {
        if let Some(env_var) = &self.client_secret_env {
            if let Ok(value) = std::env::var(env_var) {
                return Some(value);
            }
        }
        self.client_secret.clone()
    }

    /// Determine if JWT validation should be enabled for this provider
    /// Auto-enables for providers with `discovery_url`, unless explicitly disabled
    #[must_use]
    pub fn should_enable_jwt_validation(&self) -> bool {
        if let Some(jwt_config) = &self.jwt_validation {
            if let Some(enabled) = jwt_config.enabled {
                // Explicit enable/disable takes precedence
                return enabled;
            }
        }

        // Auto-enable if discovery_url is present
        self.discovery_url.is_some()
    }

    /// Get the effective JWT validation configuration with auto-determined defaults
    #[must_use]
    pub fn get_jwt_validation_config(&self) -> JwtValidationConfig {
        let mut config = self.jwt_validation.clone().unwrap_or_default();

        // Set enabled based on auto-detection logic
        config.enabled = Some(self.should_enable_jwt_validation());

        config
    }
}

impl JwtSigningConfig {
    /// Get the team ID, checking environment variable first, then falling back to direct value
    #[must_use]
    pub fn get_team_id(&self) -> Option<String> {
        if let Some(env_var) = &self.team_id_env {
            if let Ok(value) = std::env::var(env_var) {
                return Some(value);
            }
        }
        self.team_id.clone()
    }

    /// Get the key ID, checking environment variable first, then falling back to direct value
    #[must_use]
    pub fn get_key_id(&self) -> Option<String> {
        if let Some(env_var) = &self.key_id_env {
            if let Ok(value) = std::env::var(env_var) {
                return Some(value);
            }
        }
        self.key_id.clone()
    }

    /// Get the private key path, checking environment variable first, then falling back to direct value
    #[must_use]
    pub fn get_private_key_path(&self) -> Option<String> {
        if let Some(env_var) = &self.private_key_path_env {
            if let Ok(value) = std::env::var(env_var) {
                return Some(value);
            }
        }
        self.private_key_path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // Helper function to clean all relevant environment variables for tests
    fn clean_env_vars() {
        std::env::remove_var("SESSION_SECRET");
        std::env::remove_var("SESSION_DURATION_HOURS");
        std::env::remove_var("SESSION_EXPIRATION_HOURS");
        std::env::remove_var("SESSION_REFRESH_HOURS");
        std::env::remove_var("VOUCHRS_SECRETS_DIR");
    }

    #[test]
    fn test_session_secret_configuration() {
        // Test default value - should be empty and will be generated when processed
        let default_session_settings = SessionSettings::default();
        assert_eq!(default_session_settings.session_secret, "");
        assert_eq!(default_session_settings.session_duration_hours, 24);
    }

    #[test]
    #[serial]
    fn test_session_secret_env_override() {
        // Make sure the environment is clean
        clean_env_vars();

        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: "default-secret".to_string(),
            session_expiration_hours: 1,
            session_refresh_hours: 0,
        };

        // Set environment variable
        std::env::set_var("SESSION_SECRET", "env-override-secret");

        // Apply environment overrides
        VouchrsSettings::apply_session_env_overrides(&mut session_settings);

        assert_eq!(session_settings.session_secret, "env-override-secret");

        // Clean up
        std::env::remove_var("SESSION_SECRET");
    }

    #[test]
    #[serial]
    fn test_session_duration_env_override() {
        // Make sure the environment is clean
        clean_env_vars();

        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: "test-secret".to_string(),
            session_expiration_hours: 1,
            session_refresh_hours: 0,
        };

        // Set environment variable
        std::env::set_var("SESSION_DURATION_HOURS", "48");

        // Apply environment overrides
        VouchrsSettings::apply_session_env_overrides(&mut session_settings);

        assert_eq!(session_settings.session_duration_hours, 48);
        assert_eq!(session_settings.session_secret, "test-secret"); // Should remain unchanged

        // Clean up
        clean_env_vars();
    }

    #[test]
    #[serial]
    fn test_session_env_override() {
        // Make sure the environment is clean
        clean_env_vars();

        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: "test-secret".to_string(),
            session_expiration_hours: 1,
            session_refresh_hours: 0,
        };

        // Apply environment overrides
        VouchrsSettings::apply_session_env_overrides(&mut session_settings);

        assert_eq!(session_settings.session_secret, "test-secret"); // Should remain unchanged

        clean_env_vars();
    }

    #[test]
    #[serial]
    fn test_settings_dir_precedence() {
        clean_env_vars();

        // This test documents the expected behavior of settings precedence
        // In a real application, the precedence is:
        // 1. Environment variables (highest)
        // 2. VOUCHRS_SECRETS_DIR/Settings.toml (if VOUCHRS_SECRETS_DIR is set)
        // 3. ./Settings.toml (if exists)
        // 4. Default values (lowest)

        // Since we can't control file system paths in this unit test,
        // we'll test the configuration logic with mock settings

        // Mock settings from root Settings.toml
        let mut mock_root_settings = VouchrsSettings::default();
        mock_root_settings.session.session_secret = "root-secret-key".to_string();

        // Mock settings from VOUCHRS_SECRETS_DIR Settings.toml
        let mut mock_secrets_settings = VouchrsSettings::default();
        mock_secrets_settings.session.session_secret = "secrets-secret-key".to_string();

        // Scenario 1: No VOUCHRS_SECRETS_DIR, use root settings
        assert_eq!(mock_root_settings.session.session_secret, "root-secret-key");

        // Scenario 2: With VOUCHRS_SECRETS_DIR, prefer settings from secrets dir
        assert_eq!(mock_secrets_settings.session.session_secret, "secrets-secret-key");

        // Scenario 3: Environment variables override both
        let mut settings_with_env = mock_secrets_settings.clone();
        std::env::set_var("SESSION_SECRET", "env-secret-key");

        VouchrsSettings::apply_session_env_overrides(&mut settings_with_env.session);

        assert_eq!(settings_with_env.session.session_secret, "env-secret-key");

        clean_env_vars();
    }

    #[test]
    #[serial]
    fn test_vouchrs_secrets_dir_precedence() {
        clean_env_vars();

        // This is a conceptual test illustrating the expected behavior
        // of the settings precedence. A full integration test would require
        // more control over the file system.

        // Mock settings from root Settings.toml
        let mut mock_root_settings = VouchrsSettings::default();
        mock_root_settings.session.session_secret = "root-secret-key".to_string();

        // Mock settings from VOUCHRS_SECRETS_DIR Settings.toml
        let mut mock_secrets_settings = VouchrsSettings::default();
        mock_secrets_settings.session.session_secret = "secrets-secret-key".to_string();

        // Scenario 1: No VOUCHRS_SECRETS_DIR, use root settings
        assert_eq!(mock_root_settings.session.session_secret, "root-secret-key");

        // Scenario 2: With VOUCHRS_SECRETS_DIR, prefer settings from secrets dir
        assert_eq!(
            mock_secrets_settings.session.session_secret,
            "secrets-secret-key"
        );

        // Scenario 3: Environment variables override both
        let mut settings_with_env = mock_secrets_settings.clone();
        std::env::set_var("SESSION_SECRET", "env-secret-key");

        VouchrsSettings::apply_session_env_overrides(&mut settings_with_env.session);

        assert_eq!(settings_with_env.session.session_secret, "env-secret-key");

        // Clean up
        clean_env_vars();
    }

    #[test]
    #[serial]
    fn test_session_secret_auto_generation() {
        // Make sure the environment is clean
        clean_env_vars();

        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: String::new(), // Empty, should trigger auto-generation
            session_expiration_hours: 1,
            session_refresh_hours: 0,
        };

        // Apply environment overrides (which includes auto-generation)
        VouchrsSettings::apply_session_env_overrides(&mut session_settings);

        // Should have generated a non-empty secret
        assert!(!session_settings.session_secret.is_empty());
        assert!(session_settings.session_secret.len() > 40); // Base64 encoded 32 bytes should be ~44 chars

        // Generate another one to ensure they're different
        let mut session_settings2 = SessionSettings {
            session_duration_hours: 24,
            session_secret: String::new(),
            session_expiration_hours: 1,
            session_refresh_hours: 0,
        };
        VouchrsSettings::apply_session_env_overrides(&mut session_settings2);

        // Should be different each time
        assert_ne!(
            session_settings.session_secret,
            session_settings2.session_secret
        );

        clean_env_vars();
    }

    #[test]
    #[serial]
    fn test_session_refresh_env_override() {
        // Make sure the environment is clean
        clean_env_vars();

        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: "test-secret".to_string(),
            session_expiration_hours: 1,
            session_refresh_hours: 0, // Default disabled
        };

        // Set environment variable
        std::env::set_var("SESSION_REFRESH_HOURS", "2"); // 2 hours

        // Apply environment overrides
        VouchrsSettings::apply_session_env_overrides(&mut session_settings);

        assert_eq!(session_settings.session_refresh_hours, 2);
        assert_eq!(session_settings.session_secret, "test-secret"); // Should remain unchanged
        assert_eq!(session_settings.session_duration_hours, 24); // Should remain unchanged

        // Clean up
        clean_env_vars();
    }

    #[test]
    fn test_jwt_validation_auto_enabled_with_discovery_url() {
        let provider = ProviderSettings {
            name: "test".to_string(),
            discovery_url: Some("https://provider.com/.well-known/openid-configuration".to_string()),
            ..Default::default()
        };

        assert!(provider.should_enable_jwt_validation());

        let config = provider.get_jwt_validation_config();
        assert_eq!(config.enabled, Some(true));
        assert!(config.validate_audience);
        assert!(config.validate_issuer);
        assert!(config.validate_expiration);
    }

    #[test]
    fn test_jwt_validation_disabled_without_discovery_url() {
        let provider = ProviderSettings {
            name: "legacy".to_string(),
            authorization_endpoint: Some("https://legacy.com/auth".to_string()),
            token_endpoint: Some("https://legacy.com/token".to_string()),
            ..Default::default()
        };

        assert!(!provider.should_enable_jwt_validation());

        let config = provider.get_jwt_validation_config();
        assert_eq!(config.enabled, Some(false));
    }

    #[test]
    fn test_jwt_validation_explicit_override() {
        // Provider with discovery_url but validation explicitly disabled
        let provider = ProviderSettings {
            name: "test".to_string(),
            discovery_url: Some("https://provider.com/.well-known/openid-configuration".to_string()),
            jwt_validation: Some(JwtValidationConfig {
                enabled: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(!provider.should_enable_jwt_validation());

        let config = provider.get_jwt_validation_config();
        assert_eq!(config.enabled, Some(false));
    }

    #[test]
    fn test_jwt_validation_explicit_enable_without_discovery() {
        // Legacy provider with validation explicitly enabled (for future manual config)
        let provider = ProviderSettings {
            name: "legacy".to_string(),
            jwt_validation: Some(JwtValidationConfig {
                enabled: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(provider.should_enable_jwt_validation());

        let config = provider.get_jwt_validation_config();
        assert_eq!(config.enabled, Some(true));
    }

    #[test]
    fn test_jwt_validation_config_overrides() {
        let provider = ProviderSettings {
            name: "test".to_string(),
            discovery_url: Some("https://provider.com/.well-known/openid-configuration".to_string()),
            jwt_validation: Some(JwtValidationConfig {
                validate_audience: false,
                expected_issuer: Some("https://custom-issuer.com".to_string()),
                clock_skew_seconds: 600,
                ..Default::default()
            }),
            ..Default::default()
        };

        let config = provider.get_jwt_validation_config();
        assert_eq!(config.enabled, Some(true)); // Auto-enabled due to discovery_url
        assert!(!config.validate_audience); // Overridden
        assert_eq!(config.expected_issuer, Some("https://custom-issuer.com".to_string()));
        assert_eq!(config.clock_skew_seconds, 600);
        assert!(config.validate_issuer); // Default
        assert!(config.validate_expiration); // Default
    }
}
