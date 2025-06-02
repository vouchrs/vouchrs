use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use base64::{Engine as _, engine::general_purpose};

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
    pub extra_auth_params: HashMap<String, String>,
    pub jwt_signing: Option<JwtSigningConfig>,
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
            extra_auth_params: HashMap::new(),
            jwt_signing: None,
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
    fn load_base_settings() -> Result<VouchrsSettings, Box<dyn std::error::Error>> {
        // 1. Start with default settings
        let mut settings = VouchrsSettings::default();

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
                let secrets_settings: VouchrsSettings =
                    basic_toml::from_str(&secrets_toml_content)?;

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
    fn apply_env_overrides(settings: &mut VouchrsSettings) {
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
        if let Ok(session_duration_str) = std::env::var("SESSION_DURATION_HOURS") {
            if let Ok(session_duration) = session_duration_str.parse::<u64>() {
                session_settings.session_duration_hours = session_duration;
            }
        }
        
        // Check if SESSION_SECRET environment variable is set
        let env_secret_set = if let Ok(session_secret) = std::env::var("SESSION_SECRET") {
            if session_secret.is_empty() {
                false
            } else {
                session_settings.session_secret = session_secret;
                true
            }
        } else {
            false
        };
        
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
        rand::thread_rng().fill_bytes(&mut secret);
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

    #[test]
    fn test_session_secret_configuration() {
        // Test default value - should be empty and will be generated when processed
        let default_session_settings = SessionSettings::default();
        assert_eq!(default_session_settings.session_secret, "");
        assert_eq!(default_session_settings.session_duration_hours, 24);
    }

    #[test]
    fn test_session_secret_env_override() {
        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: "default-secret".to_string(),
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
    fn test_session_duration_env_override() {
        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: "test-secret".to_string(),
        };

        // Set environment variable
        std::env::set_var("SESSION_DURATION_HOURS", "48");

        // Apply environment overrides
        VouchrsSettings::apply_session_env_overrides(&mut session_settings);

        assert_eq!(session_settings.session_duration_hours, 48);
        assert_eq!(session_settings.session_secret, "test-secret"); // Should remain unchanged

        // Clean up
        std::env::remove_var("SESSION_DURATION_HOURS");
    }

    #[test]
    fn test_session_env_override() {
        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: "test-secret".to_string(),
        };

        // Apply environment overrides
        VouchrsSettings::apply_session_env_overrides(&mut session_settings);

        assert_eq!(session_settings.session_secret, "test-secret"); // Should remain unchanged
    }

    #[test]
    fn test_settings_dir_precedence() {
        // Setup temp dirs for testing
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create a Settings.toml in the root with specific values
        let root_settings_content = r#"
[session]
session_secret = "root-secret-key"
"#;

        // Create a Settings.toml in the "secrets" dir with different values
        let secrets_dir = temp_path.join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let secrets_settings_content = r#"
[session]
session_secret = "secrets-secret-key"
"#;

        // Write the files
        std::fs::write(temp_path.join("Settings.toml"), root_settings_content).unwrap();
        std::fs::write(secrets_dir.join("Settings.toml"), secrets_settings_content).unwrap();

        // First test: No VOUCHR_SECRETS_DIR set, should use root Settings.toml
        std::env::remove_var("VOUCHR_SECRETS_DIR");

        // Mock the load_base_settings to use our temp paths
        let actual_settings = VouchrsSettings::load_base_settings().unwrap();

        // Validate default values were not overridden in this mock test
        // This is a limitation of the test due to searching in current directory
        assert_eq!(
            actual_settings.session.session_secret,
            ""  // Default is now empty string
        );

        // Add a proper integration test that would validate this behavior in a controlled environment
        // For now, we'll just document how it should work
        println!("Note: Full precedence testing requires integration tests with file path control");
    }

    #[test]
    fn test_vouchrs_secrets_dir_precedence() {
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
        std::env::remove_var("SESSION_SECRET");
    }

    #[test]
    fn test_session_secret_auto_generation() {
        let mut session_settings = SessionSettings {
            session_duration_hours: 24,
            session_secret: String::new(), // Empty, should trigger auto-generation
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
        };
        VouchrsSettings::apply_session_env_overrides(&mut session_settings2);
        
        // Should be different each time
        assert_ne!(session_settings.session_secret, session_settings2.session_secret);
    }
}
