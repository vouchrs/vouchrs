#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![deny(warnings)]
#![allow(clippy::multiple_crate_versions)]

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::sync::Arc;
use vouchrs::{
    handlers::{
        complete_authentication, complete_registration, health, initialize_static_files,
        oauth_callback, oauth_debug, oauth_sign_in, oauth_sign_out, oauth_userinfo, proxy_upstream,
        serve_static, start_authentication, start_registration,
    },
    oauth::{OAuthAuthenticationServiceImpl, OAuthConfig},
    passkey::PasskeyAuthenticationServiceImpl,
    session::SessionManager,
    settings::VouchrsSettings,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load configuration from Settings.toml and environment variables
    // This also loads .env file and initializes the logger
    let settings = VouchrsSettings::load()
        .map_err(|e| std::io::Error::other(format!("Failed to load settings: {e}")))?;

    // Initialize OAuth configuration with config-driven providers
    let mut oauth_config = OAuthConfig::new();
    oauth_config
        .initialize_from_settings(&settings)
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to initialize OAuth providers: {e}")))?;

    // Initialize static files from templates
    initialize_static_files(&settings)
        .map_err(|e| std::io::Error::other(format!("Failed to initialize static files: {e}")))?;

    println!("✓ Using stateless sessions with encrypted cookies");
    start_server(oauth_config, settings).await
}

/// Start the server with stateless sessions
///
/// # Errors
///
/// Returns an error if:
/// - Server binding fails
/// - Server fails to start
async fn start_server(oauth_config: OAuthConfig, settings: VouchrsSettings) -> std::io::Result<()> {
    let bind_address = settings.get_bind_address();
    print_startup_info(&bind_address, "Stateless", &settings);

    // Initialize session manager with authentication services
    let session_manager = create_session_manager(&settings);

    // Configure CORS for SPAs
    let cors_origins = settings.get_cors_origins();

    HttpServer::new(move || {
        let cors_origins = cors_origins.clone();
        let cors = Cors::default()
            .allowed_origin_fn(move |origin, _| {
                cors_origins
                    .iter()
                    .any(|allowed| allowed == origin.to_str().unwrap_or(""))
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec!["Authorization", "Content-Type", "Accept"])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(oauth_config.clone()))
            .app_data(web::Data::new(settings.clone()))
            .app_data(web::Data::new(session_manager.clone()))
            .wrap(cors)
            .wrap(Logger::default())
            .configure(configure_services)
    })
    .bind(&bind_address)?
    .run()
    .await
}

fn configure_services(cfg: &mut web::ServiceConfig) {
    cfg
        // Common authentication endpoints
        .route("/auth/sign_in", web::get().to(oauth_sign_in))
        .route("/auth/debug", web::get().to(oauth_debug))
        .route("/auth/userinfo", web::get().to(oauth_userinfo))
        // OAuth2 endpoints
        .route("/auth/oauth2/sign_out", web::get().to(oauth_sign_out))
        .route("/auth/oauth2/sign_out", web::post().to(oauth_sign_out))
        .route("/auth/oauth2/callback", web::get().to(oauth_callback))
        .route("/auth/oauth2/callback", web::post().to(oauth_callback))
        // Passkey endpoints
        .route(
            "/auth/passkey/register/start",
            web::post().to(start_registration),
        )
        .route(
            "/auth/passkey/register/complete",
            web::post().to(complete_registration),
        )
        .route(
            "/auth/passkey/auth/start",
            web::post().to(start_authentication),
        )
        .route(
            "/auth/passkey/auth/complete",
            web::post().to(complete_authentication),
        )
        // Static files endpoint
        .route("/auth/static/{filename:.*}", web::get().to(serve_static))
        // Health endpoint
        .route("/ping", web::get().to(health))
        // Catch-all proxy for any other path - provider determined from session
        .default_service(
            web::route()
                .guard(actix_web::guard::fn_guard(|req| {
                    let path = req.head().uri.path();
                    !path.starts_with("/auth") && !path.starts_with("/ping")
                }))
                .to(proxy_upstream),
        );
}

fn print_startup_info(bind_address: &str, session_backend: &str, settings: &VouchrsSettings) {
    println!("Starting Vouchrs OIDC Reverse Proxy on http://{bind_address}");
    println!("Session Backend: {session_backend}");
    println!();
    println!("OAuth2 endpoints:");
    println!("  GET  /auth/sign_in  - Login/logout page");
    println!("  GET|POST /auth/oauth2/sign_out - Clear session");
    println!("  GET|POST /auth/oauth2/callback - OAuth callback (POST for Apple form_post)");
    println!();
    println!("Passkey endpoints:");
    println!("  POST /auth/passkey/register/start - Start passkey registration");
    println!("  POST /auth/passkey/register/complete - Complete passkey registration");
    println!("  POST /auth/passkey/auth/start - Start passkey authentication");
    println!("  POST /auth/passkey/auth/complete - Complete passkey authentication");
    println!();
    println!("OAuth callback URL for identity providers:");
    println!(
        "  {}/auth/oauth2/callback",
        settings.application.redirect_base_url
    );
    println!();
    if session_backend == "Stateless" {
        println!("Sidecar Proxy endpoints (with automatic OAuth token injection):");
        println!("  ALL {{any path}}                   - Proxy to upstream service as-is");
        println!("                                    (except /auth/* and /ping)");
        println!(
            "                                    Upstream URL: {}",
            settings.proxy.upstream_url
        );
        println!();
    }
    println!("System endpoints:");
    println!("  GET  /ping            - Health check");
    println!("  GET  /auth/static/* - Static files (HTML, CSS, JS, images)");
    println!(
        "  Static files folder: {}",
        settings.static_files.assets_folder
    );
}

/// Create a session manager with authentication services based on settings
///
/// This function replaces the complex factory pattern with a simple, direct approach.
/// It creates a `SessionManager` and conditionally adds OAuth and Passkey services
/// based on the application settings.
///
/// # Arguments
/// * `settings` - The application settings containing authentication configuration
///
/// # Returns
/// A configured `SessionManager` with appropriate authentication services enabled
fn create_session_manager(settings: &VouchrsSettings) -> SessionManager {
    // Create base session manager
    let mut session_manager = SessionManager::new(
        settings.session.session_secret.as_bytes(),
        settings.cookies.secure,
        settings.session.session_duration_hours,
        settings.session.session_expiration_hours,
        settings.session.session_refresh_hours,
    );

    // Add OAuth service if providers are enabled
    if !settings.get_enabled_providers().is_empty() {
        let oauth_service = Arc::new(OAuthAuthenticationServiceImpl::new(settings.clone()));
        session_manager = session_manager.with_oauth_service(oauth_service);
        log::info!(
            "✅ OAuth authentication enabled with {} providers",
            settings.get_enabled_providers().len()
        );
    }

    // Add Passkey service if enabled
    if settings.passkeys.enabled {
        let passkey_service = Arc::new(PasskeyAuthenticationServiceImpl::new(settings.clone()));
        session_manager = session_manager.with_passkey_service(passkey_service);
        log::info!("✅ Passkey authentication enabled");
    }

    session_manager
}
